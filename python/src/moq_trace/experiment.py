"""Run relay latency experiments on the controller or across several hosts."""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import ipaddress
import logging
import os
import pathlib
import shlex
import socket
import time
import uuid
from collections.abc import Mapping, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import network
from .analyze import run as analyze
from .artifact import open_artifact
from .capture import (
    LttngSession,
    ManagedProcess,
    start_packet_capture,
    take_sudo_password,
    wait_for_log,
    wait_for_startup,
)
from .comparison import write_comparison
from .config import ComparisonConfig, ExperimentConfig, Host
from .metadata import (
    Affinity,
    Binaries,
    CommandSet,
    Window,
    Workload,
)
from .network import NetworkManifest
from .plot.common import format_byte_size
from .remote import RemoteHost, RemoteProcess
from .render import render

# Pinned for every implementation, so a run cannot silently negotiate a version
# that makes its trace incomparable with the rest of the matrix. Must match the
# peers' own pin in `moq-bench/src/lib.rs`.
PROTOCOL = "moq-transport-16"


_log = logging.getLogger(__name__)

# Builds the reference peers in a moq-trace checkout on a peer host. The flags
# enable flakes for this command alone, since a host's Nix may leave them off.
_BENCH_BUILD = "nix --extra-experimental-features 'nix-command flakes' develop --command just moq-bench-build"
# The reference peers' binary, relative to a moq-trace checkout.
_BENCH_BINARY = "moq-bench/target/release/moq-bench"


class ExperimentError(RuntimeError):
    """Experiment configuration, capture, or analysis failed."""


class _Roles:
    """The host each role runs on for one run, and the run directory on it.

    A role without a host runs on the controller. Roles that name the same ssh
    destination share one `RemoteHost`, so identity decides whether two roles
    are on one host.
    """

    def __init__(self, config: ExperimentConfig, output: pathlib.Path) -> None:
        self.output = output
        remotes: dict[str, RemoteHost] = {}

        def remote(host: Host | None) -> RemoteHost | None:
            return None if host is None else remotes.setdefault(host.ssh, RemoteHost(host))

        self.relay = remote(config.hosts.relay)
        self.publisher = remote(config.hosts.publisher)
        self.subscriber = remote(config.hosts.subscriber)
        # Distinguishes this run's remote directory from an earlier run's of the
        # same name, which is left in place.
        self.suffix = uuid.uuid4().hex[:8]

    def directory(self, host: RemoteHost | None) -> str:
        """The run directory on `host`, or the local one."""

        if host is None:
            return str(self.output)
        return f"{host.path(host.host.workdir)}/{self.output.name}-{self.suffix}"

    @staticmethod
    def where(host: RemoteHost | None) -> str:
        """Name a role's host for progress messages."""

        return "this machine" if host is None else host.name

    def launch(
        self,
        host: RemoteHost | None,
        name: str,
        command: Sequence[str],
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
    ) -> ManagedProcess:
        """Start one role's process on its host, logging to the local run directory."""

        log = self.output / f"{name}.log"
        if host is None:
            return ManagedProcess(name, command, self.output, log, env=env, stdin=stdin)
        return RemoteProcess(name, host, command, self.directory(host), log, env=env, stdin=stdin)


@dataclasses.dataclass(frozen=True)
class Capture:
    """One CTF recording and the processes it holds.

    `trace` is `None` when the run had tracing off and recorded nothing.
    `network` is the manifest describing the packet capture and qlog taken
    beside the trace.
    """

    trace: pathlib.Path | None
    relay_pid: int
    pids: tuple[int, ...]
    network: pathlib.Path | None = None


def _bench_command(config: ExperimentConfig, url: str, binary: str) -> list[str]:
    return [
        binary,
        "--client-connect",
        url,
        "--client-backend",
        "quinn",
        "--client-version",
        PROTOCOL,
        "--client-tls-disable-verify",
        "--startup",
        "0s",
        "--report",
        "200ms",
        "--fps",
        str(config.fps),
        "--frame-size",
        str(config.object_size),
        "--group-size",
        "0",
    ]


def _run_seconds(config: ExperimentConfig) -> float:
    """Wall time the workload runs, warm up and cool down included."""

    return config.warmup_seconds + config.duration_seconds + config.cooldown_seconds


def _relay_url(config: ExperimentConfig, roles: _Roles, peer: RemoteHost | None) -> str:
    """The URL a peer dials: loopback on the relay's host, the relay's address elsewhere."""

    if peer is roles.relay:
        return f"https://{config.relay_local_host}:{config.port}"
    if config.relay_url is not None:
        return config.relay_url
    if config.hosts.relay is None:
        raise ExperimentError("relay_url is required when a peer runs on another host than a local relay")
    return f"https://{config.hosts.relay.reachable_address}:{config.port}"


def _bench_binary(config: ExperimentConfig, host: RemoteHost | None, placement: Host | None) -> str:
    """The peer binary on the host a peer role runs on."""

    if host is None or placement is None:
        return str(config.bench_bin)
    default = _BENCH_BINARY if placement.checkout is not None else "moq-bench"
    return host.binary(placement.binary or default, placement.checkout)


def _relay_binary(config: ExperimentConfig, roles: _Roles) -> str:
    """The relay binary on the relay's host."""

    if roles.relay is None or config.hosts.relay is None:
        return str(config.relay_bin)
    return roles.relay.binary(config.hosts.relay.binary or "moq-relay", config.hosts.relay.checkout)


def commands(
    config: ExperimentConfig,
    output: pathlib.Path | None = None,
    roles: _Roles | None = None,
) -> CommandSet:
    """Construct exact argv arrays, each as it runs on its role's host, without a shell."""

    run_output = (output or config.output).resolve()
    roles = roles or _Roles(config, run_output)
    relay_directory = roles.directory(roles.relay)
    relay_binary = _relay_binary(config, roles)
    if config.relay_args is None:
        relay = [
            relay_binary,
            "--server-bind",
            f"[::]:{config.port}",
            "--server-backend",
            "quinn",
            "--server-version",
            PROTOCOL,
            "--tls-generate",
            "localhost",
            "--auth-public",
            "",
        ]
    else:
        values = {
            "port": str(config.port),
            "output": relay_directory,
            "certificate": f"{relay_directory}/relay.crt",
            "key": f"{relay_directory}/relay.key",
        }
        try:
            relay = [relay_binary, *(argument.format_map(values) for argument in config.relay_args)]
        except KeyError as error:
            raise ExperimentError(f"unknown relay argument placeholder: {error.args[0]}") from error
    if config.relay_cpu is not None:
        relay[:0] = ["taskset", "-c", str(config.relay_cpu)]

    publisher = _bench_command(
        config,
        _relay_url(config, roles, roles.publisher),
        _bench_binary(config, roles.publisher, config.hosts.publisher),
    )
    publisher.extend(["--name", "relay-latency", "--connections", "1", "--broadcasts", "1", "--subscribe", "0"])

    subscriber = _bench_command(
        config,
        _relay_url(config, roles, roles.subscriber),
        _bench_binary(config, roles.subscriber, config.hosts.subscriber),
    )
    # One session per subscriber, each taking a single subscription, so the relay
    # emits `subscribers` copies of every group for the analysis to compare against.
    subscriber.extend(
        [
            "--name",
            "relay-latency-subscribers",
            "--connections",
            str(config.subscribers),
            "--broadcasts",
            "0",
            "--subscribe",
            "1",
        ]
    )
    return CommandSet(relay=tuple(relay), publisher=tuple(publisher), subscriber=tuple(subscriber))


def _check_hosts(roles: _Roles) -> None:
    """Connect to every remote host once before anything slow starts.

    The connection stays open for the run's later commands, and a host that ssh
    cannot reach, or whose host key it refuses, fails the run in seconds instead
    of after another host's build.
    """

    checked = set()
    for host in (roles.relay, roles.publisher, roles.subscriber):
        if host is None or host.name in checked:
            continue
        checked.add(host.name)
        _log.info("connecting to %s", host.name)
        host.connect()
        # Reading the home directory caches it for every later remote path.
        host.home


def _build(config: ExperimentConfig, roles: _Roles) -> None:
    """Build each remote role's binary in its checkout, once per host and checkout."""

    built = set()
    for role, host, placement, default in (
        ("relay", roles.relay, config.hosts.relay, config.relay_build),
        ("publisher", roles.publisher, config.hosts.publisher, _BENCH_BUILD),
        ("subscriber", roles.subscriber, config.hosts.subscriber, _BENCH_BUILD),
    ):
        if host is None or placement is None or placement.checkout is None:
            continue
        command = placement.build if placement.build is not None else default
        if command is None:
            raise ExperimentError(
                f"no build command for the {role} on {host.name}; set relay_build, hosts.{role}.build, "
                "or an empty build to use the existing binary"
            )
        key = (host.name, host.path(placement.checkout), command)
        if not command or key in built:
            continue
        built.add(key)
        log = roles.output / f"build-{role}.log"
        _log.info("building the %s on %s: %s (log: %s)", role, host.name, command, log)
        started = time.monotonic()
        host.build(placement.checkout, command, log)
        _log.info("built the %s on %s in %.0fs", role, host.name, time.monotonic() - started)


def _validate_environment(config: ExperimentConfig) -> None:
    # A remote relay's CPUs are checked by taskset on that host when it starts.
    if config.hosts.relay is None and config.relay_cpu is not None and hasattr(os, "sched_getaffinity"):
        if config.relay_cpu not in os.sched_getaffinity(0):
            raise ExperimentError(f"relay CPU {config.relay_cpu} is unavailable to this process")


def _loopback_ifindexes() -> tuple[int, ...]:
    """Indexes of the host's loopback interfaces, read from their device flags."""

    indexes = []
    for index, name in socket.if_nameindex():
        try:
            flags = int((pathlib.Path("/sys/class/net") / name / "flags").read_text(), 16)
        except (OSError, ValueError):
            flags = 0x8 if name == "lo" else 0
        if flags & 0x8:
            indexes.append(index)
    return tuple(indexes)


def _network_manifest(config: ExperimentConfig, output: pathlib.Path, relay: RemoteHost | None) -> pathlib.Path:
    """Describe the run's network capture so analysis can place it on the trace clock.

    The clocks and interfaces are the relay host's, because the capture and the
    trace are both taken there.
    """

    if relay is None:
        offset = time.clock_gettime_ns(time.CLOCK_REALTIME) - time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        loopbacks = _loopback_ifindexes()
    else:
        offset, loopbacks = relay.clock()
    manifest = NetworkManifest(
        relay_port=config.port,
        realtime_offset_ns=offset,
        loopback_ifindexes=loopbacks,
        pcap="relay.pcap" if config.capture_packets else None,
        qlog_dir="qlog" if config.qlog else None,
    )
    path = output / network.MANIFEST
    path.write_text(manifest.model_dump_json(indent=2) + "\n")
    return path


def _capture_directory(roles: _Roles, relay: RemoteHost) -> str:
    """Where tcpdump writes on a remote relay host: a private directory on local disk.

    tcpdump opens its file after dropping from root to the user, and that
    process may lack the credentials a network home directory requires, as with
    Kerberos NFS, so it cannot write the run directory there. The directory is
    removed once the capture is copied back.
    """

    return f"/tmp/moq-trace-{relay.user}-{roles.suffix}"


def _prepare_relay_host(output: pathlib.Path, relay: RemoteHost, directory: str, qlog: bool) -> None:
    """Create the relay's run directory on its host and copy the TLS pair there."""

    directories = [directory, f"{directory}/qlog"] if qlog else [directory]
    relay.run(f"mkdir -p {shlex.join(directories)}")
    for name in ("relay.crt", "relay.key"):
        if (output / name).exists():
            relay.put(output / name, f"{directory}/{name}")


def _wait_for_workload(processes: Sequence[ManagedProcess], seconds: float) -> None:
    """Keep the workload running for the full interval after readiness.

    Even a successful early exit shortens the measurement, so every workload
    process must stay alive until the controller's monotonic deadline.
    """

    deadline = time.monotonic() + seconds
    while True:
        for process in processes:
            status = process.process.poll()
            if status is not None:
                raise ExperimentError(f"{process.name} exited with status {status} during the workload")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.1, remaining))


def _capture(
    config: ExperimentConfig,
    command: CommandSet,
    output: pathlib.Path,
    roles: _Roles | None = None,
) -> Capture:
    roles = roles or _Roles(config, output)
    relay_host = roles.relay
    relay_directory = roles.directory(relay_host)
    ctf = output / "trace"
    session = None
    if config.trace:
        if relay_host is None:
            session = LttngSession(ctf)
        else:
            session = LttngSession(f"{relay_directory}/trace", runner=relay_host.lttng)
    processes: list[ManagedProcess] = []
    where = roles.where
    try:
        manifest = _network_manifest(config, output, relay_host)
        if relay_host is not None:
            _prepare_relay_host(output, relay_host, relay_directory, config.qlog)
        elif config.qlog:
            (output / "qlog").mkdir()
        if config.capture_packets:
            _log.info("starting the packet capture on %s", where(relay_host))
            if relay_host is None:
                processes.append(
                    start_packet_capture(output / "relay.pcap", config.port, output, password=take_sudo_password())
                )
            else:
                capture_directory = _capture_directory(roles, relay_host)
                relay_host.run(f"mkdir -m 700 -p {shlex.quote(capture_directory)}")
                processes.append(
                    start_packet_capture(
                        f"{capture_directory}/relay.pcap",
                        config.port,
                        output,
                        launch=lambda name, argv, _log, stdin: roles.launch(relay_host, name, argv, stdin=stdin),
                        user=relay_host.user,
                        password=take_sudo_password(),
                    )
                )
        _log.info("starting the relay on %s", where(relay_host))
        # A relay that supports qlog writes it here. The capture works without it.
        relay = roles.launch(
            relay_host,
            "relay",
            command.relay,
            env={network.QLOG_ENVIRONMENT: f"{relay_directory}/qlog"} if config.qlog else None,
        )
        processes.append(relay)
        if config.relay_ready_log:
            marker = config.relay_ready_log
            wait_for_log(output / "relay.log", relay, lambda value: marker in value, marker, 15)
        else:
            wait_for_startup(relay, config.relay_startup_seconds)
        if session is not None:
            _log.info("waiting for the relay's trace providers, then starting the trace")
            session.wait_for_provider(relay.pid)
            session.start([relay.pid])
        tracked = [relay.pid]

        _log.info("starting %d subscriber(s) on %s", config.subscribers, where(roles.subscriber))
        subscriber = roles.launch(roles.subscriber, "subscriber", command.subscriber)
        processes.append(subscriber)
        # A peer is recorded only on the relay's own host, because the session
        # records one host and every relay metric stays on that host's clock.
        if roles.subscriber is relay_host:
            if session is not None:
                session.track(subscriber.pid)
            tracked.append(subscriber.pid)
        # Both bench binaries report live sessions and subscriptions in their stats
        # line, so the same readiness gate works for the reference peers and for the
        # load generator in the moq repository.
        connections = f"connections={config.subscribers}"
        wait_for_log(
            output / "subscriber.log",
            subscriber,
            lambda value: connections in value,
            "subscriber connections",
            20,
        )

        _log.info("subscribers connected; starting the publisher on %s", where(roles.publisher))
        publisher = roles.launch(roles.publisher, "publisher", command.publisher)
        processes.append(publisher)
        # Track on spawn rather than after readiness, so the connection setup that
        # the lifecycle metrics start from is recorded.
        if roles.publisher is relay_host:
            if session is not None:
                session.track(publisher.pid)
            tracked.append(publisher.pid)
        wait_for_log(
            output / "publisher.log",
            publisher,
            lambda value: "connections=1" in value,
            "publisher connection",
            15,
        )
        subscriptions = f"subscriptions={config.subscribers}"
        wait_for_log(
            output / "subscriber.log",
            subscriber,
            lambda value: connections in value and subscriptions in value,
            "subscriber connections and subscriptions",
            20,
        )
        _log.info(
            "workload running for %gs (%gs warm-up, %gs measured, %gs cool-down)",
            _run_seconds(config),
            config.warmup_seconds,
            config.duration_seconds,
            config.cooldown_seconds,
        )
        _wait_for_workload((relay, subscriber, publisher), _run_seconds(config))
        _log.info("workload finished; stopping the subscriber, publisher and relay")
        subscriber.stop(True)
        processes.remove(subscriber)
        publisher.stop(True)
        processes.remove(publisher)
        relay.stop(config.relay_graceful_stop)
        processes.remove(relay)
        for recorder in processes:
            recorder.stop(True)
        processes.clear()
        if session is not None:
            session.finish()
        if relay_host is not None:
            recorded = (("trace", session is not None), ("qlog", config.qlog))
            names = [name for name, present in recorded if present]
            if config.capture_packets:
                names.append("relay.pcap")
            if names:
                _log.info("copying %s back from %s", ", ".join(names), relay_host.name)
            relay_host.fetch(relay_directory, [name for name in names if name != "relay.pcap"], output)
            if config.capture_packets:
                capture_directory = _capture_directory(roles, relay_host)
                relay_host.fetch(capture_directory, ["relay.pcap"], output)
                relay_host.run(f"rm -rf {shlex.quote(capture_directory)}")
        trace = None if session is None else ctf
        return Capture(trace=trace, relay_pid=relay.pid, pids=tuple(tracked), network=manifest)
    finally:
        for process in reversed(processes):
            process.close()
        if session is not None:
            session.close()


def _file_hash(path: pathlib.Path) -> str | None:
    try:
        with path.open("rb") as source:
            digest = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
            return digest.hexdigest()
    except OSError:
        return None


def _generate_certificate(config: ExperimentConfig, output: pathlib.Path) -> None:
    """Generate the certificate requested by relay command placeholders.

    It matches what `openssl req -x509 -newkey rsa:2048 -nodes` writes: a
    self-signed RSA certificate for localhost valid for one day, with an
    unencrypted PKCS#8 key. The peers do not verify it, so it only has to be a
    certificate every relay accepts.
    """

    if config.relay_args is None or not any(
        placeholder in argument for argument in config.relay_args for placeholder in ("{certificate}", "{key}")
    ):
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    public_key = key.public_key()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
        .sign(key, hashes.SHA256())
    )
    (output / "relay.key").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (output / "relay.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def _binaries(config: ExperimentConfig, roles: _Roles) -> Binaries:
    """Name and hash the relay and publisher binaries on the hosts they ran on.

    A remote binary is named `<ssh destination>:<path>`, so a result from one
    host is never mistaken for another's.
    """

    def describe(host: RemoteHost | None, path: str) -> tuple[str, str | None]:
        if host is None:
            return path, _file_hash(pathlib.Path(path))
        return f"{host.name}:{path}", host.sha256(path)

    relay, relay_sha256 = describe(roles.relay, _relay_binary(config, roles))
    bench, bench_sha256 = describe(roles.publisher, _bench_binary(config, roles.publisher, config.hosts.publisher))
    return Binaries(relay=relay, relay_sha256=relay_sha256, bench=bench, bench_sha256=bench_sha256)


def _validate_workload(database: pathlib.Path) -> None:
    with open_artifact(database, "run") as (connection, _, _metadata):
        count, first, last = connection.execute(
            "SELECT count(DISTINCT group_id), min(group_id), max(group_id) "
            "FROM model.selected_objects JOIN model.objects USING(process_id, trace_id)"
        ).fetchone()
        if count != last - first + 1:
            raise ExperimentError("steady-state groups are not contiguous")


def run(config: ExperimentConfig) -> pathlib.Path:
    """Capture, analyze, and optionally render one workload.

    Returns the analysis database, or the run directory holding the peers' logs
    when tracing is off.
    """

    _validate_environment(config)
    output = config.output.resolve()
    if output.exists():
        raise ExperimentError(f"run output already exists: {output}")
    output.mkdir(parents=True)
    _log.info("run directory: %s", output)
    roles = _Roles(config, output)
    _check_hosts(roles)
    _build(config, roles)
    _generate_certificate(config, output)
    command = commands(config, output, roles)
    capture = _capture(config, command, output, roles)
    if capture.trace is None:
        return output
    database = output / "analysis.duckdb"
    _log.info("analyzing the trace")
    analyze(
        capture.trace,
        database,
        workload=Workload(
            subscribers=config.subscribers,
            object_size=config.object_size,
            publishers=1,
            objects_per_group=1,
            fps=config.fps,
        ),
        window=Window(
            warmup_seconds=config.warmup_seconds,
            cooldown_seconds=config.cooldown_seconds,
            duration_seconds=config.duration_seconds,
        ),
        expected_pids=capture.pids,
        pid=capture.relay_pid,
        transport_profile=config.transport_profile,
        protocol=PROTOCOL,
        affinity=(
            Affinity(mode="unpinned")
            if config.relay_cpu is None
            else Affinity(mode="single-core", cpu=config.relay_cpu)
        ),
        binaries=_binaries(config, roles),
        commands=command,
        network=capture.network,
    )
    _validate_workload(database)
    if config.render:
        _log.info("rendering figures into %s", output / "plots")
        render(database)
    return database


def compare(config: ComparisonConfig) -> pathlib.Path:
    """Run every value for one comparison dimension."""

    output = config.experiment.output.resolve()
    if output.exists():
        raise ExperimentError(f"comparison output already exists: {output}")
    output.mkdir(parents=True)
    runs = []
    for value in config.values:
        field = config.dimension
        run_config = config.experiment.model_copy(
            update={
                field: value,
                "output": output / f"{field.replace('_', '-')}-{value}",
                "render": False,
            }
        )
        database = run(run_config)
        label = (
            f"{value} {'subscriber' if value == 1 else 'subscribers'}"
            if field == "subscribers"
            else format_byte_size(value)
        )
        runs.append((label, database, value))
    database = output / "comparison.duckdb"
    write_comparison(database, config.dimension, runs)
    if config.experiment.render:
        render(database)
    return database
