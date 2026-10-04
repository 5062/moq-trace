from __future__ import annotations

import asyncio
import pathlib
import re
import shlex
import sys
import tempfile
import time
import unittest
from unittest import mock

import duckdb
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from support import run_metadata  # noqa: E402

from moq_trace import capture, experiment, hosts, lttng, network, placement, tcpdump, tls  # noqa: E402
from moq_trace import commands as commands_module  # noqa: E402
from moq_trace.artifact import write_metadata  # noqa: E402
from moq_trace.commands import commands  # noqa: E402
from moq_trace.config import ComparisonConfig, ExperimentConfig, HostConfig, Hosts  # noqa: E402
from moq_trace.errors import CaptureError  # noqa: E402
from moq_trace.experiment import ExperimentError, _validate_workload  # noqa: E402
from moq_trace.metadata import CommandSet  # noqa: E402


def _placement(config: ExperimentConfig, output: pathlib.Path | None = None) -> placement.Placement:
    return placement.Placement(config, output or config.output, hosts.SshPool())


def _peer(*lines: str, exit_status: int | None = None) -> tuple[str, ...]:
    """A stand-in role that prints `lines`, then runs until SIGINT, which it exits 0 on.

    With `exit_status`, it exits with that status right after printing instead.
    """

    body = "".join(f"echo {shlex.quote(line)}; " for line in lines)
    if exit_status is not None:
        return ("sh", "-c", f"{body}exit {exit_status}")
    return ("sh", "-c", f"trap 'exit 0' INT; {body}while :; do sleep 0.02; done")


def _command(relay=None, publisher=None, subscriber=None, subscribers: int = 1) -> CommandSet:
    return CommandSet(
        relay=relay or _peer("listening"),
        publisher=publisher or _peer("connections=1 subscriptions=0"),
        subscriber=subscriber or _peer(f"connections={subscribers} subscriptions={subscribers}"),
    )


class _FakeRemote(hosts.LocalHost):
    """A remote host whose processes run locally and whose ssh traffic is recorded.

    Its run directory is under the configured workdir, which a test points at a
    temporary directory, so the paths a run uses there are real.
    """

    def __init__(self, config: HostConfig, _pool) -> None:
        self.config = config
        self.name = config.ssh
        self.scripts: list[str] = []
        self.fetched: list[tuple[str, list[str]]] = []

    async def _shell(self, script, timeout):
        self.scripts.append(script)
        if " -c " in script and "clock_gettime_ns" in script:
            return await super()._shell(script, timeout)
        return hosts.Completed(0, "", "")

    async def fetch(self, directory, names, destination):
        self.fetched.append((directory, list(names)))

    def run_directory(self, output, suffix):
        return f"{self.config.workdir}/{output.name}-{suffix}"

    def qualify(self, path):
        return f"{self.name}:{path}"

    def binary(self, value, checkout):
        return value

    def path(self, value, base=None):
        return value


class _FakeSshProcess:
    """An asyncssh process whose merged output is `output` and whose status is `status`."""

    def __init__(self, output: bytes, status: int | None) -> None:
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(output)
        self.stdout.feed_eof()
        self._status = status
        self.closed = False

    async def wait(self):
        return mock.Mock(returncode=self._status)

    def close(self):
        self.closed = True


class _FakeConnection:
    """Stand in for an asyncssh connection whose commands all finish with `status`."""

    def __init__(self, status: int | None = 0, output: bytes = b"", stdout: str = "", stderr: str = "") -> None:
        self.create_process = mock.AsyncMock(side_effect=lambda *_a, **_k: _FakeSshProcess(output, status))
        self.run = mock.AsyncMock(return_value=mock.Mock(returncode=status, stdout=stdout, stderr=stderr))


def _connected(connection: _FakeConnection):
    """Hand `connection` to every host, instead of opening a real one."""

    return mock.patch.object(hosts.SshPool, "get", mock.AsyncMock(return_value=connection))


class ConfigurationTests(unittest.TestCase):
    """Configuration validation and command construction, which touch no host."""

    def test_experiment_requires_contiguous_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "analysis.duckdb"
            with duckdb.connect(str(database)) as connection:
                write_metadata(connection, run_metadata())
                connection.execute("CREATE SCHEMA model")
                connection.execute(
                    """CREATE TABLE model.objects AS SELECT 0 AS process_id,
                       unnest([4, 6]) AS trace_id, unnest([4, 6]) AS group_id"""
                )
                connection.execute(
                    "CREATE TABLE model.selected_objects AS SELECT process_id, trace_id FROM model.objects"
                )
            with self.assertRaisesRegex(ExperimentError, "groups are not contiguous"):
                _validate_workload(database)
            with duckdb.connect(str(database)) as connection:
                connection.execute("INSERT INTO model.objects VALUES (0, 5, 5)")
                connection.execute("INSERT INTO model.selected_objects VALUES (0, 5)")
            _validate_workload(database)

    def test_the_relay_certificate_is_a_self_signed_localhost_pair(self) -> None:
        config = ExperimentConfig(output=pathlib.Path("run"), relay_args=("--cert", "{certificate}"))
        self.assertTrue(tls.needs_certificate(config))
        self.assertFalse(tls.needs_certificate(ExperimentConfig(output=pathlib.Path("run"))))
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            tls.generate_certificate(output)
            certificate = x509.load_pem_x509_certificate((output / tls.CERTIFICATE).read_bytes())
            key = serialization.load_pem_private_key((output / tls.KEY).read_bytes(), password=None)

        self.assertEqual(certificate.subject, certificate.issuer)
        self.assertEqual(certificate.public_key().public_numbers(), key.public_key().public_numbers())
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(names.get_values_for_type(x509.DNSName), ["localhost"])
        self.assertEqual([str(address) for address in names.get_values_for_type(x509.IPAddress)], ["127.0.0.1"])

    def test_peers_dial_loopback_on_the_relay_host_and_its_address_elsewhere(self) -> None:
        relay = HostConfig(
            ssh="me@relay.example", address="10.0.0.1", binary="/opt/relay/moq-relay", workdir="/tmp/runs"
        )
        peer = HostConfig(ssh="me@peer.example", checkout="/srv/moq-trace", workdir="/tmp/runs")
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            relay_args=("--cert", "{certificate}"),
            relay_local_host="127.0.0.1",
            hosts=Hosts(relay=relay, publisher=relay, subscriber=peer),
        )

        command = commands(config, _placement(config))

        self.assertEqual(command.relay[0], "/opt/relay/moq-relay")
        self.assertRegex(command.relay[2], r"^/tmp/runs/run-[0-9a-f]{8}/relay.crt$")
        self.assertEqual(command.publisher[command.publisher.index("--client-connect") + 1], "https://127.0.0.1:4443")
        self.assertEqual(command.subscriber[command.subscriber.index("--client-connect") + 1], "https://10.0.0.1:4443")
        self.assertEqual(command.subscriber[0], "/srv/moq-trace/moq-bench/target/release/moq-bench")

    def test_a_local_relay_needs_a_url_for_remote_peers(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            relay_url="https://relay.example.com:4443",
            hosts=Hosts(subscriber=HostConfig(ssh="me@peer.example", binary="/usr/bin/moq-bench")),
        )

        command = commands(config, _placement(config))

        self.assertEqual(command.subscriber[command.subscriber.index("--client-connect") + 1], config.relay_url)
        self.assertEqual(command.publisher[command.publisher.index("--client-connect") + 1], "https://localhost:4443")

    def test_local_binaries_are_absolute_before_working_directory_changes(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            relay_bin=pathlib.Path("target/release/moq-relay"),
            bench_bin=pathlib.Path("target/release/moq-bench"),
        )

        command = commands(config, _placement(config))

        self.assertEqual(pathlib.Path(command.relay[0]), config.relay_bin.resolve())
        self.assertEqual(pathlib.Path(command.publisher[0]), config.bench_bin.resolve())
        self.assertEqual(pathlib.Path(command.subscriber[0]), config.bench_bin.resolve())

    def test_default_binaries_are_absolute(self) -> None:
        # Child processes run from the output directory, so a defaulted relative path
        # would resolve against the wrong directory and never start.
        config = ExperimentConfig(output=pathlib.Path("run"))

        self.assertTrue(config.relay_bin.is_absolute())
        self.assertTrue(config.bench_bin.is_absolute())
        self.assertEqual(config.bench_bin.name, "moq-bench")

    def test_protocol_matches_the_reference_peers(self) -> None:
        # Both sides pin the version that every implementation has to negotiate, so a
        # drift here either fails the handshake or changes the wire under the trace.
        source = pathlib.Path(__file__).resolve().parents[2] / "moq-bench/src/lib.rs"
        pinned = re.findall(r'VERSION: &str = "([^"]+)"', source.read_text())

        self.assertEqual(pinned, [commands_module.PROTOCOL])

    def test_remote_subscriber_requires_relay_url(self) -> None:
        with self.assertRaisesRegex(ValidationError, "relay_url is required"):
            ExperimentConfig(output=pathlib.Path("run"), hosts=Hosts(subscriber=HostConfig(ssh="relay@example.com")))

    def test_remote_relay_requires_a_binary(self) -> None:
        with self.assertRaisesRegex(ValidationError, "hosts.relay.binary"):
            ExperimentConfig(output=pathlib.Path("run"), hosts=Hosts(relay=HostConfig(ssh="relay@example.com")))

    def test_experiment_validates_workload_and_window(self) -> None:
        with self.assertRaises(ValidationError):
            ExperimentConfig(output=pathlib.Path("run"), object_size=0)
        with self.assertRaises(ValidationError):
            ExperimentConfig(output=pathlib.Path("run"), warmup_seconds=-1)

    def test_peer_commands_leave_duration_to_the_controller(self) -> None:
        config = ExperimentConfig(output=pathlib.Path("run"), subscribers=3, object_size=1024, fps=15)

        command = commands(config, _placement(config))

        self.assertEqual(command.subscriber[command.subscriber.index("--connections") + 1], "3")
        self.assertNotIn("--duration", command.subscriber)
        self.assertNotIn("--duration", command.publisher)

    def test_custom_relay_arguments_expand_run_paths(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("configured"),
            relay_args=("--port", "{port}", "--certificate_file", "{certificate}"),
            port=19667,
        )

        relay = commands(config, _placement(config, pathlib.Path("actual"))).relay

        self.assertEqual(relay[1:3], ("--port", "19667"))
        self.assertEqual(relay[4], "actual/relay.crt")

    def test_comparison_values_are_distinct(self) -> None:
        with self.assertRaises(ValidationError):
            ComparisonConfig(
                experiment=ExperimentConfig(output=pathlib.Path("run")), dimension="subscribers", values=(1, 1)
            )

    def test_comparison_requires_tracing(self) -> None:
        with self.assertRaisesRegex(ValidationError, "requires tracing"):
            ComparisonConfig(
                experiment=ExperimentConfig(output=pathlib.Path("run"), trace=False),
                dimension="subscribers",
                values=(1, 2),
            )

    def test_readiness_gauges_match_whole_values(self) -> None:
        connected = experiment._gauge("connections", 1)
        self.assertTrue(connected("INFO stats connections=1 subscriptions=0"))
        self.assertFalse(connected("INFO stats connections=10 subscriptions=0"))

    def test_provider_listing_reads_the_lttng_machine_interface(self) -> None:
        # Mirrors `lttng --mi xml list --userspace` from LTTng 2.15, trimmed to the
        # elements the capture reads.
        listing = """<?xml version="1.0" encoding="UTF-8"?>
<command xmlns="https://lttng.org/xml/ns/lttng-mi" schemaVersion="4.2">
  <name>list</name>
  <output><domains><domain>
    <type>UST</type>
    <pids>
      <pid>
        <id>4242</id>
        <name>/opt/relay/moq-relay</name>
        <events>
          <event><name>lttng_ust_lib:build_id</name><type>TRACEPOINT</type></event>
          <event><name>moq_trace:moq_object_end</name><type>TRACEPOINT</type></event>
          <event><name>quic_trace:udp_socket_end</name><type>TRACEPOINT</type></event>
        </events>
      </pid>
      <pid>
        <id>424</id>
        <name>/opt/relay/moq-relay-old</name>
        <events><event><name>moq_trace:moq_object_end_extra</name></event></events>
      </pid>
    </pids>
  </domain></domains></output>
  <success>true</success>
</command>
"""
        self.assertTrue(lttng.provider_listed(listing, 4242, "moq_trace:moq_object_end"))
        self.assertTrue(lttng.provider_listed(listing, 4242, "quic_trace:udp_socket_end"))
        self.assertFalse(lttng.provider_listed(listing, 4242, "quic_trace:quic_packet_start"))
        self.assertFalse(lttng.provider_listed(listing, 424, "moq_trace:moq_object_end"))
        self.assertFalse(lttng.provider_listed(listing, 42, "moq_trace:moq_object_end"))

    def test_provider_listing_rejects_human_readable_output(self) -> None:
        with self.assertRaisesRegex(CaptureError, "machine interface XML"):
            lttng.provider_listed("PID: 1234 - Name: /opt/relay/moq-relay\n", 1234, "moq_trace:moq_object_end")

    def test_sudo_reads_a_password_from_stdin_only_when_one_is_given(self) -> None:
        self.assertEqual(tcpdump.packet_capture_command("a.pcap", 4443, "me")[:3], ["sudo", "-n", "tcpdump"])
        self.assertEqual(
            tcpdump.packet_capture_command("a.pcap", 4443, "me", password=True)[:5], ["sudo", "-S", "-p", "", "tcpdump"]
        )

    def test_the_sudo_password_leaves_the_environment(self) -> None:
        with (
            mock.patch.dict(tcpdump.os.environ, {tcpdump.SUDO_PASSWORD_ENVIRONMENT: "s3cret"}),
            mock.patch.object(tcpdump, "_sudo_password", None),
        ):
            self.assertEqual(tcpdump.take_sudo_password(), "s3cret")
            self.assertNotIn(tcpdump.SUDO_PASSWORD_ENVIRONMENT, tcpdump.os.environ)
            self.assertEqual(tcpdump.take_sudo_password(), "s3cret")


class LocalHostTests(unittest.IsolatedAsyncioTestCase):
    """Run real processes on this machine through the host interface."""

    async def asyncSetUp(self) -> None:
        self.directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.host = hosts.LocalHost()

    async def test_a_process_reports_its_own_pid_and_logs_its_output(self) -> None:
        process = await self.host.start(
            "echo", ["sh", "-c", "echo $$; echo ready"], str(self.directory), self.directory / "e.log"
        )
        self.assertEqual(await process.wait(), 0)
        self.assertEqual(process.lines, [str(process.pid), "ready"])
        self.assertEqual((self.directory / "e.log").read_text(), f"{process.pid}\nready\n")

    async def test_a_process_receives_its_stdin_and_then_end_of_input(self) -> None:
        log = self.directory / "cat.log"
        process = await self.host.start("cat", ["cat"], str(self.directory), log, stdin=b"hello\n")
        self.assertEqual(await process.wait(), 0)
        self.assertEqual(log.read_text(), "hello\n")

    async def test_a_process_sees_its_environment_and_directory(self) -> None:
        cwd = self.directory / "made"
        process = await self.host.start(
            "env", ["sh", "-c", 'echo "$K" "$PWD"'], str(cwd), self.directory / "env.log", env={"K": "a b"}
        )
        await process.wait()
        self.assertEqual(process.lines, [f"a b {cwd}"])

    async def test_readiness_waits_for_a_line_and_fails_on_exit_or_timeout(self) -> None:
        colored = (
            "sh",
            "-c",
            "trap 'exit 0' INT; printf '\\033[32mlistening\\033[0m\\n'; while :; do sleep 0.02; done",
        )
        process = await self.host.start("peer", colored, str(self.directory), self.directory / "p.log")
        await process.wait_for_line(lambda line: line == "listening", "listening", 5)
        with self.assertRaisesRegex(CaptureError, "timed out after 0.1s waiting for never"):
            await process.wait_for_line(lambda line: False, "never", 0.1)
        await process.stop(True)

        early = await self.host.start(
            "early", _peer("booting", exit_status=3), str(self.directory), self.directory / "x.log"
        )
        with self.assertRaisesRegex(CaptureError, "early exited with status 3 before it reported ready"):
            await early.wait_for_line(lambda line: line == "ready", "ready", 5)

    async def test_a_graceful_stop_requires_a_clean_exit(self) -> None:
        process = await self.host.start("sleep", ["sleep", "30"], str(self.directory), self.directory / "s.log")
        with self.assertRaisesRegex(CaptureError, "sleep exited with status -2"):
            await process.stop(True)
        await process.close()

    async def test_a_process_must_hold_through_startup(self) -> None:
        early = await self.host.start("relay", _peer(exit_status=7), str(self.directory), self.directory / "r.log")
        with self.assertRaisesRegex(CaptureError, "relay exited with status 7 during startup"):
            await early.hold(1)
        steady = await self.host.start("relay", _peer(), str(self.directory), self.directory / "r2.log")
        await steady.hold(0.05)
        await steady.stop(True)

    async def test_a_failed_build_names_its_log(self) -> None:
        log = self.directory / "build.log"
        with self.assertRaisesRegex(CaptureError, f"failed with status 2; see {log}"):
            await self.host.build(str(self.directory), "echo compiling; exit 2", log)
        self.assertEqual(log.read_text(), "compiling\n")

    async def test_the_clock_probe_reports_the_realtime_offset(self) -> None:
        clock = await self.host.clock()
        self.assertAlmostEqual(clock.offset_ns / 1e9, time.time() - time.monotonic(), delta=5)
        # The tightest of several brackets is far below a millisecond.
        self.assertLess(clock.uncertainty_ns, 1_000_000)
        self.assertIsInstance(clock.loopback_ifindexes, tuple)

    async def test_the_workload_rejects_even_successful_early_exits(self) -> None:
        for status in (0, 7):
            with self.subTest(status=status):
                steady = await self.host.start("relay", _peer(), str(self.directory), self.directory / "r.log")
                early = await self.host.start(
                    "publisher", _peer(exit_status=status), str(self.directory), self.directory / "p.log"
                )
                with self.assertRaisesRegex(
                    ExperimentError, f"publisher exited with status {status} during the workload"
                ):
                    await experiment._wait_for_workload((steady, early), 5)
                await steady.close()


class RemoteHostTests(unittest.IsolatedAsyncioTestCase):
    """Drive a remote host through a stand-in asyncssh connection."""

    async def asyncSetUp(self) -> None:
        self.directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.host = hosts.RemoteHost(HostConfig(ssh="me@peer.example"), hosts.SshPool())

    async def test_a_remote_process_reports_its_pid_and_quotes_its_command(self) -> None:
        connection = _FakeConnection(output=b"4242\nready\n")
        with _connected(connection) as connected:
            log = self.directory / "subscriber.log"
            process = await self.host.start(
                "subscriber", ["/opt/a dir/moq-bench", "--x"], "/tmp/a run", log, env={"K": "a b"}
            )
            self.assertEqual(await process.wait(), 0)

        connected.assert_awaited_with("me@peer.example")
        self.assertEqual(process.pid, 4242)
        self.assertEqual(log.read_bytes(), b"ready\n")
        script, options = connection.create_process.call_args.args[0], connection.create_process.call_args.kwargs
        self.assertEqual(
            script,
            "mkdir -p '/tmp/a run' && cd '/tmp/a run' && echo $$ && exec env K='a b' '/opt/a dir/moq-bench' --x",
        )
        self.assertIs(options["stdin"], hosts.asyncssh.DEVNULL)

    async def test_a_remote_process_receives_its_stdin_and_reports_its_status(self) -> None:
        connection = _FakeConnection(status=7, output=b"99\n")
        with _connected(connection):
            process = await self.host.start("tcpdump", ["tcpdump"], "/tmp/run", self.directory / "t.log", stdin=b"pw\n")
            with self.assertRaisesRegex(CaptureError, "tcpdump exited with status 7"):
                await process.stop(True)

        self.assertEqual(connection.create_process.call_args.kwargs["input"], b"pw\n")

    async def test_a_remote_process_that_loses_its_connection_reports_what_ssh_would(self) -> None:
        with _connected(_FakeConnection(status=None, output=b"99\n")):
            process = await self.host.start("relay", ["relay"], "/tmp/run", self.directory / "r.log")
            self.assertEqual(await process.wait(), 255)

    async def test_a_remote_process_that_never_starts_reports_why(self) -> None:
        with _connected(_FakeConnection(status=1, output=b"mkdir: cannot create directory\n")):
            with self.assertRaisesRegex(CaptureError, "relay did not start \\(status 1\\): mkdir: cannot create"):
                await self.host.start("relay", ["relay"], "/root/run", self.directory / "r.log")

    async def test_lttng_runs_through_the_hosts_configured_command(self) -> None:
        host = hosts.RemoteHost(
            HostConfig(ssh="me@relay.example", lttng="nix develop ~/moq-trace --command lttng"), hosts.SshPool()
        )
        connection = _FakeConnection(status=1, stdout="<command/>", stderr="no session daemon")
        with _connected(connection):
            result = await host.lttng(("--mi", "xml", "list", "--userspace"))

        self.assertEqual(
            connection.run.call_args.args[0], "nix develop ~/moq-trace --command lttng --mi xml list --userspace"
        )
        self.assertEqual(result, hosts.Completed(1, "<command/>", "no session daemon"))

    async def test_connecting_reads_the_remote_home_for_relative_paths(self) -> None:
        with _connected(_FakeConnection(stdout="/home/me\nme\n")):
            await self.host.connect()
        self.assertEqual(self.host.user, "me")
        self.assertEqual(self.host.path("runs"), "/home/me/runs")
        self.assertEqual(self.host.path("~/src", "/srv"), "/home/me/src")
        self.assertEqual(self.host.binary("moq-bench", None), "moq-bench")
        self.assertEqual(self.host.binary("bin/relay", "src/relay"), "/home/me/src/relay/bin/relay")

    async def test_an_unreachable_host_is_a_capture_error(self) -> None:
        with mock.patch.object(hosts.asyncssh, "connect", side_effect=OSError("connection refused")) as connect:
            with self.assertRaisesRegex(CaptureError, "ssh me@peer.example failed: connection refused"):
                await self.host.connect()

        self.assertEqual(connect.call_args.args, ("peer.example",))
        self.assertEqual(connect.call_args.kwargs["username"], "me")


class _LttngHost(hosts.LocalHost):
    """A host whose `lttng` records its arguments and lists nothing."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    async def lttng(self, args):
        self.calls.append(tuple(args))
        return hosts.Completed(0, "<command/>", "")


class LttngAndPacketCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_session_enables_both_providers_and_tracks_every_process(self) -> None:
        host = _LttngHost()
        session = lttng.LttngSession(host, "/runs/trace")
        await session.open()
        await session.start([123])
        await session.track(456)
        await session.finish()
        await session.close()

        self.assertEqual(host.calls[0][:2], ("create", session.name))
        self.assertEqual(
            [call[-1] for call in host.calls if call[0] == "enable-event"], ["moq_trace:*", "quic_trace:*"]
        )
        self.assertEqual([call[-1] for call in host.calls if call[0] == "track"], ["--vpid=123", "--vpid=456"])
        # Every event names its process and thread.
        self.assertEqual([call[-1] for call in host.calls if call[0] == "add-context"], ["vpid", "vtid"])
        self.assertEqual(host.calls[-1], ("destroy", session.name))

    async def test_the_provider_check_asks_lttng_for_xml_and_times_out(self) -> None:
        host = _LttngHost()
        with self.assertRaisesRegex(CaptureError, "timed out waiting for MoQ and QUIC trace providers"):
            await lttng.LttngSession(host, "/runs/trace").wait_for_provider(123, timeout=0.1)
        self.assertEqual(host.calls[0], ("--mi", "xml", "list", "--userspace"))

    async def test_the_sudo_password_reaches_the_capture_only_on_stdin(self) -> None:
        host = mock.Mock(user="me")
        host.start = mock.AsyncMock()
        with mock.patch.object(tcpdump, "_sudo_password", "s3cret"):
            await tcpdump.start_packet_capture(host, "/tmp/capture", 4443, pathlib.Path("tcpdump.log"))

        name, argv, cwd, _log = host.start.call_args.args
        self.assertEqual((name, cwd), ("tcpdump", "/tmp/capture"))
        self.assertEqual(host.start.call_args.kwargs["stdin"], b"s3cret\n")
        self.assertNotIn("s3cret", " ".join(argv))
        self.assertEqual(argv[argv.index("-w") + 1], "/tmp/capture/relay.pcap")
        self.assertEqual(argv[argv.index("-Z") + 1], "me")


class CaptureTests(unittest.IsolatedAsyncioTestCase):
    """Run the capture with local stand-in roles and recorded remote hosts."""

    async def asyncSetUp(self) -> None:
        self.root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(placement, "RemoteHost", _FakeRemote))

    def _config(self, **overrides) -> ExperimentConfig:
        fields = {"output": self.root / "run", "warmup_seconds": 0, "duration_seconds": 0.2, "cooldown_seconds": 0}
        fields.update(overrides)
        return ExperimentConfig(**fields)

    def _remote(self, name: str, **fields) -> HostConfig:
        return HostConfig(ssh=f"me@{name}", workdir=str(self.root / name), **fields)

    async def _capture(self, config: ExperimentConfig, command: CommandSet | None = None):
        config.output.mkdir()
        where = _placement(config)
        return where, await experiment._capture(config, command or _command(subscribers=config.subscribers), where)

    async def test_a_local_capture_runs_the_full_interval_and_records_every_role(self) -> None:
        config = self._config(trace=False, subscribers=2)
        started = time.monotonic()
        _, result = await self._capture(config)

        self.assertGreaterEqual(time.monotonic() - started, 0.2)
        self.assertIsNone(result.trace)
        self.assertEqual(len(set(result.pids)), 3)
        self.assertEqual(result.pids[0], result.relay_pid)
        for role in ("relay", "subscriber", "publisher"):
            self.assertTrue((config.output / f"{role}.log").exists())

    async def test_a_traced_capture_tracks_local_peers(self) -> None:
        with mock.patch.object(capture, "LttngSession", autospec=True) as session_class:
            _, result = await self._capture(self._config())

        session = session_class.return_value
        self.assertEqual(result.trace, self._config().output / "trace")
        session.start.assert_awaited_once_with([result.relay_pid])
        self.assertEqual(session.track.await_args_list, [mock.call(result.pids[1]), mock.call(result.pids[2])])
        session.finish.assert_awaited_once()

    async def test_a_failed_recording_open_closes_the_partial_session(self) -> None:
        with mock.patch.object(capture, "LttngSession", autospec=True) as session_class:
            session = session_class.return_value
            session.open.side_effect = CaptureError("channel creation failed")
            with self.assertRaisesRegex(CaptureError, "channel creation failed"):
                await self._capture(self._config())
            session.close.assert_awaited_once()
            session.start.assert_not_awaited()

    async def test_workload_failure_closes_recorders_without_publishing_a_manifest(self) -> None:
        config = self._config(capture_packets=True, duration_seconds=5)
        packet_capture = mock.Mock(stop=mock.AsyncMock(), close=mock.AsyncMock())
        with (
            mock.patch.object(capture, "LttngSession", autospec=True) as session_class,
            mock.patch.object(capture, "start_packet_capture", mock.AsyncMock(return_value=packet_capture)),
        ):
            publisher = ("sh", "-c", "echo connections=1; sleep 0.1; exit 0")
            with self.assertRaisesRegex(ExperimentError, "publisher exited"):
                await self._capture(config, _command(publisher=publisher))
            session_class.return_value.close.assert_awaited_once()
            session_class.return_value.finish.assert_not_awaited()
            packet_capture.close.assert_awaited_once()
            self.assertFalse((config.output / network.MANIFEST).exists())

    async def test_a_remote_subscriber_is_not_recorded(self) -> None:
        config = self._config(trace=False, hosts=Hosts(subscriber=self._remote("peer")), relay_url="https://r:4443")
        where, result = await self._capture(config)

        # The session records the relay's host, which the subscriber is not on.
        self.assertEqual(len(result.pids), 2)
        self.assertTrue(where.directory(where.subscriber).startswith(str(self.root / "peer")))

    async def test_a_remote_relay_is_traced_on_its_host_and_copied_back(self) -> None:
        config = self._config(hosts=Hosts(relay=self._remote("relay", binary="/opt/relay")), qlog=True)
        with mock.patch.object(capture, "LttngSession", autospec=True) as session_class:
            relay = ("sh", "-c", "trap 'exit 0' INT; echo \"$QLOGDIR\"; echo listening; while :; do sleep 0.02; done")
            where, result = await self._capture(config, _command(relay=relay))

        relay_directory = where.directory(where.relay)
        session_class.assert_called_once_with(where.relay, f"{relay_directory}/trace")
        self.assertEqual(where.relay.scripts[1], f"mkdir -p {relay_directory} {relay_directory}/qlog")
        self.assertEqual(where.relay.fetched, [(relay_directory, ["trace", "qlog"])])
        self.assertEqual((config.output / "relay.log").read_text().splitlines()[0], f"{relay_directory}/qlog")
        # Neither peer shares the relay's host, so only the relay is recorded.
        self.assertEqual(result.pids, (result.relay_pid,))
        manifest = network.read_manifest(result.network)
        self.assertEqual((manifest.pcap, manifest.qlog_dir), (None, "qlog"))

    async def test_a_local_packet_capture_is_copied_into_the_run(self) -> None:
        tcpdump_process = mock.Mock()
        tcpdump_process.stop = mock.AsyncMock()
        tcpdump_process.close = mock.AsyncMock()

        async def start(host, directory, port, log):
            pathlib.Path(directory, "relay.pcap").write_bytes(b"pcap")
            return tcpdump_process

        config = self._config(trace=False, capture_packets=True)
        with mock.patch.object(capture, "start_packet_capture", side_effect=start) as start_capture:
            where, _ = await self._capture(config)

        host, directory, port, _log = start_capture.call_args.args
        self.assertEqual((host, directory, port), (where.relay, where.capture_directory(), config.port))
        tcpdump_process.stop.assert_awaited_once_with(True)
        self.assertEqual((config.output / "relay.pcap").read_bytes(), b"pcap")
        self.assertFalse(pathlib.Path(directory).exists())
        manifest = network.read_manifest(config.output / network.MANIFEST)
        self.assertEqual((manifest.pcap, manifest.capture_log), ("relay.pcap", "tcpdump.log"))
        self.assertEqual(manifest.key_logs, ("subscriber.keylog", "publisher.keylog"))

    async def test_peers_log_their_tls_secrets_beside_a_packet_capture(self) -> None:
        tcpdump_process = mock.Mock()
        tcpdump_process.stop = mock.AsyncMock()
        tcpdump_process.close = mock.AsyncMock()

        async def start(host, directory, port, log):
            pathlib.Path(directory, "relay.pcap").write_bytes(b"pcap")
            return tcpdump_process

        config = self._config(
            trace=False, capture_packets=True, hosts=Hosts(subscriber=self._remote("peer")), relay_url="https://r:4443"
        )
        # Each peer reports where it was told to write its key log.
        subscriber = ("sh", "-c", "echo keylog=$SSLKEYLOGFILE; " + " ".join(_command().subscriber[2:]))
        publisher = ("sh", "-c", "echo keylog=$SSLKEYLOGFILE; " + " ".join(_command().publisher[2:]))
        with mock.patch.object(capture, "start_packet_capture", side_effect=start):
            where, _ = await self._capture(config, _command(subscriber=subscriber, publisher=publisher))

        remote = where.directory(where.subscriber)
        self.assertIn(f"keylog={remote}/subscriber.keylog", (config.output / "subscriber.log").read_text())
        self.assertIn(f"keylog={config.output}/publisher.keylog", (config.output / "publisher.log").read_text())
        self.assertIn((remote, ["subscriber.keylog"]), where.subscriber.fetched)

    async def test_a_startup_delay_replaces_the_log_marker(self) -> None:
        config = self._config(trace=False, relay_ready_log="", relay_startup_seconds=1)
        with self.assertRaisesRegex(CaptureError, "relay exited with status 5 during startup"):
            await self._capture(config, _command(relay=_peer(exit_status=5)))

    async def test_a_peer_that_exits_early_fails_the_run_and_stops_the_rest(self) -> None:
        config = self._config(trace=False, duration_seconds=5)
        publisher = ("sh", "-c", "echo connections=1; sleep 0.1; exit 0")
        started = time.monotonic()
        with self.assertRaisesRegex(ExperimentError, "publisher exited with status 0 during the workload"):
            await self._capture(config, _command(publisher=publisher))
        self.assertLess(time.monotonic() - started, 4)

    async def test_building_runs_once_per_host_and_checkout(self) -> None:
        relay = HostConfig(ssh="me@relay.example", checkout="/srv/relay", binary="bin/relay", workdir="/tmp/runs")
        peer = HostConfig(ssh="me@peer.example", checkout="/srv/moq-trace", workdir="/tmp/runs")
        config = self._config(relay_build="make relay", hosts=Hosts(relay=relay, publisher=peer, subscriber=peer))
        with mock.patch.object(_FakeRemote, "build", autospec=True) as build:
            await _placement(config).build()

        self.assertEqual(
            [call.args[1:3] for call in build.await_args_list],
            [("/srv/relay", "make relay"), ("/srv/moq-trace", placement.BENCH_BUILD)],
        )

    async def test_a_remote_relay_without_a_build_command_is_rejected(self) -> None:
        relay = HostConfig(ssh="me@relay.example", checkout="/srv/relay", binary="bin/relay")
        with self.assertRaisesRegex(CaptureError, "no build command for the relay"):
            await _placement(self._config(hosts=Hosts(relay=relay))).build()

    async def test_every_host_is_connected_once(self) -> None:
        relay = HostConfig(ssh="me@relay.example", binary="/opt/relay")
        peer = HostConfig(ssh="me@peer.example")
        config = self._config(hosts=Hosts(relay=relay, publisher=peer, subscriber=peer))
        with mock.patch.object(_FakeRemote, "connect", autospec=True) as connect:
            await _placement(config).connect()

        self.assertEqual(
            sorted(call.args[0].name for call in connect.await_args_list), ["me@peer.example", "me@relay.example"]
        )


if __name__ == "__main__":
    unittest.main()
