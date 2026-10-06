from __future__ import annotations

import pathlib
import re
import sys
import tempfile
import unittest
from unittest import mock

import duckdb
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from run_support import placement_for  # noqa: E402
from support import run_metadata  # noqa: E402

from moq_trace.analysis.artifact import write_metadata  # noqa: E402
from moq_trace.errors import CaptureError  # noqa: E402
from moq_trace.run import commands as commands_module  # noqa: E402
from moq_trace.run import experiment, lttng, tcpdump, tls  # noqa: E402
from moq_trace.run.commands import commands  # noqa: E402
from moq_trace.run.config import ComparisonConfig, ExperimentConfig, HostConfig, Hosts  # noqa: E402
from moq_trace.run.experiment import ExperimentError, _validate_workload  # noqa: E402


class ConfigurationTests(unittest.TestCase):
    """Configuration validation and command construction, which touch no host."""

    def test_experiment_requires_contiguous_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "analysis.duckdb"
            with duckdb.connect(str(database)) as connection:
                write_metadata(connection, run_metadata())
                connection.execute("CREATE SCHEMA model")
                connection.execute(
                    """CREATE TABLE model.objects AS
                       SELECT unnest([4, 6]) AS trace_id, unnest([4, 6]) AS group_id"""
                )
                connection.execute("CREATE TABLE model.selected_objects AS SELECT trace_id FROM model.objects")
            with self.assertRaisesRegex(ExperimentError, "groups are not contiguous"):
                _validate_workload(database)
            with duckdb.connect(str(database)) as connection:
                connection.execute("INSERT INTO model.objects VALUES (5, 5)")
                connection.execute("INSERT INTO model.selected_objects VALUES (5)")
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

        command = commands(config, placement_for(config))

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

        command = commands(config, placement_for(config))

        self.assertEqual(command.subscriber[command.subscriber.index("--client-connect") + 1], config.relay_url)
        self.assertEqual(command.publisher[command.publisher.index("--client-connect") + 1], "https://localhost:4443")

    def test_local_binaries_are_absolute_before_working_directory_changes(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            relay_bin=pathlib.Path("target/release/moq-relay"),
            bench_bin=pathlib.Path("target/release/moq-bench"),
        )

        command = commands(config, placement_for(config))

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

        command = commands(config, placement_for(config))

        self.assertEqual(command.subscriber[command.subscriber.index("--connections") + 1], "3")
        # The peers count the frames after each group's keyframe.
        self.assertEqual(command.publisher[command.publisher.index("--group-size") + 1], "29")
        self.assertNotIn("--duration", command.subscriber)
        self.assertNotIn("--duration", command.publisher)

    def test_custom_relay_arguments_expand_run_paths(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("configured"),
            relay_args=("--port", "{port}", "--certificate_file", "{certificate}"),
            port=19667,
        )

        relay = commands(config, placement_for(config, pathlib.Path("actual"))).relay

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
