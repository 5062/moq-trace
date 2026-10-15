from __future__ import annotations

import unittest

from moq_trace.errors import CaptureError
from moq_trace.run import hosts, local, lttng


class _LttngHost(local.LocalHost):
    """A host whose `lttng` records its arguments and lists nothing."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    async def lttng(self, args):
        self.calls.append(tuple(args))
        return hosts.Completed(0, "<command/>", "")


class LttngTests(unittest.IsolatedAsyncioTestCase):
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
