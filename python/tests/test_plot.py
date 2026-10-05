from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace.analysis.phases import Phase  # noqa: E402
from moq_trace.plot import (  # noqa: E402
    PlotRun,
    plot_breakdown,
    plot_latency_cdf,
    plot_latency_comparison,
    plot_moq_work,
    plot_segments,
    plot_stability,
    plot_transport_waits,
    timeline,  # noqa: E402
)
from moq_trace.plot.breakdown import _row_summary  # noqa: E402
from moq_trace.plot.common import _copy_rows  # noqa: E402
from moq_trace.plot.segments import _segments  # noqa: E402

SUBTITLE = "unpinned | 1 subscriber | 1024 bytes | 30 fps | test"


def _artifact(packet_phases: bool) -> duckdb.DuckDBPyConnection:
    """Build the tables the figures read, for two objects copied once each.

    Without `packet_phases` the capture looks like a generic stack that emits
    packet spans only, which every figure must still render.
    """

    connection = duckdb.connect(":memory:")
    connection.execute("CREATE SCHEMA metrics")
    connection.execute(
        """CREATE TABLE metrics.samples(process_id UINTEGER, metric VARCHAR, rx_trace_id UBIGINT,
        tx_trace_id UBIGINT, elapsed_ns BIGINT, value_ns BIGINT)"""
    )
    # Four copies whose segments chain into each span, with a negative tail.
    segments = {
        "wire_to_read": 20_000,
        "read_to_moq": 200_000,
        "full_span": 90_000,
        "moq_to_send": 10_000,
        "send_to_wire": -5_000,
        "moq_rx_work": 15_000,
        "moq_tx_work": 60_000,
        "moq_write_after_receive": -40_000,
        "moq_tx_transport": 20_000,
        "moq_delivery_wait": 30_000,
        "send_wait": 8_000,
        "blocked_congestion_window": 3_000,
        "tx_repair": 0,
    }
    rows = []
    for second in range(4):
        values = {metric: value + second * 1_000 for metric, value in segments.items()}
        values["quic_full_span"] = values["read_to_moq"] + values["full_span"] + values["moq_to_send"]
        values["wire_full_span"] = values["wire_to_read"] + values["quic_full_span"] + values["send_to_wire"]
        rows += [(metric, second, second + 10, second * 1_000_000_000, value) for metric, value in values.items()]
    connection.executemany("INSERT INTO metrics.samples VALUES (1, ?, ?, ?, ?, ?)", rows)
    packet_metrics = ["rx_packet_span", "tx_packet_span"]
    if packet_phases:
        packet_metrics += ["rx_scheduling", "rx_packet_processing_span"]
    connection.executemany(
        "INSERT INTO metrics.samples VALUES (1, ?, NULL, NULL, ?, 5000)",
        [(metric, second * 1_000_000_000) for metric in packet_metrics for second in range(4)],
    )
    connection.execute(
        """CREATE TABLE metrics.phase_totals(subject VARCHAR, direction VARCHAR, trace_id UBIGINT, phase VARCHAR,
        total_ns BIGINT)"""
    )
    connection.execute("""INSERT INTO metrics.phase_totals VALUES
        ('object', 'rx', 1, 'frame_commit', 4000), ('object', 'rx', 2, 'frame_commit', 4000),
        ('object', 'tx', 11, 'clone', 500), ('object', 'tx', 12, 'clone', 500)""")
    if packet_phases:
        connection.execute("""INSERT INTO metrics.phase_totals VALUES
            ('packet', 'rx', 100, 'scheduling', 4000), ('packet', 'tx', 200, 'packet_encrypt', 1000)""")
    return connection


class RunPlotTests(unittest.TestCase):
    """Every single-run figure renders with and without optional packet phases."""

    def test_figures_render_whatever_phases_the_provider_emitted(self) -> None:
        for packet_phases in (True, False):
            connection = _artifact(packet_phases)
            try:
                with tempfile.TemporaryDirectory() as directory:
                    for plot in (
                        plot_latency_cdf,
                        plot_segments,
                        plot_breakdown,
                        plot_moq_work,
                        plot_transport_waits,
                        plot_stability,
                    ):
                        output = pathlib.Path(directory) / f"{plot.__name__}.png"
                        if plot in (plot_latency_cdf, plot_stability):
                            plot(output, SUBTITLE, connection)
                        else:
                            plot(output, "title", SUBTITLE, (PlotRun("", connection),))
                        self.assertGreater(output.stat().st_size, 0, (plot.__name__, packet_phases))
            finally:
                connection.close()

    def test_timeline_draws_object_waits_and_leaves_packet_waits_out(self) -> None:
        tx = {row[1]: row[3] for row in timeline._rows("object", "tx", "", "")}
        self.assertTrue(tx["delivery_wait"])
        self.assertTrue(tx["write_blocked"])
        self.assertFalse(tx["clone"])
        rx_packets = [row[1] for row in timeline._rows("packet", "rx", "quic_", "QUIC ")]
        self.assertNotIn("quic_read_queue", rx_packets)
        self.assertNotIn("quic_scheduling", rx_packets)

    def test_breakdown_sums_repeated_phases_within_a_unit(self) -> None:
        connection = _artifact(packet_phases=True)
        try:
            summary = _row_summary(connection, Phase("object", "rx", "frame_commit", "Frame commit"))
            absent = _row_summary(connection, Phase("packet", "rx", "routing", "Routing"))
        finally:
            connection.close()
        self.assertIsNotNone(summary)
        self.assertAlmostEqual(summary[2], 4.0)
        self.assertIsNone(absent)

    def test_segment_rows_pair_each_copy_and_sum_to_its_span(self) -> None:
        connection = _artifact(packet_phases=False)
        try:
            (total, _label, _bounds), segments = _segments(wire=True)
            rows = _copy_rows(connection, (total, *(metric for metric, _label in segments)))
            # A copy that lacks one segment is left out rather than half drawn.
            connection.execute("DELETE FROM metrics.samples WHERE metric = 'wire_to_read' AND rx_trace_id = 0")
            partial = _copy_rows(connection, (total, *(metric for metric, _label in segments)))
        finally:
            connection.close()
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertAlmostEqual(row[0], sum(row[1:]))
        self.assertEqual(len(partial), 3)

    def test_moq_work_is_skipped_for_a_provider_without_object_phases(self) -> None:
        connection = _artifact(packet_phases=False)
        try:
            connection.execute("DELETE FROM metrics.samples WHERE metric LIKE 'moq_%'")
            with tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory) / "moq_work.png"
                self.assertFalse(plot_moq_work(output, "MoQ work", SUBTITLE, (PlotRun("", connection),)))
                self.assertFalse(output.exists())
        finally:
            connection.close()


class TransportWaitPlotTests(unittest.TestCase):
    def test_transport_waits_are_skipped_for_a_provider_without_them(self) -> None:
        connection = _artifact(packet_phases=False)
        try:
            connection.execute(
                "DELETE FROM metrics.samples WHERE metric IN ('send_wait', 'tx_repair') OR metric LIKE 'blocked_%'"
            )
            with tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory) / "transport_waits.png"
                self.assertFalse(plot_transport_waits(output, "waits", SUBTITLE, (PlotRun("", connection),)))
                self.assertFalse(output.exists())
        finally:
            connection.close()


class TransportWaitTitleTests(unittest.TestCase):
    def test_reasons_that_never_blocked_are_named_instead_of_drawn(self) -> None:
        connection = _artifact(packet_phases=False)
        try:
            connection.execute(
                "INSERT INTO metrics.samples VALUES "
                "(1, 'blocked_pacing', 0, 10, 0, 0), (1, 'blocked_pacing', 1, 11, 0, 0)"
            )
            with tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory) / "transport_waits.png"
                with mock.patch("moq_trace.plot.transport_waits._cdf_panels", return_value=True) as panels:
                    plot_transport_waits(output, "waits", SUBTITLE, (PlotRun("", connection),))
            heading, _runs, drawn = panels.call_args.args[1:4]
            self.assertIn("Never blocked by: pacing", heading)
            metrics = [metric for metric, _label in drawn]
            self.assertNotIn("blocked_pacing", metrics)
            self.assertIn("blocked_congestion_window", metrics)
        finally:
            connection.close()


class ComparisonPlotTests(unittest.TestCase):
    """Shared figures render several runs, while the latency comparison requires two."""

    def test_comparisons_render_and_reject_insufficient_runs(self) -> None:
        connections = (_artifact(packet_phases=True), _artifact(packet_phases=False))
        try:
            runs = tuple(PlotRun(f"run {index}", connection) for index, connection in enumerate(connections))
            with tempfile.TemporaryDirectory() as directory:
                for plot in (
                    plot_latency_comparison,
                    plot_segments,
                    plot_breakdown,
                    plot_moq_work,
                    plot_transport_waits,
                ):
                    output = pathlib.Path(directory) / f"{plot.__name__}.png"
                    plot(output, "title", "subtitle", runs)
                    self.assertGreater(output.stat().st_size, 0)
                    if plot is plot_latency_comparison:
                        with self.assertRaisesRegex(ValueError, "at least two runs"):
                            plot(output, "title", "subtitle", runs[:1])
                    else:
                        with self.assertRaisesRegex(ValueError, "at least one run"):
                            plot(output, "title", "subtitle", ())
        finally:
            for connection in connections:
                connection.close()


if __name__ == "__main__":
    unittest.main()
