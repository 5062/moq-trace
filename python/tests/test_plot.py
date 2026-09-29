from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace.plot import (  # noqa: E402
    ComparisonRun,
    PlotOptions,
    _Row,
    _row_summary,
    plot_breakdown,
    plot_breakdown_comparison,
    plot_latency_cdf,
    plot_latency_comparison,
    plot_stability,
)

OPTIONS = PlotOptions(None, 1, 1_024, 30, "test")


def _artifact(packet_phases: bool) -> duckdb.DuckDBPyConnection:
    """Build the tables the figures read, for two objects copied once each.

    Without `packet_phases` the capture looks like a generic stack that emits
    packet spans only, which every figure must still render.
    """

    connection = duckdb.connect(":memory:")
    for table in ("object_samples", "quic_object_samples", "packet_samples"):
        connection.execute(f"CREATE TABLE {table}(metric VARCHAR, elapsed_ns BIGINT, latency_ns BIGINT)")
    connection.executemany(
        "INSERT INTO object_samples VALUES ('full_span', ?, ?)",
        [(second * 1_000_000_000, 90_000 + second * 1_000) for second in range(4)],
    )
    connection.executemany(
        "INSERT INTO quic_object_samples VALUES ('quic_full_span', ?, ?)",
        [(second * 1_000_000_000, 300_000 + second * 1_000) for second in range(4)],
    )
    packet_metrics = ["rx_packet_span", "tx_packet_span"]
    if packet_phases:
        packet_metrics += ["rx_scheduling", "rx_packet_processing_span"]
    connection.executemany(
        "INSERT INTO packet_samples VALUES (?, ?, 5000)",
        [(metric, second * 1_000_000_000) for metric in packet_metrics for second in range(4)],
    )

    connection.execute("CREATE TABLE selected_rx(trace_id UBIGINT)")
    connection.execute("INSERT INTO selected_rx VALUES (1), (2)")
    connection.execute("CREATE TABLE object_copies(rx_trace_id UBIGINT, trace_id UBIGINT)")
    connection.execute("INSERT INTO object_copies VALUES (1, 11), (2, 12)")
    connection.execute(
        """CREATE TABLE object_phase_intervals(
               trace_id UBIGINT, phase VARCHAR, start_ns UBIGINT, end_ns UBIGINT, outcome VARCHAR
           )"""
    )
    # Object 1 commits two frames of 1 and 3 µs, so its per-object total is 4 µs.
    connection.execute(
        """INSERT INTO object_phase_intervals VALUES
           (1, 'frame_commit', 0, 1000, 'success'),
           (1, 'frame_commit', 2000, 5000, 'success'),
           (2, 'frame_commit', 0, 4000, 'success'),
           (11, 'clone', 0, 500, 'success'),
           (12, 'clone', 0, 500, 'success')"""
    )
    connection.execute("CREATE TABLE selected_packets(trace_id UBIGINT, direction VARCHAR, outcome VARCHAR)")
    connection.execute("INSERT INTO selected_packets VALUES (100, 'rx', 'success'), (200, 'tx', 'success')")
    connection.execute(
        """CREATE TABLE packet_phase_intervals(
               trace_id UBIGINT, phase VARCHAR, start_ns UBIGINT, end_ns UBIGINT, outcome VARCHAR
           )"""
    )
    if packet_phases:
        connection.execute(
            """INSERT INTO packet_phase_intervals VALUES
               (100, 'scheduling', 0, 4000, 'success'),
               (200, 'packet_encrypt', 0, 1000, 'success')"""
        )
    return connection


class RunPlotTests(unittest.TestCase):
    """Every single-run figure renders with and without optional packet phases."""

    def test_figures_render_whatever_phases_the_provider_emitted(self) -> None:
        for packet_phases in (True, False):
            connection = _artifact(packet_phases)
            try:
                with tempfile.TemporaryDirectory() as directory:
                    for plot in (plot_latency_cdf, plot_breakdown, plot_stability):
                        output = pathlib.Path(directory) / f"{plot.__name__}.png"
                        plot(output, OPTIONS, connection)
                        self.assertGreater(output.stat().st_size, 0, (plot.__name__, packet_phases))
            finally:
                connection.close()

    def test_breakdown_sums_repeated_phases_within_a_unit(self) -> None:
        connection = _artifact(packet_phases=True)
        try:
            summary = _row_summary(connection, _Row("Frame commit", "object", "rx", "frame_commit"))
            absent = _row_summary(connection, _Row("Routing", "packet", "rx", "routing"))
        finally:
            connection.close()
        self.assertIsNotNone(summary)
        self.assertAlmostEqual(summary[2], 4.0)
        self.assertIsNone(absent)


class ComparisonPlotTests(unittest.TestCase):
    """Comparison figures overlay runs and refuse a comparison of one."""

    def test_comparisons_render_and_require_two_runs(self) -> None:
        connections = (_artifact(packet_phases=True), _artifact(packet_phases=False))
        try:
            runs = tuple(ComparisonRun(f"run {index}", connection) for index, connection in enumerate(connections))
            with tempfile.TemporaryDirectory() as directory:
                for plot in (plot_latency_comparison, plot_breakdown_comparison):
                    output = pathlib.Path(directory) / f"{plot.__name__}.png"
                    plot(output, "title", "subtitle", runs)
                    self.assertGreater(output.stat().st_size, 0)
                    with self.assertRaisesRegex(ValueError, "at least two runs"):
                        plot(output, "title", "subtitle", runs[:1])
        finally:
            for connection in connections:
                connection.close()


if __name__ == "__main__":
    unittest.main()
