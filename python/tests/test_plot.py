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
    plot_breakdown,
    plot_breakdown_comparison,
    plot_latency_cdf,
    plot_latency_comparison,
    plot_stability,
)
from moq_trace.plot.breakdown import _Row, _row_summary  # noqa: E402

OPTIONS = PlotOptions(None, 1, 1_024, 30, "test")


def _artifact(packet_phases: bool) -> duckdb.DuckDBPyConnection:
    """Build the tables the figures read, for two objects copied once each.

    Without `packet_phases` the capture looks like a generic stack that emits
    packet spans only, which every figure must still render.
    """

    connection = duckdb.connect(":memory:")
    connection.execute("CREATE SCHEMA metrics")
    connection.execute("CREATE TABLE metrics.samples(metric VARCHAR, elapsed_ns BIGINT, value_ns BIGINT)")
    connection.executemany(
        "INSERT INTO metrics.samples VALUES ('full_span', ?, ?)",
        [(second * 1_000_000_000, 90_000 + second * 1_000) for second in range(4)],
    )
    connection.executemany(
        "INSERT INTO metrics.samples VALUES ('quic_full_span', ?, ?)",
        [(second * 1_000_000_000, 300_000 + second * 1_000) for second in range(4)],
    )
    packet_metrics = ["rx_packet_span", "tx_packet_span"]
    if packet_phases:
        packet_metrics += ["rx_scheduling", "rx_packet_processing_span"]
    connection.executemany(
        "INSERT INTO metrics.samples VALUES (?, ?, 5000)",
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
