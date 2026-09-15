from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace.plot import PlotOptions, plot_metrics, plot_packet_latency_cdf  # noqa: E402


class MetricPlotTests(unittest.TestCase):
    """Exercise plot sizing independently of the current metric catalog."""

    def test_supports_more_series_than_the_old_fixed_palette(self) -> None:
        metrics = tuple(f"metric_{index}" for index in range(12))
        connection = duckdb.connect(":memory:")
        try:
            connection.execute("CREATE TABLE object_samples(metric VARCHAR, elapsed_ns BIGINT, latency_ns BIGINT)")
            connection.executemany("INSERT INTO object_samples VALUES (?, 0, 1000)", [(metric,) for metric in metrics])
            connection.execute(
                "CREATE TABLE metric_definitions(domain VARCHAR, metric VARCHAR, label VARCHAR, display_order INTEGER)"
            )
            connection.executemany(
                "INSERT INTO metric_definitions VALUES ('object', ?, ?, ?)",
                [(metric, metric, index) for index, metric in enumerate(metrics)],
            )
            connection.execute(
                """CREATE VIEW metric_statistics AS
                   SELECT 'object' AS domain, metric, count(*) AS count,
                          avg(latency_ns) / 1000.0 AS mean,
                          quantile_cont(latency_ns, 0.50) / 1000.0 AS p50,
                          quantile_cont(latency_ns, 0.95) / 1000.0 AS p95,
                          quantile_cont(latency_ns, 0.99) / 1000.0 AS p99,
                          max(latency_ns) / 1000.0 AS max
                   FROM object_samples GROUP BY metric"""
            )
            options = PlotOptions(None, 1, 1_024, 30, "test")

            with tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory) / "metrics.png"
                plot_metrics(output, options, connection, "object")
                self.assertGreater(output.stat().st_size, 0)
        finally:
            connection.close()

    def test_packet_plot_falls_back_when_processing_phases_are_absent(self) -> None:
        """Generic quiche traces still produce a packet diagnostic figure."""

        connection = duckdb.connect(":memory:")
        try:
            connection.execute("CREATE TABLE packet_samples(metric VARCHAR, elapsed_ns BIGINT, latency_ns BIGINT)")
            connection.executemany(
                "INSERT INTO packet_samples VALUES (?, 0, 1000)",
                [("rx_packet_span",), ("tx_packet_span",)],
            )
            connection.execute(
                """CREATE TABLE metric_statistics(
                       domain VARCHAR, metric VARCHAR, count BIGINT,
                       mean DOUBLE, p50 DOUBLE, p95 DOUBLE, p99 DOUBLE, max DOUBLE
                   )"""
            )
            connection.executemany(
                "INSERT INTO metric_statistics VALUES ('packet', ?, 1, 1, 1, 1, 1, 1)",
                [("rx_packet_span",), ("tx_packet_span",)],
            )
            options = PlotOptions(None, 1, 1_024, 30, "test")

            with tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory) / "packet.png"
                plot_packet_latency_cdf(output, options, connection)
                self.assertGreater(output.stat().st_size, 0)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
