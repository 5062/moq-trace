INSERT INTO metrics.statistics
SELECT process_id, metric, count(*)::UBIGINT AS count, avg(value_ns) AS mean_ns,
       quantile_cont(value_ns, 0.50)::DOUBLE AS p50_ns,
       quantile_cont(value_ns, 0.95)::DOUBLE AS p95_ns,
       quantile_cont(value_ns, 0.99)::DOUBLE AS p99_ns, max(value_ns)::BIGINT AS max_ns
FROM metrics.samples GROUP BY process_id, metric;
