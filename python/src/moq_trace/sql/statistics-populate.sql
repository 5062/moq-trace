INSERT INTO metrics.statistics
SELECT process_id, metric, count(*)::UBIGINT AS count, avg(value_ns) AS mean_ns,
       quantile_cont(value_ns, 0.50)::DOUBLE AS p50_ns,
       quantile_cont(value_ns, 0.95)::DOUBLE AS p95_ns,
       quantile_cont(value_ns, 0.99)::DOUBLE AS p99_ns, max(value_ns)::BIGINT AS max_ns
FROM metrics.samples GROUP BY process_id, metric;

-- An RX object and its TX copies share one logical frame, so either trace ID
-- locates the sample's position in its group.
INSERT INTO metrics.position_statistics
SELECT samples.process_id, samples.metric,
       CASE WHEN objects.logical_frame = 0 THEN 'first' ELSE 'later' END AS position,
       count(*)::UBIGINT AS count, avg(samples.value_ns) AS mean_ns,
       quantile_cont(samples.value_ns, 0.50)::DOUBLE AS p50_ns,
       quantile_cont(samples.value_ns, 0.95)::DOUBLE AS p95_ns,
       quantile_cont(samples.value_ns, 0.99)::DOUBLE AS p99_ns, max(samples.value_ns)::BIGINT AS max_ns
FROM metrics.samples AS samples
JOIN model.objects AS objects
  ON objects.process_id = samples.process_id
 AND objects.trace_id = coalesce(samples.rx_trace_id, samples.tx_trace_id)
GROUP BY samples.process_id, samples.metric, position;
