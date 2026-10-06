-- One summary, so the whole and positional statistics agree on what they report.
CREATE OR REPLACE TEMP MACRO latency_summary(value_ns) AS {
    'count': count(value_ns)::UBIGINT,
    'mean_ns': avg(value_ns),
    'p50_ns': quantile_cont(value_ns, 0.50)::DOUBLE,
    'p95_ns': quantile_cont(value_ns, 0.95)::DOUBLE,
    'p99_ns': quantile_cont(value_ns, 0.99)::DOUBLE,
    'max_ns': max(value_ns)::BIGINT
};

INSERT INTO metrics.statistics BY NAME
SELECT metric, unnest(latency_summary(value_ns)) FROM metrics.samples GROUP BY metric;

-- An RX object and its TX copies share one logical frame, so either trace ID
-- locates the sample's position in its group.
INSERT INTO metrics.position_statistics BY NAME
SELECT samples.metric, CASE WHEN objects.logical_frame = 0 THEN 'first' ELSE 'later' END AS position,
       unnest(latency_summary(samples.value_ns))
FROM metrics.samples AS samples
JOIN model.objects AS objects ON objects.trace_id = coalesce(samples.rx_trace_id, samples.tx_trace_id)
GROUP BY samples.metric, position;
