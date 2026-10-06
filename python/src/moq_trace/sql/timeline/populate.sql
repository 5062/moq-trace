INSERT INTO metrics.timeline_selections BY NAME
WITH slowest AS (
    SELECT rx_trace_id, max(span_ns(rx_start_ns, tx_end_ns)) AS actual_ns
    FROM selected_copies GROUP BY ALL
), targets(selection_order, statistic, target_ns) AS (
    SELECT 0, 'mean', avg(actual_ns) FROM slowest
    UNION ALL SELECT 1, 'median', quantile_cont(actual_ns, 0.50)::DOUBLE FROM slowest
    UNION ALL SELECT 2, 'p99', quantile_cont(actual_ns, 0.99)::DOUBLE FROM slowest
)
SELECT target.selection_order, target.statistic, target.target_ns, object.rx_trace_id, object.actual_ns
FROM targets target CROSS JOIN LATERAL (
    SELECT * FROM slowest ORDER BY abs(actual_ns - target.target_ns), rx_trace_id LIMIT 1
) object;
