CREATE TEMP TABLE object_samples AS
SELECT rx.process_id, rx.trace_id AS rx_trace_id, tx.trace_id AS tx_trace_id,
       rx.group_id, rx.object_id, 'full_span' AS metric,
       tx.copy_ordinal,
       elapsed_ns(rx.start_ns, $origin) AS elapsed_ns,
       span_ns(rx.start_ns, tx.end_ns) AS latency_ns
FROM selected_rx AS rx
JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id;
