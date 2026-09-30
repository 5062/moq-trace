-- Every metric sample carries exactly the lifecycle identity its grain declares,
-- once, and no latency is negative.
SELECT 'QUIC object metrics are negative' AS defect, count(*) AS count
FROM quic_object_samples WHERE latency_ns < 0
UNION ALL
SELECT 'metric samples have invalid identity columns', count(*)
FROM metrics.samples s JOIN metrics.definitions d USING (metric)
WHERE NOT (
  (grain = 'copy' AND rx_trace_id IS NOT NULL AND tx_trace_id IS NOT NULL
    AND packet_trace_id IS NULL AND span_id IS NULL) OR
  (grain = 'packet' AND rx_trace_id IS NULL AND tx_trace_id IS NULL
    AND packet_trace_id IS NOT NULL AND span_id IS NULL) OR
  (grain = 'occurrence' AND rx_trace_id IS NULL AND tx_trace_id IS NULL
    AND packet_trace_id IS NOT NULL AND span_id IS NOT NULL))
UNION ALL
SELECT 'duplicate metric sample identities', count(*)
FROM (
  SELECT process_id, metric, rx_trace_id, tx_trace_id, packet_trace_id, span_id
  FROM metrics.samples GROUP BY ALL HAVING count(*) > 1
);
