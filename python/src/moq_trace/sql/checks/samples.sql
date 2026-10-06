-- Every metric sample carries exactly the lifecycle identity its grain declares,
-- once, and no QUIC span of a copy is negative: data cannot be sent before it is
-- accepted, so a negative one is a provider defect.
SELECT 'QUIC object metrics are negative' AS defect, count(*) AS count
FROM metrics.samples
WHERE metric IN ('quic_forward_start', 'quic_tail_gap', 'quic_full_span') AND value_ns < 0
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
  SELECT metric, rx_trace_id, tx_trace_id, packet_trace_id, span_id
  FROM metrics.samples GROUP BY ALL HAVING count(*) > 1
);
