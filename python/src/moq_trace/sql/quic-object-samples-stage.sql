CREATE TEMP TABLE quic_object_samples AS
WITH copies AS (
  SELECT rx.process_id, rx.trace_id AS rx_trace_id, tx.trace_id AS tx_trace_id,
         rx.group_id, rx.object_id, tx.copy_ordinal,
         inbound.first_start_ns, inbound.first_end_ns,
         outbound.first_end_ns AS outbound_first_end_ns,
         inbound.complete_end_ns AS inbound_complete_end_ns,
         outbound.complete_end_ns AS outbound_complete_end_ns
  FROM selected_rx AS rx
  JOIN model.coverage AS inbound ON inbound.process_id = rx.process_id AND inbound.object_trace_id =
  rx.trace_id
  JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
  JOIN model.coverage AS outbound ON outbound.process_id = tx.process_id AND outbound.object_trace_id =
  tx.trace_id
)
SELECT process_id, rx_trace_id, tx_trace_id, group_id, object_id, metric, copy_ordinal,
       elapsed_ns(first_start_ns, $origin) AS elapsed_ns,
       CASE WHEN metric = 'quic_tail_gap'
            THEN greatest(span_ns(start_ns, finish_ns), 0)
            ELSE span_ns(start_ns, finish_ns)
       END AS latency_ns
FROM copies
CROSS JOIN LATERAL (VALUES
  ('quic_forward_start', first_start_ns, outbound_first_end_ns),
  ('quic_tail_gap', inbound_complete_end_ns, outbound_complete_end_ns),
  ('quic_full_span', first_start_ns, outbound_complete_end_ns)
) AS metric(metric, start_ns, finish_ns);
