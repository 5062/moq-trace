-- Where `quic_full_span` goes, around the MoQ span each stack reports.
--
-- `read_to_moq` runs from the first socket read carrying an inbound object to
-- the start of its MoQ lifecycle, and `moq_to_send` from the end of a copy's
-- MoQ lifecycle to the send that completed it. With `full_span` between them
-- the three sum to `quic_full_span` for every copy, because their boundaries
-- chain exactly. Each stack places the MoQ boundary differently, so a segment
-- can be negative when a stack ends its MoQ lifecycle after the send it caused.
CREATE TEMP TABLE segment_samples AS
SELECT rx.process_id, rx.trace_id AS rx_trace_id, tx.trace_id AS tx_trace_id, metric,
       elapsed_ns(inbound.origin_ns, $origin) AS elapsed_ns, span_ns(segment.start_ns, segment.finish_ns) AS latency_ns
FROM selected_rx AS rx
JOIN model.coverage AS inbound ON inbound.process_id = rx.process_id AND inbound.object_trace_id = rx.trace_id
JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
JOIN model.coverage AS outbound ON outbound.process_id = tx.process_id AND outbound.object_trace_id = tx.trace_id
CROSS JOIN LATERAL (VALUES
  ('read_to_moq', inbound.origin_ns, rx.start_ns),
  ('moq_to_send', tx.end_ns, outbound.complete_ns)
) AS segment(metric, start_ns, finish_ns);
