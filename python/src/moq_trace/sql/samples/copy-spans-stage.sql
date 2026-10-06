-- The spans of each copy, from its lifecycle boundaries and the packets that
-- carried its bytes.
--
-- `full_span` runs from the start of the inbound object's MoQ lifecycle to the
-- end of the copy's. The QUIC spans start at the inbound object's origin, the
-- first socket read carrying its bytes: `quic_forward_start` ends when the first
-- outbound frame of the copy completed, `quic_full_span` when the frame
-- completing the copy did, and `quic_tail_gap` runs from the inbound object's
-- completion to the copy's. None is clamped: data cannot be sent before it is
-- accepted, so a negative QUIC span is a provider defect that `checks/samples`
-- rejects.
--
-- `read_to_moq` runs from the inbound origin to the start of the MoQ lifecycle,
-- and `moq_to_send` from the end of the copy's MoQ lifecycle to the send that
-- completed it. With `full_span` between them the three sum to
-- `quic_full_span`, because their boundaries chain exactly. Each stack places
-- the MoQ boundary differently, so a segment can be negative when a stack ends
-- its MoQ lifecycle after the send it caused.
INSERT INTO staged_samples BY NAME
SELECT rx_trace_id, tx_trace_id, span.metric,
       elapsed_ns(span.elapsed_from, $origin) AS elapsed_ns,
       span_ns(span.start_ns, span.finish_ns) AS value_ns
FROM covered_copies
CROSS JOIN LATERAL (VALUES
  ('full_span', rx_start_ns, rx_start_ns, tx_end_ns),
  ('quic_forward_start', rx_origin_ns, rx_origin_ns, tx_first_ns),
  ('quic_tail_gap', rx_origin_ns, rx_complete_ns, tx_complete_ns),
  ('quic_full_span', rx_origin_ns, rx_origin_ns, tx_complete_ns),
  ('read_to_moq', rx_origin_ns, rx_origin_ns, rx_start_ns),
  ('moq_to_send', rx_origin_ns, tx_end_ns, tx_complete_ns)
) AS span(metric, elapsed_from, start_ns, finish_ns);
