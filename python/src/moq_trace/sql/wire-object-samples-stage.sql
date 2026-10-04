-- `wire_full_span` runs from the capture of the first datagram carrying an
-- inbound object to the capture of the datagram completing each outbound copy.
--
-- `wire_to_read` and `send_to_wire` are the kernel's share at each end: from
-- that first capture to the socket read that returned the datagram, and from
-- the send that completed the copy to its capture. With the segments of
-- `segment_samples` they sum to `wire_full_span`. The capture point sits inside
-- the send system call, so `send_to_wire` is usually negative.
INSERT INTO wire_object_samples
SELECT rx.process_id, rx.trace_id, tx.trace_id, metric,
       elapsed_ns(inbound.origin_ns, $origin), span_ns(segment.start_ns, segment.finish_ns)
FROM selected_rx AS rx
JOIN network.wire_coverage AS inbound ON inbound.process_id = rx.process_id AND inbound.object_trace_id = rx.trace_id
JOIN model.coverage AS quic_in ON quic_in.process_id = rx.process_id AND quic_in.object_trace_id = rx.trace_id
JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
JOIN network.wire_coverage AS outbound ON outbound.process_id = tx.process_id AND outbound.object_trace_id = tx.trace_id
JOIN model.coverage AS quic_out ON quic_out.process_id = tx.process_id AND quic_out.object_trace_id = tx.trace_id
CROSS JOIN LATERAL (VALUES
  ('wire_full_span', inbound.origin_ns, outbound.complete_ns),
  ('wire_to_read', inbound.origin_ns, quic_in.origin_ns),
  ('send_to_wire', quic_out.complete_ns, outbound.complete_ns)
) AS segment(metric, start_ns, finish_ns);
