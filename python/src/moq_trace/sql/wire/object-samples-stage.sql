-- `wire_full_span` runs from the capture of the first datagram carrying an
-- inbound object to the capture of the datagram completing each outbound copy.
--
-- `wire_to_read` and `send_to_wire` are the kernel's share at each end: from
-- that first capture to the socket read that returned the datagram, and from
-- the send that completed the copy to its capture. With the segments staged by
-- `samples/copy-spans-stage` they sum to `wire_full_span`. The capture point
-- sits inside the send system call, so `send_to_wire` is usually negative.
INSERT INTO staged_samples BY NAME
SELECT copy.rx_trace_id, copy.tx_trace_id, segment.metric,
       elapsed_ns(inbound.origin_ns, $origin) AS elapsed_ns,
       span_ns(segment.start_ns, segment.finish_ns) AS value_ns
FROM covered_copies AS copy
JOIN network.wire_coverage AS inbound ON inbound.object_trace_id = copy.rx_trace_id
JOIN network.wire_coverage AS outbound ON outbound.object_trace_id = copy.tx_trace_id
CROSS JOIN LATERAL (VALUES
  ('wire_full_span', inbound.origin_ns, outbound.complete_ns),
  ('wire_to_read', inbound.origin_ns, copy.rx_origin_ns),
  ('send_to_wire', copy.tx_complete_ns, outbound.complete_ns)
) AS segment(metric, start_ns, finish_ns);
