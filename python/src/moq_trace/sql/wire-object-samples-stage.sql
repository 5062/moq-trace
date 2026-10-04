-- `wire_full_span` runs from the capture of the first datagram carrying an
-- inbound object to the capture of the datagram completing each outbound copy.
INSERT INTO wire_object_samples
SELECT rx.process_id, rx.trace_id, tx.trace_id, 'wire_full_span',
       elapsed_ns(inbound.origin_ns, $origin), span_ns(inbound.origin_ns, outbound.complete_ns)
FROM selected_rx AS rx
JOIN network.wire_coverage AS inbound ON inbound.process_id = rx.process_id AND inbound.object_trace_id = rx.trace_id
JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
JOIN network.wire_coverage AS outbound ON outbound.process_id = tx.process_id AND outbound.object_trace_id = tx.trace_id;
