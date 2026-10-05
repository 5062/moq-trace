-- The residuals between a packet's socket boundary and its capture time. The
-- RX residual is the time from capture to the end of the read, and is never
-- negative. The TX residual is the time from the end of the send to capture,
-- and is signed, because the capture can see a datagram before its send
-- returns.
INSERT INTO wire_packet_samples
SELECT trace.process_id, 'rx_wire_residual', trace.trace_id,
       elapsed_ns(trace.start_ns, $origin), span_ns(wire.timestamp_ns, trace.start_ns)
FROM selected_packets AS trace
JOIN network.wire_packets AS wire ON wire.process_id = trace.process_id AND wire.trace_id = trace.trace_id
WHERE trace.direction = 'rx' AND trace.outcome = 'success'
UNION ALL
SELECT trace.process_id, 'tx_wire_residual', trace.trace_id,
       elapsed_ns(trace.start_ns, $origin), span_ns(trace.end_ns, wire.timestamp_ns)
FROM selected_packets AS trace
JOIN network.wire_packets AS wire ON wire.process_id = trace.process_id AND wire.trace_id = trace.trace_id
WHERE trace.direction = 'tx' AND trace.outcome = 'success';
