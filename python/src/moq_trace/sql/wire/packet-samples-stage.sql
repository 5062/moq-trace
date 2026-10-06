-- The residuals between a packet's socket boundary and its capture time. The
-- RX residual is the time from capture to the end of the read, and is never
-- negative. The TX residual is the time from the end of the send to capture,
-- and is signed, because the capture can see a datagram before its send
-- returns.
INSERT INTO staged_samples BY NAME
SELECT trace.direction || '_wire_residual' AS metric, trace.trace_id AS packet_trace_id,
       elapsed_ns(trace.start_ns, $origin) AS elapsed_ns,
       CASE trace.direction
         WHEN 'rx' THEN span_ns(wire.timestamp_ns, trace.start_ns)
         ELSE span_ns(trace.end_ns, wire.timestamp_ns)
       END AS value_ns
FROM selected_packets AS trace
JOIN network.wire_packets AS wire USING (trace_id)
WHERE trace.outcome = 'success';
