-- How long the transport held each copy's bytes, why, and how long it repaired them.
--
-- `send_wait` runs from the end of the copy's last successful payload write to
-- the start of the first-transmission packet that completed the copy's bytes. A
-- TX packet starts when frame encoding starts, so this is how long the bytes the
-- MoQ layer handed over sat in the transport's send buffer. It is negative for
-- a stack that builds the packet inside the write call, as Google QUICHE does,
-- and such a copy has no send wait for a blocked interval to overlap.
--
-- `blocked_<reason>` is how much of the copy's waiting overlapped intervals in
-- which its connection could not send for that reason. The copy waits during its
-- send wait and during each write the transport blocked. A reason scoped to a
-- stream counts only on the copy's own stream. A process that emitted no blocked
-- interval did not measure them, so its copies have no sample rather than zero.
--
-- `tx_repair` is how long after the copy's first transmission completed the last
-- retransmission of its bytes completed: zero when no repair was needed or every
-- repair finished first. Only a process whose TX frames mark retransmissions
-- has samples.
CREATE TEMP TABLE transport_wait_samples AS
WITH copies AS (
  SELECT rx.process_id, rx.trace_id AS rx_trace_id, copy.trace_id AS tx_trace_id,
         rx.start_ns AS rx_start_ns, copy.connection_id, copy.stream_id,
         copy.stream_offset_start, copy.stream_offset_end
  FROM selected_rx AS rx
  JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
  JOIN object_lifecycles AS copy ON copy.process_id = tx.process_id AND copy.trace_id = tx.trace_id
), send_window AS (
  SELECT copy.*, written.end_ns AS start_ns, packet.start_ns AS end_ns
  FROM copies AS copy
  JOIN (
    SELECT process_id, trace_id, max(end_ns) AS end_ns FROM object_phase_intervals
    WHERE phase = 'payload_write' AND outcome = 'success' GROUP BY ALL
  ) AS written ON written.process_id = copy.process_id AND written.trace_id = copy.tx_trace_id
  JOIN model.coverage AS coverage
    ON coverage.process_id = copy.process_id AND coverage.object_trace_id = copy.tx_trace_id
  JOIN packet_lifecycles AS packet
    ON packet.process_id = coverage.process_id AND packet.trace_id = coverage.complete_packet_trace_id
), waiting AS (
  SELECT process_id, tx_trace_id, connection_id, stream_id, start_ns, end_ns
  FROM send_window WHERE start_ns < end_ns
  UNION ALL
  SELECT copy.process_id, copy.tx_trace_id, copy.connection_id, copy.stream_id, phase.start_ns, phase.end_ns
  FROM copies AS copy
  JOIN object_phase_intervals AS phase
    ON phase.process_id = copy.process_id AND phase.trace_id = copy.tx_trace_id
  WHERE phase.phase = 'write_blocked' AND phase.outcome = 'success'
), blocked_time AS (
  SELECT waiting.process_id, waiting.tx_trace_id, blocked.reason,
         sum(least(waiting.end_ns, blocked.end_ns) - greatest(waiting.start_ns, blocked.start_ns)) AS ns
  FROM waiting JOIN model.send_blocked AS blocked
    ON blocked.process_id = waiting.process_id AND blocked.connection_id = waiting.connection_id
   AND (blocked.stream_id IS NULL OR blocked.stream_id = waiting.stream_id)
   AND blocked.start_ns < waiting.end_ns AND waiting.start_ns < blocked.end_ns
  GROUP BY ALL
), reasons AS (
  SELECT unnest([
    'congestion_window', 'pacing', 'amplification',
    'connection_flow_control', 'stream_flow_control', 'send_buffer'
  ]) AS reason
), blocking_measured AS (
  SELECT DISTINCT process_id FROM quic_send_blocked
), repairs AS (
  SELECT copy.process_id, copy.tx_trace_id, max(packet.end_ns) AS end_ns
  FROM copies AS copy
  JOIN packet_lifecycles AS packet
    ON packet.process_id = copy.process_id AND packet.connection_id = copy.connection_id
   AND packet.direction = 'tx' AND packet.outcome = 'success'
  JOIN quic_stream_frame AS frame
    ON frame.process_id = packet.process_id AND frame.trace_id = packet.trace_id
   AND frame.stream_id = copy.stream_id AND frame.outcome = 'success' AND frame.retransmission = 1
   AND frame.offset_start < copy.stream_offset_end AND copy.stream_offset_start < frame.offset_end
  GROUP BY ALL
), repair_measured AS (
  SELECT DISTINCT frame.process_id FROM quic_stream_frame AS frame
  JOIN packet_lifecycles AS packet USING (process_id, trace_id)
  WHERE packet.direction = 'tx' AND frame.retransmission IS NOT NULL
)
SELECT process_id, rx_trace_id, tx_trace_id, 'send_wait' AS metric,
       elapsed_ns(rx_start_ns, $origin) AS elapsed_ns, span_ns(start_ns, end_ns) AS latency_ns
FROM send_window
UNION ALL
SELECT copy.process_id, copy.rx_trace_id, copy.tx_trace_id, 'blocked_' || reasons.reason,
       elapsed_ns(copy.rx_start_ns, $origin), coalesce(blocked_time.ns, 0)
FROM copies AS copy
SEMI JOIN blocking_measured USING (process_id)
CROSS JOIN reasons
LEFT JOIN blocked_time
  ON blocked_time.process_id = copy.process_id AND blocked_time.tx_trace_id = copy.tx_trace_id
 AND blocked_time.reason = reasons.reason
UNION ALL
SELECT copy.process_id, copy.rx_trace_id, copy.tx_trace_id, 'tx_repair',
       elapsed_ns(copy.rx_start_ns, $origin),
       greatest(0, coalesce(span_ns(coverage.complete_ns, repairs.end_ns), 0))
FROM copies AS copy
SEMI JOIN repair_measured USING (process_id)
JOIN model.coverage AS coverage
  ON coverage.process_id = copy.process_id AND coverage.object_trace_id = copy.tx_trace_id
LEFT JOIN repairs ON repairs.process_id = copy.process_id AND repairs.tx_trace_id = copy.tx_trace_id;
