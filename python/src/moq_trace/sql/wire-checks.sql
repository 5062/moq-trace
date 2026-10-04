-- Disagreements between the decrypted capture and the trace. Each row names one
-- defect and how many packets have it; the analysis rejects a run with any.
-- Packets are checked inside the analysis window, where the trace is complete.
WITH joined AS (
  SELECT DISTINCT process_id, trace_connection_id AS connection_id FROM network.wire_connections
), traced AS (
  SELECT trace.* FROM packet_lifecycles AS trace SEMI JOIN joined USING (process_id, connection_id)
), wire_frames AS (
  SELECT process_id, packet_id,
         list((stream_id, offset_start, offset_end) ORDER BY stream_id, offset_start, offset_end) AS frames
  FROM network.wire_stream_frames WHERE offset_start < offset_end GROUP BY ALL
), trace_frames AS (
  SELECT process_id, trace_id,
         list((stream_id, offset_start, offset_end) ORDER BY stream_id, offset_start, offset_end) AS frames
  FROM quic_stream_frame WHERE offset_start < offset_end GROUP BY ALL
)
SELECT 'successful trace packets that never appeared on the wire' AS defect, count(*) AS count
FROM traced AS trace
WHERE trace.outcome = 'success'
  AND trace.start_ns BETWEEN (SELECT start_ns FROM analysis_window) AND (SELECT end_ns FROM analysis_window)
  AND NOT EXISTS (
    SELECT 1 FROM network.wire_packets AS wire
    WHERE wire.process_id = trace.process_id AND wire.trace_id = trace.trace_id
  )
UNION ALL
SELECT 'wire packets without a trace packet', count(*)
FROM network.wire_packets
WHERE trace_id IS NULL
  AND timestamp_ns BETWEEN (SELECT start_ns FROM analysis_window) AND (SELECT end_ns FROM analysis_window)
UNION ALL
SELECT 'trace packets matched by more than one wire packet', count(*)
FROM (
  SELECT process_id, trace_id FROM network.wire_packets WHERE trace_id IS NOT NULL GROUP BY ALL HAVING count(*) > 1
)
UNION ALL
SELECT 'trace packets sharing a connection, direction, and packet number', count(*)
FROM (
  SELECT process_id, connection_id, direction, packet_space, packet_number
  FROM traced WHERE packet_number IS NOT NULL GROUP BY ALL HAVING count(*) > 1
)
UNION ALL
SELECT 'TX packets the trace never sent that appeared on the wire', count(*)
FROM network.wire_packets AS wire JOIN traced AS trace USING (process_id, trace_id)
WHERE trace.direction = 'tx' AND trace.outcome <> 'success'
UNION ALL
SELECT 'matched packets carrying different STREAM frames', count(*)
FROM network.wire_packets AS wire
LEFT JOIN wire_frames USING (process_id, packet_id)
LEFT JOIN trace_frames ON trace_frames.process_id = wire.process_id AND trace_frames.trace_id = wire.trace_id
WHERE wire.trace_id IS NOT NULL AND wire_frames.frames IS DISTINCT FROM trace_frames.frames
UNION ALL
-- A read cannot complete before the kernel received the datagram, so an RX
-- packet that starts before its capture time, beyond the uncertainty of the
-- clock conversion, has a misplaced start.
SELECT 'RX packets that start before their datagram was captured', count(*)
FROM network.wire_packets AS wire JOIN traced AS trace USING (process_id, trace_id)
WHERE wire.direction = 'rx' AND trace.start_ns < wire.timestamp_ns - $tolerance;
