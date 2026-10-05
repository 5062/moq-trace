-- Shared addresses do not identify a connection. Require a candidate to carry
-- every transmitted packet observed in the measurement window, with the same
-- packet number, size, and nonempty STREAM ranges. Capture timestamps can fall
-- after a send returns, so individual send lifetimes cannot identify the peer.
CREATE OR REPLACE TEMP TABLE wire_connection_candidates_stage AS
WITH wire_frames AS (
  SELECT process_id, packet_id,
         list((stream_id, offset_start, offset_end) ORDER BY stream_id, offset_start, offset_end) AS frames
  FROM network.wire_stream_frames WHERE offset_start < offset_end GROUP BY ALL
), trace_frames AS (
  SELECT process_id, trace_id,
         list((stream_id, offset_start, offset_end) ORDER BY stream_id, offset_start, offset_end) AS frames
  FROM quic_stream_frame WHERE offset_start < offset_end GROUP BY ALL
), wire AS (
  SELECT packets.*, frames FROM network.wire_packets AS packets
  LEFT JOIN wire_frames USING (process_id, packet_id)
  WHERE direction = 'tx'
    AND timestamp_ns BETWEEN (SELECT start_ns FROM analysis_window) AND (SELECT end_ns FROM analysis_window)
), trace AS (
  SELECT packets.*, frames FROM packet_lifecycles AS packets
  LEFT JOIN trace_frames USING (process_id, trace_id)
  WHERE direction = 'tx' AND outcome = 'success'
), totals AS (
  SELECT process_id, connection, count(*) AS packets FROM wire GROUP BY ALL
)
SELECT wire.process_id, wire.connection, trace.connection_id
FROM wire JOIN trace
  ON trace.process_id = wire.process_id
 AND trace.packet_space = wire.packet_space AND trace.packet_number = wire.packet_number
 AND trace.byte_len = wire.byte_len AND trace.frames IS NOT DISTINCT FROM wire.frames
JOIN totals ON totals.process_id = wire.process_id AND totals.connection = wire.connection
GROUP BY wire.process_id, wire.connection, trace.connection_id, totals.packets
HAVING count(DISTINCT wire.packet_id) = totals.packets;
