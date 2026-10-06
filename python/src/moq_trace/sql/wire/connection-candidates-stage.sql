-- Shared addresses do not identify a connection. Require a candidate to carry
-- every transmitted packet observed in the measurement window, with the same
-- packet number, size, and nonempty STREAM ranges. Capture timestamps can fall
-- after a send returns, so individual send lifetimes cannot identify the peer.
CREATE OR REPLACE TEMP TABLE wire_connection_candidates_stage AS
WITH wire AS (
  SELECT packets.*, frames FROM network.wire_packets AS packets
  LEFT JOIN wire_frame_lists USING (packet_id)
  WHERE direction = 'tx'
    AND timestamp_ns BETWEEN (SELECT start_ns FROM model.window) AND (SELECT end_ns FROM model.window)
), trace AS (
  SELECT packets.*, frames FROM model.packets AS packets
  LEFT JOIN trace_frame_lists USING (trace_id)
  WHERE direction = 'tx' AND outcome = 'success'
), totals AS (
  SELECT connection, count(*) AS packets FROM wire GROUP BY ALL
)
SELECT wire.connection, trace.connection_id
FROM wire JOIN trace
  ON trace.packet_space = wire.packet_space AND trace.packet_number = wire.packet_number
 AND trace.byte_len = wire.byte_len AND trace.frames IS NOT DISTINCT FROM wire.frames
JOIN totals USING (connection)
GROUP BY wire.connection, trace.connection_id, totals.packets
HAVING count(DISTINCT wire.packet_id) = totals.packets;
