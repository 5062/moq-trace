-- A wire packet matches the trace packet of its joined connection with the same
-- direction, packet number space, and packet number.
UPDATE network.wire_packets AS wire SET trace_id = trace.trace_id
FROM network.wire_connections AS joined, packet_lifecycles AS trace
WHERE joined.process_id = wire.process_id AND joined.connection = wire.connection
  AND trace.process_id = wire.process_id AND trace.connection_id = joined.trace_connection_id
  AND trace.direction = wire.direction::VARCHAR AND trace.packet_space = wire.packet_space
  AND trace.packet_number = wire.packet_number;
