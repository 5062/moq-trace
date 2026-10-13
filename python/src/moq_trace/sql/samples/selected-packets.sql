-- The packets that carried bytes of a selected object or copy.
CREATE TEMP VIEW selected_packets AS
SELECT * FROM model.packets
SEMI JOIN (SELECT DISTINCT packet_trace_id AS trace_id FROM model.coverage_packets) USING (trace_id);
