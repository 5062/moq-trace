-- The trace and the wire must choose the same packets for every object and
-- copy, and the same packet must complete each. Each row names one defect and
-- how many objects have it.
WITH trace AS (
  SELECT object_trace_id, list(packet_trace_id ORDER BY packet_trace_id) AS packets
  FROM model.coverage_packets GROUP BY ALL
), wire AS (
  SELECT coverage.object_trace_id, list(packet.trace_id ORDER BY packet.trace_id) AS packets
  FROM network.wire_coverage_packets AS coverage
  JOIN network.wire_packets AS packet ON packet.packet_id = coverage.packet_trace_id
  GROUP BY ALL
)
SELECT 'objects covered by different packets' AS defect, count(*) AS count
FROM trace FULL JOIN wire USING (object_trace_id)
WHERE trace.packets IS DISTINCT FROM wire.packets
UNION ALL
SELECT 'objects completed by a different packet', count(*)
FROM model.coverage AS trace
JOIN network.wire_coverage AS wire USING (object_trace_id)
JOIN network.wire_packets AS packet ON packet.packet_id = wire.complete_packet_trace_id
WHERE packet.trace_id IS DISTINCT FROM trace.complete_packet_trace_id;
