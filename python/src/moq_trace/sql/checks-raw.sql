-- Raw boundary defects that no pairing can correlate. Each row names one defect
-- and how many records have it; the analysis rejects a trace with any nonzero row.
SELECT 'moq_object_start contains duplicate trace IDs' AS defect, count(*) AS count
FROM (SELECT process_id, trace_id FROM moq_object_start GROUP BY ALL HAVING count(*) <> 1)
UNION ALL
SELECT 'moq_object_end contains duplicate trace IDs', count(*)
FROM (SELECT process_id, trace_id FROM moq_object_end GROUP BY ALL HAVING count(*) <> 1)
UNION ALL
SELECT 'quic_packet_start contains duplicate trace IDs', count(*)
FROM (SELECT process_id, trace_id FROM quic_packet_start GROUP BY ALL HAVING count(*) <> 1)
UNION ALL
SELECT 'quic_packet_end contains duplicate trace IDs', count(*)
FROM (SELECT process_id, trace_id FROM quic_packet_end GROUP BY ALL HAVING count(*) <> 1)
UNION ALL
SELECT 'object completions without starts', count(*)
FROM moq_object_end ANTI JOIN moq_object_start USING (process_id, trace_id)
UNION ALL
SELECT 'packet completions without starts', count(*)
FROM quic_packet_end ANTI JOIN quic_packet_start USING (process_id, trace_id)
UNION ALL
SELECT 'moq_object_phase contains duplicate phase boundaries', count(*)
FROM (SELECT process_id, trace_id, span_id, phase, edge FROM moq_object_phase GROUP BY ALL HAVING count(*) > 1)
UNION ALL
SELECT 'quic_packet_phase contains duplicate phase boundaries', count(*)
FROM (SELECT process_id, trace_id, span_id, phase, edge FROM quic_packet_phase GROUP BY ALL HAVING count(*) > 1)
UNION ALL
SELECT 'moq_object_phase contains unmatched phase boundaries', count(*)
FROM moq_object_phase AS done ANTI JOIN moq_object_phase AS start
  ON start.process_id = done.process_id AND start.trace_id = done.trace_id AND start.span_id = done.span_id
 AND start.phase = done.phase AND start.edge = 'start'
WHERE done.edge = 'done'
UNION ALL
SELECT 'quic_packet_phase contains unmatched phase boundaries', count(*)
FROM quic_packet_phase AS done ANTI JOIN quic_packet_phase AS start
  ON start.process_id = done.process_id AND start.trace_id = done.trace_id AND start.span_id = done.span_id
 AND start.phase = done.phase AND start.edge = 'start'
WHERE done.edge = 'done';
