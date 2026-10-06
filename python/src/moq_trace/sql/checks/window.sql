-- Starts without ends inside the analysis window. A relay without a graceful stop
-- is killed, and what it was handling then never records its end; those start
-- after the window closes and reach no metric. One that starts inside the window
-- lost its end some other way, which is an instrumentation fault.
SELECT 'object starts without completions inside the analysis window' AS defect, count(*) AS count
FROM moq_object_start ANTI JOIN moq_object_end USING (trace_id)
WHERE timestamp_ns <= (SELECT end_ns FROM model.window)
UNION ALL
SELECT 'packet starts without completions inside the analysis window', count(*)
FROM quic_packet_start ANTI JOIN quic_packet_end USING (trace_id)
WHERE timestamp_ns <= (SELECT end_ns FROM model.window)
UNION ALL
SELECT 'moq_object_phase contains unmatched phase boundaries inside the analysis window', count(*)
FROM moq_object_phase AS start ANTI JOIN moq_object_phase AS done
  ON done.trace_id = start.trace_id AND done.span_id = start.span_id
 AND done.phase = start.phase AND done.edge = 'done'
WHERE start.edge = 'start' AND start.timestamp_ns <= (SELECT end_ns FROM model.window)
UNION ALL
SELECT 'quic_packet_phase contains unmatched phase boundaries inside the analysis window', count(*)
FROM quic_packet_phase AS start ANTI JOIN quic_packet_phase AS done
  ON done.trace_id = start.trace_id AND done.span_id = start.span_id
 AND done.phase = start.phase AND done.edge = 'done'
WHERE start.edge = 'start' AND start.timestamp_ns <= (SELECT end_ns FROM model.window);
