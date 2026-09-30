-- Invariants of the paired lifecycles and phase intervals, checked once they are
-- materialized. Known phases must run in the direction `phase_catalog` gives them.
SELECT 'objects completing before they start' AS defect, count(*) AS count
FROM object_lifecycles WHERE end_ns < start_ns
UNION ALL
SELECT 'packets completing before they start', count(*)
FROM packet_lifecycles WHERE end_ns < start_ns
UNION ALL
SELECT 'moq_object_phase contains phases completing before they start', count(*)
FROM object_phase_intervals WHERE end_ns < start_ns
UNION ALL
SELECT 'quic_packet_phase contains phases completing before they start', count(*)
FROM packet_phase_intervals WHERE end_ns < start_ns
UNION ALL
SELECT 'object phases have invalid directions', count(*)
FROM object_phase_intervals AS phase JOIN object_lifecycles AS object USING (process_id, trace_id)
ANTI JOIN phase_catalog AS known
  ON known.subject = 'object' AND known.phase = phase.phase AND known.direction = object.direction
UNION ALL
SELECT 'packet phases have invalid directions', count(*)
FROM packet_phase_intervals AS phase JOIN packet_lifecycles AS packet USING (process_id, trace_id)
SEMI JOIN phase_catalog AS known ON known.subject = 'packet' AND known.phase = phase.phase
ANTI JOIN phase_catalog AS valid
  ON valid.subject = 'packet' AND valid.phase = phase.phase AND valid.direction = packet.direction
UNION ALL
-- The transport share of a packet subtracts application time from the packet
-- span, which is only sound when that time overlaps no other phase.
SELECT 'application packet phases overlap other packet phases', count(*)
FROM packet_phase_intervals AS application JOIN packet_phase_intervals AS other USING (process_id, trace_id)
WHERE application.phase = 'application' AND other.span_id <> application.span_id
  AND other.start_ns < application.end_ns AND application.start_ns < other.end_ns
UNION ALL
SELECT 'logical objects do not have exactly one ingress lifecycle', count(*)
FROM (
  SELECT process_id, logical_group, logical_frame, count(*) FILTER (direction = 'rx') AS ingress
  FROM object_lifecycles GROUP BY ALL HAVING ingress <> 1
);
