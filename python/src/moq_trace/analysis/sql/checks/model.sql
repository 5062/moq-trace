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
)
UNION ALL
-- An RX packet starts when the read that returned its datagram completes, and a
-- TX packet ends when the send that accepted it completes. The queue phases mark
-- those boundaries, so a successful packet without one was traced with other
-- boundaries and cannot be measured with these.
SELECT 'successful RX packets without one read_queue phase starting at the packet start', count(*)
FROM packet_lifecycles AS packet
LEFT JOIN (
  SELECT process_id, trace_id, count(*) AS phases,
         count(*) FILTER (outcome = 'success') AS successes, min(start_ns) AS start_ns
  FROM packet_phase_intervals WHERE phase = 'read_queue' GROUP BY ALL
) AS queue USING (process_id, trace_id)
WHERE packet.direction = 'rx' AND packet.outcome = 'success'
  AND (queue.phases IS DISTINCT FROM 1 OR queue.successes <> 1 OR queue.start_ns <> packet.start_ns)
UNION ALL
SELECT 'successful TX packets without one send_queue phase ending at the packet end', count(*)
FROM packet_lifecycles AS packet
LEFT JOIN (
  SELECT process_id, trace_id, count(*) AS phases,
         count(*) FILTER (outcome = 'success') AS successes, max(end_ns) AS end_ns
  FROM packet_phase_intervals WHERE phase = 'send_queue' GROUP BY ALL
) AS queue USING (process_id, trace_id)
WHERE packet.direction = 'tx' AND packet.outcome = 'success'
  AND (queue.phases IS DISTINCT FROM 1 OR queue.successes <> 1 OR queue.end_ns <> packet.end_ns)
UNION ALL
-- A nested phase is subtracted from the work phase around it, which is only
-- sound when one successful work occurrence of the same object contains it.
SELECT 'nested object phases outside a work phase of their object', count(*)
FROM object_phase_intervals AS inner_phase
SEMI JOIN phase_catalog AS kind
  ON kind.subject = 'object' AND kind.phase = inner_phase.phase AND kind.nested
ANTI JOIN (
  SELECT outer_phase.* FROM object_phase_intervals AS outer_phase
  SEMI JOIN phase_catalog AS kind
    ON kind.subject = 'object' AND kind.phase = outer_phase.phase AND NOT kind.wait AND NOT kind.nested
) AS outer_phase
  ON outer_phase.process_id = inner_phase.process_id AND outer_phase.trace_id = inner_phase.trace_id
 AND outer_phase.start_ns <= inner_phase.start_ns AND inner_phase.end_ns <= outer_phase.end_ns
WHERE inner_phase.outcome = 'success';
