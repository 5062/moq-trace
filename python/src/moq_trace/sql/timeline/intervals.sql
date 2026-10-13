-- The lifecycle, phases, and carrying packets of one selected object and all
-- its successful copies, in microseconds from `$origin`. The heading measures
-- all copies, while the drawing shows only the first and last.
WITH objects AS (
  SELECT * FROM model.objects
  WHERE trace_id = $rx OR (rx_trace_id = $rx AND copy_ordinal IS NOT NULL)
), packets AS (
  SELECT coverage.* FROM model.coverage_packets coverage
  JOIN objects object ON object.trace_id = coverage.object_trace_id
), intervals AS (
  SELECT trace_id, 'object' AS phase, 0 AS occurrence, start_ns, end_ns FROM objects
  UNION ALL
  SELECT phase.trace_id, phase.phase, phase.occurrence, phase.start_ns, phase.end_ns
  FROM model.intervals phase JOIN objects object USING (trace_id)
  WHERE phase.subject = 'object' AND phase.outcome = 'success'
  UNION ALL
  SELECT packet.object_trace_id, 'quic_packet', packet.ordinal, lifecycle.start_ns, lifecycle.end_ns
  FROM packets packet JOIN model.packets lifecycle ON lifecycle.trace_id = packet.packet_trace_id
  UNION ALL
  SELECT packet.object_trace_id, 'quic_' || phase.phase, phase.occurrence, phase.start_ns, phase.end_ns
  FROM packets packet JOIN model.intervals phase ON phase.trace_id = packet.packet_trace_id
  WHERE phase.subject = 'packet' AND phase.outcome = 'success'
)
SELECT object.direction, object.session_id, interval.phase, interval.occurrence,
       (interval.start_ns - $origin) / 1000.0, (interval.end_ns - $origin) / 1000.0
FROM intervals interval JOIN objects object USING (trace_id)
ORDER BY object.direction, object.session_id, interval.phase, interval.occurrence, interval.start_ns;
