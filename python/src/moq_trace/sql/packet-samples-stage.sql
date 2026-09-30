CREATE TEMP TABLE packet_samples AS
WITH application AS (
  SELECT process_id, trace_id, start_ns, span_ns(start_ns, end_ns) AS ns
  FROM packet_phase_intervals WHERE phase = 'application'
)
SELECT process_id, direction || '_packet_span' AS metric, direction, connection_id,
       trace_id, NULL::UBIGINT AS span_id, 0 AS occurrence,
       elapsed_ns(start_ns, $origin) AS elapsed_ns,
       span_ns(start_ns, end_ns) AS latency_ns
FROM selected_packets WHERE outcome = 'success'
UNION ALL
-- A stack that delivers data after the packet returns records no
-- application phase, so its transport span equals its packet span.
SELECT packet.process_id, 'rx_packet_transport_span', packet.direction, packet.connection_id,
       packet.trace_id, NULL::UBIGINT, 0,
       elapsed_ns(packet.start_ns, $origin),
       span_ns(packet.start_ns, packet.end_ns)
         - coalesce((SELECT sum(ns) FROM application
                     WHERE application.process_id = packet.process_id AND application.trace_id =
                     packet.trace_id), 0)
FROM selected_packets AS packet
WHERE packet.direction = 'rx' AND packet.outcome = 'success'
UNION ALL
SELECT packet.process_id, packet.direction || '_' || phase.phase, packet.direction,
       packet.connection_id, packet.trace_id, phase.span_id, phase.occurrence,
       elapsed_ns(phase.start_ns, $origin),
       span_ns(phase.start_ns, phase.end_ns)
FROM packet_phase_intervals AS phase
JOIN selected_packets AS packet USING (process_id, trace_id)
WHERE phase.outcome = 'success'
UNION ALL
SELECT packet.process_id, 'rx_packet_processing_span', packet.direction, packet.connection_id,
       packet.trace_id, NULL::UBIGINT, 0,
       elapsed_ns(schedule.end_ns, $origin),
       span_ns(schedule.end_ns, packet.end_ns)
         - coalesce((SELECT sum(ns) FROM application
                     WHERE application.process_id = packet.process_id AND application.trace_id =
                     packet.trace_id
                       AND application.start_ns >= schedule.end_ns), 0)
FROM selected_packets AS packet
JOIN (
  SELECT process_id, trace_id, max(end_ns) AS end_ns
  FROM packet_phase_intervals
  WHERE phase = 'scheduling' AND outcome = 'success'
  GROUP BY process_id, trace_id
) AS schedule USING (process_id, trace_id)
WHERE packet.direction = 'rx' AND packet.outcome = 'success'
  AND packet.end_ns >= schedule.end_ns;
