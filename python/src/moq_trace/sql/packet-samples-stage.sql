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
  AND packet.end_ns >= schedule.end_ns
UNION ALL
-- A TX packet's `send_queue` covers both waiting to be batched into a send and the
-- send system call itself. A packet ends at exactly the completion its send
-- reported, so the successful TX socket operation that ended at that instant on
-- the packet's connection is the send that carried it. The split is left out
-- when no send, or more than one, ended at that instant.
SELECT packet.process_id, sample.metric, packet.direction, packet.connection_id,
       packet.trace_id, queue.span_id, 0, elapsed_ns(queue.start_ns, $origin), sample.value
FROM selected_packets AS packet
JOIN packet_phase_intervals AS queue
  ON queue.process_id = packet.process_id AND queue.trace_id = packet.trace_id
 AND queue.phase = 'send_queue' AND queue.outcome = 'success'
JOIN (
  SELECT start.process_id, start.connection_id, start.timestamp_ns AS start_ns, finish.timestamp_ns AS end_ns
  FROM udp_socket_start AS start
  JOIN udp_socket_end AS finish USING (process_id, trace_id)
  WHERE start.direction = 'tx' AND finish.outcome = 'success'
) AS send
  ON send.process_id = packet.process_id AND send.end_ns = packet.end_ns
 AND (send.connection_id IS NULL OR send.connection_id = packet.connection_id)
CROSS JOIN LATERAL (VALUES
  ('tx_send_batching', span_ns(queue.start_ns, send.start_ns)),
  ('tx_send_syscall', span_ns(send.start_ns, send.end_ns))
) AS sample(metric, value)
WHERE packet.direction = 'tx' AND packet.outcome = 'success'
QUALIFY count(*) OVER (PARTITION BY packet.process_id, packet.trace_id, sample.metric) = 1;
