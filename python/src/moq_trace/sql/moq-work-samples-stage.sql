-- What each copy cost the MoQ layer, what it waited on, and when the relay began
-- forwarding it.
--
-- `moq_rx_work` sums the inbound object's successful MoQ work phases, and
-- `moq_tx_work` the copy's. Neither counts a wait phase, and other waiting,
-- such as for bytes that have not arrived, belongs to no phase. Both subtract
-- the transport calls nested in their phases, so a stack that builds and sends
-- packets inside its write call, or contends on a transport lock there, charges
-- that time to the transport rather than to MoQ. `moq_rx_transport` and
-- `moq_tx_transport` sum those calls.
--
-- `moq_delivery_wait` and `moq_write_blocked` sum the copy's occurrences of
-- those wait phases. A process that never emitted a wait or a transport call did
-- not measure it, so its copies have no sample rather than a zero. Once a
-- process emitted it, a copy without an occurrence did not spend that time, and
-- its sample is zero.
--
-- `moq_write_after_receive` is the copy's first write start minus the end of
-- the inbound object's last payload read. It is negative when the relay forwards
-- bytes before the whole object has arrived, and positive when it waits for it.
CREATE TEMP TABLE moq_work_samples AS
WITH copies AS (
  SELECT rx.process_id, rx.trace_id AS rx_trace_id, tx.trace_id AS tx_trace_id, rx.start_ns AS rx_start_ns
  FROM selected_rx AS rx
  JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
), kinds AS (
  SELECT DISTINCT phase, wait, nested FROM phase_catalog WHERE subject = 'object'
), work AS (
  SELECT process_id, trace_id,
         coalesce(sum(span_ns(start_ns, end_ns)) FILTER (NOT kinds.wait AND NOT kinds.nested), 0)
           - coalesce(sum(span_ns(start_ns, end_ns)) FILTER (kinds.nested), 0) AS work_ns,
         sum(span_ns(start_ns, end_ns)) FILTER (phase = 'transport_call') AS transport_ns,
         sum(span_ns(start_ns, end_ns)) FILTER (phase = 'delivery_wait') AS delivery_wait_ns,
         sum(span_ns(start_ns, end_ns)) FILTER (phase = 'write_blocked') AS write_blocked_ns,
         max(end_ns) FILTER (phase = 'payload_read') AS received_ns,
         min(start_ns) FILTER (phase = 'payload_write') AS first_write_ns
  FROM object_phase_intervals JOIN kinds USING (phase)
  WHERE outcome = 'success' GROUP BY ALL
), measured AS (
  SELECT process_id, bool_or(phase = 'delivery_wait') AS delivery_wait,
         bool_or(phase = 'write_blocked') AS write_blocked,
         bool_or(phase = 'transport_call') AS transport_call
  FROM object_phase_intervals GROUP BY ALL
)
SELECT copy.process_id, copy.rx_trace_id, copy.tx_trace_id, metric,
       elapsed_ns(copy.rx_start_ns, $origin) AS elapsed_ns, value AS latency_ns
FROM copies AS copy
JOIN work AS rx ON rx.process_id = copy.process_id AND rx.trace_id = copy.rx_trace_id
JOIN work AS tx ON tx.process_id = copy.process_id AND tx.trace_id = copy.tx_trace_id
JOIN measured ON measured.process_id = copy.process_id
CROSS JOIN LATERAL (VALUES
  ('moq_rx_work', rx.work_ns),
  ('moq_tx_work', tx.work_ns),
  ('moq_rx_transport', CASE WHEN measured.transport_call THEN coalesce(rx.transport_ns, 0) END),
  ('moq_tx_transport', CASE WHEN measured.transport_call THEN coalesce(tx.transport_ns, 0) END),
  ('moq_write_after_receive', span_ns(rx.received_ns, tx.first_write_ns)),
  ('moq_delivery_wait', CASE WHEN measured.delivery_wait THEN coalesce(tx.delivery_wait_ns, 0) END),
  ('moq_write_blocked', CASE WHEN measured.write_blocked THEN coalesce(tx.write_blocked_ns, 0) END)
) AS sample(metric, value)
WHERE value IS NOT NULL;
