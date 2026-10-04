-- What each copy cost the MoQ layer, and when the relay began forwarding it.
--
-- `moq_rx_work` sums the inbound object's successful MoQ phases, and
-- `moq_tx_work` the copy's. Phases record processing only, so neither counts
-- time spent waiting for bytes or for flow control.
--
-- A stack that sends inside its write call, as Google QUICHE does, runs
-- transport work inside `payload_write`. `write_transport` holds that work per
-- outbound object, and both `moq_tx_work` and the object's `payload_write`
-- phase total subtract it.
--
-- `moq_write_after_receive` is the copy's first write start minus the end of
-- the inbound object's last payload read. It is negative when the relay forwards
-- bytes before the whole object has arrived, and positive when it waits for it.
CREATE TEMP TABLE moq_work_samples AS
WITH copies AS (
  SELECT rx.process_id, rx.trace_id AS rx_trace_id, tx.trace_id AS tx_trace_id, rx.start_ns AS rx_start_ns
  FROM selected_rx AS rx
  JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
), work AS (
  SELECT process_id, trace_id, sum(span_ns(start_ns, end_ns)) AS work_ns,
         max(end_ns) FILTER (phase = 'payload_read') AS received_ns,
         min(start_ns) FILTER (phase = 'payload_write') AS first_write_ns
  FROM object_phase_intervals WHERE outcome = 'success' GROUP BY ALL
)
SELECT copy.process_id, copy.rx_trace_id, copy.tx_trace_id, metric,
       elapsed_ns(copy.rx_start_ns, $origin) AS elapsed_ns, value AS latency_ns
FROM copies AS copy
JOIN work AS rx ON rx.process_id = copy.process_id AND rx.trace_id = copy.rx_trace_id
JOIN work AS tx ON tx.process_id = copy.process_id AND tx.trace_id = copy.tx_trace_id
LEFT JOIN write_transport AS transport
  ON transport.process_id = copy.process_id AND transport.trace_id = copy.tx_trace_id
CROSS JOIN LATERAL (VALUES
  ('moq_rx_work', rx.work_ns),
  ('moq_tx_work', tx.work_ns - coalesce(transport.transport_ns, 0)),
  ('moq_write_after_receive', span_ns(rx.received_ns, tx.first_write_ns))
) AS sample(metric, value)
WHERE value IS NOT NULL;
