-- Every completed inbound object of the workload's size, with how many of its
-- copies accounted for their subscriber: delivered, or deliberately not
-- delivered with one of the `$undelivered` outcomes.
CREATE TEMP TABLE inbound_objects AS
SELECT rx.trace_id, rx.start_ns,
       count(tx.trace_id) FILTER (
         tx.outcome = 'success' OR list_contains($undelivered, tx.outcome::VARCHAR)
       ) AS copies
FROM model.objects AS rx
LEFT JOIN model.objects AS tx ON tx.rx_trace_id = rx.trace_id AND tx.direction = 'tx'
WHERE rx.direction = 'rx' AND rx.outcome = 'success' AND rx.payload_bytes = $size
GROUP BY rx.trace_id, rx.start_ns;
