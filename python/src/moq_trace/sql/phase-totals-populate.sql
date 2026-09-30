INSERT INTO metrics.phase_totals
WITH subjects AS (
    SELECT object.process_id, 'object'::subject AS subject, object.trace_id, object.direction
    FROM model.objects AS object SEMI JOIN (
        SELECT process_id, trace_id FROM model.selected_objects
        UNION ALL
        SELECT tx.process_id, tx.trace_id FROM object_copies tx
        JOIN model.selected_objects rx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
    ) selected USING(process_id, trace_id)
    UNION ALL
    SELECT process_id, 'packet'::subject, trace_id, direction FROM selected_packets WHERE outcome = 'success'
)
SELECT phase.process_id, phase.subject, object.direction, phase.trace_id, phase.phase,
       sum(span_ns(phase.start_ns, phase.end_ns))::BIGINT AS total_ns
FROM model.intervals phase JOIN subjects object USING(process_id, subject, trace_id)
WHERE phase.outcome = 'success' GROUP BY ALL;
