-- A nested phase, such as a transport call, is subtracted from the work phase
-- occurrence that contains it, so each work row charges the MoQ layer only for
-- its own work. The nested phase keeps a row of its own.
INSERT INTO metrics.phase_totals BY NAME
WITH subjects AS (
    SELECT 'object'::subject AS subject, trace_id, direction FROM model.objects
    SEMI JOIN (
        SELECT trace_id FROM model.selected_objects
        UNION ALL
        SELECT tx_trace_id FROM selected_copies
    ) selected USING (trace_id)
    UNION ALL
    SELECT 'packet'::subject, trace_id, direction FROM selected_packets WHERE outcome = 'success'
), kinds AS (
    SELECT DISTINCT subject::subject AS subject, phase, wait, nested FROM phase_catalog
), intervals AS (
    SELECT phase.*, coalesce(kind.wait, false) AS wait, coalesce(kind.nested, false) AS nested
    FROM model.intervals phase
    SEMI JOIN subjects USING (subject, trace_id)
    LEFT JOIN kinds kind USING (subject, phase)
    WHERE phase.outcome = 'success'
), contained AS (
    SELECT outer_phase.subject, outer_phase.trace_id, outer_phase.phase,
           span_ns(inner_phase.start_ns, inner_phase.end_ns) AS ns
    FROM intervals inner_phase JOIN intervals outer_phase
      ON outer_phase.subject = inner_phase.subject AND outer_phase.trace_id = inner_phase.trace_id
     AND NOT outer_phase.wait AND NOT outer_phase.nested
     AND outer_phase.start_ns <= inner_phase.start_ns AND inner_phase.end_ns <= outer_phase.end_ns
    WHERE inner_phase.nested
    -- Work phases of one object never overlap, so one occurrence contains it.
    QUALIFY row_number() OVER (
        PARTITION BY inner_phase.trace_id, inner_phase.span_id ORDER BY outer_phase.start_ns
    ) = 1
)
SELECT total.subject, subject.direction, total.trace_id, total.phase,
       (total.total_ns - coalesce(nested.ns, 0))::BIGINT AS total_ns
FROM (
  SELECT subject, trace_id, phase, sum(span_ns(start_ns, end_ns)) AS total_ns
  FROM intervals GROUP BY ALL
) total
JOIN subjects subject USING (subject, trace_id)
LEFT JOIN (SELECT subject, trace_id, phase, sum(ns) AS ns FROM contained GROUP BY ALL) nested
  USING (subject, trace_id, phase);
