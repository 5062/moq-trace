INSERT INTO model.objects BY NAME
SELECT * EXCLUDE(pid, start_ctf_timestamp_ns, end_ctf_timestamp_ns)
    REPLACE(direction::direction AS direction, outcome::outcome AS outcome),
       start_ctf_timestamp_ns AS start_ctf_ns,
       end_ctf_timestamp_ns AS end_ctf_ns
FROM object_lifecycles;

INSERT INTO model.packets BY NAME
SELECT * EXCLUDE(pid, start_ctf_timestamp_ns, end_ctf_timestamp_ns)
    REPLACE(direction::direction AS direction, outcome::outcome AS outcome),
       start_ctf_timestamp_ns AS start_ctf_ns,
       end_ctf_timestamp_ns AS end_ctf_ns
FROM packet_lifecycles;

UPDATE model.objects AS tx SET rx_trace_id = rx.trace_id
FROM model.objects AS rx
WHERE rx.process_id = tx.process_id AND rx.logical_group = tx.logical_group
  AND rx.logical_frame = tx.logical_frame AND rx.direction = 'rx' AND tx.direction = 'tx';

UPDATE model.objects AS tx SET copy_ordinal = copy.ordinal
FROM (SELECT process_id, trace_id,
             (row_number() OVER (PARTITION BY process_id, rx_trace_id
              ORDER BY session_id, trace_id) - 1)::UINTEGER AS ordinal
      FROM model.objects WHERE direction = 'tx' AND outcome = 'success'
        AND rx_trace_id IS NOT NULL) AS copy
WHERE tx.process_id = copy.process_id AND tx.trace_id = copy.trace_id;

INSERT INTO model.intervals
SELECT process_id, 'object'::subject AS subject, trace_id, span_id, phase,
       occurrence::UINTEGER AS occurrence, start_ns, end_ns,
       outcome::outcome AS outcome FROM object_phase_intervals
UNION ALL
SELECT process_id, 'packet'::subject, trace_id, span_id, phase,
       occurrence::UINTEGER, start_ns, end_ns, outcome::outcome
FROM packet_phase_intervals;
