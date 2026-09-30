CREATE TEMP VIEW object_lifecycles AS
SELECT start.* EXCLUDE (ctf_timestamp_ns, timestamp_ns),
       start.ctf_timestamp_ns AS start_ctf_timestamp_ns,
       start.timestamp_ns AS start_ns,
       finish.ctf_timestamp_ns AS end_ctf_timestamp_ns,
       finish.timestamp_ns AS end_ns,
       finish.stream_offset_end,
       finish.payload_bytes,
       finish.outcome
FROM moq_object_start AS start
JOIN moq_object_end AS finish USING (process_id, trace_id);

CREATE TEMP VIEW packet_lifecycles AS
SELECT start.* EXCLUDE (ctf_timestamp_ns, timestamp_ns, packet_number, packet_space, byte_len),
       finish.packet_number, finish.packet_space, finish.byte_len,
       start.ctf_timestamp_ns AS start_ctf_timestamp_ns,
       start.timestamp_ns AS start_ns,
       finish.ctf_timestamp_ns AS end_ctf_timestamp_ns,
       finish.timestamp_ns AS end_ns,
       finish.outcome
FROM quic_packet_start AS start
JOIN quic_packet_end AS finish USING (process_id, trace_id);

-- Every successful outbound copy of a logical object, keyed by the
-- trace of its ingress lifecycle. Validation guarantees one ingress
-- per logical object, so `rx_trace_id` names it unambiguously.
CREATE TEMP VIEW object_copies AS
SELECT rx.process_id, rx.trace_id AS rx_trace_id, tx.trace_id, tx.session_id, tx.end_ns
FROM object_lifecycles AS rx
JOIN object_lifecycles AS tx USING (process_id, logical_group, logical_frame)
WHERE rx.direction = 'rx' AND tx.direction = 'tx' AND tx.outcome = 'success';

CREATE TEMP VIEW object_phase_intervals AS
WITH paired AS (
  SELECT starts.process_id, starts.trace_id, starts.span_id, starts.phase,
         starts.ctf_timestamp_ns, starts.timestamp_ns AS start_ns,
         finishes.timestamp_ns AS end_ns, finishes.outcome
  FROM moq_object_phase AS starts
  JOIN moq_object_phase AS finishes USING (process_id, trace_id, span_id, phase)
  WHERE starts.edge = 'start' AND finishes.edge = 'done'
)
SELECT process_id, trace_id, span_id, phase,
       row_number() OVER (
         PARTITION BY process_id, trace_id, phase ORDER BY ctf_timestamp_ns, start_ns, span_id
       ) - 1 AS occurrence,
       start_ns, end_ns, outcome
FROM paired;

CREATE TEMP VIEW packet_phase_intervals AS
WITH paired AS (
  SELECT starts.process_id, starts.trace_id, starts.span_id, starts.phase,
         starts.ctf_timestamp_ns, starts.timestamp_ns AS start_ns,
         finishes.timestamp_ns AS end_ns, finishes.outcome
  FROM quic_packet_phase AS starts
  JOIN quic_packet_phase AS finishes USING (process_id, trace_id, span_id, phase)
  WHERE starts.edge = 'start' AND finishes.edge = 'done'
)
SELECT process_id, trace_id, span_id, phase,
       row_number() OVER (
         PARTITION BY process_id, trace_id, phase ORDER BY ctf_timestamp_ns, start_ns, span_id
       ) - 1 AS occurrence,
       start_ns, end_ns, outcome
FROM paired;
