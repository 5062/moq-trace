-- Pair every lifecycle's start and end events, and every interval's start and
-- done edges, into the model tables. `checks/raw` has already rejected
-- duplicate and unmatched boundaries, so each pairing is one to one.
INSERT INTO model.objects BY NAME
SELECT start.* EXCLUDE (pid, ctf_timestamp_ns, timestamp_ns),
       start.ctf_timestamp_ns AS start_ctf_ns, start.timestamp_ns AS start_ns,
       finish.ctf_timestamp_ns AS end_ctf_ns, finish.timestamp_ns AS end_ns,
       finish.stream_offset_end, finish.payload_bytes, finish.outcome
FROM moq_object_start AS start
JOIN moq_object_end AS finish USING (trace_id);

-- A packet's number, space, and size are final only once it ends.
INSERT INTO model.packets BY NAME
SELECT start.* EXCLUDE (pid, ctf_timestamp_ns, timestamp_ns, packet_number, packet_space, byte_len),
       finish.packet_number, finish.packet_space, finish.byte_len,
       start.ctf_timestamp_ns AS start_ctf_ns, start.timestamp_ns AS start_ns,
       finish.ctf_timestamp_ns AS end_ctf_ns, finish.timestamp_ns AS end_ns,
       finish.outcome
FROM quic_packet_start AS start
JOIN quic_packet_end AS finish USING (trace_id);

-- A copy names the ingress lifecycle of its logical object, which
-- `checks/model` requires to be unique.
UPDATE model.objects AS tx SET rx_trace_id = rx.trace_id
FROM model.objects AS rx
WHERE rx.logical_group = tx.logical_group AND rx.logical_frame = tx.logical_frame
  AND rx.direction = 'rx' AND tx.direction = 'tx';

-- Successful copies of one inbound object are numbered by session.
UPDATE model.objects AS tx SET copy_ordinal = copy.ordinal
FROM (SELECT trace_id,
             (row_number() OVER (PARTITION BY rx_trace_id ORDER BY session_id, trace_id) - 1)::UINTEGER AS ordinal
      FROM model.objects WHERE direction = 'tx' AND outcome = 'success' AND rx_trace_id IS NOT NULL) AS copy
WHERE tx.trace_id = copy.trace_id;

-- A phase can recur within one lifecycle, and `occurrence` numbers its
-- intervals in the order they started.
INSERT INTO model.intervals BY NAME
WITH edges AS (
  SELECT 'object'::subject AS subject, * FROM moq_object_phase
  UNION ALL
  SELECT 'packet'::subject, * FROM quic_packet_phase
)
SELECT start.subject, start.trace_id, start.span_id, start.phase,
       (row_number() OVER (
         PARTITION BY start.subject, start.trace_id, start.phase
         ORDER BY start.ctf_timestamp_ns, start.timestamp_ns, start.span_id
       ) - 1)::UINTEGER AS occurrence,
       start.timestamp_ns AS start_ns, finish.timestamp_ns AS end_ns, finish.outcome, start.tid
FROM edges AS start
JOIN edges AS finish USING (subject, trace_id, span_id, phase)
WHERE start.edge = 'start' AND finish.edge = 'done';

-- An interval the capture cut off before it ended has no done edge and is
-- left out, as an unfinished phase is.
INSERT INTO model.send_blocked BY NAME
SELECT start.span_id, start.connection_id, start.stream_id, start.reason,
       start.timestamp_ns AS start_ns, finish.timestamp_ns AS end_ns
FROM quic_send_blocked AS start
JOIN quic_send_blocked AS finish USING (span_id)
WHERE start.edge = 'start' AND finish.edge = 'done';

-- Construction shorthands, dropped with the builder connection.
CREATE TEMP VIEW object_copies AS
SELECT * FROM model.objects WHERE direction = 'tx' AND copy_ordinal IS NOT NULL;

CREATE TEMP VIEW object_phase_intervals AS
SELECT * EXCLUDE (subject) FROM model.intervals WHERE subject = 'object';

CREATE TEMP VIEW packet_phase_intervals AS
SELECT * EXCLUDE (subject) FROM model.intervals WHERE subject = 'packet';
