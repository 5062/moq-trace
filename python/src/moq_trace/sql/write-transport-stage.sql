-- Transport work a stack ran inside its MoQ write calls, per outbound object.
--
-- A stack that sends inside its write call, as Google QUICHE does, runs packet
-- building and the send system call inside `payload_write`. Both `moq_tx_work`
-- and the object's `payload_write` phase total subtract this work, so each
-- charges the MoQ layer only for its own.
--
-- Every TX packet that the writing thread started during a write is transport
-- work done inside that call, from its start until it ended or the write
-- returned. A packet started on another thread, or before the write began,
-- belongs to some other call. Overlapping packets, such as those one GSO send
-- carries, are merged so their time counts once.
CREATE TEMP TABLE write_transport AS
WITH writes AS (
  SELECT process_id, trace_id, span_id, start_ns, end_ns, tid
  FROM object_phase_intervals WHERE outcome = 'success' AND phase = 'payload_write'
), nested AS (
  SELECT write.process_id, write.trace_id, write.span_id,
         packet.start_ns, least(packet.end_ns, write.end_ns) AS end_ns
  FROM writes AS write
  JOIN packet_lifecycles AS packet
    ON packet.process_id = write.process_id AND packet.direction = 'tx' AND packet.tid = write.tid
   AND packet.start_ns >= write.start_ns AND packet.start_ns < write.end_ns
), ordered AS (
  SELECT *, max(end_ns) OVER (
           PARTITION BY process_id, trace_id, span_id ORDER BY start_ns, end_ns
           ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
         ) AS previous_end_ns
  FROM nested
), islands AS (
  SELECT *, sum(CASE WHEN previous_end_ns IS NULL OR start_ns > previous_end_ns THEN 1 ELSE 0 END) OVER (
           PARTITION BY process_id, trace_id, span_id ORDER BY start_ns, end_ns ROWS UNBOUNDED PRECEDING
         ) AS island
  FROM ordered
)
SELECT process_id, trace_id, sum(span_ns(start_ns, end_ns))::BIGINT AS transport_ns
FROM (
  SELECT process_id, trace_id, span_id, island, min(start_ns) AS start_ns, max(end_ns) AS end_ns
  FROM islands GROUP BY ALL
) GROUP BY ALL;
