INSERT INTO model.coverage_frames
SELECT frame.process_id, frame.trace_id AS object_trace_id, frame.seq::UINTEGER AS seq,
       frame.packet_id AS packet_trace_id, frame.offset_start, frame.offset_end,
       frame.covered_start, frame.covered_end
FROM coverage_frames frame JOIN coverage_completion completion USING(process_id, trace_id)
WHERE frame.seq <= completion.complete_seq;

INSERT INTO model.coverage
SELECT completion.process_id, completion.trace_id AS object_trace_id,
       completion.complete_seq::UINTEGER AS complete_seq,
       opening.packet_id AS first_packet_trace_id, closing.packet_id AS complete_packet_trace_id,
       opening.packet_start_ns::BIGINT AS first_start_ns,
       opening.packet_end_ns::BIGINT AS first_end_ns,
       closing.packet_end_ns::BIGINT AS complete_end_ns
FROM coverage_completion completion JOIN coverage_frames opening
  ON opening.process_id = completion.process_id AND opening.trace_id = completion.trace_id AND opening.seq = 1
JOIN coverage_frames closing ON closing.process_id = completion.process_id
  AND closing.trace_id = completion.trace_id AND closing.seq = completion.complete_seq;

INSERT INTO model.coverage_packets
SELECT process_id, object_trace_id, packet_trace_id, min(seq)::UINTEGER AS first_seq,
       (dense_rank() OVER (PARTITION BY process_id, object_trace_id ORDER BY min(seq)) - 1)::UINTEGER AS ordinal
FROM model.coverage_frames GROUP BY process_id, object_trace_id, packet_trace_id;
