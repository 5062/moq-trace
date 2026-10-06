-- Each object records the first packet in completion order, the packet that
-- completed its byte range, and every packet up to that one in `seq` order.
-- Frames after the completing one, such as late retransmissions, do not extend
-- the object.
INSERT INTO {coverage}_frames
SELECT frame.trace_id AS object_trace_id, frame.seq::UINTEGER AS seq,
       frame.packet_id AS packet_trace_id, frame.offset_start, frame.offset_end,
       frame.covered_start, frame.covered_end
FROM coverage_frames frame JOIN coverage_completion completion USING (trace_id)
WHERE frame.seq <= completion.complete_seq;

-- The origin is the earliest packet start among the frames up to completion,
-- chosen apart from the completion order: an RX packet read first can be
-- accepted after one read later.
INSERT INTO {coverage}
SELECT completion.trace_id AS object_trace_id,
       completion.complete_seq::UINTEGER AS complete_seq,
       opening.packet_id AS first_packet_trace_id, closing.packet_id AS complete_packet_trace_id,
       retained.origin_ns::BIGINT AS origin_ns,
       opening.completion_ns::BIGINT AS first_ns,
       closing.completion_ns::BIGINT AS complete_ns
FROM coverage_completion completion
JOIN coverage_frames opening ON opening.trace_id = completion.trace_id AND opening.seq = 1
JOIN coverage_frames closing ON closing.trace_id = completion.trace_id AND closing.seq = completion.complete_seq
JOIN (
  SELECT frame.trace_id, min(frame.packet_start_ns) AS origin_ns
  FROM coverage_frames frame JOIN coverage_completion completion USING (trace_id)
  WHERE frame.seq <= completion.complete_seq
  GROUP BY ALL
) AS retained ON retained.trace_id = completion.trace_id;

INSERT INTO {coverage}_packets
SELECT object_trace_id, packet_trace_id, min(seq)::UINTEGER AS first_seq,
       (dense_rank() OVER (PARTITION BY object_trace_id ORDER BY min(seq)) - 1)::UINTEGER AS ordinal
FROM {coverage}_frames GROUP BY object_trace_id, packet_trace_id;
