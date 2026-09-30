CREATE TEMP TABLE coverage_completion AS
WITH boundaries AS (
  SELECT process_id, trace_id, stream_offset_start AS boundary FROM coverage_targets
  UNION
  SELECT process_id, trace_id, stream_offset_end FROM coverage_targets
  UNION
  SELECT process_id, trace_id, covered_start FROM coverage_frames
  UNION
  SELECT process_id, trace_id, covered_end FROM coverage_frames
), segments AS (
  SELECT process_id, trace_id, segment_start, segment_end,
         (segment_start // $bucket)::BIGINT AS bucket
  FROM (
    SELECT process_id, trace_id, boundary AS segment_start,
           lead(boundary) OVER (PARTITION BY process_id, trace_id ORDER BY boundary) AS segment_end
    FROM boundaries
  )
  WHERE segment_end IS NOT NULL
), covering AS (
  SELECT process_id, trace_id, seq, covered_start, covered_end,
         unnest(offset_buckets(covered_start, covered_end, $bucket)) AS bucket
  FROM coverage_frames
  WHERE covered_start < covered_end
), first_cover AS (
  SELECT segment.process_id, segment.trace_id, min(frame.seq) AS seq
  FROM segments AS segment
  LEFT JOIN covering AS frame
    ON frame.process_id = segment.process_id AND frame.trace_id = segment.trace_id
   AND frame.bucket = segment.bucket
   AND frame.covered_start <= segment.segment_start
   AND segment.segment_end <= frame.covered_end
  GROUP BY segment.process_id, segment.trace_id, segment.segment_start
)
SELECT process_id, trace_id,
       CASE WHEN count(seq) = count(*) THEN max(seq) END AS complete_seq
FROM first_cover
GROUP BY process_id, trace_id;
