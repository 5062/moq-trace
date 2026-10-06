-- The `seq` of the frame that completes each target.
--
-- Cutting a target at every clipped frame edge yields segments that each frame
-- covers entirely or not at all. A segment is first covered by the lowest `seq`
-- among the frames spanning it, and the target is complete once its last
-- segment is, so the completing frame is the maximum of those first covers.
-- This is the frame at which subtracting frames in `seq` order leaves no gap,
-- without replaying the frames one at a time. A target with a segment no frame
-- covers has a NULL `complete_seq`.
--
-- Segments are matched to frames on the bucket holding the segment start, so a
-- large object compares each segment only with the frames near it.
CREATE TEMP TABLE coverage_completion AS
WITH boundaries AS (
  SELECT trace_id, stream_offset_start AS boundary FROM coverage_targets
  UNION
  SELECT trace_id, stream_offset_end FROM coverage_targets
  UNION
  SELECT trace_id, covered_start FROM coverage_frames
  UNION
  SELECT trace_id, covered_end FROM coverage_frames
), segments AS (
  SELECT trace_id, segment_start, segment_end, (segment_start // $bucket)::BIGINT AS bucket
  FROM (
    SELECT trace_id, boundary AS segment_start,
           lead(boundary) OVER (PARTITION BY trace_id ORDER BY boundary) AS segment_end
    FROM boundaries
  )
  WHERE segment_end IS NOT NULL
), covering AS (
  SELECT trace_id, seq, covered_start, covered_end,
         unnest(offset_buckets(covered_start, covered_end, $bucket)) AS bucket
  FROM coverage_frames
  WHERE covered_start < covered_end
), first_cover AS (
  SELECT segment.trace_id, min(frame.seq) AS seq
  FROM segments AS segment
  LEFT JOIN covering AS frame
    ON frame.trace_id = segment.trace_id
   AND frame.bucket = segment.bucket
   AND frame.covered_start <= segment.segment_start
   AND segment.segment_end <= frame.covered_end
  GROUP BY segment.trace_id, segment.segment_start
)
SELECT trace_id, CASE WHEN count(seq) = count(*) THEN max(seq) END AS complete_seq
FROM first_cover
GROUP BY trace_id;
