-- Every successful STREAM frame overlapping a target, one row per object and
-- frame, clipped to the object's range. `seq` numbers an object's frames in the
-- order they completed their bytes, then by packet trace ID and offsets. A TX
-- frame completes when the send carrying its packet completes, so TX frames
-- follow send order even when a packet encoded early is sent late. An RX frame
-- completes when the stream's receive buffer accepts it.
--
-- A connection carries few streams, so matching frames to objects on the stream
-- alone compares every object with every frame on it, and the work grows with
-- the square of the capture length. Both sides are split into the offset
-- buckets they cover and also matched on the bucket. An overlapping pair shares
-- the bucket where its overlap begins, and only that bucket reports it, so each
-- pair appears exactly once.
CREATE TEMP TABLE coverage_frames AS
WITH targets AS (
  SELECT *, unnest(offset_buckets(stream_offset_start, stream_offset_end, $bucket)) AS bucket
  FROM coverage_targets
), frames AS (
  SELECT *, unnest(offset_buckets(offset_start, offset_end, $bucket)) AS bucket
  FROM coverage_frame_source
  WHERE offset_start < offset_end
)
SELECT object.trace_id, frame.offset_start, frame.offset_end,
       greatest(frame.offset_start, object.stream_offset_start) AS covered_start,
       least(frame.offset_end, object.stream_offset_end) AS covered_end,
       frame.trace_id AS packet_id,
       frame.start_ns AS packet_start_ns,
       frame.completion_ns,
       row_number() OVER (
         PARTITION BY object.trace_id
         ORDER BY frame.completion_ns, frame.trace_id, frame.offset_start, frame.offset_end
       ) AS seq
FROM targets AS object
JOIN frames AS frame
  ON frame.connection_id = object.connection_id
 AND frame.direction = object.direction
 AND frame.stream_id = object.stream_id
 AND frame.bucket = object.bucket
 AND frame.offset_start < object.stream_offset_end
 AND object.stream_offset_start < frame.offset_end
 AND object.bucket = greatest(object.stream_offset_start, frame.offset_start) // $bucket;
