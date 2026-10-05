CREATE TEMP TABLE coverage_frames AS
WITH targets AS (
  SELECT *, unnest(offset_buckets(stream_offset_start, stream_offset_end, $bucket)) AS bucket
  FROM coverage_targets
), frames AS (
  SELECT *, unnest(offset_buckets(offset_start, offset_end, $bucket)) AS bucket
  FROM coverage_frame_source
  WHERE offset_start < offset_end
)
SELECT object.process_id, object.trace_id, frame.offset_start, frame.offset_end,
       greatest(frame.offset_start, object.stream_offset_start) AS covered_start,
       least(frame.offset_end, object.stream_offset_end) AS covered_end,
       frame.trace_id AS packet_id,
       frame.start_ns AS packet_start_ns,
       frame.completion_ns,
       row_number() OVER (
         PARTITION BY object.process_id, object.trace_id
         ORDER BY frame.completion_ns, frame.trace_id, frame.offset_start, frame.offset_end
       ) AS seq
FROM targets AS object
JOIN frames AS frame
  ON frame.process_id = object.process_id AND frame.connection_id = object.connection_id
 AND frame.direction = object.direction
 AND frame.stream_id = object.stream_id
 AND frame.bucket = object.bucket
 AND frame.offset_start < object.stream_offset_end
 AND object.stream_offset_start < frame.offset_end
 AND object.bucket = greatest(object.stream_offset_start, frame.offset_start) // $bucket;
