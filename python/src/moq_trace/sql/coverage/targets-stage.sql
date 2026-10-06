-- Every selected inbound object and each of its copies, with the byte range
-- coverage resolves.
CREATE TEMP TABLE coverage_targets AS
SELECT trace_id, connection_id, direction, stream_id, stream_offset_start, stream_offset_end
FROM model.objects
SEMI JOIN (
  SELECT trace_id FROM selected_rx
  UNION ALL
  SELECT tx_trace_id FROM selected_copies
) AS selected USING (trace_id);
