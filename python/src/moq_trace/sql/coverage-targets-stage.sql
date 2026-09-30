CREATE TEMP TABLE coverage_targets AS
SELECT lifecycle.process_id, lifecycle.trace_id, lifecycle.connection_id, lifecycle.direction,
       lifecycle.stream_id, lifecycle.stream_offset_start, lifecycle.stream_offset_end
FROM object_lifecycles AS lifecycle
SEMI JOIN (
  SELECT process_id, trace_id FROM selected_rx
  UNION ALL
  SELECT tx.process_id, tx.trace_id FROM selected_rx AS rx
  JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
) AS selected USING (process_id, trace_id);
