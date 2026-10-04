-- The trace's successful STREAM frames, as coverage reads them. A frame
-- completes its bytes when the send that carried it completes (TX) or when the
-- stream's receive buffer accepted it (RX).
CREATE OR REPLACE TEMP VIEW coverage_frame_source AS
SELECT packet.process_id, packet.connection_id, packet.direction, frame.stream_id,
       frame.offset_start, frame.offset_end,
       CASE packet.direction WHEN 'tx' THEN packet.end_ns ELSE frame.timestamp_ns END AS completion_ns,
       packet.trace_id, packet.start_ns
FROM quic_stream_frame AS frame
JOIN packet_lifecycles AS packet USING (process_id, trace_id)
WHERE packet.outcome = 'success' AND frame.outcome = 'success';
