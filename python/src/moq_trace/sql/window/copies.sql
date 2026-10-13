-- Each selected inbound object beside every copy of it.
CREATE TEMP VIEW selected_copies AS
SELECT rx.trace_id AS rx_trace_id, rx.start_ns AS rx_start_ns,
       tx.trace_id AS tx_trace_id, tx.end_ns AS tx_end_ns,
       tx.connection_id, tx.stream_id, tx.stream_offset_start, tx.stream_offset_end
FROM selected_rx AS rx JOIN object_copies AS tx ON tx.rx_trace_id = rx.trace_id;
