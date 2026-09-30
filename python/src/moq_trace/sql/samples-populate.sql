INSERT INTO metrics.samples
SELECT process_id, metric, rx_trace_id, tx_trace_id, NULL, NULL, elapsed_ns, latency_ns FROM object_samples
UNION ALL
SELECT process_id, metric, rx_trace_id, tx_trace_id, NULL, NULL, elapsed_ns, latency_ns FROM quic_object_samples
UNION ALL
SELECT process_id, metric, NULL, NULL, trace_id, span_id, elapsed_ns, latency_ns FROM packet_samples;
