-- Samples measured from the decrypted capture. They stay empty for a run
-- without one.
CREATE TEMP TABLE wire_object_samples (
    process_id UINTEGER,
    rx_trace_id UBIGINT,
    tx_trace_id UBIGINT,
    metric VARCHAR,
    elapsed_ns BIGINT,
    latency_ns BIGINT
);

CREATE TEMP TABLE wire_packet_samples (
    process_id UINTEGER,
    metric VARCHAR,
    trace_id UBIGINT,
    elapsed_ns BIGINT,
    latency_ns BIGINT
);
