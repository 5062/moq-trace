CREATE TABLE metrics.timeline_selections (
    process_id UINTEGER NOT NULL,
    selection_order INTEGER NOT NULL,
    statistic VARCHAR NOT NULL,
    target_ns DOUBLE NOT NULL,
    rx_trace_id UBIGINT NOT NULL,
    actual_ns BIGINT NOT NULL,
    PRIMARY KEY (process_id, selection_order)
);
