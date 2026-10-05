CREATE TABLE model.window (
    process_id UINTEGER NOT NULL,
    origin_ns BIGINT NOT NULL,
    start_ns BIGINT NOT NULL,
    end_ns BIGINT NOT NULL,
    PRIMARY KEY (process_id)
);

CREATE TABLE model.selected_objects (
    process_id UINTEGER NOT NULL,
    trace_id UBIGINT NOT NULL,
    PRIMARY KEY (process_id, trace_id)
);
