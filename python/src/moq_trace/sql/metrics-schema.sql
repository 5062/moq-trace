CREATE TABLE metrics.definitions (
    metric VARCHAR NOT NULL,
    domain VARCHAR NOT NULL,
    label VARCHAR NOT NULL,
    unit VARCHAR NOT NULL,
    grain VARCHAR NOT NULL,
    display_order INTEGER NOT NULL,
    PRIMARY KEY (metric)
);

CREATE TABLE metrics.samples (
    process_id UINTEGER NOT NULL,
    metric VARCHAR NOT NULL,
    rx_trace_id UBIGINT,
    tx_trace_id UBIGINT,
    packet_trace_id UBIGINT,
    span_id UBIGINT,
    elapsed_ns BIGINT NOT NULL,
    value_ns BIGINT NOT NULL,
    FOREIGN KEY (metric) REFERENCES metrics.definitions(metric)
);

CREATE TABLE metrics.statistics (
    process_id UINTEGER NOT NULL,
    metric VARCHAR NOT NULL,
    count UBIGINT NOT NULL,
    mean_ns DOUBLE NOT NULL,
    p50_ns DOUBLE NOT NULL,
    p95_ns DOUBLE NOT NULL,
    p99_ns DOUBLE NOT NULL,
    max_ns BIGINT NOT NULL,
    PRIMARY KEY (process_id, metric)
);

CREATE TABLE metrics.phase_totals (
    process_id UINTEGER NOT NULL,
    subject subject NOT NULL,
    direction direction NOT NULL,
    trace_id UBIGINT NOT NULL,
    phase VARCHAR NOT NULL,
    total_ns BIGINT NOT NULL,
    PRIMARY KEY (process_id, subject, trace_id, phase)
);

-- Object statistics split by the object's position in its group. Every group
-- opens a new stream, so the first object carries the stream setup that later
-- objects in the group reuse. Packet samples belong to no single object and
-- have no position.
CREATE TABLE metrics.position_statistics (
    process_id UINTEGER NOT NULL,
    metric VARCHAR NOT NULL,
    position VARCHAR NOT NULL CHECK (position IN ('first', 'later')),
    count UBIGINT NOT NULL,
    mean_ns DOUBLE NOT NULL,
    p50_ns DOUBLE NOT NULL,
    p95_ns DOUBLE NOT NULL,
    p99_ns DOUBLE NOT NULL,
    max_ns BIGINT NOT NULL,
    PRIMARY KEY (process_id, metric, position)
);
