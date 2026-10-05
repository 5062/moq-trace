CREATE SCHEMA metrics;

CREATE TYPE direction AS ENUM ('rx', 'tx');

CREATE TYPE subject AS ENUM ('object', 'packet');

CREATE TABLE runs (
    run_id UINTEGER NOT NULL,
    label VARCHAR NOT NULL,
    dimension_value BIGINT,
    repeat UINTEGER NOT NULL,
    database VARCHAR NOT NULL,
    metadata JSON NOT NULL,
    PRIMARY KEY (run_id)
);

CREATE TABLE processes (
    run_id UINTEGER NOT NULL,
    process_id UINTEGER NOT NULL,
    capture VARCHAR NOT NULL,
    hostname VARCHAR NOT NULL,
    pid UBIGINT NOT NULL,
    first_ctf_ns BIGINT NOT NULL,
    last_ctf_ns BIGINT NOT NULL,
    analyzed BOOLEAN NOT NULL,
    PRIMARY KEY (run_id, process_id)
);

CREATE TABLE metrics.definitions (
    run_id UINTEGER NOT NULL,
    metric VARCHAR NOT NULL,
    domain VARCHAR NOT NULL,
    label VARCHAR NOT NULL,
    unit VARCHAR NOT NULL,
    grain VARCHAR NOT NULL,
    display_order INTEGER NOT NULL,
    PRIMARY KEY (run_id, metric)
);

CREATE TABLE metrics.samples (
    run_id UINTEGER NOT NULL,
    process_id UINTEGER NOT NULL,
    metric VARCHAR NOT NULL,
    rx_trace_id UBIGINT,
    tx_trace_id UBIGINT,
    packet_trace_id UBIGINT,
    span_id UBIGINT,
    elapsed_ns BIGINT NOT NULL,
    value_ns BIGINT NOT NULL,
    FOREIGN KEY (run_id, metric) REFERENCES metrics.definitions(run_id, metric)
);

CREATE TABLE metrics.phase_totals (
    run_id UINTEGER NOT NULL,
    process_id UINTEGER NOT NULL,
    subject subject NOT NULL,
    direction direction NOT NULL,
    trace_id UBIGINT NOT NULL,
    phase VARCHAR NOT NULL,
    total_ns BIGINT NOT NULL,
    PRIMARY KEY (run_id, process_id, subject, trace_id, phase)
);

CREATE TABLE metrics.statistics (
    run_id UINTEGER NOT NULL,
    process_id UINTEGER NOT NULL,
    metric VARCHAR NOT NULL,
    count UBIGINT NOT NULL,
    mean_ns DOUBLE NOT NULL,
    p50_ns DOUBLE NOT NULL,
    p95_ns DOUBLE NOT NULL,
    p99_ns DOUBLE NOT NULL,
    max_ns BIGINT NOT NULL,
    PRIMARY KEY (run_id, process_id, metric)
);

CREATE TABLE metrics.position_statistics (
    run_id UINTEGER NOT NULL,
    process_id UINTEGER NOT NULL,
    metric VARCHAR NOT NULL,
    position VARCHAR NOT NULL CHECK (position IN ('first', 'later')),
    count UBIGINT NOT NULL,
    mean_ns DOUBLE NOT NULL,
    p50_ns DOUBLE NOT NULL,
    p95_ns DOUBLE NOT NULL,
    p99_ns DOUBLE NOT NULL,
    max_ns BIGINT NOT NULL,
    PRIMARY KEY (run_id, process_id, metric, position)
);
