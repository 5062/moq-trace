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
    metric VARCHAR NOT NULL,
    count UBIGINT NOT NULL,
    mean_ns DOUBLE NOT NULL,
    p50_ns DOUBLE NOT NULL,
    p95_ns DOUBLE NOT NULL,
    p99_ns DOUBLE NOT NULL,
    max_ns BIGINT NOT NULL,
    PRIMARY KEY (metric)
);

CREATE TABLE metrics.phase_totals (
    subject subject NOT NULL,
    direction direction NOT NULL,
    trace_id UBIGINT NOT NULL,
    phase VARCHAR NOT NULL,
    total_ns BIGINT NOT NULL,
    PRIMARY KEY (subject, trace_id, phase)
);

-- Object statistics split by the object's position in its group. Every group
-- opens a new stream, so the first object carries the stream setup that later
-- objects in the group reuse. Packet samples belong to no single object and
-- have no position.
CREATE TABLE metrics.position_statistics (
    metric VARCHAR NOT NULL,
    position VARCHAR NOT NULL CHECK (position IN ('first', 'later')),
    count UBIGINT NOT NULL,
    mean_ns DOUBLE NOT NULL,
    p50_ns DOUBLE NOT NULL,
    p95_ns DOUBLE NOT NULL,
    p99_ns DOUBLE NOT NULL,
    max_ns BIGINT NOT NULL,
    PRIMARY KEY (metric, position)
);

-- The inbound objects whose slowest copy lies nearest each summary statistic of
-- every object's slowest copy, which the timeline figure draws.
CREATE TABLE metrics.timeline_selections (
    selection_order INTEGER NOT NULL,
    statistic VARCHAR NOT NULL,
    target_ns DOUBLE NOT NULL,
    rx_trace_id UBIGINT NOT NULL,
    actual_ns BIGINT NOT NULL,
    PRIMARY KEY (selection_order)
);
