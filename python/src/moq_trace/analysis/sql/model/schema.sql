CREATE SCHEMA model;

CREATE SCHEMA metrics;

CREATE SCHEMA network;

CREATE TYPE direction AS ENUM ('rx', 'tx');

CREATE TYPE subject AS ENUM ('object', 'packet');

CREATE TABLE model.objects (
    trace_id UBIGINT NOT NULL,
    logical_group UBIGINT NOT NULL,
    logical_frame UBIGINT NOT NULL,
    session_id UBIGINT NOT NULL,
    connection_id UBIGINT,
    direction direction NOT NULL,
    track_alias UBIGINT NOT NULL,
    group_id UBIGINT NOT NULL,
    object_id UBIGINT NOT NULL,
    stream_id UBIGINT,
    stream_offset_start UBIGINT,
    process_id UINTEGER NOT NULL,
    start_ns BIGINT NOT NULL,
    end_ns BIGINT NOT NULL,
    stream_offset_end UBIGINT,
    payload_bytes UBIGINT NOT NULL,
    outcome outcome NOT NULL,
    start_ctf_ns BIGINT NOT NULL,
    end_ctf_ns BIGINT NOT NULL,
    rx_trace_id UBIGINT,
    copy_ordinal UINTEGER,
    -- The thread that started the lifecycle.
    tid UBIGINT NOT NULL,
    PRIMARY KEY (process_id, trace_id)
);

CREATE TABLE model.packets (
    trace_id UBIGINT NOT NULL,
    connection_id UBIGINT,
    direction direction NOT NULL,
    process_id UINTEGER NOT NULL,
    packet_number UBIGINT,
    packet_space VARCHAR,
    byte_len UBIGINT,
    start_ns BIGINT NOT NULL,
    end_ns BIGINT NOT NULL,
    outcome outcome NOT NULL,
    start_ctf_ns BIGINT NOT NULL,
    end_ctf_ns BIGINT NOT NULL,
    -- The thread that started the lifecycle.
    tid UBIGINT NOT NULL,
    PRIMARY KEY (process_id, trace_id)
);

CREATE TABLE model.intervals (
    process_id UINTEGER NOT NULL,
    subject subject NOT NULL,
    trace_id UBIGINT NOT NULL,
    span_id UBIGINT NOT NULL,
    phase VARCHAR NOT NULL,
    occurrence UINTEGER NOT NULL,
    start_ns BIGINT NOT NULL,
    end_ns BIGINT NOT NULL,
    outcome outcome NOT NULL,
    -- The thread that started the interval.
    tid UBIGINT NOT NULL,
    PRIMARY KEY (process_id, subject, trace_id, span_id, phase)
);

-- Intervals in which a connection could not send, and why. A blocked write
-- names its stream; a connection that could not transmit at all does not.
CREATE TABLE model.send_blocked (
    process_id UINTEGER NOT NULL,
    span_id UBIGINT NOT NULL,
    connection_id UBIGINT NOT NULL,
    stream_id UBIGINT,
    reason VARCHAR NOT NULL,
    start_ns BIGINT NOT NULL,
    end_ns BIGINT NOT NULL,
    PRIMARY KEY (process_id, span_id)
);
