CREATE SCHEMA IF NOT EXISTS network;

CREATE TABLE network.datagrams (
    process_id UINTEGER NOT NULL,
    elapsed_ns BIGINT NOT NULL,
    direction VARCHAR,
    peer VARCHAR,
    role VARCHAR,
    bytes INTEGER
);

CREATE TABLE network.recovery (
    process_id UINTEGER NOT NULL,
    elapsed_ns BIGINT NOT NULL,
    connection VARCHAR,
    smoothed_rtt_ns DOUBLE,
    min_rtt_ns DOUBLE,
    latest_rtt_ns DOUBLE,
    congestion_window BIGINT,
    bytes_in_flight BIGINT,
    role VARCHAR
);

CREATE TABLE network.losses (
    process_id UINTEGER NOT NULL,
    elapsed_ns BIGINT NOT NULL,
    connection VARCHAR,
    packet_number UBIGINT,
    bytes INTEGER,
    trigger VARCHAR,
    role VARCHAR
);
