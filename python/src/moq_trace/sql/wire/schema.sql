-- The decrypted packet capture. Each wire connection names the trace connection
-- it joined, and each wire packet the trace packet it matched.
CREATE SCHEMA IF NOT EXISTS network;

CREATE TABLE network.wire_connections (
    process_id UINTEGER NOT NULL,
    connection UINTEGER NOT NULL,
    local_address VARCHAR NOT NULL,
    local_port USMALLINT NOT NULL,
    peer_address VARCHAR NOT NULL,
    peer_port USMALLINT NOT NULL,
    client_is_peer BOOLEAN NOT NULL,
    -- Trace-clock times of the connection's first and last captured datagram.
    first_ns BIGINT NOT NULL,
    last_ns BIGINT NOT NULL,
    trace_connection_id UBIGINT,
    PRIMARY KEY (process_id, connection)
);

CREATE TABLE network.wire_packets (
    process_id UINTEGER NOT NULL,
    packet_id UBIGINT NOT NULL,
    connection UINTEGER NOT NULL,
    -- `rx` for a packet the relay received, `tx` for one it sent.
    direction direction NOT NULL,
    -- The capture time of the packet's datagram, on the trace clock.
    timestamp_ns BIGINT NOT NULL,
    packet_space VARCHAR NOT NULL,
    packet_number UBIGINT NOT NULL,
    byte_len UBIGINT NOT NULL,
    -- The captured datagram, the GSO segment within it, and the packet's
    -- position among the datagram's coalesced packets.
    datagram UBIGINT NOT NULL,
    segment UINTEGER NOT NULL,
    packet_index UINTEGER NOT NULL,
    trace_id UBIGINT,
    PRIMARY KEY (process_id, packet_id)
);

CREATE TABLE network.wire_stream_frames (
    process_id UINTEGER NOT NULL,
    packet_id UBIGINT NOT NULL,
    stream_id UBIGINT NOT NULL,
    offset_start UBIGINT NOT NULL,
    offset_end UBIGINT NOT NULL,
    fin BOOLEAN NOT NULL
);
