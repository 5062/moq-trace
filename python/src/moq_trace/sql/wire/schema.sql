-- The decrypted packet capture. Each wire connection names the trace connection
-- it joined, and each wire packet the trace packet it matched.
CREATE SCHEMA IF NOT EXISTS network;

CREATE TABLE network.wire_connections (
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
    PRIMARY KEY (connection)
);

CREATE TABLE network.wire_packets (
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
    PRIMARY KEY (packet_id)
);

CREATE TABLE network.wire_stream_frames (
    packet_id UBIGINT NOT NULL,
    stream_id UBIGINT NOT NULL,
    offset_start UBIGINT NOT NULL,
    offset_end UBIGINT NOT NULL,
    fin BOOLEAN NOT NULL
);

-- Each packet's nonempty STREAM ranges in one comparable list, on the wire and
-- in the trace, which the connection join and the checks compare.
CREATE TEMP VIEW wire_frame_lists AS
SELECT packet_id,
       list((stream_id, offset_start, offset_end) ORDER BY stream_id, offset_start, offset_end) AS frames
FROM network.wire_stream_frames WHERE offset_start < offset_end GROUP BY ALL;

CREATE TEMP VIEW trace_frame_lists AS
SELECT trace_id,
       list((stream_id, offset_start, offset_end) ORDER BY stream_id, offset_start, offset_end) AS frames
FROM quic_stream_frame WHERE offset_start < offset_end GROUP BY ALL;
