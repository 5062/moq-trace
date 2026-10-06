-- One family of coverage tables. `{coverage}` names the family, and both the
-- trace and the decrypted capture resolve into a family of this layout.
CREATE TABLE {coverage}_frames (
    object_trace_id UBIGINT NOT NULL,
    seq UINTEGER NOT NULL,
    packet_trace_id UBIGINT NOT NULL,
    offset_start UBIGINT NOT NULL,
    offset_end UBIGINT NOT NULL,
    covered_start UBIGINT NOT NULL,
    covered_end UBIGINT NOT NULL,
    PRIMARY KEY (object_trace_id, seq)
);

CREATE TABLE {coverage} (
    object_trace_id UBIGINT NOT NULL,
    complete_seq UINTEGER NOT NULL,
    first_packet_trace_id UBIGINT NOT NULL,
    complete_packet_trace_id UBIGINT NOT NULL,
    -- The earliest start among the packets retained through completion: for RX,
    -- the earliest read completion of a datagram carrying the object's bytes.
    origin_ns BIGINT NOT NULL,
    -- When the first frame in completion order completed its bytes, and when
    -- the frame completing the object did. A TX frame completes when the send
    -- carrying it completes, and an RX frame when the stream's receive buffer
    -- accepts it.
    first_ns BIGINT NOT NULL,
    complete_ns BIGINT NOT NULL,
    PRIMARY KEY (object_trace_id)
);

CREATE TABLE {coverage}_packets (
    object_trace_id UBIGINT NOT NULL,
    packet_trace_id UBIGINT NOT NULL,
    first_seq UINTEGER NOT NULL,
    ordinal UINTEGER NOT NULL,
    PRIMARY KEY (object_trace_id, packet_trace_id)
);
