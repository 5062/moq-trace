CREATE TABLE processes (
    process_id UINTEGER NOT NULL,
    capture VARCHAR NOT NULL,
    hostname VARCHAR NOT NULL,
    pid UBIGINT NOT NULL,
    first_ctf_ns BIGINT NOT NULL,
    last_ctf_ns BIGINT NOT NULL,
    analyzed BOOLEAN NOT NULL,
    PRIMARY KEY (process_id),
    UNIQUE (capture, hostname, pid)
);
