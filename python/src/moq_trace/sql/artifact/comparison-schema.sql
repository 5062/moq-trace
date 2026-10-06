-- The runs a comparison holds. The tables snapshotted from each run take their
-- layout from the run artifact, with `run_id` prepended.
CREATE SCHEMA metrics;

CREATE TABLE runs (
    run_id UINTEGER NOT NULL,
    label VARCHAR NOT NULL,
    dimension_value BIGINT,
    repeat UINTEGER NOT NULL,
    database VARCHAR NOT NULL,
    metadata JSON NOT NULL,
    PRIMARY KEY (run_id)
);
