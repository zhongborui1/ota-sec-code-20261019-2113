BEGIN;
CREATE TABLE IF NOT EXISTS report_nonces (
    ecu_id TEXT NOT NULL, nonce TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (ecu_id, nonce)
);
CREATE TABLE IF NOT EXISTS report_sequences (
    vin TEXT NOT NULL, task_id TEXT NOT NULL, max_seq BIGINT NOT NULL CHECK (max_seq > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vin, task_id)
);
COMMIT;
