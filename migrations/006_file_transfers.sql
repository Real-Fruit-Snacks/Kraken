-- File transfer tracking table
CREATE TABLE IF NOT EXISTS file_transfers (
    transfer_id TEXT PRIMARY KEY,
    implant_id BLOB NOT NULL,
    file_path TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('upload', 'download')),
    total_size INTEGER NOT NULL,
    bytes_transferred INTEGER NOT NULL DEFAULT 0,
    chunks_completed INTEGER NOT NULL DEFAULT 0,
    total_chunks INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('initializing', 'in_progress', 'paused', 'completed', 'failed')),
    error TEXT,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    FOREIGN KEY (implant_id) REFERENCES implants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_file_transfers_implant ON file_transfers(implant_id);
CREATE INDEX IF NOT EXISTS idx_file_transfers_state ON file_transfers(state);
CREATE INDEX IF NOT EXISTS idx_file_transfers_started ON file_transfers(started_at DESC);
