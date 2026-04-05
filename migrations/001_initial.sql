-- Kraken C2 Framework - Initial Schema
-- Phase 1: MVP tables
-- Note: Uses IF NOT EXISTS for idempotent migrations

-- ============================================================================
-- Operators
-- ============================================================================

CREATE TABLE IF NOT EXISTS operators (
    id              BLOB PRIMARY KEY,           -- 16-byte UUID
    username        TEXT NOT NULL UNIQUE,
    role            TEXT NOT NULL DEFAULT 'operator',
    cert_fingerprint TEXT NOT NULL UNIQUE,
    created_at      INTEGER NOT NULL,           -- Unix timestamp millis
    last_seen       INTEGER,
    is_active       INTEGER NOT NULL DEFAULT 1
);

-- ============================================================================
-- Implants
-- ============================================================================

CREATE TABLE IF NOT EXISTS implants (
    id              BLOB PRIMARY KEY,           -- 16-byte UUID
    name            TEXT NOT NULL,              -- Water-themed name
    state           TEXT NOT NULL DEFAULT 'staging',
    hostname        TEXT,
    username        TEXT,
    domain          TEXT,
    os_name         TEXT,
    os_version      TEXT,
    os_arch         TEXT,
    process_id      INTEGER,
    process_name    TEXT,
    process_path    TEXT,
    is_elevated     INTEGER,
    integrity_level TEXT,
    local_ips       TEXT,                       -- JSON array
    checkin_interval INTEGER NOT NULL DEFAULT 60,
    jitter_percent  INTEGER NOT NULL DEFAULT 20,
    config_hash     BLOB,
    symmetric_key   BLOB,                       -- Encrypted session key
    key_nonce_counter INTEGER NOT NULL DEFAULT 0,
    registered_at   INTEGER NOT NULL,           -- Unix timestamp millis
    last_seen       INTEGER,
    burned_at       INTEGER,
    retired_at      INTEGER,
    tags            TEXT,                       -- JSON array
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_implants_state ON implants(state);
CREATE INDEX IF NOT EXISTS idx_implants_last_seen ON implants(last_seen);
CREATE INDEX IF NOT EXISTS idx_implants_name ON implants(name);

-- ============================================================================
-- Implant State History
-- ============================================================================

CREATE TABLE IF NOT EXISTS implant_state_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    implant_id      BLOB NOT NULL REFERENCES implants(id) ON DELETE CASCADE,
    old_state       TEXT NOT NULL,
    new_state       TEXT NOT NULL,
    changed_at      INTEGER NOT NULL,           -- Unix timestamp millis
    operator_id     BLOB REFERENCES operators(id),
    reason          TEXT
);

CREATE INDEX IF NOT EXISTS idx_implant_state_history_implant ON implant_state_history(implant_id);

-- ============================================================================
-- Listeners
-- ============================================================================

CREATE TABLE IF NOT EXISTS listeners (
    id              BLOB PRIMARY KEY,           -- 16-byte UUID
    listener_type   TEXT NOT NULL,              -- 'http', 'https'
    bind_host       TEXT NOT NULL,
    bind_port       INTEGER NOT NULL,
    profile_id      TEXT REFERENCES profiles(id),
    tls_cert_path   TEXT,
    tls_key_path    TEXT,
    is_running      INTEGER NOT NULL DEFAULT 0,
    started_at      INTEGER,
    stopped_at      INTEGER,
    created_at      INTEGER NOT NULL,
    connections_total INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_listeners_running ON listeners(is_running);

-- ============================================================================
-- Profiles
-- ============================================================================

CREATE TABLE IF NOT EXISTS profiles (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    config          TEXT NOT NULL,              -- JSON profile config
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    created_by      BLOB REFERENCES operators(id)
);

-- Insert default profile (ignore if exists)
INSERT OR IGNORE INTO profiles (id, name, description, config, created_at, updated_at) VALUES (
    'default',
    'Default Profile',
    'Standard HTTP profile with base64 encoding',
    '{
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "checkin_uri": "/api/v1/status",
        "task_uri": "/api/v1/submit",
        "request_headers": [
            ["Accept", "application/json"],
            ["Accept-Language", "en-US,en;q=0.9"]
        ],
        "response_headers": [
            ["Content-Type", "application/json"]
        ],
        "request_transform": "base64",
        "response_transform": "base64"
    }',
    strftime('%s', 'now') * 1000,
    strftime('%s', 'now') * 1000
);

-- ============================================================================
-- Tasks
-- ============================================================================

CREATE TABLE IF NOT EXISTS tasks (
    id              BLOB PRIMARY KEY,           -- 16-byte UUID
    implant_id      BLOB NOT NULL REFERENCES implants(id) ON DELETE CASCADE,
    operator_id     BLOB NOT NULL REFERENCES operators(id),
    task_type       TEXT NOT NULL,              -- 'shell', 'sleep', 'exit', etc.
    task_data       BLOB NOT NULL,              -- Serialized task message
    status          TEXT NOT NULL DEFAULT 'pending',
    issued_at       INTEGER NOT NULL,
    dispatched_at   INTEGER,
    completed_at    INTEGER,
    result_data     BLOB,
    error_code      INTEGER,
    error_message   TEXT,
    error_details   TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_implant ON tasks(implant_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_issued ON tasks(issued_at);

-- ============================================================================
-- Task Chunks (for streaming results)
-- ============================================================================

CREATE TABLE IF NOT EXISTS task_chunks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         BLOB NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    sequence        INTEGER NOT NULL,
    chunk_data      BLOB NOT NULL,
    is_final        INTEGER NOT NULL DEFAULT 0,
    received_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_task_chunks_task ON task_chunks(task_id);

-- ============================================================================
-- Audit Log
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       INTEGER NOT NULL,           -- Unix timestamp millis
    operator_id     BLOB REFERENCES operators(id),
    implant_id      BLOB REFERENCES implants(id),
    action          TEXT NOT NULL,
    details         TEXT,                       -- JSON
    source_ip       TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_operator ON audit_log(operator_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_implant ON audit_log(implant_id);

-- ============================================================================
-- Server Config
-- ============================================================================

CREATE TABLE IF NOT EXISTS server_config (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- Insert default server config (ignore if exists)
INSERT OR IGNORE INTO server_config (key, value, updated_at) VALUES
    ('server_name', 'Kraken Teamserver', strftime('%s', 'now') * 1000),
    ('protocol_version', '1.0.0', strftime('%s', 'now') * 1000);

-- ============================================================================
-- Loot Store (Phase 2)
-- ============================================================================

CREATE TABLE IF NOT EXISTS loot (
    id              BLOB PRIMARY KEY,           -- 16-byte UUID
    implant_id      BLOB NOT NULL REFERENCES implants(id) ON DELETE CASCADE,
    task_id         BLOB REFERENCES tasks(id),
    loot_type       TEXT NOT NULL,              -- 'credential', 'hash', 'token', 'file'
    captured_at     INTEGER NOT NULL,           -- Unix timestamp millis
    source          TEXT,                       -- Module that captured it

    -- Credential fields
    username        TEXT,
    password        TEXT,
    domain          TEXT,
    host            TEXT,
    port            INTEGER,
    protocol        TEXT,                       -- 'smb', 'rdp', 'ssh', 'web'

    -- Hash fields
    hash_type       TEXT,                       -- 'ntlm', 'ntlmv2', 'kerberos', etc.
    hash_value      TEXT,

    -- Token fields
    token_type      TEXT,                       -- 'kerberos', 'jwt', 'saml', 'oauth'
    token_data      BLOB,
    expires_at      INTEGER,
    principal       TEXT,
    service         TEXT,

    -- File fields
    filename        TEXT,
    original_path   TEXT,
    file_size       INTEGER,
    file_hash       TEXT,                       -- SHA-256
    blob_path       TEXT                        -- Local storage path
);

CREATE INDEX IF NOT EXISTS idx_loot_implant ON loot(implant_id);
CREATE INDEX IF NOT EXISTS idx_loot_type ON loot(loot_type);
CREATE INDEX IF NOT EXISTS idx_loot_username ON loot(username);
CREATE INDEX IF NOT EXISTS idx_loot_captured ON loot(captured_at);

-- Full-text search for loot (contentless for explicit sync via triggers)
-- Drop and recreate to handle schema changes
DROP TABLE IF EXISTS loot_fts;
CREATE VIRTUAL TABLE loot_fts USING fts5(
    username,
    domain,
    host,
    principal,
    service,
    filename,
    source,
    content=''
);

-- Triggers to keep FTS in sync (drop first for idempotency)
DROP TRIGGER IF EXISTS loot_ai;
CREATE TRIGGER loot_ai AFTER INSERT ON loot BEGIN
    INSERT INTO loot_fts(rowid, username, domain, host, principal, service, filename, source)
    VALUES (NEW.rowid, NEW.username, NEW.domain, NEW.host, NEW.principal, NEW.service, NEW.filename, NEW.source);
END;

DROP TRIGGER IF EXISTS loot_ad;
CREATE TRIGGER loot_ad AFTER DELETE ON loot BEGIN
    INSERT INTO loot_fts(loot_fts, rowid, username, domain, host, principal, service, filename, source)
    VALUES ('delete', OLD.rowid, OLD.username, OLD.domain, OLD.host, OLD.principal, OLD.service, OLD.filename, OLD.source);
END;

DROP TRIGGER IF EXISTS loot_au;
CREATE TRIGGER loot_au AFTER UPDATE ON loot BEGIN
    INSERT INTO loot_fts(loot_fts, rowid, username, domain, host, principal, service, filename, source)
    VALUES ('delete', OLD.rowid, OLD.username, OLD.domain, OLD.host, OLD.principal, OLD.service, OLD.filename, OLD.source);
    INSERT INTO loot_fts(rowid, username, domain, host, principal, service, filename, source)
    VALUES (NEW.rowid, NEW.username, NEW.domain, NEW.host, NEW.principal, NEW.service, NEW.filename, NEW.source);
END;

-- ============================================================================
-- Views (drop and recreate for idempotency)
-- ============================================================================

-- Active implants with time since last check-in
DROP VIEW IF EXISTS active_implants;
CREATE VIEW active_implants AS
SELECT
    i.*,
    (strftime('%s', 'now') * 1000 - i.last_seen) / 1000 AS seconds_since_checkin
FROM implants i
WHERE i.state = 'active';

-- Recent tasks
DROP VIEW IF EXISTS recent_tasks;
CREATE VIEW recent_tasks AS
SELECT
    t.*,
    i.name AS implant_name,
    o.username AS operator_name
FROM tasks t
JOIN implants i ON i.id = t.implant_id
JOIN operators o ON o.id = t.operator_id
ORDER BY t.issued_at DESC
LIMIT 100;

-- ============================================================================
-- Background Jobs (Phase 11)
-- ============================================================================

CREATE TABLE IF NOT EXISTS jobs (
    job_id          INTEGER PRIMARY KEY,
    implant_id      BLOB NOT NULL REFERENCES implants(id) ON DELETE CASCADE,
    task_id         BLOB NOT NULL,              -- 16-byte UUID
    description     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running',  -- 'running', 'completed', 'failed', 'cancelled'
    progress        INTEGER NOT NULL DEFAULT 0, -- 0-100
    created_at      INTEGER NOT NULL,           -- Unix timestamp millis
    completed_at    INTEGER,
    error_message   TEXT,
    output_size     INTEGER NOT NULL DEFAULT 0  -- Bytes of output received
);

CREATE INDEX IF NOT EXISTS idx_jobs_implant ON jobs(implant_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_task ON jobs(task_id);

-- Job outputs (chunked storage)
CREATE TABLE IF NOT EXISTS job_outputs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          INTEGER NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    sequence        INTEGER NOT NULL,           -- Chunk sequence number
    output_data     BLOB NOT NULL,
    received_at     INTEGER NOT NULL,           -- Unix timestamp millis
    is_final        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_job_outputs_job ON job_outputs(job_id);
