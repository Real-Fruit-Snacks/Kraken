-- Module storage for dynamic loading (Phase 3)

CREATE TABLE IF NOT EXISTS modules (
    id TEXT NOT NULL,
    platform TEXT NOT NULL,
    version TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    hash BLOB NOT NULL,
    size INTEGER NOT NULL,
    blob BLOB NOT NULL,
    compiled_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    PRIMARY KEY (id, platform, version)
);

CREATE INDEX IF NOT EXISTS idx_modules_id ON modules(id);
CREATE INDEX IF NOT EXISTS idx_modules_platform ON modules(platform);

-- Track latest version per module/platform
CREATE TABLE IF NOT EXISTS module_latest (
    module_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    version TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    PRIMARY KEY (module_id, platform),
    FOREIGN KEY (module_id, platform, version) REFERENCES modules(id, platform, version) ON DELETE CASCADE
);
