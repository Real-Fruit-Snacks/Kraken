-- Kraken C2 Framework - Chat Messages
-- Phase 5: Persistent operator chat

CREATE TABLE IF NOT EXISTS chat_messages (
    id              BLOB PRIMARY KEY,           -- 16-byte UUID
    from_operator_id BLOB NOT NULL REFERENCES operators(id),
    from_username   TEXT NOT NULL,              -- Denormalized for display
    message         TEXT NOT NULL,
    session_id      BLOB,                       -- Optional session context
    created_at      INTEGER NOT NULL            -- Unix timestamp millis
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_created ON chat_messages(created_at);
CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON chat_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_operator ON chat_messages(from_operator_id);
