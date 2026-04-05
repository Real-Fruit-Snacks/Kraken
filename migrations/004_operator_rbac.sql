-- Kraken C2 Framework - RBAC Extensions
-- Phase 6: Operator access control junction tables

-- ============================================================================
-- Operator Allowed Sessions (fine-grained session access)
-- ============================================================================

CREATE TABLE IF NOT EXISTS operator_allowed_sessions (
    operator_id     BLOB NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    session_id      BLOB NOT NULL REFERENCES implants(id) ON DELETE CASCADE,
    granted_at      INTEGER NOT NULL,           -- Unix timestamp millis
    granted_by      BLOB REFERENCES operators(id),
    PRIMARY KEY (operator_id, session_id)
);

CREATE INDEX IF NOT EXISTS idx_oas_operator ON operator_allowed_sessions(operator_id);
CREATE INDEX IF NOT EXISTS idx_oas_session ON operator_allowed_sessions(session_id);

-- ============================================================================
-- Operator Allowed Listeners (fine-grained listener access)
-- ============================================================================

CREATE TABLE IF NOT EXISTS operator_allowed_listeners (
    operator_id     BLOB NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    listener_id     BLOB NOT NULL REFERENCES listeners(id) ON DELETE CASCADE,
    granted_at      INTEGER NOT NULL,           -- Unix timestamp millis
    granted_by      BLOB REFERENCES operators(id),
    PRIMARY KEY (operator_id, listener_id)
);

CREATE INDEX IF NOT EXISTS idx_oal_operator ON operator_allowed_listeners(operator_id);
CREATE INDEX IF NOT EXISTS idx_oal_listener ON operator_allowed_listeners(listener_id);
