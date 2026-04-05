-- Migration 007: Add session tags support
-- Allows operators to tag sessions for organization

-- Set default value for existing NULL tags
UPDATE implants SET tags = '[]' WHERE tags IS NULL;

-- Create index for tag filtering (SQLite supports JSON operations)
CREATE INDEX IF NOT EXISTS idx_implants_tags ON implants(tags);
