-- Add picture column to sessions table
ALTER TABLE sessions ADD COLUMN picture TEXT;

-- Record execution of this migration
INSERT OR IGNORE INTO migrations (migration_number, migration_name)
VALUES (005, '005-session-picture');
