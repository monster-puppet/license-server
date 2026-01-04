-- Add name column to sessions table
ALTER TABLE sessions ADD COLUMN name TEXT;

-- Record execution of this migration
INSERT OR IGNORE INTO migrations (migration_number, migration_name)
VALUES (012, '012-session-name');
