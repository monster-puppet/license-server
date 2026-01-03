-- Add requirements column to tokens table for pip packages
ALTER TABLE tokens ADD COLUMN requirements TEXT DEFAULT 'pymel';

-- Record execution of this migration
INSERT OR IGNORE INTO migrations (migration_number, migration_name)
VALUES (010, '010-requirements');
