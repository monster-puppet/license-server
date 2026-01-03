-- Add default_maya_version column to tokens table
ALTER TABLE tokens ADD COLUMN default_maya_version TEXT DEFAULT '2024';

-- Record execution of this migration
INSERT OR IGNORE INTO migrations (migration_number, migration_name)
VALUES (006, '006-default-maya-version');
