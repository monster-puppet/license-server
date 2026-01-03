-- Add maya_version column to upload_history table
ALTER TABLE upload_history ADD COLUMN maya_version TEXT DEFAULT NULL;

-- Record execution of this migration
INSERT OR IGNORE INTO migrations (migration_number, migration_name)
VALUES (007, '007-upload-history-maya-version');
