-- Add maya_versions column to tokens table
ALTER TABLE tokens ADD COLUMN maya_versions TEXT DEFAULT '2024,2025,2026';

-- Record execution of this migration
INSERT OR IGNORE INTO migrations (migration_number, migration_name)
VALUES (003, '003-maya-versions');
