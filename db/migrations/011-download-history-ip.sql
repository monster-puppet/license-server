-- Add ip_address column to download_history table
ALTER TABLE download_history ADD COLUMN ip_address TEXT;

-- Record execution of this migration
INSERT OR IGNORE INTO migrations (migration_number, migration_name)
VALUES (011, '011-download-history-ip');
