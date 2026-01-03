-- Add scene_settings column to tokens table for Maya scene defaults
-- Stores JSON: {"axis": "y", "fps": "ntsc", "unit": "cm"}
ALTER TABLE tokens ADD COLUMN scene_settings TEXT DEFAULT '{"axis": "y", "fps": "ntsc", "unit": "cm"}';

-- Record execution of this migration
INSERT OR IGNORE INTO migrations (migration_number, migration_name)
VALUES (009, '009-scene-settings');
