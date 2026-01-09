-- Add disabled column to tokens table
ALTER TABLE tokens ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
