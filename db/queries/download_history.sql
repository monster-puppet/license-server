-- name: AddDownloadHistory :exec
INSERT INTO download_history (token_name, maya_version, ip_address, downloaded_at) VALUES (?, ?, ?, ?);

-- name: GetDownloadHistory :many
SELECT id, token_name, maya_version, ip_address, downloaded_at FROM download_history ORDER BY downloaded_at DESC LIMIT ?;

-- name: TrimDownloadHistory :exec
DELETE FROM download_history WHERE id NOT IN (
    SELECT id FROM download_history ORDER BY downloaded_at DESC LIMIT 100
);
