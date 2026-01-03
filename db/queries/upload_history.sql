-- name: AddUploadHistory :exec
INSERT INTO upload_history (file_name, file_size, uploaded_at, maya_version) VALUES (?, ?, ?, ?);

-- name: GetUploadHistory :many
SELECT id, file_name, file_size, uploaded_at, maya_version FROM upload_history ORDER BY uploaded_at DESC LIMIT ?;

-- name: GetUploadHistoryByMayaVersion :many
SELECT id, file_name, file_size, uploaded_at, maya_version FROM upload_history WHERE maya_version = ? ORDER BY uploaded_at DESC LIMIT ?;

-- name: TrimUploadHistory :exec
DELETE FROM upload_history WHERE id NOT IN (
    SELECT id FROM upload_history ORDER BY uploaded_at DESC LIMIT 100
);
