-- name: AddUploadHistory :exec
INSERT INTO upload_history (file_name, file_size, uploaded_at) VALUES (?, ?, ?);

-- name: GetUploadHistory :many
SELECT id, file_name, file_size, uploaded_at FROM upload_history ORDER BY uploaded_at DESC LIMIT ?;

-- name: TrimUploadHistory :exec
DELETE FROM upload_history WHERE id NOT IN (
    SELECT id FROM upload_history ORDER BY uploaded_at DESC LIMIT 100
);
