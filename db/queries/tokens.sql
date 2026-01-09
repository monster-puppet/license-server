-- name: GetAllTokens :many
SELECT id, name, token, token_type, maya_versions, default_maya_version, scene_settings, requirements, disabled, created_at, updated_at FROM tokens ORDER BY token_type, name;

-- name: GetActiveTokens :many
SELECT id, name, token, token_type, maya_versions, default_maya_version, scene_settings, requirements, disabled, created_at, updated_at FROM tokens WHERE disabled = 0 ORDER BY token_type, name;

-- name: GetDisabledTokens :many
SELECT id, name, token, token_type, maya_versions, default_maya_version, scene_settings, requirements, disabled, created_at, updated_at FROM tokens WHERE disabled = 1 ORDER BY token_type, name;

-- name: GetDownloadTokens :many
SELECT token FROM tokens WHERE token_type = 'download' AND disabled = 0;

-- name: GetTokenNameByToken :one
SELECT name FROM tokens WHERE token = ?;

-- name: GetUploadToken :one
SELECT token FROM tokens WHERE token_type = 'upload' LIMIT 1;

-- name: CreateToken :one
INSERT INTO tokens (name, token, token_type, maya_versions, default_maya_version, scene_settings, requirements) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, name, token, token_type, maya_versions, default_maya_version, scene_settings, requirements, created_at, updated_at;

-- name: GetTokenByName :one
SELECT id, name, token, token_type, maya_versions, default_maya_version, scene_settings, requirements, disabled, created_at, updated_at FROM tokens WHERE name = ?;

-- name: UpdateToken :exec
UPDATE tokens SET token = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DisableToken :exec
UPDATE tokens SET disabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: EnableToken :exec
UPDATE tokens SET disabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DeleteToken :exec
DELETE FROM tokens WHERE id = ?;

-- name: CreateSession :exec
INSERT INTO sessions (id, email, name, picture, expires_at) VALUES (?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT id, email, name, picture, created_at, expires_at FROM sessions WHERE id = ? AND expires_at > CURRENT_TIMESTAMP;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = ?;

-- name: CleanExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP;
