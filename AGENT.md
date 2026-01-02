# Agent Notes

Package Manager for distributing Maya tools to clients. Ported from PythonAnywhere Flask to Go.

## IMPORTANT: Always push to GitHub after changes

After making and verifying any code changes:
```bash
cd /home/exedev/hubv2
git add <changed files>
git commit -m "Description of changes"
git push
```

## Quick Reference

- **Service name:** `srv`
- **Port:** 8000
- **Public URL:** https://license-server.exe.xyz:8000/
- **Binary:** `/home/exedev/hubv2/hubv2`
- **Core package:** `/home/exedev/hubv2/lib/mk.zip`
- **Client template:** `/home/exedev/hubv2/templates/`
- **Database:** `/home/exedev/hubv2/db.sqlite3`
- **Env file:** `/home/exedev/hubv2/.env`

## Features

### Admin UI (Google OAuth protected)
- **Current Package:** Shows mk.zip file info and upload history (last 100 uploads)
- **Client Packages:** List of all client tokens with actions:
  - Regenerate token (with confirmation dialog)
  - Download client package (generated on-the-fly)
  - Delete client (download tokens only)
- **Create New Client Package:** Add new clients with Maya version selection

### Package Generation
When downloading a client package, the system generates a customized zip:
- `scripts/pbp/` → `scripts/{clientName}/`
- `shelf_PBP_*.mel` → `shelf_{clientName}_*.mel`
- `newclient.mod` → `{clientName}.mod`
- Replaces `pbp.` imports with `{clientName}.`
- Replaces `PBP` text with `{CLIENTNAME}` (uppercase)
- Embeds the client's token in `bin/token`
- Generates `.mod` file for selected Maya versions

### API Endpoints
- `GET /` - Admin UI (requires login)
- `GET /login` - Google OAuth login
- `GET /logout` - Logout
- `GET /download/latest` - Download mk.zip (requires token header)
- `POST /upload/latest` - Upload new mk.zip (requires upload token)
- `POST /upload/template` - Upload client workspace template
- `GET /package/{name}` - Download client package (requires login)
- `GET /upload/history` - Get upload history JSON (requires login)
- `POST /token/create` - Create new client
- `POST /token/regenerate` - Regenerate client token
- `POST /token/delete` - Delete client

## Common Tasks

### Restart service
```bash
sudo systemctl restart srv
```

### View logs
```bash
journalctl -u srv -f
```

### Rebuild after code changes
```bash
cd /home/exedev/hubv2
go build -o hubv2 ./cmd/srv
sudo systemctl restart srv
```

### Regenerate DB code after schema changes
```bash
cd /home/exedev/hubv2/db
go generate
```

### View tokens in database
```bash
sqlite3 /home/exedev/hubv2/db.sqlite3 "SELECT * FROM tokens;"
```

### View upload history
```bash
sqlite3 /home/exedev/hubv2/db.sqlite3 "SELECT * FROM upload_history ORDER BY uploaded_at DESC LIMIT 10;"
```

### Test endpoints
```bash
# Test download (use token from DB)
curl -H "Authorization: <TOKEN>" http://localhost:8000/download/latest

# Test upload
curl -X POST -H "Authorization: <UPLOAD_TOKEN>" -F "file=@test.zip" http://localhost:8000/upload/latest
```

## Database Schema

- **tokens:** Client tokens (name, token, type, maya_versions)
- **sessions:** Admin login sessions
- **upload_history:** History of mk.zip uploads (last 100 kept)
- **migrations:** Schema version tracking

## Architecture

- Single Go binary with SQLite database
- Tokens stored in database
- Google OAuth for admin authentication
- Sessions stored in database with 24-hour expiry
- Client packages generated on-the-fly when downloaded
- Systemd manages process lifecycle

## Security Notes

- `.env` file contains secrets - never commit
- `db.sqlite3` contains tokens - never commit
- `lib/` and `templates/` directories excluded from git
- Only authorized email addresses can access admin panel
- OAuth state parameter prevents CSRF
- Session cookies are HttpOnly and Secure
- Tokens hidden by default in UI (click "show" to reveal)

## Google OAuth Setup

Callback URL configured in Google Cloud Console:
`https://license-server.exe.xyz:8000/callback`
