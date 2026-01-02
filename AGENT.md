# Agent Notes

This is a file distribution server ported from PythonAnywhere Flask to Go.

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
- **Admin URL:** https://license-server.exe.xyz:8000/admin
- **Binary:** `/home/exedev/hubv2/hubv2`
- **Files stored:** `/home/exedev/hubv2/lib/mk.zip`
- **Database:** `/home/exedev/hubv2/db.sqlite3`
- **Env file:** `/home/exedev/hubv2/.env`

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

### Test endpoints
```bash
# Test download (use token from DB)
curl -H "Authorization: <TOKEN>" http://localhost:8000/download/latest

# Test upload
curl -X POST -H "Authorization: <UPLOAD_TOKEN>" -F "file=@test.zip" http://localhost:8000/upload/latest
```

## Architecture

- Single Go binary with SQLite database
- Tokens stored in database (initially migrated from env vars)
- Google OAuth for admin authentication
- Sessions stored in database with 24-hour expiry
- Systemd manages process lifecycle

## Security Notes

- `.env` file contains secrets - never commit
- `db.sqlite3` contains tokens - never commit
- `lib/` directory excluded from git
- Only authorized email addresses can access admin panel
- OAuth state parameter prevents CSRF
- Session cookies are HttpOnly and Secure

## Google OAuth Setup

Callback URL configured in Google Cloud Console:
`https://license-server.exe.xyz:8000/admin/callback`
