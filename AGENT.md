# Agent Notes

This is a file distribution server ported from PythonAnywhere Flask to Go.

## Quick Reference

- **Service name:** `srv`
- **Port:** 8000
- **Public URL:** https://license-server.exe.xyz:8000/
- **Binary:** `/home/exedev/hubv2/hubv2`
- **Files stored:** `/home/exedev/hubv2/lib/mk.zip`
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

### Test endpoints
```bash
# Test download (use token from .env)
curl -H "Authorization: $DOWNLOAD_TOKEN_PLAYBYPAY" http://localhost:8000/download/latest

# Test upload
curl -X POST -H "Authorization: $UPLOAD_TOKEN" -F "file=@test.zip" http://localhost:8000/upload/latest
```

## Architecture

- Single Go binary, no database required
- Tokens loaded from environment variables at startup
- Files saved directly to disk in `lib/` directory
- Systemd manages process lifecycle

## Security Notes

- `.env` file contains secrets - never commit
- `lib/` directory excluded from git
- Tokens are compared as plain strings (same as original Flask app)
