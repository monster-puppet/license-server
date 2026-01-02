# License Server (Hub v2)

A simple file upload/download server with token-based authentication and an admin panel. Used to distribute files securely to authorized clients.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Returns 404 |
| `/download/latest` | GET | Download the latest file (mk.zip) |
| `/upload/latest` | POST | Upload a new file to replace mk.zip |
| `/admin` | GET | Admin panel (requires Google login) |

## Authentication

API endpoints require an `Authorization` header with a valid token.

### Download
```bash
curl -H "Authorization: <DOWNLOAD_TOKEN>" https://license-server.exe.xyz:8000/download/latest -o mk.zip
```

### Upload
```bash
curl -X POST -H "Authorization: <UPLOAD_TOKEN>" -F "file=@myfile.zip" https://license-server.exe.xyz:8000/upload/latest
```

## Admin Panel

Access the admin panel at `/admin`. Requires Google login with an authorized email.

Features:
- View all tokens
- Edit token values
- Create new tokens
- Delete tokens

## Environment Variables

| Variable | Description |
|----------|-------------|
| `UPLOAD_TOKEN` | Initial upload token (migrated to DB on first run) |
| `DOWNLOAD_TOKEN_*` | Initial download tokens (migrated to DB on first run) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `ADMIN_EMAIL` | Email address allowed to access admin |
| `BASE_URL` | Public URL for OAuth callback |

These are stored in `/home/exedev/hubv2/.env` (not committed to git).

## File Storage

- Uploaded files: `/home/exedev/hubv2/lib/mk.zip`
- Database: `/home/exedev/hubv2/db.sqlite3`

## Running

### Development
```bash
export $(cat .env | xargs)
go run ./cmd/srv -listen :8000
```

### Production

The service runs via systemd:
```bash
sudo systemctl status srv
sudo systemctl restart srv
journalctl -u srv -f
```

## Building

```bash
go build -o hubv2 ./cmd/srv
```

## Deployment

1. Build the binary: `go build -o hubv2 ./cmd/srv`
2. Copy service file: `sudo cp srv.service /etc/systemd/system/`
3. Reload systemd: `sudo systemctl daemon-reload`
4. Enable and start: `sudo systemctl enable srv && sudo systemctl start srv`

## Project Structure

```
/home/exedev/hubv2/
├── cmd/srv/          # Main application entry point
├── srv/              # Server implementation
│   └── templates/    # HTML templates (admin.html)
├── db/               # Database code and migrations
├── lib/              # File storage directory (not in git)
├── .env              # Environment variables (not in git)
├── db.sqlite3        # SQLite database (not in git)
├── srv.service       # Systemd service file
├── hubv2             # Compiled binary (not in git)
└── go.mod            # Go module file
```
