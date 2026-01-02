# License Server (Hub v2)

A simple file upload/download server with token-based authentication. Used to distribute files securely to authorized clients.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Returns 404 |
| `/download/latest` | GET | Download the latest file (mk.zip) |
| `/upload/latest` | POST | Upload a new file to replace mk.zip |

## Authentication

All endpoints (except `/`) require an `Authorization` header with a valid token.

### Download
```bash
curl -H "Authorization: <DOWNLOAD_TOKEN>" https://license-server.exe.xyz:8000/download/latest -o mk.zip
```

### Upload
```bash
curl -X POST -H "Authorization: <UPLOAD_TOKEN>" -F "file=@myfile.zip" https://license-server.exe.xyz:8000/upload/latest
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `UPLOAD_TOKEN` | Token required for upload endpoint |
| `DOWNLOAD_TOKEN_PLAYBYPAY` | Download token for PlayByPay client |
| `DOWNLOAD_TOKEN_ADMIN` | Download token for admin access |

These are stored in `/home/exedev/hubv2/.env` (not committed to git).

## File Storage

Uploaded files are stored at `/home/exedev/hubv2/lib/mk.zip`.

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
├── lib/              # File storage directory (not in git)
├── .env              # Environment variables (not in git)
├── srv.service       # Systemd service file
├── hubv2             # Compiled binary (not in git)
└── go.mod            # Go module file
```
