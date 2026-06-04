<div align="center">
  <br/>
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" alt="Status"/>
  <img src="https://img.shields.io/github/license/Nikku2716/Z-Scanner?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/rust-1.87-orange?style=flat-square" alt="Rust"/>
  <br/><br/>
</div>

 # Z-Scanner

**Z-Scanner** is a web application security scanner powered by [OWASP ZAP](https://www.zaproxy.org/). It provides a clean, real-time dashboard to spider websites, run active vulnerability scans, and inspect findings -- all from your browser.

Built with a **Rust/Actix-web** backend and a vanilla **HTML/CSS/JS** frontend, orchestrated via Docker Compose.

---

## Features

- **4 Scan Modes** -- Quick, Fast, Deep, Stealth (each with different depth/CPU profiles)
- **Real-Time Progress** -- Live spider + active scan percentage updates
- **Risk-Based Filtering** -- Filter alerts by High / Medium / Low severity
- **Stop & Retry** -- Cancel running scans, start new ones instantly
- **OWASP Top 10 Coverage** -- Scans for XSS, SQL injection, broken auth, misconfigurations, and more
- **Export Results** -- Download scan results as JSON or CSV

---

## Architecture

```
┌─────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│   Browser       │────▶│  Actix-web API   │────▶│  OWASP ZAP       │
│  (Frontend)     │◀────│  (Rust Backend)  │◀────│  (Scanner Engine)│
└─────────────────┘      └──────────────────┘      └──────────────────┘
        │                        │
    index.html              main.rs
    app.js                  scanner.rs
    style.css               models.rs
                            owasp.rs
```

### Scan Modes

| Mode    | Spider Threads | Max Children | Active Scan | Strength | Threshold | Description |
|---------|---------------|-------------|-------------|----------|-----------|-------------|
| Quick   | 1             | 5           | No          | —        | —         | Surface-level -- headers, cookies, basic misconfig |
| Fast    | 3             | 10          | Yes         | LOW      | MEDIUM    | Standard scan with limited attack depth |
| Deep    | 5             | Unlimited   | Yes         | HIGH     | LOW       | Comprehensive full-depth vulnerability scan |
| Stealth | 1             | 10          | No          | —        | —         | Passive only -- zero noise on target |

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)
- Git

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Nikku2716/Z-Scanner.git
cd Z-Scanner
```

### 2. Start the Services

```bash
docker compose up --build
```

This starts two containers:

| Container      | Port | Role                          |
|----------------|------|-------------------------------|
| `zscanner-zap` | 8080 | OWASP ZAP daemon              |
| `zscanner-api` | 8000 | Rust API server + frontend    |

Wait for the ZAP health check to pass (typically 30–60 seconds on first run).

### 3. Open the Dashboard

Visit [http://localhost:8000](http://localhost:8000)

Enter a target URL (e.g. `http://example.com`), select a scan mode, and click **Scan**.

### 4. Scanning Local / LAN Apps

Z-Scanner can scan web apps running on your local machine or LAN:

| Target Type | URL Example | Notes |
|---|---|---|
| **localhost** | `http://localhost:3000` | Auto-rewritten to `host.docker.internal` |
| **127.0.0.1** | `http://127.0.0.1:8080` | Auto-rewritten to `host.docker.internal` |
| **LAN IP** | `http://192.168.1.50:3000` | Works directly — ZAP can reach LAN IPs |
| **Docker host** | `http://host.docker.internal:3000` | Explicit Docker host reference |

> **How it works:** When you enter `localhost` or `127.0.0.1`, the backend automatically rewrites it to `host.docker.internal` so ZAP (running inside Docker) can reach your host machine's services. LAN IPs (e.g. `192.168.x.x`, `10.x.x.x`) work as-is.

---

## Development (Without Docker)

### Backend

```bash
cd backend

# Make sure ZAP is running locally on port 8080
ZAP_API_URL=http://localhost:8080 cargo run
```

For development with auto-rebuild, install [cargo-watch](https://crates.io/crates/cargo-watch):

```bash
cargo install cargo-watch
ZAP_API_URL=http://localhost:8080 cargo watch -x run
```

### Frontend

The frontend is served automatically by the Actix-web backend. Static files are in `frontend/`. Edit `index.html`, `app.js`, or `style.css` and refresh.

---

## API Endpoints

| Method | Endpoint              | Description                    |
|--------|-----------------------|--------------------------------|
| GET    | `/`                   | Serves the web dashboard       |
| GET    | `/api/health`         | Health check                   |
| POST   | `/api/scan`           | Start a new scan               |
| GET    | `/api/status/{id}`    | Poll scan progress             |
| POST   | `/api/stop/{id}`      | Stop a running scan            |
| GET    | `/api/results/{id}`   | Retrieve vulnerability results |
| GET    | `/api/history`        | List all scan history          |
| GET    | `/api/export/{id}`    | Export results (JSON/CSV)      |

### Start a Scan

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://example.com", "scan_mode": "fast"}'
```

Response:

```json
{
  "scan_id": "a1b2c3d4e5f6",
  "message": "Scan started successfully"
}
```

### Poll Status

```bash
curl http://localhost:8000/api/status/a1b2c3d4e5f6
```

### Get Results

```bash
curl http://localhost:8000/api/results/a1b2c3d4e5f6
```

### Export as CSV

```bash
curl "http://localhost:8000/api/export/a1b2c3d4e5f6?format=csv" -o results.csv
```

---

## Project Structure

```
Z-Scanner/
├── docker-compose.yml          # Orchestrates ZAP + API containers
├── backend/
│   ├── Cargo.toml              # Rust dependencies
│   ├── Dockerfile              # Multi-stage Rust build
│   └── src/
│       ├── main.rs             # Actix-web application + endpoints
│       ├── scanner.rs          # ZapScanner — ZAP API wrapper
│       ├── models.rs           # Request/response types & scan state
│       └── owasp.rs            # CWE → OWASP Top 10 mapping
└── frontend/
    ├── index.html              # Single-page dashboard
    ├── app.js                  # UI logic + API polling
    └── style.css               # Cyberpunk/HUD-inspired theme
```

---

## Configuration

### Environment Variables

| Variable       | Default                | Description            |
|----------------|------------------------|------------------------|
| `ZAP_API_URL`  | `http://zap:8080`      | ZAP daemon address     |

### Scan Mode Config

Edit `get_scan_mode_config()` in `backend/src/models.rs` to tune spider threads, attack strength, and alert thresholds per mode.

---

## License

[MIT](LICENSE)
