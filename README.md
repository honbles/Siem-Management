# OpenSIEM Management Platform

Browser-based dashboard for the OpenSIEM stack. Connects to the same TimescaleDB used by the agent backend and provides real-time event monitoring, agent fleet management, automated alerting, and threat intelligence views.

**Version: v0.2.0**

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Dashboard Pages](#dashboard-pages)
- [API Reference](#api-reference)
- [Database Schema](#database-schema)
- [Operations](#operations)
- [Security Hardening](#security-hardening)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

The management platform adds a browser UI on top of the OpenSIEM backend. It runs as two Docker containers alongside the existing stack:

- **mgmt-api** — Go REST API + WebSocket server + JWT auth + background alert engine
- **mgmt-ui** — React SPA served by nginx, proxies all API/WebSocket traffic to mgmt-api

It shares the existing `opensiem-db` TimescaleDB (read from `events` and `agents`) and adds its own `users` and `alerts` tables via auto-migration.

---

## Architecture

```
Browser
  └── nginx :80  (mgmt-ui)
        ├── /              → React SPA
        ├── /api/          → proxy → mgmt-api :8080
        ├── /auth/         → proxy → mgmt-api :8080
        └── /ws/           → WebSocket proxy → mgmt-api :8080

mgmt-api :8080
  └── TimescaleDB (opensiem-db)
        ├── events         (read — shared with agent backend)
        ├── agents         (read — shared with agent backend)
        ├── users          (read/write — management platform only)
        └── alerts         (read/write — management platform only)
```

The management Docker Compose joins the agent backend's Docker network (`docker_default`) so `mgmt-api` can reach `opensiem-db` by service name without exposing the database port publicly.

---

## Prerequisites

- Docker 24+ and Docker Compose v2
- The agent backend already running (`opensiem-db` must be healthy)
- Ports `80` (UI) and `8080` (API) available on the server
- The agent backend database password

---

## Quick Start

```bash
# 1. Extract
unzip opensiem-management.zip
cd management/backend/docker

# 2. Edit runtime config
nano server.yaml
# Set: database.password (must match agent backend POSTGRES_PASSWORD)
# Set: auth.jwt_secret   (generate: openssl rand -hex 32)

# 3. Check Docker network name
sudo docker network ls
# Look for: docker_default (agent backend network)
# If different, update networks.backend_net.name in docker-compose.yml

# 4. Deploy
sudo docker compose up -d --build

# 5. Open browser
# http://192.168.1.140
# Default login: admin / changeme  ← CHANGE THIS
```

> **Warning:** Change the admin password and `jwt_secret` before exposing this on a network.

---

## Configuration

Edit `docker/server.yaml` — mounted read-only into the container. Restart `mgmt-api` after any changes.

```yaml
server:
  listen_addr: ":8080"
  read_timeout:  "30s"
  write_timeout: "30s"
  cors_origins:
    - "*"           # tighten to http://your-server-ip in production

database:
  host:     "timescaledb"   # Docker service name — do not change when using compose
  port:     5432
  name:     "opensiem"
  user:     "opensiem"
  password: "changeme"      # MUST match agent backend POSTGRES_PASSWORD
  ssl_mode: "disable"
  max_open_conns:    10
  max_idle_conns:    5
  conn_max_lifetime: "5m"

auth:
  # Generate: openssl rand -hex 32
  jwt_secret:     "your-secret-here"
  token_duration: "24h"

log:
  level:  "info"    # debug | info | warn | error
  format: "json"    # json  | text
```

---

## Dashboard Pages

### Dashboard
Main overview. Auto-refreshes every 30 seconds. Live event feed via WebSocket.

- Events today + all-time total
- High-severity events (last 24h)
- Agent online/offline count
- Open alert count
- Event timeline chart (24h, 1-hour buckets)
- Severity breakdown pie chart
- Top event types bar chart
- Real-time live event feed

### Events
Full searchable event table with historical and live modes.

- Filter by: host, agent ID, event type, severity, src/dst IP, username, free-text
- Time range selection
- Pagination (100/page, max 1000/query)
- Live mode — replaces table with real-time WebSocket feed

### Agents
Fleet overview. Auto-refreshes every 15 seconds.

- Online/offline status (online = last seen within 2 minutes)
- Hostname, OS, version, last IP, last seen, total event count

### Alerts
Auto-generated from the background alert engine + analyst workflow.

- Auto-created for any event with severity ≥ 4 (runs every 30 seconds)
- One alert per event (deduplicated by event ID)
- Workflow: `open` → `acknowledged` → `closed`
- Acknowledge records the analyst's username
- Filter tabs: open, acknowledged, closed, all

### Threat Intelligence
Aggregated activity — last 24 hours.

- Top 20 queried DNS domains (suspicious entries flagged in red)
- Top 15 source IPs and destination IPs
- Top 15 processes by event count
- Top 15 users by event count
- Flagged domain banner — auto-detects `rustdesk`, `urban-vpn`, `ngrok`, `.onion`

---

## API Reference

All `/api/` and `/auth/me` endpoints require `Authorization: Bearer <token>`. The `/health` and `/auth/login` endpoints are public.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Server and DB liveness |
| `POST` | `/auth/login` | Authenticate, receive JWT |
| `GET` | `/auth/me` | Current user from token |
| `GET` | `/api/v1/events` | Query events with filters |
| `GET` | `/api/v1/agents` | List agents with online status |
| `GET` | `/api/v1/alerts` | List alerts, filter by status |
| `PATCH` | `/api/v1/alerts/{id}/acknowledge` | Acknowledge an open alert |
| `PATCH` | `/api/v1/alerts/{id}/close` | Close an alert |
| `GET` | `/api/v1/stats` | Dashboard stats + timeline |
| `GET` | `/api/v1/threat-intel` | Top DNS, IPs, processes, users |
| `GET` | `/ws/events` | WebSocket live event stream |

### Event query parameters

| Parameter | Description |
|---|---|
| `agent_id` | Exact match |
| `host` | Case-insensitive partial match |
| `event_type` | `process` `network` `logon` `registry` `file` `dns` `health` `raw` |
| `severity` | Minimum severity (1–5) |
| `src_ip` | Exact match |
| `dst_ip` | Exact match |
| `user_name` | Case-insensitive partial match |
| `search` | Free text across host, user, process, command line, src/dst IP |
| `since` | RFC3339 start of range (default: 24h ago) |
| `until` | RFC3339 end of range |
| `limit` | Results per page (default 100, max 1000) |
| `offset` | Pagination offset (default 0) |

### WebSocket

Connect to `ws://host/ws/events?token=<JWT>`. Server pushes every 5 seconds:

```json
{ "type": "events", "events": [ ...event objects... ] }
```

### Authentication

```bash
# Login
curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'

# Use token
curl -s "http://localhost:8080/api/v1/agents" \
  -H "Authorization: Bearer <token>"
```

---

## Database Schema

The management platform shares `events` and `agents` with the agent backend (read-only). It adds:

### `users`

| Column | Type | Description |
|---|---|---|
| `id` | BIGSERIAL PK | Auto-increment |
| `username` | TEXT UNIQUE | Login username |
| `password_hash` | TEXT | bcrypt hash |
| `role` | TEXT | `admin` or `analyst` |
| `created_at` | TIMESTAMPTZ | Account creation time |
| `last_login` | TIMESTAMPTZ | Last successful login |

Default user: `admin` / `changeme`

### `alerts`

| Column | Type | Description |
|---|---|---|
| `id` | BIGSERIAL PK | Auto-increment |
| `created_at` | TIMESTAMPTZ | When created |
| `title` | TEXT | Short description |
| `description` | TEXT | Full context |
| `severity` | SMALLINT | 1–5 from triggering event |
| `status` | TEXT | `open` / `acknowledged` / `closed` |
| `agent_id` / `host` / `event_type` | TEXT | Context from triggering event |
| `event_id` | TEXT | Triggering event reference (dedup key) |
| `acknowledged_by` | TEXT | Analyst username |
| `acknowledged_at` | TIMESTAMPTZ | Action timestamp |

---

## Operations

```bash
# Start / rebuild
sudo docker compose up -d --build

# Restart API after config change
sudo docker compose restart mgmt-api

# View logs
sudo docker logs opensiem-mgmt-api -f
sudo docker logs opensiem-mgmt-ui -f

# Stop (data preserved)
sudo docker compose down

# Health check
curl -s http://localhost:8080/health
```

### Changing the admin password

```bash
# Generate bcrypt hash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'yournewpassword', bcrypt.gensalt()).decode())"

# Apply
sudo docker exec -it opensiem-db psql -U opensiem -d opensiem \
  -c "UPDATE users SET password_hash = '<hash>' WHERE username = 'admin';"
```

---

## Security Hardening

- Change `database.password`, `auth.jwt_secret`, and the admin password before exposing publicly
- Set `server.cors_origins` to your exact frontend origin instead of `*`
- Block port `8080` at the firewall — nginx on port `80` is the only public entry point
- Add HTTPS with a reverse proxy (Caddy, nginx, Traefik) in front of port `80`
- Rotate `jwt_secret` periodically — all active sessions will be invalidated on restart

---

## Project Structure

```
management/
├── backend/
│   ├── cmd/server/main.go                  # Entry point
│   ├── internal/
│   │   ├── api/
│   │   │   ├── server.go                   # Routes, middleware, TLS
│   │   │   ├── handlers.go                 # All REST handlers
│   │   │   ├── ws.go                       # WebSocket hub + broadcaster
│   │   │   └── alerts_engine.go            # Background alert auto-creation
│   │   ├── auth/
│   │   │   ├── jwt.go                      # JWT signing and validation
│   │   │   └── middleware.go               # HTTP auth middleware
│   │   ├── store/
│   │   │   ├── db.go                       # Connection pool
│   │   │   ├── events.go                   # Event queries
│   │   │   ├── agents.go                   # Agent queries
│   │   │   ├── alerts.go                   # Alert CRUD
│   │   │   ├── stats.go                    # Dashboard stats + threat intel
│   │   │   ├── users.go                    # User auth queries
│   │   │   └── migrations/
│   │   │       ├── migrate.go              # Auto-migration runner
│   │   │       ├── 003_users.sql
│   │   │       └── 004_alerts.sql
│   │   └── config/config.go                # YAML config loader
│   ├── docker/
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   └── server.yaml                     # Runtime config (edit this)
│   └── go.mod
└── frontend/
    ├── src/
    │   ├── pages/                          # Dashboard, Events, Agents, Alerts, ThreatIntel, Login
    │   ├── components/                     # Navbar, SeverityBadge
    │   └── api/                            # Axios client + useLiveFeed WebSocket hook
    ├── nginx.conf                          # SPA routing + API proxy
    └── Dockerfile
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE) for details.
