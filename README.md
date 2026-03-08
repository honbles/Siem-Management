# OpenSIEM Management Platform

> Browser-based SIEM dashboard — real-time event monitoring, fleet management, automated alerting with email notifications, and full analyst workflow.

**Version: v0.3.0** · Agent compatible: v0.2.0+

---

## Table of Contents

- [What is OpenSIEM](#what-is-opensiem)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [Email Alerts (SMTP)](#email-alerts-smtp)
- [Platform Guide](#platform-guide)
- [API Reference](#api-reference)
- [Database Schema](#database-schema)
- [Operations](#operations)
- [Security Hardening](#security-hardening)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## What is OpenSIEM

OpenSIEM is a lightweight, self-hosted Security Information and Event Management (SIEM) stack. It consists of three components:

| Component | Role |
|---|---|
| **Agent** (v0.2.0) | Windows endpoint agent — collects process, network, logon, registry, file, DNS, and Sysmon events and forwards them to the backend. |
| **Backend** | Go API that receives events from agents and stores them in TimescaleDB. |
| **Management Platform** (this repo) | Browser dashboard that connects to the same database and adds alerting, analyst workflows, user management, and threat intelligence. |

---

## Architecture

```
Browser
  └── nginx :80  (mgmt-ui)
        ├── /api/    → mgmt-api :8080
        ├── /auth/   → mgmt-api :8080
        └── /ws/     → mgmt-api :8080 (WebSocket)

mgmt-api :8080
  └── TimescaleDB (shared with agent backend)
        ├── events / agents   (read — agent telemetry)
        ├── users             (read/write)
        ├── alerts            (read/write)
        ├── alert_rules       (read/write)
        └── audit_log         (write)
```

---

## Prerequisites

- Docker 24+ and Docker Compose v2
- Agent backend already running (`opensiem-db` healthy)
- Ports `80` and `8080` available
- Agent backend database password

---

## Quick Start

```bash
unzip opensiem-management.zip
cd management/backend/docker
nano server.yaml         # set database.password and auth.jwt_secret
sudo docker compose up -d --build
```

Open `http://192.168.1.140` — login with `admin / changeme`.

**You will be immediately redirected to a mandatory password change screen.** This is enforced for all users on first login.

---

## Configuration Reference

Edit `docker/server.yaml`, then `sudo docker compose restart mgmt-api`.

```yaml
server:
  listen_addr: ":8080"
  cors_origins: ["*"]        # tighten to http://your-ip in production

database:
  host:     "timescaledb"    # Docker service name — do not change
  password: "REQUIRED"       # must match agent backend POSTGRES_PASSWORD

auth:
  jwt_secret:     "REQUIRED" # openssl rand -hex 32
  token_duration: "24h"

smtp:
  enabled:      false        # set true to enable email alerts
  host:         "smtp.gmail.com"
  port:         587
  username:     "you@gmail.com"
  password:     "app-password"
  from:         "OpenSIEM <you@gmail.com>"
  to:
    - "soc@yourcompany.com"
  min_severity: 4            # 1=info 2=low 3=medium 4=high 5=critical
  use_tls:      true

log:
  level:  "info"             # debug | info | warn | error
  format: "json"
```

---

## Email Alerts (SMTP)

When enabled, an email is sent automatically whenever a new alert is created and its severity meets `min_severity`.

### Gmail

1. Enable 2FA on your Google account.
2. Generate an App Password: Google Account → Security → App Passwords.
3. Use the 16-character app password (not your account password).

```yaml
smtp:
  enabled: true
  host: "smtp.gmail.com"
  port: 587
  username: "you@gmail.com"
  password: "abcd efgh ijkl mnop"
  from: "OpenSIEM Alerts <you@gmail.com>"
  to: ["soc@yourcompany.com"]
  min_severity: 4
  use_tls: true
```

### Office 365

```yaml
smtp:
  enabled: true
  host: "smtp.office365.com"
  port: 587
  username: "you@company.com"
  password: "your-password"
  from: "OpenSIEM Alerts <you@company.com>"
  to: ["soc@yourcompany.com"]
  min_severity: 4
  use_tls: true
```

After enabling, go to **Settings** in the dashboard and click **Send test email** to verify.

---

## Platform Guide

### Dashboard

Main overview — auto-refreshes every 30 seconds.

- **Events today** — total events in the last 24 hours
- **High severity** — severity ≥ 4 events in the last 24 hours
- **Agents online** — agents checked in within the last 2 minutes
- **Open alerts** — alerts requiring attention
- **Event timeline** — 24-hour area chart in 1-hour buckets
- **Severity pie** — distribution across severity levels 1–5
- **Top event types** — most frequent event categories
- **Live feed** — real-time event stream via WebSocket

---

### Events

Full searchable event history with deep-dive capability.

**Filters:** free-text search, event type, severity, agent ID, time range.

**Live mode** — toggle to show real-time events instead of historical data.

**Export** — download current filtered results as CSV or JSON (up to 10,000 events).

**Event deep-dive** — click any row to open a side panel showing:
- All event fields (process, user, network, registry, etc.)
- Full raw JSON payload from the agent
- Related events on the same host within ±5 minutes
- Quick action to create an alert from the event

---

### Agents

Fleet overview — auto-refreshes every 15 seconds. Shows online/offline status, hostname, OS, version, last IP, last seen, and total event count. A green dot means the agent checked in within the last 2 minutes.

---

### Alerts

Alert management with full triage workflow.

**How alerts are created:**
1. **Automatically** — the alert engine evaluates events against enabled Alert Rules every 30 seconds. Each event+rule match creates one alert (deduplicated). If SMTP is enabled and severity meets the threshold, an email is sent.
2. **Manually** — click **New alert** to create from scratch.
3. **From an event** — open any event's deep-dive panel and click *Create alert from this event*.

**Workflow:** `open` → `acknowledged` → `closed`

Each status change records the analyst's username and timestamp.

**Alert detail panel** — click any alert to open a side panel showing:
- Full alert metadata
- The triggering event's details (if auto-generated from a known event)
- Inline Acknowledge and Close buttons

---

### Alert Rules

Configurable detection rules that drive automated alert generation.

| Field | Description |
|---|---|
| Min Severity | Match events at or above this level (1–5) |
| Event Type | Optional — restrict to one event category |
| Host contains | Optional — case-insensitive substring match |
| User contains | Optional — case-insensitive substring match |
| Process contains | Optional — case-insensitive substring match |
| Enabled | Toggle on/off without deleting |

**Default rules:** High Severity Event (≥4), Critical Event (5), Privileged Logon, Suspicious Network, Process Execution Alert.

Rules can be edited, disabled, or deleted. New rules take effect on the next engine cycle (within 30 seconds).

---

### Threat Intelligence

Aggregated intelligence from your own agents — no external feeds required.

- **Top DNS Domains** — most queried. Suspicious domains flagged in red (RustDesk, urban-vpn, ngrok, WPAD, .onion).
- **Top Source / Destination IPs** — most active network endpoints
- **Top Processes** — most active process names across fleet
- **Top Users** — most active usernames across fleet
- **Flagged domain banner** — automatic alert if suspicious domains are detected

---

### Users

Admin-only page. Roles: `admin` (full access) or `analyst` (no user management).

New users are forced to change their password on first login. The **Password** column shows `Default` (risk) or `Changed`. The `admin` account cannot be deleted.

---

### Audit Log

Every platform action is recorded with: timestamp, username, action type, target, detail, and source IP. Paginated, 100 entries per page.

Logged actions: `login`, `change_password`, `create/delete_user`, `create/ack/close_alert`, `create/update/delete_alert_rule`.

---

### Settings

Shows current SMTP configuration (password redacted) and a **Send test email** button when SMTP is enabled. If SMTP is disabled, shows the exact YAML configuration block needed to enable it.

---

## API Reference

All `/api/` and `/auth/me` require `Authorization: Bearer <token>`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `POST` | `/auth/login` | Authenticate → JWT + `require_password_change` flag |
| `GET` | `/auth/me` | Current user |
| `PATCH` | `/auth/password` | Change password |
| `GET` | `/api/v1/events` | Query events (filters + pagination) |
| `GET` | `/api/v1/events/export?format=csv\|json` | Download events |
| `GET` | `/api/v1/events/{id}` | Single event + related events |
| `GET` | `/api/v1/agents` | Agent fleet list |
| `GET` | `/api/v1/agents/{id}` | Agent detail + recent events |
| `GET` | `/api/v1/alerts` | List alerts |
| `POST` | `/api/v1/alerts` | Create manual alert |
| `GET` | `/api/v1/alerts/{id}` | Alert detail + triggering event |
| `PATCH` | `/api/v1/alerts/{id}/acknowledge` | Acknowledge |
| `PATCH` | `/api/v1/alerts/{id}/close` | Close |
| `GET` | `/api/v1/alert-rules` | List rules |
| `POST` | `/api/v1/alert-rules` | Create rule |
| `PUT` | `/api/v1/alert-rules/{id}` | Update rule |
| `DELETE` | `/api/v1/alert-rules/{id}` | Delete rule |
| `GET` | `/api/v1/users` | List users (admin) |
| `POST` | `/api/v1/users` | Create user (admin) |
| `DELETE` | `/api/v1/users/{id}` | Delete user (admin) |
| `GET` | `/api/v1/audit-log` | Audit entries |
| `GET` | `/api/v1/stats` | Dashboard stats |
| `GET` | `/api/v1/threat-intel` | Threat intel aggregations |
| `GET` | `/api/v1/settings/smtp` | SMTP config (no password) |
| `POST` | `/api/v1/settings/smtp/test` | Send test email |
| `GET` | `/ws/events?token=<jwt>` | WebSocket live feed |

**Event query parameters:** `agent_id`, `host`, `event_type`, `severity`, `src_ip`, `dst_ip`, `user_name`, `search`, `since`, `until`, `limit` (max 1000), `offset`.

---

## Database Schema

### `users`
`id`, `username` (unique), `password_hash`, `role` (admin/analyst), `password_changed`, `created_at`, `last_login`

### `alerts`
`id`, `created_at`, `title`, `description`, `severity`, `status` (open/acknowledged/closed), `agent_id`, `host`, `event_type`, `event_id` (dedup key), `acknowledged_by`, `acknowledged_at`

### `alert_rules`
`id`, `name`, `description`, `enabled`, `event_type`, `severity`, `host_match`, `user_match`, `process_match`, `created_by`, `created_at`

### `audit_log`
`id`, `created_at`, `username`, `action`, `target`, `detail`, `ip_address`

---

## Operations

```bash
# Rebuild and restart
sudo docker compose up -d --build

# Restart API after config change
sudo docker compose restart mgmt-api

# Logs
sudo docker logs opensiem-mgmt-api -f
sudo docker logs opensiem-mgmt-ui  -f

# Health check
curl -s http://localhost:8080/health

# Stop (data preserved)
sudo docker compose down
```

### Reset admin password (if locked out)

```bash
pip3 install bcrypt --break-system-packages
HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'newpassword', bcrypt.gensalt()).decode())")
sudo docker exec opensiem-db psql -U opensiem -d opensiem \
  -c "UPDATE users SET password_hash='$HASH', password_changed=TRUE WHERE username='admin';"
```

---

## Security Hardening

- Generate `auth.jwt_secret` with `openssl rand -hex 32` before first deploy
- Force password change is automatic — but rotate admin password periodically
- Set `cors_origins` to your exact server IP instead of `*`
- Block port `8080` at the firewall — nginx on `80` is the only public entry point
- Add HTTPS with a reverse proxy (Caddy, Traefik, nginx) in front of port `80`
- Use App Passwords for SMTP — never use your main email account password
- Review the Audit Log periodically for unexpected logins or configuration changes

---

## Project Structure

```
management/
├── backend/
│   ├── cmd/server/main.go                  # Entry point + SeedAdmin
│   ├── internal/
│   │   ├── api/                            # HTTP server, handlers, WebSocket, alert engine
│   │   ├── auth/                           # JWT + middleware
│   │   ├── config/config.go                # Config with SMTP
│   │   ├── notify/mailer.go                # SMTP email service
│   │   └── store/                          # All DB queries + migrations
│   └── docker/                             # Dockerfile, compose, server.yaml
└── frontend/src/
    ├── pages/                              # All pages (see Platform Guide)
    ├── components/                         # Navbar, SeverityBadge
    └── api/                                # Axios client + WebSocket hook
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).
