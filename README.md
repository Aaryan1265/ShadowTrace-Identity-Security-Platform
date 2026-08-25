# ShadowTrace

**Identity & Access Anomaly Detection Platform**

ShadowTrace is a portfolio-grade security application that ingests authentication telemetry, applies deterministic and explainable anomaly rules, calculates a 0–100 risk score, and surfaces actionable alerts through a FastAPI dashboard.

The project is intentionally small enough to understand end-to-end while demonstrating the same building blocks used in larger security platforms: event ingestion, persistence, detection logic, APIs, alert workflows, testing, CI, and containerized deployment.

## What it does

ShadowTrace analyzes authentication events and looks for:

- **Impossible travel** — a user appears in geographically distant cities too quickly.
- **Brute-force behavior** — multiple failed logins occur immediately before a successful attempt.
- **New devices** — a successful login comes from a device not previously seen for that user.
- **Unusual login hours** — successful access occurs outside the 07:00–22:00 window.
- **High-risk IPs** — events from configured high-risk addresses receive additional risk.
- **Explainable scoring** — every score is backed by visible detection signals.
- **Security alerts** — HIGH and CRITICAL events become investigation items.
- **Alert workflow** — alerts can be acknowledged and re-opened through the API/dashboard.
- **User timelines** — analysts can retrieve a user's recent authentication history.

## Architecture

```text
Application / Identity Provider
            |
            | POST /api/events
            v
      +-------------+
      |  FastAPI    |
      | Event API   |
      +------+------+ 
             |
             v
      +-------------+
      | Detection   |
      | Engine      |
      +------+------+ 
             |
             v
      +-------------+
      | Risk Score  |
      | + Signals   |
      +------+------+ 
             |
       +-----+------+
       |            |
       v            v
   PostgreSQL    Alerts
       |            |
       +-----+------+
             v
       Security Dashboard
             |
             v
      Analyst Investigation
```

## Risk model

| Signal | Points |
|---|---:|
| Impossible travel | +45 |
| Brute-force pattern | +30 |
| High-risk IP | +25 |
| New device | +15 |
| Unusual login hour | +10 |

Risk levels:

- `LOW`: 0–24
- `MEDIUM`: 25–49
- `HIGH`: 50–74
- `CRITICAL`: 75–100

The engine is deterministic and explainable. A future version could add statistical or ML-based detection without replacing these baseline rules.

## Tech stack

- Python 3.11+
- FastAPI
- SQLAlchemy 2
- SQLite for zero-setup local development
- PostgreSQL 16 for containerized deployment
- Pydantic
- Pytest
- Docker / Docker Compose
- GitHub Actions
- HTML/CSS/JavaScript dashboard

## Run locally

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest -q
uvicorn shadowtrace.main:app --reload
```

Open:

`http://127.0.0.1:8000`

Click **Load demo data**. The seed resets the local demo database and creates separate LOW, MEDIUM, HIGH, and CRITICAL scenarios.

API documentation:

`http://127.0.0.1:8000/docs`

## Docker + PostgreSQL

Start the full stack:

```powershell
docker compose up --build
```

Open:

`http://127.0.0.1:8000`

The Compose stack uses PostgreSQL instead of SQLite.

> Change `SHADOWTRACE_API_KEY` before using the stack outside a local demo environment.

## Real-world event ingestion

A production application or identity provider can send an authentication event to:

```http
POST /api/events
```

Example:

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/events `
  -H "Content-Type: application/json" `
  -H "X-API-Key: your-key" `
  -d '{"user_id":"alice","timestamp":"2026-08-24T14:15:00Z","ip_address":"192.0.2.10","country":"Canada","city":"Toronto","device_id":"alice-laptop","success":true,"source":"my-application"}'
```

Set `SHADOWTRACE_API_KEY` to enable API-key protection for event ingestion. In development, leaving it unset keeps the local demo easy to run.

For larger ingestion jobs, `POST /api/events/batch` accepts a JSON array of events.

## API endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Service health check |
| `POST /api/events` | Ingest one authentication event |
| `POST /api/events/batch` | Ingest multiple events |
| `GET /api/events` | Search recent events by user/risk |
| `GET /api/users/{user_id}/timeline` | Investigate one user's timeline |
| `GET /api/alerts` | List security alerts |
| `PATCH /api/alerts/{id}` | Acknowledge/re-open an alert |
| `GET /api/summary` | Dashboard metrics |
| `POST /api/demo/seed` | Reset and load synthetic scenarios |

Interactive OpenAPI documentation is available at `/docs`.

## Testing

Run:

```powershell
python -m pytest -q
```

The test suite covers detection boundaries, impossible travel, brute force, new-device behavior, timezone handling, API ingestion, demo scenarios, and dashboard summary data.

## CI

Every push and pull request to `main` or `master` runs the Pytest suite through GitHub Actions.

## Security notes

- Demo IPs and authentication events are synthetic.
- Do not commit production authentication logs, API keys, passwords, tokens, or secrets.
- Configure `SHADOWTRACE_API_KEY` in real deployments.
- Use HTTPS and a proper secret manager in production.
- The current risk engine is a demonstration/portfolio implementation, not a replacement for a mature SIEM or identity-security product.

## Why this is a useful software project

ShadowTrace demonstrates an end-to-end programming workflow:

**event data → algorithms → database → REST API → risk scoring → alerts → analyst dashboard → tests → CI → Docker**

That makes it useful as a Computer Programming & Analysis portfolio project because the implementation demonstrates programming, algorithms, databases, API development, testing, Git/GitHub workflow, and deployment rather than only a visual interface.
