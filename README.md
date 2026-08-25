# ShadowTrace

**Identity & Access Anomaly Detection Platform**

ShadowTrace is a portfolio-grade security application that ingests
authentication telemetry, applies deterministic and explainable
anomaly-detection rules, calculates a 0--100 risk score, and surfaces
actionable security alerts through a FastAPI dashboard.

The project is intentionally small enough to understand end-to-end while
demonstrating the building blocks used in larger security platforms:
event ingestion, persistence, detection logic, REST APIs, alert
workflows, testing, CI, and containerized deployment.

------------------------------------------------------------------------

## Why ShadowTrace?

Authentication systems generate large amounts of telemetry, but raw
login events do not immediately tell an analyst whether an event is
suspicious.

ShadowTrace turns authentication events into explainable security
signals.

For example:

``` text
14:00  Toronto
       |
       | 20 minutes
       v
14:20  Singapore
       |
       +-- Different device
       +-- High-risk IP
       +-- Impossible travel
              |
              v
        Risk Score: 85
        CRITICAL
```

Instead of returning only a risk score, ShadowTrace explains which
signals contributed to the decision.

------------------------------------------------------------------------

## What it detects

-   **Impossible travel** --- a user appears in geographically distant
    cities too quickly.
-   **Brute-force behavior** --- repeated failed authentication attempts
    within a short time window.
-   **New devices** --- an authentication attempt comes from a device
    not previously seen for that user.
-   **Unusual login hours** --- authentication activity occurs outside
    the 07:00--22:00 window.
-   **High-risk IPs** --- configured high-risk addresses receive
    additional risk.
-   **Explainable scoring** --- every non-zero score is backed by
    visible detection signals.
-   **Security alerts** --- HIGH and CRITICAL events become
    investigation items.
-   **Alert workflow** --- analysts can acknowledge and re-open alerts.
-   **User timelines** --- analysts can retrieve a user's recent
    authentication history.
-   **Batch ingestion** --- multiple authentication events can be
    submitted through one API request.
-   **Dashboard filtering** --- recent telemetry can be filtered by user
    and risk level.

> The current IP reputation and geographic data are synthetic/demo data.
> A production deployment would normally connect these rules to external
> threat-intelligence and geolocation providers.

------------------------------------------------------------------------

## Example detection

A first authentication establishes the user's baseline:

``` text
User: attack-test-2
Location: Toronto
Device: laptop-1
Result: SUCCESS

Risk: 0 / LOW
```

A second event arrives shortly afterward:

``` text
User: attack-test-2
Location: Singapore
Device: unknown-device
IP: 203.0.113.99
Result: FAILED
```

ShadowTrace can combine:

``` text
High-risk IP          +25
New device            +15
Impossible travel     +45
--------------------------------
Total                  85
```

Result:

``` text
Risk Score: 85
Risk Level: CRITICAL
```

Signals:

``` text
High-risk IP address
New device detected
Impossible travel from Toronto to Singapore
```

The engine is deterministic and explainable rather than a black-box
model.

------------------------------------------------------------------------

## Architecture

``` text
Application / Identity Provider
              |
              | POST /api/events
              v
       +-------------+
       |   FastAPI   |
       |   Event API |
       +------+------+ 
              |
              v
       +-------------+
       |  Detection  |
       |   Engine    |
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
    PostgreSQL     Alerts
        |            |
        +-----+------+
              |
              v
       Security Dashboard
              |
              v
       Analyst Investigation
```

### Main components

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  `shadowtrace/main.py`               FastAPI application and HTTP
                                      endpoints

  `shadowtrace/detection.py`          Explainable anomaly-detection
                                      engine

  `shadowtrace/service.py`            Event processing, scoring,
                                      persistence, and alert creation

  `shadowtrace/models.py`             SQLAlchemy database models

  `shadowtrace/schemas.py`            Pydantic API schemas

  `shadowtrace/database.py`           Database configuration and sessions

  `shadowtrace/seed.py`               Synthetic demo scenarios

  `shadowtrace/static/`               Dashboard HTML/CSS/JavaScript

  `tests/`                            Automated test suite

  `.github/workflows/`                Continuous integration
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## Risk model

  Signal                  Points
  --------------------- --------
  Impossible travel          +45
  Brute-force pattern        +30
  High-risk IP               +25
  New device                 +15
  Unusual login hour         +10

Scores are capped at 100.

### Risk levels

      Score Level
  --------- ------------
      0--24 `LOW`
     25--49 `MEDIUM`
     50--74 `HIGH`
    75--100 `CRITICAL`

Multiple signals can be combined for a single event.

------------------------------------------------------------------------

## Tech stack

-   Python 3.11+
-   FastAPI
-   SQLAlchemy 2
-   Pydantic
-   SQLite for zero-setup local development
-   PostgreSQL 16 for containerized deployment
-   Pytest
-   Docker / Docker Compose
-   GitHub Actions
-   HTML / CSS / JavaScript
-   REST / OpenAPI

------------------------------------------------------------------------

# Run locally

## Windows PowerShell

Clone the repository:

``` powershell
git clone https://github.com/Aaryan1265/ShadowTrace-Identity-Security-Platform.git
cd ShadowTrace-Identity-Security-Platform
```

Create a virtual environment:

``` powershell
python -m venv .venv
```

Activate it:

``` powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

``` powershell
pip install -r requirements.txt
```

Run the tests:

``` powershell
python -m pytest -q
```

Start the application:

``` powershell
uvicorn shadowtrace.main:app --reload
```

Open the dashboard:

``` text
http://127.0.0.1:8000
```

Open the interactive API documentation:

``` text
http://127.0.0.1:8000/docs
```

------------------------------------------------------------------------

## Demo data

Click **Load demo data** on the dashboard.

The seed process creates synthetic authentication scenarios representing
different risk levels, including LOW, MEDIUM, HIGH, and CRITICAL
activity.

The demo database is local and is intentionally excluded from Git with
`.gitignore`.

------------------------------------------------------------------------

# Docker + PostgreSQL

The project includes Docker and Docker Compose configuration for a more
production-like environment.

Start the stack:

``` powershell
docker compose up --build
```

Open:

``` text
http://127.0.0.1:8000
```

The Compose environment uses PostgreSQL instead of the local SQLite
database.

> Change `SHADOWTRACE_API_KEY` before using the stack outside a local
> development/demo environment.

------------------------------------------------------------------------

# Real-world event ingestion

ShadowTrace is designed so that an application, identity provider,
authentication service, or internal security system can send
authentication telemetry to the API.

### Single event

``` http
POST /api/events
```

Example:

``` powershell
curl.exe -X POST http://127.0.0.1:8000/api/events `
  -H "Content-Type: application/json" `
  -H "X-API-Key: your-key" `
  -d '{"user_id":"alice","timestamp":"2026-08-24T14:15:00Z","ip_address":"192.0.2.10","country":"Canada","city":"Toronto","device_id":"alice-laptop","success":true,"source":"my-application"}'
```

Set `SHADOWTRACE_API_KEY` to enable API-key protection for event
ingestion.

For local development, leaving it unset keeps the demo easy to run.

### Batch ingestion

Larger ingestion jobs can use:

``` http
POST /api/events/batch
```

The endpoint accepts a JSON array of authentication events.

------------------------------------------------------------------------

# API endpoints

  ---------------------------------------------------------------------------------
  Endpoint                          Method                  Purpose
  --------------------------------- ----------------------- -----------------------
  `/api/health`                     `GET`                   Service health check

  `/api/events`                     `POST`                  Ingest one
                                                            authentication event

  `/api/events/batch`               `POST`                  Ingest multiple
                                                            authentication events

  `/api/events`                     `GET`                   Search recent events by
                                                            user/risk

  `/api/users/{user_id}/timeline`   `GET`                   Investigate one user's
                                                            authentication timeline

  `/api/alerts`                     `GET`                   List security alerts

  `/api/alerts/{id}`                `PATCH`                 Acknowledge or re-open
                                                            an alert

  `/api/summary`                    `GET`                   Dashboard metrics

  `/api/demo/seed`                  `POST`                  Reset and load
                                                            synthetic demo
                                                            scenarios
  ---------------------------------------------------------------------------------

Interactive OpenAPI documentation is available at:

``` text
http://127.0.0.1:8000/docs
```

------------------------------------------------------------------------

# Example workflow

A realistic integration can follow this flow:

``` text
1. Application / Identity Provider
          |
          | authentication event
          v
2. ShadowTrace API
          |
          v
3. Detection Engine
          |
          +-- IP reputation
          +-- device history
          +-- geographic distance
          +-- login timing
          +-- failed-login history
          |
          v
4. Risk Score
          |
          +-- LOW
          +-- MEDIUM
          +-- HIGH
          +-- CRITICAL
          |
          v
5. Alert Creation
          |
          v
6. Security Dashboard
          |
          v
7. Analyst Acknowledgement / Investigation
```

This makes ShadowTrace usable as a lightweight authentication-risk
service that can sit beside an application's existing authentication
system.

------------------------------------------------------------------------

# Testing

Run:

``` powershell
python -m pytest -q
```

The automated suite covers:

-   Detection boundaries
-   Impossible-travel behavior
-   Brute-force detection
-   New-device behavior
-   Timezone handling
-   API event ingestion
-   Demo scenarios
-   Dashboard summary data
-   Alert behavior

A successful run currently produces:

``` text
......... [100%]
```

The project also runs its test suite through GitHub Actions for pushes
and pull requests targeting `main` or `master`.

------------------------------------------------------------------------

# Security considerations

-   Demo IP addresses and authentication events are synthetic.
-   Never commit production authentication logs.
-   Never commit API keys, passwords, tokens, or other secrets.
-   Configure `SHADOWTRACE_API_KEY` for protected deployments.
-   Use HTTPS in production.
-   Use a proper secret manager for production credentials.
-   Use a production PostgreSQL configuration rather than local SQLite.
-   The current detection engine is a portfolio/demo implementation and
    is not intended to replace a mature SIEM, IAM security platform, or
    commercial identity-threat detection product.
-   Production deployments should add stronger authentication,
    authorization, rate limiting, structured logging, monitoring, and
    external threat-intelligence sources.

------------------------------------------------------------------------

# Project structure

``` text
ShadowTrace/
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── shadowtrace/
│   ├── __init__.py
│   ├── config.py
│   ├── database.py
│   ├── detection.py
│   ├── main.py
│   ├── models.py
│   ├── schemas.py
│   ├── seed.py
│   ├── service.py
│   └── static/
│       ├── index.html
│       └── style.css
│
├── tests/
│   ├── test_api.py
│   └── test_detection.py
│
├── .dockerignore
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── README.md
└── requirements.txt
```

------------------------------------------------------------------------

# Why this is a strong portfolio project

ShadowTrace demonstrates an end-to-end software engineering workflow:

``` text
Authentication telemetry
        ↓
Algorithms / detection rules
        ↓
Risk scoring
        ↓
Database persistence
        ↓
REST API
        ↓
Alert workflow
        ↓
Security dashboard
        ↓
Automated tests
        ↓
CI
        ↓
Docker / PostgreSQL
```

For a **Computer Programming & Analysis** portfolio, the project
demonstrates practical work across:

-   Python programming
-   Object-oriented application structure
-   Algorithms and rule-based detection
-   Relational databases
-   SQLAlchemy ORM
-   REST API development
-   FastAPI
-   Data validation with Pydantic
-   Automated testing with Pytest
-   Git and GitHub
-   Continuous integration
-   Docker
-   PostgreSQL
-   Front-end integration
-   Security-focused application design

------------------------------------------------------------------------

# Future improvements

Possible production-oriented extensions include:

-   Real IP reputation feeds
-   Real geolocation APIs
-   Redis-based rate limiting
-   JWT/OAuth2 integration
-   Role-based analyst access
-   WebSocket live alerts
-   Email/Slack alert notifications
-   Historical risk analytics
-   Machine-learning anomaly detection
-   SIEM integrations
-   Prometheus/Grafana monitoring
-   Cloud deployment
-   Background event processing with a message queue

------------------------------------------------------------------------

## License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for details.
