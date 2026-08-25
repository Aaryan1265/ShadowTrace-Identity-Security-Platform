from pathlib import Path

from fastapi import Body, Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import SHADOWTRACE_API_KEY
from .database import Base, engine, get_db
from .models import Alert, AuthEvent
from .schemas import AlertStatusUpdate, AuthEventCreate
from .service import process_event, serialize_alert, serialize_event


Base.metadata.create_all(engine)


app = FastAPI(
    title="ShadowTrace",
    version="1.0.0",
    description=(
        "Identity and access anomaly detection platform. "
        "Ingest authentication telemetry, score suspicious behavior, "
        "and surface explainable security alerts."
    ),
)


STATIC = Path(__file__).parent / "static"

app.mount(
    "/static",
    StaticFiles(directory=STATIC),
    name="static",
)


def require_ingestion_key(
    x_api_key: str | None = Header(default=None),
):
    """Protect event ingestion when SHADOWTRACE_API_KEY is configured."""

    if SHADOWTRACE_API_KEY and x_api_key != SHADOWTRACE_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "ShadowTrace",
    }


@app.post(
    "/api/events",
    status_code=201,
    dependencies=[Depends(require_ingestion_key)],
)
def create_event(
    payload: AuthEventCreate,
    db: Session = Depends(get_db),
):
    """Ingest one authentication event."""

    return serialize_event(
        process_event(db, payload)
    )


@app.post(
    "/api/events/batch",
    status_code=201,
    dependencies=[Depends(require_ingestion_key)],
)
def create_events(
    payloads: list[AuthEventCreate] = Body(...),
    db: Session = Depends(get_db),
):
    """Ingest multiple authentication events."""

    if not 1 <= len(payloads) <= 500:
        raise HTTPException(
            status_code=400,
            detail="Batch size must be 1-500 events",
        )

    return [
        serialize_event(
            process_event(db, payload)
        )
        for payload in payloads
    ]


@app.get("/api/events")
def list_events(
    limit: int = 50,
    user_id: str | None = None,
    risk: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(AuthEvent)

    if user_id:
        query = query.filter(
            AuthEvent.user_id == user_id
        )

    if risk:
        query = query.filter(
            AuthEvent.risk_level == risk.upper()
        )

    events = (
        query
        .order_by(AuthEvent.timestamp.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )

    return [
        serialize_event(event)
        for event in events
    ]


@app.get("/api/users/{user_id}/timeline")
def user_timeline(
    user_id: str,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    events = (
        db.query(AuthEvent)
        .filter(AuthEvent.user_id == user_id)
        .order_by(AuthEvent.timestamp.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )

    if not events:
        raise HTTPException(
            status_code=404,
            detail="User has no authentication events",
        )

    return [
        serialize_event(event)
        for event in events
    ]


@app.get("/api/alerts")
def list_alerts(
    limit: int = 50,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)

    if status:
        query = query.filter(
            Alert.status == status.upper()
        )

    alerts = (
        query
        .order_by(Alert.created_at.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )

    return [
        serialize_alert(alert)
        for alert in alerts
    ]


@app.patch("/api/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    alert = db.get(Alert, alert_id)

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    alert.status = payload.status.upper()

    db.commit()
    db.refresh(alert)

    return serialize_alert(alert)


@app.get("/api/summary")
def summary(db: Session = Depends(get_db)):
    """
    Return dashboard statistics.

    Events and failed logins are historical totals.

    Severity counts represent currently OPEN alerts.
    This means acknowledging an alert immediately decreases
    the corresponding open-severity counter.
    """

    # -----------------------------------------
    # Historical authentication statistics
    # -----------------------------------------

    total_events = (
        db.query(func.count(AuthEvent.id))
        .scalar()
        or 0
    )

    failed_logins = (
        db.query(func.count(AuthEvent.id))
        .filter(AuthEvent.success.is_(False))
        .scalar()
        or 0
    )

    # -----------------------------------------
    # Current OPEN alert statistics
    # -----------------------------------------

    open_critical = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.status == "OPEN",
            Alert.severity == "CRITICAL",
        )
        .scalar()
        or 0
    )

    open_high = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.status == "OPEN",
            Alert.severity == "HIGH",
        )
        .scalar()
        or 0
    )

    open_medium = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.status == "OPEN",
            Alert.severity == "MEDIUM",
        )
        .scalar()
        or 0
    )

    open_low = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.status == "OPEN",
            Alert.severity == "LOW",
        )
        .scalar()
        or 0
    )

    open_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.status == "OPEN")
        .scalar()
        or 0
    )

    return {
        "total_events": total_events,
        "failed_logins": failed_logins,

        "open_critical": open_critical,
        "open_high": open_high,
        "open_medium": open_medium,
        "open_low": open_low,

        "open_alerts": open_alerts,
    }


@app.post("/api/demo/seed")
def seed_demo_events():
    from .seed import seed_demo

    count = seed_demo()

    return {
        "message": "Demo data reset and seeded.",
        "events": count,
    }