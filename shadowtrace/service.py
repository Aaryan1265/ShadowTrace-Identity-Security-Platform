import json

from sqlalchemy.orm import Session

from .detection import analyze_event
from .models import Alert, AuthEvent


def process_event(db: Session, payload):
    previous = (
        db.query(AuthEvent)
        .filter(AuthEvent.user_id == payload.user_id)
        .order_by(AuthEvent.timestamp.desc())
        .limit(50)
        .all()
    )

    score, level, reasons = analyze_event(payload, previous)

    event = AuthEvent(
        user_id=payload.user_id,
        timestamp=payload.timestamp,
        ip_address=payload.ip_address,
        country=payload.country,
        city=payload.city,
        device_id=payload.device_id,
        success=payload.success,
        source=payload.source,
        risk_score=score,
        risk_level=level,
        reasons=json.dumps(reasons),
    )

    db.add(event)
    db.flush()

    if score >= 50:
        db.add(
            Alert(
                event_id=event.id,
                user_id=event.user_id,
                severity=level,
                title=f"{level} authentication anomaly",
                message="; ".join(reasons) or "Multiple risk signals detected.",
            )
        )

    db.commit()
    db.refresh(event)
    return event


def serialize_event(event):
    return {
        "id": event.id,
        "user_id": event.user_id,
        "timestamp": event.timestamp,
        "ip_address": event.ip_address,
        "country": event.country,
        "city": event.city,
        "device_id": event.device_id,
        "success": event.success,
        "source": event.source,
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "reasons": json.loads(event.reasons or "[]"),
    }


def serialize_alert(alert):
    return {
        "id": alert.id,
        "event_id": alert.event_id,
        "user_id": alert.user_id,
        "created_at": alert.created_at,
        "severity": alert.severity,
        "title": alert.title,
        "message": alert.message,
        "status": alert.status,
    }
