from datetime import datetime, timedelta, timezone

from .database import Base, SessionLocal, engine
from .models import Alert, AuthEvent
from .schemas import AuthEventCreate
from .service import process_event

Base.metadata.create_all(engine)


def seed_demo():
    """Reset and seed deterministic synthetic scenarios for demonstrations."""
    db = SessionLocal()
    try:
        db.query(Alert).delete()
        db.query(AuthEvent).delete()
        db.commit()

        base = datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc)

        events = [
            # LOW — normal login
            AuthEventCreate(
                user_id="alice",
                timestamp=base,
                ip_address="192.0.2.10",
                country="Canada",
                city="Toronto",
                device_id="alice-laptop",
                success=True,
                source="demo-app",
            ),
            # MEDIUM — new device
            AuthEventCreate(
                user_id="alice",
                timestamp=base + timedelta(hours=1),
                ip_address="192.0.2.11",
                country="Canada",
                city="Toronto",
                device_id="alice-new-phone",
                success=True,
                source="demo-app",
            ),
            # MEDIUM — high-risk IP
            AuthEventCreate(
                user_id="bob",
                timestamp=base + timedelta(minutes=10),
                ip_address="203.0.113.66",
                country="Canada",
                city="Toronto",
                device_id="bob-laptop",
                success=True,
                source="demo-app",
            ),
            # MEDIUM — unusual login hour
            AuthEventCreate(
                user_id="eve",
                timestamp=base.replace(hour=2),
                ip_address="192.0.2.30",
                country="Canada",
                city="Toronto",
                device_id="eve-laptop",
                success=True,
                source="demo-app",
            ),
            # HIGH — impossible travel + new device
            AuthEventCreate(
                user_id="dave",
                timestamp=base - timedelta(minutes=30),
                ip_address="192.0.2.40",
                country="Canada",
                city="Toronto",
                device_id="dave-laptop",
                success=True,
                source="demo-app",
            ),
            AuthEventCreate(
                user_id="dave",
                timestamp=base,
                ip_address="192.0.2.41",
                country="United Kingdom",
                city="London",
                device_id="dave-unknown",
                success=True,
                source="demo-app",
            ),
            # HIGH — brute force + high-risk IP
            *[
                AuthEventCreate(
                    user_id="charlie",
                    timestamp=base - timedelta(minutes=10 - i),
                    ip_address="192.0.2.50",
                    country="Canada",
                    city="Toronto",
                    device_id="charlie-laptop",
                    success=False,
                    source="demo-app",
                )
                for i in range(5)
            ],
            AuthEventCreate(
                user_id="charlie",
                timestamp=base,
                ip_address="203.0.113.66",
                country="Canada",
                city="Toronto",
                device_id="charlie-laptop",
                success=True,
                source="demo-app",
            ),
            # CRITICAL — impossible travel + new device + high-risk IP
            AuthEventCreate(
                user_id="hannah",
                timestamp=base - timedelta(minutes=20),
                ip_address="192.0.2.70",
                country="Canada",
                city="Toronto",
                device_id="hannah-laptop",
                success=True,
                source="demo-app",
            ),
            AuthEventCreate(
                user_id="hannah",
                timestamp=base,
                ip_address="198.51.100.77",
                country="Singapore",
                city="Singapore",
                device_id="hannah-unknown",
                success=True,
                source="demo-app",
            ),
        ]

        for payload in events:
            process_event(db, payload)

        return len(events)
    finally:
        db.close()


if __name__ == "__main__":
    print(f"Seeded {seed_demo()} demo events.")
