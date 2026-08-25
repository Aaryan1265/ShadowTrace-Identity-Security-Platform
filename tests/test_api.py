import os
from pathlib import Path

from fastapi.testclient import TestClient

# Keep API tests isolated from a developer's database/API-key environment.
os.environ.pop("SHADOWTRACE_API_KEY", None)
os.environ["DATABASE_URL"] = f"sqlite:///{Path.cwd() / 'test_shadowtrace.sqlite'}"

from shadowtrace.main import app  # noqa: E402

client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_event_ingestion_and_summary():
    payload = {
        "user_id": "api-test-user",
        "timestamp": "2026-08-24T14:00:00Z",
        "ip_address": "192.0.2.100",
        "country": "Canada",
        "city": "Toronto",
        "device_id": "test-device",
        "success": True,
        "source": "pytest",
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 201
    assert response.json()["user_id"] == "api-test-user"

    summary = client.get("/api/summary")
    assert summary.status_code == 200
    assert summary.json()["total_events"] >= 1


def test_demo_seed_creates_multiple_scenarios():
    response = client.post("/api/demo/seed")
    assert response.status_code == 200
    assert response.json()["events"] >= 10

    events = client.get("/api/events?limit=100").json()
    levels = {event["risk_level"] for event in events}
    assert {"LOW", "MEDIUM", "HIGH", "CRITICAL"}.issubset(levels)

    alerts = client.get("/api/alerts").json()
    assert len(alerts) >= 3
