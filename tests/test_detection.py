from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from shadowtrace.detection import analyze_event, risk_level


def event(**kwargs):
    data = dict(
        user_id="u1",
        timestamp=datetime(2026, 8, 24, 14, tzinfo=timezone.utc),
        ip_address="192.0.2.1",
        country="Canada",
        city="Toronto",
        device_id="laptop",
        success=True,
    )
    data.update(kwargs)
    return SimpleNamespace(**data)


def test_risk_boundaries():
    assert [risk_level(x) for x in (0, 25, 50, 75)] == [
        "LOW", "MEDIUM", "HIGH", "CRITICAL"
    ]


def test_new_device_adds_risk():
    score, _, reasons = analyze_event(
        event(device_id="new-device"),
        [event(device_id="old-device", timestamp=datetime(2026, 8, 24, 13, tzinfo=timezone.utc))],
    )
    assert score >= 15
    assert "New device detected" in reasons


def test_impossible_travel():
    score, _, reasons = analyze_event(
        event(city="London", timestamp=datetime(2026, 8, 24, 11, tzinfo=timezone.utc)),
        [event(city="Toronto", timestamp=datetime(2026, 8, 24, 10, tzinfo=timezone.utc))],
    )
    assert score >= 45
    assert any("Impossible travel" in reason for reason in reasons)


def test_bruteforce():
    now = datetime(2026, 8, 24, 14, tzinfo=timezone.utc)
    failures = [event(timestamp=now - timedelta(minutes=i), success=False) for i in range(5)]
    score, _, reasons = analyze_event(event(timestamp=now), failures)
    assert score >= 30
    assert "Brute-force pattern detected" in reasons


def test_timezone_naive_and_aware_are_safe():
    previous = event(timestamp=datetime(2026, 8, 24, 10))
    current = event(timestamp=datetime(2026, 8, 24, 10, 1, tzinfo=timezone.utc))
    score, _, reasons = analyze_event(current, [previous])
    assert score >= 0
    assert isinstance(reasons, list)


def test_high_risk_ip():
    score, _, reasons = analyze_event(event(ip_address="203.0.113.66"), [])
    assert score >= 25
    assert "High-risk IP address" in reasons
