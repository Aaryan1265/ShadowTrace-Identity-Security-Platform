from datetime import datetime, timezone
from math import asin, cos, radians, sin, sqrt


HIGH_RISK_IPS = {
    "203.0.113.66",
    "203.0.113.99",
    "198.51.100.77",
}


CITY_COORDS = {
    "Toronto": (43.6532, -79.3832),
    "Vancouver": (49.2827, -123.1207),
    "New York": (40.7128, -74.0060),
    "London": (51.5074, -0.1278),
    "Singapore": (1.3521, 103.8198),
    "Mumbai": (19.0760, 72.8777),
}


def distance_km(a: str, b: str) -> float:
    if a not in CITY_COORDS or b not in CITY_COORDS:
        return 0.0

    lat1, lon1 = CITY_COORDS[a]
    lat2, lon2 = CITY_COORDS[b]

    earth = 6371.0

    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)

    x = (
        sin(dlat / 2) ** 2
        + cos(radians(lat1))
        * cos(radians(lat2))
        * sin(dlon / 2) ** 2
    )

    return 2 * earth * asin(sqrt(x))


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(
            tzinfo=None
        )

    return value


def _hours_between(a: datetime, b: datetime) -> float:
    return abs(
        (
            _utc_naive(a)
            - _utc_naive(b)
        ).total_seconds()
    ) / 3600


def _seconds_between(a: datetime, b: datetime) -> float:
    return (
        _utc_naive(a)
        - _utc_naive(b)
    ).total_seconds()


def risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


def analyze_event(event, previous_events):
    """
    Analyze an authentication event using explainable
    security signals.
    """

    score = 0
    reasons = []


    # ---------------------------------------------------------
    # High-risk IP
    # ---------------------------------------------------------

    if event.ip_address in HIGH_RISK_IPS:

        score += 25

        reasons.append(
            "High-risk IP address"
        )


    # ---------------------------------------------------------
    # Historical behavior
    # ---------------------------------------------------------

    if previous_events:

        # -----------------------------------------------------
        # New device
        #
        # Only evaluated when the user already has history.
        # The first device establishes the user's baseline.
        # -----------------------------------------------------

        known_devices = {
            x.device_id
            for x in previous_events
        }

        if event.device_id not in known_devices:

            score += 15

            reasons.append(
                "New device detected"
            )


        # -----------------------------------------------------
        # Impossible travel
        #
        # Compare against the most recent successful login.
        # -----------------------------------------------------

        previous_successful = [
            x
            for x in previous_events
            if x.success
        ]

        if previous_successful:

            previous = max(
                previous_successful,
                key=lambda x: x.timestamp,
            )

            hours = _hours_between(
                event.timestamp,
                previous.timestamp,
            )

            distance = distance_km(
                previous.city,
                event.city,
            )

            if hours > 0:

                speed = distance / hours

                if speed > 900:

                    score += 45

                    reasons.append(
                        "Impossible travel from "
                        f"{previous.city} to "
                        f"{event.city}"
                    )


        # -----------------------------------------------------
        # Brute-force detection
        # -----------------------------------------------------

        failures = [
            x
            for x in previous_events
            if (
                not x.success
                and 0
                <= _seconds_between(
                    event.timestamp,
                    x.timestamp,
                )
                <= 900
            )
        ]

        if len(failures) >= 4:

            score += 30

            reasons.append(
                "Brute-force pattern detected"
            )


    # ---------------------------------------------------------
    # Unusual login hours
    # ---------------------------------------------------------

    if not 7 <= event.timestamp.hour <= 22:

        score += 10

        reasons.append(
            "Login occurred during unusual hours"
        )


    # ---------------------------------------------------------
    # Final score
    # ---------------------------------------------------------

    score = min(
        score,
        100,
    )


    return (
        score,
        risk_level(score),
        reasons,
    )