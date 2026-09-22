from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


LIFECYCLE_STATES = {
    "FRESH",
    "ACTIVE",
    "AGING",
    "STALE",
    "EXPIRED",
    "UNKNOWN",
}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def calculate_lifecycle(
    *,
    first_seen: datetime | None,
    last_seen: datetime | None,
    now: datetime | None = None,
    expiration_days: int = 90,
) -> dict[str, Any]:
    current_time = _utc(now) or datetime.now(timezone.utc)

    first = _utc(first_seen)
    last = _utc(last_seen)

    if not first and not last:
        return {
            "state": "UNKNOWN",
            "age_days": None,
            "days_since_last_seen": None,
            "expiration_days": expiration_days,
            "is_expired": False,
            "needs_revalidation": True,
        }

    reference = last or first

    age_days = max(
        0.0,
        (current_time - first).total_seconds() / 86400,
    )

    days_since_last_seen = max(
        0.0,
        (current_time - reference).total_seconds() / 86400,
    )

    if days_since_last_seen > expiration_days:
        state = "EXPIRED"
        is_expired = True
        needs_revalidation = True

    elif days_since_last_seen <= 1:
        state = "FRESH"
        is_expired = False
        needs_revalidation = False

    elif days_since_last_seen <= 7:
        state = "ACTIVE"
        is_expired = False
        needs_revalidation = False

    elif days_since_last_seen <= 30:
        state = "AGING"
        is_expired = False
        needs_revalidation = True

    else:
        state = "STALE"
        is_expired = False
        needs_revalidation = True

    return {
        "state": state,
        "age_days": round(age_days, 2),
        "days_since_last_seen": round(
            days_since_last_seen,
            2,
        ),
        "expiration_days": expiration_days,
        "is_expired": is_expired,
        "needs_revalidation": needs_revalidation,
    }


def observe_ioc(
    *,
    first_seen: datetime | None,
    last_seen: datetime | None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    observation_time = (
        _utc(observed_at)
        or datetime.now(timezone.utc)
    )

    existing_first = _utc(first_seen)
    existing_last = _utc(last_seen)

    if existing_first is None:
        new_first = observation_time
    else:
        new_first = min(
            existing_first,
            observation_time,
        )

    if existing_last is None:
        new_last = observation_time
    else:
        new_last = max(
            existing_last,
            observation_time,
        )

    lifecycle = calculate_lifecycle(
        first_seen=new_first,
        last_seen=new_last,
        now=observation_time,
    )

    return {
        "first_seen": new_first,
        "last_seen": new_last,
        "lifecycle": lifecycle,
    }


def build_lifecycle_profile(
    *,
    first_seen: datetime | None,
    last_seen: datetime | None,
    reputation: str | None = None,
    confidence: float | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    lifecycle = calculate_lifecycle(
        first_seen=first_seen,
        last_seen=last_seen,
    )

    return {
        "first_seen": (
            first_seen.isoformat()
            if first_seen
            else None
        ),
        "last_seen": (
            last_seen.isoformat()
            if last_seen
            else None
        ),
        "reputation": (
            reputation or "UNKNOWN"
        ).upper(),
        "confidence": round(
            float(confidence or 0.0),
            4,
        ),
        "source": source or "unknown",
        "lifecycle": lifecycle,
    }
