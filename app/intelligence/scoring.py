from __future__ import annotations

from datetime import datetime, timezone


REPUTATION_SCORES = {
    "MALICIOUS": 100,
    "SUSPICIOUS": 70,
    "BENIGN": 20,
    "UNKNOWN": 0,
}

SOURCE_RELIABILITY = {
    "internal": 0.90,
    "manual": 0.80,
    "lab": 0.75,
    "analyst": 0.90,
    "threat_feed": 0.85,
    "community": 0.70,
    "unknown": 0.40,
}


def normalize_reputation(
    reputation: str | None,
) -> str:
    value = (
        reputation or "UNKNOWN"
    ).strip().upper()

    if value not in REPUTATION_SCORES:
        return "UNKNOWN"

    return value


def normalize_source(
    source: str | None,
) -> str:
    value = (
        source or "unknown"
    ).strip().lower()

    return value


def calculate_freshness(
    first_seen: datetime | None,
    last_seen: datetime | None,
    now: datetime | None = None,
) -> dict:
    if not first_seen and not last_seen:
        return {
            "state": "UNKNOWN",
            "score": 0,
            "age_days": None,
            "days_since_last_seen": None,
        }

    now = now or datetime.now(timezone.utc)

    def normalize_dt(value: datetime):
        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value.astimezone(timezone.utc)

    reference = (
        last_seen or first_seen
    )

    reference = normalize_dt(reference)
    first = (
        normalize_dt(first_seen)
        if first_seen
        else reference
    )

    age_days = max(
        0,
        (now - first).total_seconds()
        / 86400,
    )

    days_since_last_seen = max(
        0,
        (now - reference).total_seconds()
        / 86400,
    )

    if days_since_last_seen <= 1:
        state = "FRESH"
        score = 100
    elif days_since_last_seen <= 7:
        state = "ACTIVE"
        score = 85
    elif days_since_last_seen <= 30:
        state = "AGING"
        score = 60
    else:
        state = "STALE"
        score = 25

    return {
        "state": state,
        "score": score,
        "age_days": round(
            age_days,
            2,
        ),
        "days_since_last_seen": round(
            days_since_last_seen,
            2,
        ),
    }


def calculate_intelligence_score(
    *,
    reputation: str | None,
    confidence: float | None,
    source: str | None,
    freshness_score: int,
) -> dict:
    reputation_value = normalize_reputation(
        reputation
    )

    source_value = normalize_source(
        source
    )

    confidence_value = max(
        0.0,
        min(
            float(confidence or 0.0),
            1.0,
        ),
    )

    reputation_score = (
        REPUTATION_SCORES[
            reputation_value
        ]
    )

    source_reliability = (
        SOURCE_RELIABILITY.get(
            source_value,
            SOURCE_RELIABILITY["unknown"],
        )
    )

    confidence_score = (
        confidence_value * 100
    )

    score = (
        reputation_score * 0.35
        + confidence_score * 0.30
        + freshness_score * 0.20
        + source_reliability * 100 * 0.15
    )

    score = round(
        max(
            0,
            min(
                score,
                100,
            ),
        ),
        2,
    )

    if score >= 85:
        quality = "VERY_HIGH"
    elif score >= 70:
        quality = "HIGH"
    elif score >= 50:
        quality = "MEDIUM"
    elif score > 0:
        quality = "LOW"
    else:
        quality = "UNKNOWN"

    return {
        "score": score,
        "quality": quality,
        "components": {
            "reputation_score": reputation_score,
            "confidence_score": round(
                confidence_score,
                2,
            ),
            "freshness_score": freshness_score,
            "source_reliability": round(
                source_reliability,
                2,
            ),
        },
    }


def build_intelligence_profile(
    *,
    reputation: str | None,
    confidence: float | None,
    source: str | None,
    first_seen: datetime | None,
    last_seen: datetime | None,
    threat_type: str | None = None,
    tags: list | None = None,
) -> dict:
    freshness = calculate_freshness(
        first_seen,
        last_seen,
    )

    intelligence = (
        calculate_intelligence_score(
            reputation=reputation,
            confidence=confidence,
            source=source,
            freshness_score=freshness[
                "score"
            ],
        )
    )

    return {
        "reputation": normalize_reputation(
            reputation
        ),
        "confidence": round(
            max(
                0.0,
                min(
                    float(confidence or 0.0),
                    1.0,
                ),
            ),
            2,
        ),
        "source": normalize_source(
            source
        ),
        "threat_type": threat_type,
        "tags": tags or [],
        "freshness": freshness,
        "intelligence": intelligence,
    }
