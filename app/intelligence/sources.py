from __future__ import annotations

from collections import defaultdict
from typing import Any


SOURCE_PRIORITY = {
    "internal": 100,
    "analyst": 95,
    "threat_feed": 90,
    "manual": 80,
    "community": 70,
    "lab": 60,
    "unknown": 10,
}


def normalize_source(source: str | None) -> str:
    value = (source or "unknown").strip().lower()

    aliases = {
        "threatfeed": "threat_feed",
        "threat-feed": "threat_feed",
        "feed": "threat_feed",
        "intel_feed": "threat_feed",
        "analyst_added": "analyst",
        "soc": "analyst",
        "community_feed": "community",
    }

    return aliases.get(value, value)


def source_priority(source: str | None) -> int:
    return SOURCE_PRIORITY.get(
        normalize_source(source),
        SOURCE_PRIORITY["unknown"],
    )


def normalize_evidence(
    *,
    source: str | None,
    reputation: str | None,
    confidence: float | int | None,
    threat_type: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    normalized_source = normalize_source(source)

    reputation_value = (
        (reputation or "UNKNOWN")
        .strip()
        .upper()
    )

    allowed_reputations = {
        "MALICIOUS",
        "SUSPICIOUS",
        "BENIGN",
        "UNKNOWN",
    }

    if reputation_value not in allowed_reputations:
        reputation_value = "UNKNOWN"

    try:
        confidence_value = float(confidence or 0.0)
    except (TypeError, ValueError):
        confidence_value = 0.0

    confidence_value = max(
        0.0,
        min(confidence_value, 1.0),
    )

    clean_tags = []

    for tag in tags or []:
        value = str(tag).strip().lower()

        if value and value not in clean_tags:
            clean_tags.append(value)

    return {
        "source": normalized_source,
        "source_priority": source_priority(normalized_source),
        "reputation": reputation_value,
        "confidence": round(confidence_value, 4),
        "threat_type": threat_type,
        "tags": clean_tags,
    }


def correlate_sources(
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized = []

    for item in evidence:
        normalized.append(
            normalize_evidence(
                source=item.get("source"),
                reputation=item.get("reputation"),
                confidence=item.get("confidence"),
                threat_type=item.get("threat_type"),
                tags=item.get("tags"),
            )
        )

    if not normalized:
        return {
            "source_count": 0,
            "sources": [],
            "reputation": "UNKNOWN",
            "confidence": 0.0,
            "agreement": 0.0,
            "consensus": "NO_DATA",
            "threat_types": [],
            "tags": [],
            "evidence": [],
        }

    reputation_weights = defaultdict(float)
    reputation_confidence = defaultdict(float)

    threat_types = set()
    tags = set()
    sources = set()

    total_confidence = 0.0

    for item in normalized:
        reputation = item["reputation"]
        confidence = item["confidence"]
        priority = item["source_priority"]

        weight = max(priority, 1) * max(confidence, 0.01)

        reputation_weights[reputation] += weight
        reputation_confidence[reputation] += confidence

        total_confidence += confidence

        sources.add(item["source"])

        if item["threat_type"]:
            threat_types.add(item["threat_type"])

        tags.update(item["tags"])

    winning_reputation = max(
        reputation_weights,
        key=reputation_weights.get,
    )

    total_weight = sum(
        reputation_weights.values()
    )

    agreement = (
        reputation_weights[winning_reputation]
        / total_weight
        if total_weight
        else 0.0
    )

    average_confidence = (
        total_confidence / len(normalized)
        if normalized
        else 0.0
    )

    if agreement >= 0.80:
        consensus = "STRONG"
    elif agreement >= 0.60:
        consensus = "MODERATE"
    elif agreement > 0:
        consensus = "CONFLICTING"
    else:
        consensus = "NO_DATA"

    return {
        "source_count": len(normalized),
        "sources": sorted(sources),
        "reputation": winning_reputation,
        "confidence": round(
            average_confidence,
            4,
        ),
        "agreement": round(
            agreement,
            4,
        ),
        "consensus": consensus,
        "threat_types": sorted(threat_types),
        "tags": sorted(tags),
        "evidence": normalized,
    }
