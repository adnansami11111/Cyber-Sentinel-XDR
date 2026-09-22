from __future__ import annotations

from datetime import datetime
from typing import Any

from app.intelligence.fusion import fuse_intelligence
from app.intelligence.lifecycle import calculate_lifecycle
from app.intelligence.scoring import build_intelligence_profile


def build_unified_ioc_profile(
    *,
    ioc: Any,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    evidence = evidence or []

    primary_profile = build_intelligence_profile(
        reputation=ioc.reputation,
        confidence=ioc.confidence,
        source=ioc.source,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        threat_type=ioc.threat_type,
        tags=ioc.tags,
    )

    fusion = fuse_intelligence(evidence)

    lifecycle = calculate_lifecycle(
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
    )

    if fusion["source_count"] > 0:
        effective_reputation = fusion[
            "fused_reputation"
        ]

        effective_confidence = fusion[
            "fused_confidence"
        ]
    else:
        effective_reputation = (
            primary_profile["reputation"]
        )

        effective_confidence = (
            primary_profile["confidence"]
        )

    if effective_reputation == "MALICIOUS":
        assessment = "MALICIOUS"
    elif effective_reputation == "SUSPICIOUS":
        assessment = "SUSPICIOUS"
    elif effective_reputation == "BENIGN":
        assessment = "BENIGN"
    else:
        assessment = "UNKNOWN"

    return {
        "ioc": {
            "id": ioc.id,
            "indicator_type": ioc.indicator_type,
            "value": ioc.value,
            "threat_type": ioc.threat_type,
            "tags": ioc.tags or [],
        },
        "assessment": {
            "reputation": effective_reputation,
            "confidence": round(
                effective_confidence,
                4,
            ),
            "classification": assessment,
        },
        "primary_intelligence": primary_profile,
        "source_fusion": fusion,
        "lifecycle": lifecycle,
        "generated_at": datetime.utcnow().isoformat(),
    }
