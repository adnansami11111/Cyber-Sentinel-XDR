from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.intelligence.sources import (
    normalize_evidence,
    source_priority,
)


REPUTATION_SCORE = {
    "MALICIOUS": 100,
    "SUSPICIOUS": 70,
    "BENIGN": 20,
    "UNKNOWN": 0,
}


def fuse_intelligence(
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
            "fused_reputation": "UNKNOWN",
            "fused_confidence": 0.0,
            "fusion_score": 0.0,
            "decision": "INSUFFICIENT_EVIDENCE",
            "source_count": 0,
            "agreement": 0.0,
            "conflicts": [],
            "evidence": [],
        }

    reputation_weights = defaultdict(float)
    source_contributions = []

    for item in normalized:
        reputation = item["reputation"]
        confidence = item["confidence"]
        priority = item["source_priority"]

        weight = max(
            confidence * priority,
            0.01,
        )

        reputation_weights[reputation] += weight

        source_contributions.append(
            {
                "source": item["source"],
                "reputation": reputation,
                "confidence": confidence,
                "priority": priority,
                "weight": round(weight, 2),
            }
        )

    fused_reputation = max(
        reputation_weights,
        key=reputation_weights.get,
    )

    total_weight = sum(
        reputation_weights.values()
    )

    winning_weight = reputation_weights[
        fused_reputation
    ]

    agreement = (
        winning_weight / total_weight
        if total_weight
        else 0.0
    )

    confidence_sum = sum(
        item["confidence"]
        for item in normalized
    )

    average_confidence = (
        confidence_sum / len(normalized)
    )

    fusion_score = (
        REPUTATION_SCORE[fused_reputation]
        * agreement
        * average_confidence
    )

    fusion_score = round(
        max(0.0, min(fusion_score, 100.0)),
        2,
    )

    reputations_present = {
        item["reputation"]
        for item in normalized
    }

    conflicts = []

    if len(reputations_present) > 1:
        conflicts = sorted(
            reputations_present
        )

    if fused_reputation == "MALICIOUS":
        if agreement >= 0.70:
            decision = "HIGH_CONFIDENCE_MALICIOUS"
        else:
            decision = "MALICIOUS_WITH_CONFLICT"

    elif fused_reputation == "SUSPICIOUS":
        if agreement >= 0.70:
            decision = "HIGH_CONFIDENCE_SUSPICIOUS"
        else:
            decision = "SUSPICIOUS_WITH_CONFLICT"

    elif fused_reputation == "BENIGN":
        if agreement >= 0.70:
            decision = "HIGH_CONFIDENCE_BENIGN"
        else:
            decision = "BENIGN_WITH_CONFLICT"

    else:
        decision = "INSUFFICIENT_EVIDENCE"

    return {
        "fused_reputation": fused_reputation,
        "fused_confidence": round(
            average_confidence,
            4,
        ),
        "fusion_score": fusion_score,
        "decision": decision,
        "source_count": len(normalized),
        "agreement": round(
            agreement,
            4,
        ),
        "conflicts": conflicts,
        "source_contributions": source_contributions,
        "evidence": normalized,
    }
