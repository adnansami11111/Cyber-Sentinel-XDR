from __future__ import annotations

from typing import Any

from app.intelligence.detection_correlation import correlate_detection_with_cti


async def enrich_detection(
    db,
    *,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    domain: str | None = None,
    detection_name: str | None = None,
    detection_category: str | None = None,
    base_risk: int = 0,
) -> dict[str, Any]:

    correlation = await correlate_detection_with_cti(
        db,
        source_ip=source_ip,
        destination_ip=destination_ip,
        domains=[domain] if domain else [],
    )

    risk_adjustment = 0

    if correlation["assessment"] == "MALICIOUS_SUPPORTING_INTELLIGENCE":
        risk_adjustment = 30
    elif correlation["assessment"] == "SUSPICIOUS_SUPPORTING_INTELLIGENCE":
        risk_adjustment = 15
    elif correlation["assessment"] == "BENIGN_SUPPORTING_INTELLIGENCE":
        risk_adjustment = -10

    enriched_risk = max(
        0,
        min(100, int(base_risk) + risk_adjustment),
    )

    return {
        "detection": {
            "name": detection_name,
            "category": detection_category,
            "base_risk": int(base_risk),
        },
        "cti": correlation,
        "risk": {
            "adjustment": risk_adjustment,
            "enriched_risk": enriched_risk,
        },
        "enrichment_status": (
            "ENRICHED"
            if correlation["matched"]
            else "NO_CTI_MATCH"
        ),
    }
