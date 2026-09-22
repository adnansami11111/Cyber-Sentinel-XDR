from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IOC
from app.intelligence.profile import build_unified_ioc_profile


async def correlate_detection_with_cti(
    db: AsyncSession,
    *,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    domains: list[str] | None = None,
) -> dict[str, Any]:
    indicators: list[tuple[str, str]] = []

    if source_ip:
        indicators.append(("ip", source_ip.strip()))

    if destination_ip:
        indicators.append(("ip", destination_ip.strip()))

    for domain in domains or []:
        if domain:
            indicators.append(("domain", domain.strip().lower()))

    matches: list[dict[str, Any]] = []

    for indicator_type, value in indicators:
        result = await db.execute(
            select(IOC).where(
                IOC.indicator_type == indicator_type,
                IOC.value == value,
            )
        )

        ioc = result.scalar_one_or_none()

        if not ioc:
            continue

        profile = build_unified_ioc_profile(
            ioc=ioc,
            evidence=[],
        )

        matches.append(
            {
                "indicator_type": indicator_type,
                "value": value,
                "ioc_id": ioc.id,
                "profile": profile,
            }
        )

    if not matches:
        assessment = "NO_CTI_MATCH"
    else:
        reputations = {
            match["profile"]["assessment"]["reputation"]
            for match in matches
        }

        if "MALICIOUS" in reputations:
            assessment = "MALICIOUS_SUPPORTING_INTELLIGENCE"
        elif "SUSPICIOUS" in reputations:
            assessment = "SUSPICIOUS_SUPPORTING_INTELLIGENCE"
        elif "BENIGN" in reputations:
            assessment = "BENIGN_SUPPORTING_INTELLIGENCE"
        else:
            assessment = "UNKNOWN_INTELLIGENCE"

    return {
        "matched": bool(matches),
        "match_count": len(matches),
        "assessment": assessment,
        "matches": matches,
    }
