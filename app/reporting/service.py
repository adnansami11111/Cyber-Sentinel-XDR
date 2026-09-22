from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.reporting.generator import generate_incident_report


async def build_incident_report(
    db: AsyncSession,
    incident_id: int,
) -> dict[str, Any] | None:
    """
    Generate a complete structured security report
    for an existing incident.
    """

    report = await generate_incident_report(
        db=db,
        incident_id=incident_id,
    )

    if report is None:
        return None

    return report.to_dict()
