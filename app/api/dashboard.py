from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Asset,
    Detection,
    Incident,
    IOC,
    SecurityEvent,
)


async def dashboard_summary(
    db: AsyncSession,
):
    assets = await db.scalar(
        select(func.count(Asset.id))
    )

    events = await db.scalar(
        select(func.count(SecurityEvent.id))
    )

    detections = await db.scalar(
        select(func.count(Detection.id))
    )

    incidents = await db.scalar(
        select(func.count(Incident.id))
        .where(Incident.status == "OPEN")
    )

    critical = await db.scalar(
        select(func.count(Incident.id))
        .where(
            Incident.status == "OPEN",
            Incident.severity == "CRITICAL",
        )
    )

    iocs = await db.scalar(
        select(func.count(IOC.id))
    )

    return {
        "assets_monitored": assets or 0,
        "events_collected": events or 0,
        "detections": detections or 0,
        "active_incidents": incidents or 0,
        "critical_incidents": critical or 0,
        "iocs": iocs or 0,
    }
