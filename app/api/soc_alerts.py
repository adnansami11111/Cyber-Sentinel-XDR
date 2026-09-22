from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Detection, Incident


router = APIRouter(
    prefix="/api/soc",
    tags=["SOC Live Alerts"],
)


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get(
        str(value or "INFO").upper(),
        0,
    )


@router.get("/alerts")
async def live_alerts(
    limit: int = Query(
        default=25,
        ge=1,
        le=100,
    ),
    db: AsyncSession = Depends(get_db),
):
    detection_result = await db.execute(
        select(Detection)
        .order_by(Detection.created_at.desc())
        .limit(limit)
    )

    detections = detection_result.scalars().all()

    incident_result = await db.execute(
        select(Incident)
        .order_by(Incident.updated_at.desc())
        .limit(limit)
    )

    incidents = incident_result.scalars().all()

    alerts = []

    for detection in detections:
        detection_id = getattr(detection, "id", None)

        severity = str(
            getattr(
                detection,
                "severity",
                "MEDIUM",
            )
            or "MEDIUM"
        ).upper()

        alerts.append({
            "alert_id": f"detection:{detection_id}",
            "entity_id": f"detection:{detection_id}",
            "entity_type": "DETECTION",
            "type": "DETECTION",
            "id": detection_id,
            "title": str(
                getattr(
                    detection,
                    "detection_name",
                    "Security Detection",
                )
            ),
            "name": str(
                getattr(
                    detection,
                    "detection_name",
                    "Security Detection",
                )
            ),
            "severity": severity,
            "confidence": float(
                getattr(
                    detection,
                    "confidence",
                    0,
                )
                or 0
            ),
            "source_ip": getattr(
                detection,
                "source_ip",
                None,
            ),
            "created_at": (
                detection.created_at.isoformat()
                if getattr(
                    detection,
                    "created_at",
                    None,
                )
                else None
            ),
            "investigation_url":
                f"/api/soc/investigation/detection:{detection_id}",
        })

    for incident in incidents:
        incident_id = getattr(incident, "id", None)

        severity = str(
            getattr(
                incident,
                "severity",
                "MEDIUM",
            )
            or "MEDIUM"
        ).upper()

        alerts.append({
            "alert_id": f"incident:{incident_id}",
            "entity_id": f"incident:{incident_id}",
            "entity_type": "INCIDENT",
            "type": "INCIDENT",
            "id": incident_id,
            "title": str(
                getattr(
                    incident,
                    "title",
                    "Security Incident",
                )
            ),
            "name": str(
                getattr(
                    incident,
                    "title",
                    "Security Incident",
                )
            ),
            "severity": severity,
            "risk_score": int(
                getattr(
                    incident,
                    "risk_score",
                    0,
                )
                or 0
            ),
            "source_ip": getattr(
                incident,
                "source_ip",
                None,
            ),
            "target_asset": getattr(
                incident,
                "target_asset",
                None,
            ),
            "status": getattr(
                incident,
                "status",
                None,
            ),
            "created_at": (
                incident.created_at.isoformat()
                if getattr(
                    incident,
                    "created_at",
                    None,
                )
                else None
            ),
            "updated_at": (
                incident.updated_at.isoformat()
                if getattr(
                    incident,
                    "updated_at",
                    None,
                )
                else None
            ),
            "investigation_url":
                f"/api/soc/investigation/incident:{incident_id}",
        })

    alerts.sort(
        key=lambda item: (
            severity_rank(
                item.get("severity")
            ),
            item.get("risk_score", 0),
            item.get("created_at")
            or item.get("updated_at")
            or "",
        ),
        reverse=True,
    )

    alerts = alerts[:limit]

    severity_counts = {}

    for alert in alerts:
        severity = alert.get(
            "severity",
            "INFO",
        )

        severity_counts[severity] = (
            severity_counts.get(
                severity,
                0,
            )
            + 1
        )

    return {
        "status": "LIVE_ALERT_STREAM_READY",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "count": len(alerts),
        "alerts": alerts,
        "severity_counts": severity_counts,
    }
