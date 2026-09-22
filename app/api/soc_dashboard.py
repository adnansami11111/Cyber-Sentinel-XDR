from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    Asset,
    Detection,
    Incident,
    IOC,
    SecurityEvent,
)

from app.api.graph import (
    _incident_risk_seeds,
    _refresh_db_graph,
)
from app.graph.risk import propagate_risk


router = APIRouter(
    prefix="/api/soc",
    tags=["SOC Dashboard"],
)


@router.get("/overview")
async def soc_overview(
    db: AsyncSession = Depends(get_db),
):
    # ---------------------------------------------------------
    # DATABASE COUNTS
    # ---------------------------------------------------------

    asset_count = (
        await db.scalar(
            select(func.count(Asset.id))
        )
        or 0
    )

    event_count = (
        await db.scalar(
            select(func.count(SecurityEvent.id))
        )
        or 0
    )

    detection_count = (
        await db.scalar(
            select(func.count(Detection.id))
        )
        or 0
    )

    incident_count = (
        await db.scalar(
            select(func.count(Incident.id))
        )
        or 0
    )

    ioc_count = (
        await db.scalar(
            select(func.count(IOC.id))
        )
        or 0
    )

    # ---------------------------------------------------------
    # INCIDENT SEVERITY
    # ---------------------------------------------------------

    severity_rows = (
        await db.execute(
            select(
                Incident.severity,
                func.count(Incident.id),
            )
            .group_by(Incident.severity)
        )
    ).all()

    severity_distribution = {
        str(severity or "UNKNOWN").upper(): int(count)
        for severity, count in severity_rows
    }

    # ---------------------------------------------------------
    # INCIDENT STATUS
    # ---------------------------------------------------------

    status_rows = (
        await db.execute(
            select(
                Incident.status,
                func.count(Incident.id),
            )
            .group_by(Incident.status)
        )
    ).all()

    status_distribution = {
        str(status or "UNKNOWN").upper(): int(count)
        for status, count in status_rows
    }

    # ---------------------------------------------------------
    # DETECTION DISTRIBUTION
    # ---------------------------------------------------------

    detection_rows = (
        await db.execute(
            select(
                Detection.detection_name,
                func.count(Detection.id),
            )
            .group_by(Detection.detection_name)
            .order_by(
                func.count(Detection.id).desc()
            )
            .limit(10)
        )
    ).all()

    detection_distribution = [
        {
            "name": str(name),
            "count": int(count),
        }
        for name, count in detection_rows
    ]

    # ---------------------------------------------------------
    # RECENT INCIDENTS
    # ---------------------------------------------------------

    incident_rows = (
        await db.execute(
            select(Incident)
            .order_by(
                Incident.updated_at.desc()
            )
            .limit(10)
        )
    )

    recent_incidents = (
        incident_rows.scalars().all()
    )

    recent_incident_data = [
        {
            "id": incident.id,
            "incident_key": incident.incident_key,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "source_ip": incident.source_ip,
            "target_asset": incident.target_asset,
            "created_at": (
                incident.created_at.isoformat()
                if incident.created_at
                else None
            ),
            "updated_at": (
                incident.updated_at.isoformat()
                if incident.updated_at
                else None
            ),
        }
        for incident in recent_incidents
    ]

    # ---------------------------------------------------------
    # RECENT DETECTIONS
    # ---------------------------------------------------------

    detection_rows_recent = (
        await db.execute(
            select(Detection)
            .order_by(
                Detection.created_at.desc()
            )
            .limit(10)
        )
    )

    recent_detections = (
        detection_rows_recent.scalars().all()
    )

    recent_detection_data = [
        {
            "id": detection.id,
            "name": detection.detection_name,
            "severity": detection.severity,
            "confidence": detection.confidence,
            "source_ip": detection.source_ip,
            "created_at": (
                detection.created_at.isoformat()
                if detection.created_at
                else None
            ),
        }
        for detection in recent_detections
    ]

    # ---------------------------------------------------------
    # ENTITY GRAPH
    # ---------------------------------------------------------

    graph = await _refresh_db_graph(db)

    graph_summary = {
        "entity_count":
            len(graph.entities),
        "relationship_count":
            len(graph.relationships),
    }

    # ---------------------------------------------------------
    # GRAPH RISK
    # ---------------------------------------------------------

    try:
        graph_risk = propagate_risk(
            graph,
            seed_risks=_incident_risk_seeds(
                graph
            ),
        )

        graph_max_risk = int(
            graph_risk.get(
                "max_risk",
                0,
            )
        )

        high_risk_entities = (
            graph_risk.get(
                "high_risk_entities",
                [],
            )
        )

    except Exception:
        graph_max_risk = 0
        high_risk_entities = []

    # ---------------------------------------------------------
    # SOC POSTURE
    # ---------------------------------------------------------

    high_incidents = sum(
        count
        for severity, count
        in severity_distribution.items()
        if severity in {
            "HIGH",
            "CRITICAL",
        }
    )

    if graph_max_risk >= 85:
        posture = "CRITICAL"

    elif (
        high_incidents > 0
        or graph_max_risk >= 70
    ):
        posture = "HIGH"

    elif detection_count > 0:
        posture = "ELEVATED"

    else:
        posture = "NORMAL"

    # ---------------------------------------------------------
    # FINAL RESPONSE
    # ---------------------------------------------------------

    return {
        "status": "SOC_DASHBOARD_READY",

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "posture": posture,

        "metrics": {
            "assets": asset_count,
            "security_events": event_count,
            "detections": detection_count,
            "incidents": incident_count,
            "iocs": ioc_count,
            "graph_entities":
                graph_summary[
                    "entity_count"
                ],
            "graph_relationships":
                graph_summary[
                    "relationship_count"
                ],
            "graph_max_risk":
                graph_max_risk,
        },

        "severity_distribution":
            severity_distribution,

        "status_distribution":
            status_distribution,

        "detection_distribution":
            detection_distribution,

        "recent_incidents":
            recent_incident_data,

        "recent_detections":
            recent_detection_data,

        "graph":
            graph_summary,

        "risk": {
            "max_risk":
                graph_max_risk,
            "high_risk_entities":
                high_risk_entities,
        },
    }
