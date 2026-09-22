from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Detection, Incident
from app.detection.registry import (
    get_rule_metadata,
)


router = APIRouter(
    prefix="/api/detection-quality",
    tags=["Detection Quality"],
)


@router.get(
    "/detection/{detection_id}"
)
async def detection_quality(
    detection_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Return detection-rule metadata and analyst
    quality information.
    """

    detection = await db.scalar(
        select(Detection).where(
            Detection.id == detection_id
        )
    )

    if not detection:
        raise HTTPException(
            status_code=404,
            detail="Detection not found",
        )

    metadata = get_rule_metadata(
        detection.detection_name
    )

    return {
        "detection": {
            "id": detection.id,
            "name": detection.detection_name,
            "severity": detection.severity,
            "risk_score": detection.risk_score,
            "confidence": detection.confidence,
            "status": detection.status,
            "source_ip": detection.source_ip,
            "mitre_tactic": detection.mitre_tactic,
            "mitre_technique": (
                detection.mitre_technique
            ),
        },
        "rule": metadata,
        "quality": {
            "confidence_alignment": round(
                (
                    detection.confidence
                    + metadata["confidence"]
                ) / 2,
                2,
            ),
            "false_positive_risk": (
                metadata["false_positive_risk"]
            ),
            "analyst_action": (
                "INVESTIGATE"
                if detection.risk_score >= 70
                else "MONITOR"
            ),
        },
    }


@router.get(
    "/incident/{incident_id}"
)
async def incident_detection_quality(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Return detection-quality information for
    every detection associated with an incident.
    """

    incident = await db.scalar(
        select(Incident).where(
            Incident.id == incident_id
        )
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    result = await db.scalars(
        select(Detection)
        .where(
            Detection.source_ip
            == incident.source_ip
        )
        .order_by(
            Detection.created_at.asc()
        )
    )

    detections = list(result)

    items = []

    for detection in detections:

        metadata = get_rule_metadata(
            detection.detection_name
        )

        items.append(
            {
                "id": detection.id,
                "name": detection.detection_name,
                "severity": detection.severity,
                "risk_score": detection.risk_score,
                "confidence": detection.confidence,
                "rule_id": metadata["rule_id"],
                "category": metadata["category"],
                "false_positive_risk": (
                    metadata["false_positive_risk"]
                ),
                "mitre_technique": (
                    detection.mitre_technique
                ),
                "status": detection.status,
            }
        )

    return {
        "incident_id": incident.id,
        "incident_key": incident.incident_key,
        "source_ip": incident.source_ip,
        "detection_count": len(items),
        "detections": items,
    }
