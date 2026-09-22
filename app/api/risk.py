from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Detection, Incident
from app.detection.risk import explain_risk_score


router = APIRouter(
    prefix="/api/risk",
    tags=["Risk Analysis"],
)


@router.get(
    "/incident/{incident_id}"
)
async def incident_risk_explanation(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Return an explainable risk analysis for an incident.

    The incident score is based on the highest-risk
    detection plus a correlation bonus.
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

    detections_result = await db.scalars(
        select(Detection)
        .where(
            Detection.source_ip
            == incident.source_ip
        )
        .order_by(
            Detection.created_at.asc()
        )
    )

    detections = list(detections_result)

    if not detections:
        return {
            "incident_id": incident.id,
            "incident_key": incident.incident_key,
            "source_ip": incident.source_ip,
            "stored_risk_score": incident.risk_score,
            "explanation": {
                "final_score": incident.risk_score,
                "raw_incident_score": incident.risk_score,
                "base_detection_score": incident.risk_score,
                "correlation_bonus": 0,
                "capped": False,
                "factors": [],
            },
        }

    highest_detection = max(
        detections,
        key=lambda detection:
        detection.risk_score,
    )

    base_detection_score = (
        highest_detection.risk_score
    )

    correlation_bonus = min(
        max(len(detections) - 1, 0) * 5,
        20,
    )

    raw_incident_score = (
        base_detection_score
        + correlation_bonus
    )

    final_score = min(
        100,
        raw_incident_score,
    )

    detection_explanation = explain_risk_score(
        severity=highest_detection.severity,
        confidence=highest_detection.confidence,
        event_count=1,
        source_reputation="UNKNOWN",
        asset_criticality="medium",
    )

    factors = [
        {
            "factor": "Highest Detection Risk",
            "value": base_detection_score,
            "impact": base_detection_score,
            "description": (
                f"The highest-risk detection "
                f"'{highest_detection.detection_name}' "
                f"contributes {base_detection_score} "
                f"points."
            ),
        },
        {
            "factor": "Detection Severity",
            "value": highest_detection.severity,
            "impact": (
                detection_explanation["factors"][0][
                    "impact"
                ]
            ),
            "description": (
                f"Detection severity "
                f"'{highest_detection.severity}' "
                f"forms the primary severity component."
            ),
        },
        {
            "factor": "Detection Confidence",
            "value": round(
                highest_detection.confidence,
                2,
            ),
            "impact": (
                detection_explanation["factors"][1][
                    "impact"
                ]
            ),
            "description": (
                f"Detection confidence of "
                f"{round(highest_detection.confidence * 100)}% "
                f"supports the detection."
            ),
        },
        {
            "factor": "Correlation",
            "value": len(detections),
            "impact": correlation_bonus,
            "description": (
                f"{len(detections)} correlated detection(s) "
                f"add {correlation_bonus} points."
            ),
        },
    ]

    return {
        "incident_id": incident.id,
        "incident_key": incident.incident_key,
        "source_ip": incident.source_ip,
        "severity": incident.severity,
        "stored_risk_score": incident.risk_score,
        "explanation": {
            "final_score": final_score,
            "raw_incident_score": raw_incident_score,
            "base_detection_score": base_detection_score,
            "correlation_bonus": correlation_bonus,
            "capped": raw_incident_score > 100,
            "highest_detection": {
                "id": highest_detection.id,
                "name": highest_detection.detection_name,
                "severity": highest_detection.severity,
                "risk_score": highest_detection.risk_score,
                "confidence": highest_detection.confidence,
                "mitre_technique": (
                    highest_detection.mitre_technique
                ),
            },
            "factors": factors,
        },
    }
