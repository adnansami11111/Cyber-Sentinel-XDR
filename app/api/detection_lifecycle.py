from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Detection


router = APIRouter(
    prefix="/api/detection-lifecycle",
    tags=["Detection Lifecycle"],
)


VALID_STATUSES = {
    "NEW",
    "TRIAGED",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE",
    "SUPPRESSED",
}


TRANSITIONS = {
    "NEW": [
        "TRIAGED",
        "FALSE_POSITIVE",
        "SUPPRESSED",
    ],
    "TRIAGED": [
        "INVESTIGATING",
        "FALSE_POSITIVE",
        "RESOLVED",
    ],
    "INVESTIGATING": [
        "RESOLVED",
        "FALSE_POSITIVE",
    ],
    "RESOLVED": [],
    "FALSE_POSITIVE": [],
    "SUPPRESSED": [],
}


@router.get("/detection/{detection_id}")
async def get_detection_lifecycle(
    detection_id: int,
    db: AsyncSession = Depends(get_db),
):
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

    return {
        "id": detection.id,
        "detection_name": detection.detection_name,
        "severity": detection.severity,
        "risk_score": detection.risk_score,
        "status": detection.status,
        "allowed_next_states": TRANSITIONS.get(
            detection.status,
            [],
        ),
        "updated_at": detection.created_at,
    }


@router.post("/detection/{detection_id}/transition")
async def transition_detection(
    detection_id: int,
    payload: dict,
    db: AsyncSession = Depends(get_db),
):
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

    new_status = str(
        payload.get("status", "")
    ).upper()

    if new_status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid detection status",
                "allowed_statuses": sorted(
                    VALID_STATUSES
                ),
            },
        )

    allowed = TRANSITIONS.get(
        detection.status,
        [],
    )

    if new_status not in allowed:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "Invalid state transition",
                "current_status": detection.status,
                "requested_status": new_status,
                "allowed_next_states": allowed,
            },
        )

    old_status = detection.status

    detection.status = new_status

    await db.commit()
    await db.refresh(detection)

    return {
        "status": "updated",
        "detection_id": detection.id,
        "previous_status": old_status,
        "current_status": detection.status,
        "transitioned_at": datetime.utcnow(),
    }
