import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.engine import correlate_detections
from app.db.database import get_db
from app.db.models import Detection, SecurityEvent
from app.detection.dispatcher import run_detection_rules


router = APIRouter(
    prefix="/api/telemetry",
    tags=["Telemetry"],
)


# ---------------------------------------------------------
# Detection deduplication window
# ---------------------------------------------------------

DEDUP_WINDOW_MINUTES = 5


async def find_recent_duplicate(
    db: AsyncSession,
    detection_name: str,
    source_ip: str | None,
):
    """
    Find an existing detection with the same detection name
    and source IP within the deduplication window.

    The newly-created detection is intentionally handled by
    the caller so it cannot be considered a duplicate of itself.
    """

    if not source_ip:
        return None

    cutoff = datetime.utcnow() - timedelta(
        minutes=DEDUP_WINDOW_MINUTES
    )

    result = await db.scalar(
        select(Detection)
        .where(
            Detection.detection_name == detection_name,
            Detection.source_ip == source_ip,
            Detection.created_at >= cutoff,
        )
        .order_by(
            Detection.created_at.desc()
        )
    )

    return result


# ---------------------------------------------------------
# Telemetry ingestion
# ---------------------------------------------------------

@router.post("/events")
async def ingest_event(
    event: dict,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest a security telemetry event.

    Pipeline:

        Telemetry
            ↓
        SecurityEvent
            ↓
        Detection Rules
            ↓
        Runtime Threshold
            ↓
        Deduplication
            ↓
        Correlation
            ↓
        Incident
    """

    # -----------------------------------------------------
    # 1. Store raw security event
    # -----------------------------------------------------

    security_event = SecurityEvent(
        timestamp=datetime.utcnow(),
        event_type=event.get(
            "event_type",
            "unknown",
        ),
        source_ip=event.get(
            "source_ip"
        ),
        destination_ip=event.get(
            "destination_ip"
        ),
        source_port=event.get(
            "source_port"
        ),
        destination_port=event.get(
            "destination_port"
        ),
        username=event.get(
            "username"
        ),
        process_name=event.get(
            "process_name"
        ),
        command_line=event.get(
            "command_line"
        ),
        protocol=event.get(
            "protocol"
        ),
        raw_data=json.dumps(
            event,
            default=str,
        ),
    )

    db.add(security_event)

    await db.commit()
    await db.refresh(security_event)

    # -----------------------------------------------------
    # 2. Run detection engine
    # -----------------------------------------------------

    detections = await run_detection_rules(
        db,
        security_event,
    )

    detection_results = []
    suppressed_detections = []
    correlated_incidents = []

    # -----------------------------------------------------
    # 3. Process generated detections
    # -----------------------------------------------------

    for detection in detections:

        existing = await find_recent_duplicate(
            db,
            detection.detection_name,
            detection.source_ip,
        )

        # -------------------------------------------------
        # IMPORTANT:
        # Do NOT suppress a detection against itself.
        #
        # Detection engines commit the detection before
        # returning it, therefore the query above can return
        # the newly-created detection itself.
        # -------------------------------------------------

        if (
            existing
            and existing.id != detection.id
        ):
            detection.status = "SUPPRESSED"

            suppressed_detections.append(
                {
                    "detection_id": detection.id,
                    "detection_name": detection.detection_name,
                    "duplicate_of": existing.id,
                    "status": "SUPPRESSED",
                }
            )

        # -------------------------------------------------
        # Detection response
        # -------------------------------------------------

        detection_results.append(
            {
                "id": detection.id,
                "detection_name": detection.detection_name,
                "severity": detection.severity,
                "confidence": detection.confidence,
                "risk_score": detection.risk_score,
                "status": detection.status,
                "mitre_technique": detection.mitre_technique,
            }
        )

        # -------------------------------------------------
        # 4. Correlate only active detections
        # -------------------------------------------------

        if (
            detection.status != "SUPPRESSED"
            and detection.source_ip
        ):
            incident = await correlate_detections(
                db,
                detection.source_ip,
            )

            if incident:
                correlated_incidents.append(
                    {
                        "incident_id": incident.id,
                        "incident_key": incident.incident_key,
                        "severity": incident.severity,
                        "risk_score": incident.risk_score,
                        "status": incident.status,
                    }
                )

    # -----------------------------------------------------
    # 5. Persist final detection state
    # -----------------------------------------------------

    await db.commit()

    # -----------------------------------------------------
    # 6. Return normalized API response
    # -----------------------------------------------------

    return {
        "status": "accepted",
        "event_id": security_event.id,
        "event_type": security_event.event_type,

        "detections": detection_results,

        "suppressed_detections": suppressed_detections,

        "correlated_incidents": correlated_incidents,

        "deduplication": {
            "enabled": True,
            "window_minutes": DEDUP_WINDOW_MINUTES,
            "suppressed_count": len(
                suppressed_detections
            ),
        },
    }
