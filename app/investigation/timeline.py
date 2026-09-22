from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Detection, SecurityEvent


async def build_incident_timeline(
    db: AsyncSession,
    source_ip: str,
):
    """
    Build a chronological investigation timeline
    from security events and detections belonging
    to the same source IP.
    """

    events_result = await db.scalars(
        select(SecurityEvent)
        .where(
            SecurityEvent.source_ip == source_ip
        )
        .order_by(
            SecurityEvent.timestamp.asc()
        )
    )

    events = list(events_result)

    detections_result = await db.scalars(
        select(Detection)
        .where(
            Detection.source_ip == source_ip
        )
        .order_by(
            Detection.created_at.asc()
        )
    )

    detections = list(detections_result)

    timeline = []

    for event in events:
        timeline.append(
            {
                "timestamp": (
                    event.timestamp.isoformat()
                    if event.timestamp
                    else None
                ),
                "type": "EVENT",
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "username": event.username,
                "process_name": event.process_name,
                "protocol": event.protocol,
                "event_id": event.id,
            }
        )

    for detection in detections:
        timeline.append(
            {
                "timestamp": (
                    detection.created_at.isoformat()
                    if detection.created_at
                    else None
                ),
                "type": "DETECTION",
                "event_type": detection.detection_name,
                "source_ip": detection.source_ip,
                "destination_ip": None,
                "destination_port": None,
                "username": None,
                "process_name": None,
                "protocol": None,
                "event_id": detection.event_id,
                "detection_id": detection.id,
                "severity": detection.severity,
                "risk_score": detection.risk_score,
                "mitre_technique": (
                    detection.mitre_technique
                ),
                "mitre_tactic": (
                    detection.mitre_tactic
                ),
            }
        )

    timeline.sort(
        key=lambda item: item["timestamp"]
        or ""
    )

    for index, item in enumerate(
        timeline,
        start=1,
    ):
        item["sequence"] = index

    return timeline
