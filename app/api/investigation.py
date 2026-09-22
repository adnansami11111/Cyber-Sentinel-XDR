from collections import Counter

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Detection, Incident, IOC, SecurityEvent


router = APIRouter(
    prefix="/api/investigation",
    tags=["Investigation"],
)


def parse_incident_techniques(value) -> list[str]:
    if not value:
        return []

    if isinstance(value, list):
        return [
            str(item)
            for item in value
            if item
        ]

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return []

        try:
            import json

            parsed = json.loads(value)

            if isinstance(parsed, list):
                return [
                    str(item)
                    for item in parsed
                    if item
                ]
        except Exception:
            pass

        return [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

    return [str(value)]


def timeline_entry(
    *,
    timestamp,
    evidence_type: str,
    title: str,
    description: str,
    severity: str = "INFO",
    risk_score: int = 0,
    confidence: float = 0.0,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    mitre_tactic: str | None = None,
    mitre_technique: str | None = None,
    entity_id: int | None = None,
    metadata: dict | None = None,
):
    return {
        "timestamp": (
            timestamp.isoformat()
            if timestamp
            else None
        ),
        "evidence_type": evidence_type,
        "title": title,
        "description": description,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": round(
            max(0.0, min(confidence, 1.0)),
            2,
        ),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "entity_id": entity_id,
        "metadata": metadata or {},
    }


@router.get("/incident/{incident_id}/timeline")
async def incident_timeline(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
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

    timeline = []

    # ---------------------------------------------------------
    # INCIDENT ORIGIN
    # ---------------------------------------------------------

    timeline.append(
        timeline_entry(
            timestamp=incident.created_at,
            evidence_type="INCIDENT",
            title=incident.title,
            description=(
                incident.description
                or "Incident created by correlation engine."
            ),
            severity=incident.severity,
            risk_score=incident.risk_score,
            confidence=1.0,
            source_ip=incident.source_ip,
            entity_id=incident.id,
            metadata={
                "incident_key": incident.incident_key,
                "status": incident.status,
            },
        )
    )

    # ---------------------------------------------------------
    # SECURITY EVENTS
    # ---------------------------------------------------------

    event_conditions = []

    if incident.source_ip:
        event_conditions.extend(
            [
                SecurityEvent.source_ip
                == incident.source_ip,
                SecurityEvent.destination_ip
                == incident.source_ip,
            ]
        )

    if event_conditions:
        event_result = await db.scalars(
            select(SecurityEvent)
            .where(or_(*event_conditions))
            .order_by(SecurityEvent.timestamp.asc())
        )
        events = list(event_result)
    else:
        events = []

    for event in events:
        timeline.append(
            timeline_entry(
                timestamp=event.timestamp,
                evidence_type="SECURITY_EVENT",
                title=event.event_type,
                description=(
                    f"Security event '{event.event_type}' "
                    f"was observed."
                ),
                severity="INFO",
                confidence=0.90,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                entity_id=event.id,
                metadata={
                    "event_type": event.event_type,
                    "username": event.username,
                    "process_name": event.process_name,
                    "source_port": event.source_port,
                    "destination_port": (
                        event.destination_port
                    ),
                    "protocol": event.protocol,
                    "command_line": event.command_line,
                },
            )
        )

    # ---------------------------------------------------------
    # DETECTIONS
    # ---------------------------------------------------------

    detection_result = await db.scalars(
        select(Detection)
        .where(
            or_(
                Detection.source_ip
                == incident.source_ip,
                Detection.destination_ip
                == incident.source_ip,
            )
        )
        .order_by(Detection.created_at.asc())
    )

    detections = list(detection_result)

    for detection in detections:
        timeline.append(
            timeline_entry(
                timestamp=detection.created_at,
                evidence_type="DETECTION",
                title=detection.detection_name,
                description=(
                    detection.description
                    if hasattr(
                        detection,
                        "description",
                    )
                    else (
                        f"Detection '{detection.detection_name}' "
                        "was triggered."
                    )
                ),
                severity=detection.severity,
                risk_score=detection.risk_score,
                confidence=float(
                    detection.confidence or 0.0
                ),
                source_ip=detection.source_ip,
                destination_ip=detection.destination_ip,
                mitre_tactic=detection.mitre_tactic,
                mitre_technique=detection.mitre_technique,
                entity_id=detection.id,
                metadata={
                    "status": detection.status,
                },
            )
        )

    # ---------------------------------------------------------
    # IOC EVIDENCE
    # ---------------------------------------------------------

    related_ips = set()

    if incident.source_ip:
        related_ips.add(incident.source_ip)

    for detection in detections:
        if detection.source_ip:
            related_ips.add(
                detection.source_ip
            )

        if detection.destination_ip:
            related_ips.add(
                detection.destination_ip
            )

    if related_ips:
        ioc_result = await db.scalars(
            select(IOC)
            .where(
                IOC.value.in_(
                    list(related_ips)
                )
            )
            .order_by(IOC.created_at.asc())
        )

        iocs = list(ioc_result)
    else:
        iocs = []

    for ioc in iocs:
        reputation = (
            ioc.reputation
            or "UNKNOWN"
        ).upper()

        severity = {
            "MALICIOUS": "HIGH",
            "SUSPICIOUS": "MEDIUM",
            "BENIGN": "LOW",
            "UNKNOWN": "INFO",
        }.get(
            reputation,
            "INFO",
        )

        risk_score = {
            "MALICIOUS": 90,
            "SUSPICIOUS": 60,
            "BENIGN": 10,
            "UNKNOWN": 0,
        }.get(
            reputation,
            0,
        )

        timeline.append(
            timeline_entry(
                timestamp=ioc.created_at,
                evidence_type="IOC",
                title=(
                    f"{ioc.indicator_type}: "
                    f"{ioc.value}"
                ),
                description=(
                    f"IOC matched with reputation "
                    f"'{reputation}'."
                ),
                severity=severity,
                risk_score=risk_score,
                confidence=float(
                    ioc.confidence or 0.0
                ),
                source_ip=(
                    ioc.value
                    if ioc.indicator_type.lower()
                    in {"ip", "ipv4", "ipv6"}
                    else None
                ),
                entity_id=ioc.id,
                metadata={
                    "indicator_type": (
                        ioc.indicator_type
                    ),
                    "value": ioc.value,
                    "reputation": reputation,
                    "threat_type": ioc.threat_type,
                    "source": ioc.source,
                    "tags": ioc.tags,
                },
            )
        )

    # ---------------------------------------------------------
    # MITRE EVIDENCE
    # ---------------------------------------------------------

    for technique in parse_incident_techniques(
        incident.mitre_techniques
    ):
        timeline.append(
            timeline_entry(
                timestamp=incident.updated_at,
                evidence_type="MITRE_TECHNIQUE",
                title=technique,
                description=(
                    f"Incident is mapped to MITRE "
                    f"technique {technique}."
                ),
                severity=incident.severity,
                risk_score=incident.risk_score,
                confidence=0.90,
                source_ip=incident.source_ip,
                mitre_technique=technique,
                entity_id=incident.id,
                metadata={
                    "mapping_source": "incident",
                },
            )
        )

    # ---------------------------------------------------------
    # SORT TIMELINE
    # ---------------------------------------------------------

    timeline.sort(
        key=lambda item: (
            item["timestamp"] or ""
        )
    )

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    evidence_counts = Counter(
        item["evidence_type"]
        for item in timeline
    )

    severity_counts = Counter(
        item["severity"]
        for item in timeline
    )

    technique_counts = Counter(
        item["mitre_technique"]
        for item in timeline
        if item["mitre_technique"]
    )

    max_risk = max(
        (
            item["risk_score"]
            for item in timeline
        ),
        default=0,
    )

    average_confidence = (
        round(
            sum(
                item["confidence"]
                for item in timeline
            )
            / len(timeline),
            3,
        )
        if timeline
        else 0.0
    )

    return {
        "status": "success",
        "incident": {
            "id": incident.id,
            "incident_key": incident.incident_key,
            "title": incident.title,
            "description": incident.description,
            "source_ip": incident.source_ip,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "attack_story": incident.attack_story,
        },
        "timeline": timeline,
        "statistics": {
            "total_evidence": len(timeline),
            "evidence_counts": dict(
                evidence_counts
            ),
            "severity_counts": dict(
                severity_counts
            ),
            "mitre_technique_counts": dict(
                technique_counts
            ),
            "highest_evidence_risk": max_risk,
            "average_confidence": (
                average_confidence
            ),
        },
    }


@router.get("/incident/{incident_id}/summary")
async def investigation_summary(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    result = await incident_timeline(
        incident_id,
        db,
    )

    return {
        "status": "success",
        "incident": result["incident"],
        "statistics": result["statistics"],
        "timeline_length": len(
            result["timeline"]
        ),
        "first_evidence": (
            result["timeline"][0]
            if result["timeline"]
            else None
        ),
        "latest_evidence": (
            result["timeline"][-1]
            if result["timeline"]
            else None
        ),
    }
