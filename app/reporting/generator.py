from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Incident,
    Detection,
    ResponseAction,
)
from app.reporting.mitre import build_mitre_mapping
from app.reporting.risk import calculate_risk_assessment
from app.reporting.response import build_response_summary
from app.reporting.models import (
    ReportMetadata,
    IncidentSummary,
    DetectionFinding,
    EvidenceItem,
    TimelineItem,
    ResponseActionItem,
    SecurityReport,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_json_loads(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, (list, dict)):
        return value

    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value


def build_executive_summary(
    incident: Incident,
    detections: list[Detection],
) -> str:
    detection_names = sorted(
        {
            detection.detection_name
            for detection in detections
            if detection.detection_name
        }
    )

    names = ", ".join(detection_names) or "No named detections"

    severity = incident.severity or "UNKNOWN"
    risk = incident.risk_score if incident.risk_score is not None else "N/A"

    return (
        f"Security incident {incident.incident_key or incident.id} "
        f"was identified with severity {severity} and risk score {risk}. "
        f"The investigation contains {len(detections)} detection finding(s). "
        f"Observed detection types: {names}."
    )


async def generate_incident_report(
    db: AsyncSession,
    incident_id: int,
) -> SecurityReport | None:

    # ---------------------------------------------------------
    # 1. Load incident
    # ---------------------------------------------------------

    incident_result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id
        )
    )

    incident = incident_result.scalar_one_or_none()

    if incident is None:
        return None

    # ---------------------------------------------------------
    # 2. Load detections associated with the incident
    # ---------------------------------------------------------
    detection_result = await db.execute(
        select(Detection)
        .where(Detection.source_ip == incident.source_ip)
        .order_by(Detection.created_at.asc())
    )
    detections = list(detection_result.scalars().all())
    # ---------------------------------------------------------
    # 3. Load response actions
    # ---------------------------------------------------------

    response_result = await db.execute(
        select(ResponseAction)
        .where(
            ResponseAction.incident_id == incident.id
        )
        .order_by(ResponseAction.created_at.asc())
    )

    response_actions = list(
        response_result.scalars().all()
    )

    # ---------------------------------------------------------
    # 4. Metadata
    # ---------------------------------------------------------

    metadata = ReportMetadata(
        report_id=(
            f"RPT-{incident.id}-"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        ),
        generated_at=utc_now(),
        report_type="INCIDENT_SECURITY_REPORT",
        format="JSON",
        mode="LAB",
    )

    # ---------------------------------------------------------
    # 5. Incident summary
    # ---------------------------------------------------------

    incident_summary = IncidentSummary(
        incident_id=incident.id,
        incident_key=incident.incident_key,
        title=incident.title,
        severity=incident.severity,
        risk_score=incident.risk_score,
        status=incident.status,
        source_ip=incident.source_ip,
        target_asset=incident.target_asset,
    )

    # ---------------------------------------------------------
    # 6. Detection findings
    # ---------------------------------------------------------

    detection_findings = []

    for detection in detections:
        detection_findings.append(
            DetectionFinding(
                detection_id=detection.id,
                detection_name=detection.detection_name,
                severity=detection.severity,
                confidence=detection.confidence,
                risk_score=detection.risk_score,
                status=detection.status,
                mitre_technique=detection.mitre_technique,
            )
        )

    # ---------------------------------------------------------
    # 7. MITRE techniques
    # ---------------------------------------------------------

    mitre_techniques = sorted(
        {
            detection.mitre_technique
            for detection in detections
            if detection.mitre_technique
        }
    )

    # Include incident-level techniques when available.
    incident_techniques = safe_json_loads(
        getattr(
            incident,
            "mitre_techniques",
            None,
        )
    )

    if isinstance(incident_techniques, list):
        mitre_techniques = sorted(
            set(mitre_techniques)
            | set(
                str(item)
                for item in incident_techniques
            )
        )

    # ---------------------------------------------------------
    # 8. Evidence
    # ---------------------------------------------------------

    evidence_items = []

    incident_evidence = safe_json_loads(
        getattr(
            incident,
            "evidence",
            None,
        )
    )

    if isinstance(incident_evidence, list):
        for item in incident_evidence:
            if not isinstance(item, dict):
                continue

            evidence_items.append(
                EvidenceItem(
                    timestamp=str(
                        item.get("timestamp")
                    )
                    if item.get("timestamp")
                    else None,
                    event_type=item.get(
                        "event_type"
                    ),
                    source_ip=item.get(
                        "source_ip"
                    ),
                    destination_ip=item.get(
                        "destination_ip"
                    ),
                    description=item.get(
                        "description"
                    ),
                    raw_data=item,
                )
            )

    # ---------------------------------------------------------
    # 9. Timeline
    # ---------------------------------------------------------

    timeline_items: list[TimelineItem] = []

    # Evidence timeline
    for item in evidence_items:
        timeline_items.append(
            TimelineItem(
                timestamp=item.timestamp,
                event=item.event_type or "Security Event",
                severity=None,
                source=item.source_ip,
                details={
                    "destination_ip": item.destination_ip,
                    "description": item.description,
                    "raw_data": item.raw_data,
                },
            )
        )

    # Detection timeline
    for detection in detections:
        timeline_items.append(
            TimelineItem(
                timestamp=(
                    detection.created_at.isoformat()
                    if detection.created_at
                    else None
                ),
                event=detection.detection_name or "Detection",
                severity=detection.severity,
                source=detection.source_ip,
                details={
                    "detection_id": detection.id,
                    "risk_score": detection.risk_score,
                    "confidence": detection.confidence,
                    "mitre_technique": detection.mitre_technique,
                },
            )
        )

    # Response timeline
    for action in response_actions:
        timeline_items.append(
            TimelineItem(
                timestamp=(
                    action.created_at.isoformat()
                    if action.created_at
                    else None
                ),
                event=f"Response: {action.action_type}",
                severity=None,
                source=action.target,
                details={
                    "action_id": action.id,
                    "mode": action.mode,
                    "status": action.status,
                    "reason": action.reason,
                },
            )
        )

    # Chronological ordering
    timeline_items.sort(
        key=lambda item: item.timestamp or ""
    )
    # ---------------------------------------------------------
    # 10. Response actions
    # ---------------------------------------------------------

    response_items = []

    for action in response_actions:
        response_items.append(
            ResponseActionItem(
                action_id=action.id,
                action_type=action.action_type,
                target=action.target,
                mode=action.mode,
                status=action.status,
                reason=action.reason,
                created_at=(
                    action.created_at.isoformat()
                    if action.created_at
                    else None
                ),
            )
        )

    # ---------------------------------------------------------
    # 11. Affected assets
    # ---------------------------------------------------------

    affected_assets = []

    if incident.target_asset:
        affected_assets.append(
            incident.target_asset
        )

    # ---------------------------------------------------------
    # 12. Indicators of compromise
    # ---------------------------------------------------------

    indicators = []

    if incident.source_ip:
        indicators.append(
            incident.source_ip
        )

    # ---------------------------------------------------------
    # 13. Recommendations
    # ---------------------------------------------------------

    recommendations = [
        "Review the affected asset and associated security events.",
        "Investigate the source of the observed activity.",
        "Validate all associated authentication and network activity.",
        "Review detection evidence and MITRE ATT&CK mappings.",
        "Continue monitoring the affected asset for related activity.",
    ]

    # ---------------------------------------------------------
    # 14. Build final report
    # ---------------------------------------------------------

    risk_assessment = calculate_risk_assessment(
        risk_score=incident.risk_score,
        severity=incident.severity,
        detection_count=len(detection_findings),
        mitre_count=len(mitre_techniques),
        ioc_count=len(indicators),
        response_action_count=len(response_items),
    )

    response_summary = build_response_summary(
        response_actions=response_actions,
        incident_status=incident.status,
    )

    return SecurityReport(
        metadata=metadata,
        executive_summary=build_executive_summary(
            incident,
            detections,
        ),
        incident=incident_summary,
        detections=detection_findings,
        mitre_techniques=mitre_techniques,
        mitre_mapping=build_mitre_mapping(mitre_techniques),
        risk_assessment=risk_assessment,
        response_summary=response_summary,
        evidence=evidence_items,
        timeline=timeline_items,
        response_actions=response_items,
        affected_assets=affected_assets,
        indicators_of_compromise=indicators,
        recommendations=recommendations,
        report_status="GENERATED",
    )
