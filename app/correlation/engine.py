import json
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import Detection, Incident


SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# Ordered attack-chain stages.
# Lower number = earlier stage in the chain.
ATTACK_STAGE_MAP = {
    "Network Port Scan": {
        "stage": 1,
        "stage_name": "Discovery",
        "tactic": "TA0043",
        "technique": "T1046",
    },
    "SSH Brute Force": {
        "stage": 2,
        "stage_name": "Credential Access",
        "tactic": "TA0006",
        "technique": "T1110",
    },
    "Suspicious Authentication Success": {
        "stage": 3,
        "stage_name": "Valid Accounts",
        "tactic": "TA0001",
        "technique": "T1078",
    },
    "Suspicious Network Utility": {
        "stage": 4,
        "stage_name": "Command and Control",
        "tactic": "TA0011",
        "technique": "T1059",
    },
}


CHAIN_TYPES = {
    (
        "Discovery",
        "Credential Access",
    ): "RECON_TO_CREDENTIAL_ACCESS",

    (
        "Credential Access",
        "Valid Accounts",
    ): "CREDENTIAL_ACCESS_TO_VALID_ACCOUNTS",

    (
        "Valid Accounts",
        "Command and Control",
    ): "ACCOUNT_TO_COMMAND_AND_CONTROL",

    (
        "Discovery",
        "Credential Access",
        "Valid Accounts",
    ): "RECON_TO_COMPROMISE",

    (
        "Discovery",
        "Credential Access",
        "Valid Accounts",
        "Command and Control",
    ): "FULL_INTRUSION_CHAIN",
}


async def correlate_detections(
    db: AsyncSession,
    source_ip: str,
):
    """
    Correlate recent detections from the same source
    into a single security incident.

    Phase 3.35 adds attack-chain analysis so that
    multiple detections are interpreted as a sequence
    of related attack stages.
    """

    window_start = datetime.utcnow() - timedelta(
        minutes=settings.CORRELATION_WINDOW_MINUTES
    )

    detections_result = await db.scalars(
        select(Detection)
        .where(
            Detection.source_ip == source_ip,
            Detection.created_at >= window_start,
            Detection.status == "NEW",
        )
        .order_by(Detection.created_at.asc())
    )

    detections = list(detections_result)

    if not detections:
        return None

    existing_incident = await db.scalar(
        select(Incident)
        .where(
            Incident.source_ip == source_ip,
            Incident.status == "OPEN",
        )
        .order_by(Incident.created_at.desc())
    )

    if existing_incident:
        return await update_existing_incident(
            db,
            existing_incident,
            detections,
            source_ip,
        )

    return await create_incident(
        db,
        detections,
        source_ip,
    )


async def create_incident(
    db: AsyncSession,
    detections: list[Detection],
    source_ip: str,
):
    severity = calculate_incident_severity(
        detections
    )

    risk_score = calculate_incident_risk(
        detections
    )

    technique_set = extract_techniques(
        detections
    )

    detection_names = extract_detection_names(
        detections
    )

    attack_chain = build_attack_chain(
        detections
    )

    attack_story = build_attack_story(
        source_ip=source_ip,
        detections=detections,
    )

    evidence = build_evidence_timeline(
        detections
    )

    incident = Incident(
        incident_key=(
            f"INC-{source_ip}-"
            f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        ),
        title=build_incident_title(
            source_ip=source_ip,
            detections=detections,
            attack_chain=attack_chain,
        ),
        description=build_incident_description(
            source_ip=source_ip,
            detections=detections,
            attack_chain=attack_chain,
        ),
        severity=severity,
        risk_score=risk_score,
        status="OPEN",
        source_ip=source_ip,
        target_asset="LAB-ENDPOINT",
        attack_story=attack_story,
        mitre_techniques=json.dumps(technique_set),
        evidence=json.dumps(evidence),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(incident)

    await db.commit()
    await db.refresh(incident)

    return incident


async def update_existing_incident(
    db: AsyncSession,
    incident: Incident,
    detections: list[Detection],
    source_ip: str,
):
    """
    Update an existing open incident with the latest
    correlated detections and rebuilt attack chain.
    """

    severity = calculate_incident_severity(
        detections
    )

    risk_score = calculate_incident_risk(
        detections
    )

    attack_chain = build_attack_chain(
        detections
    )

    incident.severity = severity
    incident.risk_score = risk_score

    incident.mitre_techniques = json.dumps(
        extract_techniques(detections)
    )

    incident.evidence = json.dumps(
        build_evidence_timeline(detections)
    )

    incident.attack_story = build_attack_story(
        source_ip=source_ip,
        detections=detections,
    )

    incident.title = build_incident_title(
        source_ip=source_ip,
        detections=detections,
        attack_chain=attack_chain,
    )

    incident.description = build_incident_description(
        source_ip=source_ip,
        detections=detections,
        attack_chain=attack_chain,
    )

    incident.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(incident)

    return incident


def calculate_incident_severity(
    detections: list[Detection],
) -> str:
    """
    Select the highest severity among correlated
    detections.
    """

    if not detections:
        return "LOW"

    highest = max(
        detections,
        key=lambda detection:
        SEVERITY_WEIGHT.get(
            detection.severity.upper(),
            1,
        ),
    )

    return highest.severity


def calculate_incident_risk(
    detections: list[Detection],
) -> int:
    """
    Calculate incident risk using:

    - highest detection risk
    - number of correlated detections
    - number of unique attack stages
    - ordered attack-chain progression
    """

    if not detections:
        return 0

    highest_risk = max(
        detection.risk_score
        for detection in detections
    )

    correlation_bonus = min(
        max(len(detections) - 1, 0) * 5,
        20,
    )

    chain = build_attack_chain(
        detections
    )

    stage_count = chain["stage_count"]

    stage_bonus = min(
        max(stage_count - 1, 0) * 5,
        15,
    )

    progression_bonus = (
        chain["progression_score"]
    )

    return min(
        100,
        highest_risk
        + correlation_bonus
        + stage_bonus
        + progression_bonus,
    )


def extract_techniques(
    detections: list[Detection],
) -> list[str]:
    """
    Extract unique MITRE ATT&CK techniques from
    the actual detection records.
    """

    techniques = []

    for detection in detections:
        technique = detection.mitre_technique

        if technique and technique not in techniques:
            techniques.append(technique)

    return techniques


def extract_detection_names(
    detections: list[Detection],
) -> list[str]:
    """
    Extract unique detection names.
    """

    names = []

    for detection in detections:
        name = detection.detection_name

        if name and name not in names:
            names.append(name)

    return names


def build_attack_chain(
    detections: list[Detection],
) -> dict:
    """
    Build an ordered attack chain from correlated
    detections.

    The chain is based on known detection-to-stage
    mappings and chronological activity.
    """

    ordered = sorted(
        detections,
        key=lambda detection: detection.created_at
    )

    stages = []
    seen_stage_names = set()

    for detection in ordered:
        metadata = ATTACK_STAGE_MAP.get(
            detection.detection_name
        )

        if not metadata:
            continue

        stage_name = metadata["stage_name"]

        if stage_name in seen_stage_names:
            continue

        seen_stage_names.add(stage_name)

        stages.append(
            {
                "stage": metadata["stage"],
                "stage_name": stage_name,
                "detection": detection.detection_name,
                "tactic": metadata["tactic"],
                "technique": metadata["technique"],
                "timestamp": (
                    detection.created_at.isoformat()
                    if detection.created_at
                    else None
                ),
            }
        )

    stages.sort(
        key=lambda item: item["stage"]
    )

    stage_names = [
        item["stage_name"]
        for item in stages
    ]

    stage_count = len(stages)

    expected_progression = all(
        stages[index]["stage"]
        <= stages[index + 1]["stage"]
        for index in range(
            len(stages) - 1
        )
    )

    progression_score = min(
        max(stage_count - 1, 0) * 3,
        9,
    )

    if stage_count >= 2:
        chain_key = tuple(
            stage_names
        )

        chain_type = CHAIN_TYPES.get(
            chain_key,
            "MULTI_STAGE_ACTIVITY",
        )
    else:
        chain_type = (
            "SINGLE_STAGE_ACTIVITY"
            if stage_count == 1
            else "UNMAPPED_ACTIVITY"
        )

    if stage_count >= 4:
        confidence = 0.95
    elif stage_count == 3:
        confidence = 0.90
    elif stage_count == 2:
        confidence = 0.80
    elif stage_count == 1:
        confidence = 0.60
    else:
        confidence = 0.40

    return {
        "chain_type": chain_type,
        "stage_count": stage_count,
        "stages": stages,
        "stage_names": stage_names,
        "progression_valid": expected_progression,
        "progression_score": progression_score,
        "confidence": confidence,
        "complete": stage_count >= 4,
    }


def build_evidence_timeline(
    detections: list[Detection],
) -> list[dict]:
    """
    Build chronological evidence records for
    analyst investigation.
    """

    timeline = []

    ordered = sorted(
        detections,
        key=lambda detection: detection.created_at
    )

    for detection in ordered:
        metadata = ATTACK_STAGE_MAP.get(
            detection.detection_name,
            {},
        )

        timeline.append(
            {
                "detection_id": detection.id,
                "detection_name": (
                    detection.detection_name
                ),
                "timestamp": (
                    detection.created_at.isoformat()
                    if detection.created_at
                    else None
                ),
                "severity": detection.severity,
                "risk_score": detection.risk_score,
                "confidence": detection.confidence,
                "source_ip": detection.source_ip,
                "destination_ip": detection.destination_ip,
                "mitre_tactic": (
                    detection.mitre_tactic
                ),
                "mitre_technique": (
                    detection.mitre_technique
                ),
                "attack_stage": (
                    metadata.get("stage_name")
                ),
            }
        )

    return timeline


def build_incident_title(
    source_ip: str,
    detections: list[Detection],
    attack_chain: dict,
) -> str:
    """
    Produce an analyst-friendly incident title.
    """

    chain_type = attack_chain["chain_type"]

    if attack_chain["stage_count"] >= 2:
        return (
            f"{chain_type.replace('_', ' ').title()} "
            f"from {source_ip}"
        )

    return (
        f"Correlated Security Activity "
        f"from {source_ip}"
    )


def build_incident_description(
    source_ip: str,
    detections: list[Detection],
    attack_chain: dict,
) -> str:
    """
    Produce a structured incident description.
    """

    stages = attack_chain["stage_names"]

    if stages:
        progression = " -> ".join(
            stages
        )
    else:
        progression = "UNMAPPED"

    return (
        f"Cyber Sentinel XDR correlated "
        f"{len(detections)} detection(s) from "
        f"source {source_ip} within the "
        f"{settings.CORRELATION_WINDOW_MINUTES}-minute "
        f"correlation window. "
        f"Observed attack progression: "
        f"{progression}. "
        f"Chain confidence: "
        f"{attack_chain['confidence']:.0%}."
    )


def build_attack_story(
    source_ip: str,
    detections: list[Detection],
) -> str:
    """
    Convert correlated detections into a readable
    analyst-style attack narrative.
    """

    chain = build_attack_chain(
        detections
    )

    stages = []

    for item in chain["stages"]:
        stage = item["stage_name"]
        detection = item["detection"]

        if stage == "Discovery":
            stages.append(
                "Discovery activity was observed "
                f"through {detection}."
            )

        elif stage == "Credential Access":
            stages.append(
                "Credential-access activity followed "
                f"through {detection}."
            )

        elif stage == "Valid Accounts":
            stages.append(
                "A successful authentication followed "
                "the preceding credential-access activity."
            )

        elif stage == "Command and Control":
            stages.append(
                "Potential command-and-control related "
                f"activity was observed through {detection}."
            )

        else:
            stages.append(
                f"{stage} activity was observed "
                f"through {detection}."
            )

    story = (
        f"Cyber Sentinel XDR correlated activity "
        f"associated with source {source_ip}. "
    )

    if stages:
        story += " ".join(stages)

    story += (
        f" Observed attack stages: "
        f"{' -> '.join(chain['stage_names']) or 'UNMAPPED'}. "
        f"Correlation confidence: "
        f"{chain['confidence']:.0%}."
    )

    return story
