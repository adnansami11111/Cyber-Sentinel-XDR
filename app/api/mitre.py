from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Detection, Incident
from app.mitre.attack_chain import build_attack_chain


router = APIRouter(
    prefix="/api/mitre",
    tags=["MITRE ATT&CK"],
)


# MITRE ATT&CK Enterprise tactic catalogue.
# This is intentionally kept as a local coverage catalogue
# for the XDR lab rather than claiming that every technique
# is implemented by the platform.
MITRE_TACTICS = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


# Techniques currently represented by Cyber Sentinel XDR.
# Keep this list aligned with the detection capabilities
# already implemented in the project.
MITRE_TECHNIQUES = {
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "TA0007",
        "detection": "Network Port Scan",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "TA0006",
        "detection": "SSH Brute Force",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "TA0001",
        "detection": "Suspicious Authentication Success",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "TA0002",
        "detection": "Suspicious Network Utility",
    },
}


@router.get("/incident/{incident_id}/attack-chain")
async def incident_attack_chain(
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

    attack_chain = build_attack_chain(
        detections
    )

    return {
        "incident_id": incident.id,
        "incident_key": incident.incident_key,
        "source_ip": incident.source_ip,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "attack_chain": attack_chain["chain"],
        "technique_count": attack_chain[
            "technique_count"
        ],
        "tactics": attack_chain["tactics"],
    }


@router.get("/coverage")
async def mitre_coverage(
    db: AsyncSession = Depends(get_db),
):
    """
    Calculate MITRE ATT&CK coverage from detections
    currently stored in the XDR database.
    """

    detections_result = await db.scalars(
        select(Detection)
        .order_by(
            Detection.created_at.asc()
        )
    )

    detections = list(detections_result)

    observed_techniques = defaultdict(
        lambda: {
            "technique_id": None,
            "technique_name": None,
            "tactic_id": None,
            "tactic_name": None,
            "detection_names": set(),
            "event_count": 0,
        }
    )

    for detection in detections:
        technique_id = (
            detection.mitre_technique
        )

        if not technique_id:
            continue

        metadata = MITRE_TECHNIQUES.get(
            technique_id,
            {},
        )

        tactic_id = (
            detection.mitre_tactic
            or metadata.get("tactic")
        )

        technique_name = (
            metadata.get("name")
            or technique_id
        )

        tactic_name = (
            MITRE_TACTICS.get(
                tactic_id,
                "Unknown",
            )
            if tactic_id
            else "Unknown"
        )

        item = observed_techniques[
            technique_id
        ]

        item["technique_id"] = technique_id
        item["technique_name"] = technique_name
        item["tactic_id"] = tactic_id
        item["tactic_name"] = tactic_name
        item["event_count"] += 1

        if detection.detection_name:
            item["detection_names"].add(
                detection.detection_name
            )

    observed = []

    for technique_id, item in (
        observed_techniques.items()
    ):
        observed.append(
            {
                "technique_id": item[
                    "technique_id"
                ],
                "technique_name": item[
                    "technique_name"
                ],
                "tactic_id": item[
                    "tactic_id"
                ],
                "tactic_name": item[
                    "tactic_name"
                ],
                "event_count": item[
                    "event_count"
                ],
                "detection_names": sorted(
                    item["detection_names"]
                ),
            }
        )

    observed.sort(
        key=lambda item: (
            item["tactic_name"] or "",
            item["technique_id"] or "",
        )
    )

    supported_ids = set(
        MITRE_TECHNIQUES.keys()
    )

    observed_ids = {
        item["technique_id"]
        for item in observed
        if item["technique_id"]
        in supported_ids
    }

    uncovered = []

    for technique_id, metadata in (
        MITRE_TECHNIQUES.items()
    ):
        if technique_id in observed_ids:
            continue

        tactic_id = metadata["tactic"]

        uncovered.append(
            {
                "technique_id": technique_id,
                "technique_name": metadata[
                    "name"
                ],
                "tactic_id": tactic_id,
                "tactic_name": MITRE_TACTICS.get(
                    tactic_id,
                    "Unknown",
                ),
                "detection": metadata[
                    "detection"
                ],
                "status": "NO_OBSERVED_ACTIVITY",
            }
        )

    covered_tactics = set()

    for item in observed:
        tactic_id = item["tactic_id"]

        if tactic_id:
            covered_tactics.add(
                tactic_id
            )

    tactic_coverage = []

    for tactic_id, tactic_name in (
        MITRE_TACTICS.items()
    ):
        technique_count = sum(
            1
            for metadata in
            MITRE_TECHNIQUES.values()
            if metadata["tactic"] == tactic_id
        )

        observed_count = sum(
            1
            for item in observed
            if item["tactic_id"] == tactic_id
            and item["technique_id"]
            in supported_ids
        )

        if technique_count == 0:
            percentage = 0.0
        else:
            percentage = round(
                (
                    observed_count
                    / technique_count
                )
                * 100,
                2,
            )

        tactic_coverage.append(
            {
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "supported_techniques": (
                    technique_count
                ),
                "observed_techniques": (
                    observed_count
                ),
                "coverage_percentage": (
                    percentage
                ),
                "status": (
                    "COVERED"
                    if observed_count > 0
                    else "NO_ACTIVITY"
                ),
            }
        )

    total_supported = len(
        supported_ids
    )

    total_observed = len(
        observed_ids
    )

    coverage_percentage = (
        round(
            (
                total_observed
                / total_supported
            )
            * 100,
            2,
        )
        if total_supported
        else 0.0
    )

    return {
        "status": "success",
        "framework": (
            "MITRE ATT&CK Enterprise"
        ),
        "summary": {
            "supported_techniques": (
                total_supported
            ),
            "observed_techniques": (
                total_observed
            ),
            "uncovered_techniques": len(
                uncovered
            ),
            "coverage_percentage": (
                coverage_percentage
            ),
            "covered_tactics": len(
                covered_tactics
            ),
            "total_tactics": len(
                MITRE_TACTICS
            ),
        },
        "observed_techniques": observed,
        "uncovered_techniques": uncovered,
        "tactic_coverage": tactic_coverage,
    }


@router.get("/techniques")
async def mitre_techniques(
    db: AsyncSession = Depends(get_db),
):
    """
    Return the local MITRE technique catalogue
    together with observed activity counts.
    """

    detections_result = await db.scalars(
        select(Detection)
    )

    detections = list(detections_result)

    counts = defaultdict(int)

    for detection in detections:
        if detection.mitre_technique:
            counts[
                detection.mitre_technique
            ] += 1

    techniques = []

    for technique_id, metadata in (
        MITRE_TECHNIQUES.items()
    ):
        count = counts.get(
            technique_id,
            0,
        )

        tactic_id = metadata["tactic"]

        techniques.append(
            {
                "technique_id": technique_id,
                "technique_name": metadata[
                    "name"
                ],
                "tactic_id": tactic_id,
                "tactic_name": MITRE_TACTICS.get(
                    tactic_id,
                    "Unknown",
                ),
                "mapped_detection": metadata[
                    "detection"
                ],
                "observed_event_count": count,
                "status": (
                    "OBSERVED"
                    if count > 0
                    else "NOT_OBSERVED"
                ),
            }
        )

    return {
        "status": "success",
        "count": len(techniques),
        "techniques": techniques,
    }
