from collections import OrderedDict


MITRE_TECHNIQUES = {
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "phase": 1,
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "phase": 2,
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "phase": 3,
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "phase": 4,
    },
}


def build_attack_chain(
    detections,
):
    """
    Convert correlated detections into an ordered
    MITRE ATT&CK-style attack chain.
    """

    if not detections:
        return {
            "chain": [],
            "technique_count": 0,
            "tactics": [],
        }

    unique = OrderedDict()

    for detection in detections:
        technique_id = detection.mitre_technique

        if not technique_id:
            continue

        if technique_id not in unique:
            unique[technique_id] = detection

    chain = []

    for technique_id, detection in unique.items():

        metadata = MITRE_TECHNIQUES.get(
            technique_id,
            {
                "name": detection.detection_name,
                "tactic": "Unknown",
                "phase": 99,
            },
        )

        chain.append(
            {
                "step": len(chain) + 1,
                "technique_id": technique_id,
                "technique_name": metadata["name"],
                "tactic": metadata["tactic"],
                "detection": detection.detection_name,
                "severity": detection.severity,
                "risk_score": detection.risk_score,
                "timestamp": (
                    detection.created_at.isoformat()
                    if detection.created_at
                    else None
                ),
            }
        )

    chain.sort(
        key=lambda item: MITRE_TECHNIQUES.get(
            item["technique_id"],
            {"phase": 99},
        )["phase"]
    )

    for index, step in enumerate(chain, start=1):
        step["step"] = index

    tactics = []

    for step in chain:
        tactic = step["tactic"]

        if tactic not in tactics:
            tactics.append(tactic)

    return {
        "chain": chain,
        "technique_count": len(chain),
        "tactics": tactics,
    }
