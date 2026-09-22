from __future__ import annotations

from typing import Any


MITRE_TECHNIQUE_INFO: dict[str, dict[str, str]] = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Repeated authentication failures may indicate brute-force activity.",
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Multiple destination ports may indicate network service discovery.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "description": "A suspicious successful authentication following repeated failures may indicate account compromise.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Suspicious command-line network utilities may indicate command execution activity.",
    },
}


def build_mitre_mapping(
    techniques: list[str],
) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []

    for technique in sorted(set(techniques)):
        info = MITRE_TECHNIQUE_INFO.get(
            technique,
            {
                "name": "Unknown Technique",
                "tactic": "Unknown",
                "description": "No additional technique metadata is available.",
            },
        )

        mappings.append(
            {
                "technique_id": technique,
                "technique_name": info["name"],
                "tactic": info["tactic"],
                "description": info["description"],
            }
        )

    return mappings
