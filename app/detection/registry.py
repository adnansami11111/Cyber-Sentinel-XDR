from collections.abc import Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SecurityEvent
from app.detection.engine import (
    detect_authentication_anomaly,
    detect_brute_force,
    detect_port_scan,
    detect_suspicious_process,
)

DetectionFunction = Callable[
    [AsyncSession, SecurityEvent | str],
    Awaitable[object | None],
]


RULE_METADATA = {
    "SSH Brute Force": {
        "rule_id": "DET-AUTH-001",
        "category": "Credential Access",
        "confidence": 0.95,
        "false_positive_risk": "LOW",
        "description": (
            "Detects repeated authentication failures "
            "from a single source within a defined "
            "time window."
        ),
    },
    "Network Port Scan": {
        "rule_id": "DET-DISC-001",
        "category": "Discovery",
        "confidence": 0.90,
        "false_positive_risk": "MEDIUM",
        "description": (
            "Detects connections to multiple unique "
            "destination ports from a single source."
        ),
    },
    "Suspicious Network Utility": {
        "rule_id": "DET-C2-001",
        "category": "Command and Control",
        "confidence": 0.85,
        "false_positive_risk": "MEDIUM",
        "description": (
            "Detects execution of network utilities "
            "that may require analyst investigation."
        ),
    },
    "Suspicious Authentication Success": {
        "rule_id": "DET-AUTH-002",
        "category": "Credential Access",
        "confidence": 0.90,
        "false_positive_risk": "LOW",
        "description": (
            "Detects successful authentication following "
            "multiple recent authentication failures."
        ),
    },
}


RULES = {
    "authentication_failure": [
        detect_brute_force,
    ],
    "authentication_success": [
        detect_authentication_anomaly,
    ],
    "network_connection": [
        detect_port_scan,
    ],
    "process_start": [
        detect_suspicious_process,
    ],
}


def get_rules(event_type: str):
    return RULES.get(
        event_type,
        [],
    )


def get_rule_metadata(
    detection_name: str,
) -> dict:
    return RULE_METADATA.get(
        detection_name,
        {
            "rule_id": "DET-UNKNOWN",
            "category": "Unknown",
            "confidence": 0.50,
            "false_positive_risk": "HIGH",
            "description": (
                "No dedicated rule metadata "
                "is available."
            ),
        },
    )
