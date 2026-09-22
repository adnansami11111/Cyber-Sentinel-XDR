from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


CONTAINMENT_ACTIONS = {
    "BLOCK_IP": {
        "category": "NETWORK",
        "target_type": "IP_ADDRESS",
        "operation": "SIMULATED_IP_BLOCK",
    },
    "ISOLATE_ENDPOINT": {
        "category": "ENDPOINT",
        "target_type": "ENDPOINT",
        "operation": "SIMULATED_ENDPOINT_ISOLATION",
    },
    "QUARANTINE_ENDPOINT": {
        "category": "ENDPOINT",
        "target_type": "ENDPOINT",
        "operation": "SIMULATED_ENDPOINT_QUARANTINE",
    },
    "DISABLE_ACCOUNT": {
        "category": "IDENTITY",
        "target_type": "ACCOUNT",
        "operation": "SIMULATED_ACCOUNT_DISABLE",
    },
    "REVOKE_SESSION": {
        "category": "IDENTITY",
        "target_type": "SESSION",
        "operation": "SIMULATED_SESSION_REVOCATION",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def simulate_containment(
    *,
    action_type: str,
    target: str,
    incident_id: int | None = None,
    analyst: str = "SOC_ANALYST",
    reason: str = "",
) -> dict[str, Any]:

    action_type = str(
        action_type
    ).upper().strip()

    target = str(target).strip()

    if not target:
        return {
            "status": "CONTAINMENT_REJECTED",
            "reason": "Containment target is required.",
            "mode": "LAB",
            "simulation_only": True,
            "real_containment": False,
        }

    if action_type not in CONTAINMENT_ACTIONS:
        return {
            "status": "CONTAINMENT_REJECTED",
            "reason": (
                f"Unsupported containment action: "
                f"{action_type}"
            ),
            "mode": "LAB",
            "simulation_only": True,
            "real_containment": False,
        }

    definition = CONTAINMENT_ACTIONS[
        action_type
    ]

    return {
        "status": "CONTAINMENT_SIMULATED",
        "timestamp": utc_now(),
        "mode": "LAB",
        "simulation_only": True,
        "real_containment": False,
        "containment": {
            "action_type": action_type,
            "category": definition["category"],
            "target_type": definition["target_type"],
            "operation": definition["operation"],
            "target": target,
            "incident_id": incident_id,
            "analyst": analyst,
            "reason": reason,
            "state": "SIMULATED_CONTAINED",
        },
    }
