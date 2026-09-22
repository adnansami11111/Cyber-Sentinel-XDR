from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


ENDPOINT_ACTIONS = {
    "ISOLATE_ENDPOINT": {
        "operation": "SIMULATED_ENDPOINT_ISOLATION",
        "state": "ISOLATED",
    },
    "QUARANTINE_ENDPOINT": {
        "operation": "SIMULATED_ENDPOINT_QUARANTINE",
        "state": "QUARANTINED",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def simulate_endpoint_response(
    *,
    action_type: str,
    target: str,
    incident_id: int | None = None,
    analyst: str = "SOC_ANALYST",
    reason: str = "",
) -> dict[str, Any]:

    action_type = str(action_type).upper().strip()
    target = str(target).strip()

    if not target:
        return {
            "status": "ENDPOINT_RESPONSE_REJECTED",
            "reason": "Endpoint target is required.",
            "mode": "LAB",
            "simulation_only": True,
            "real_containment": False,
        }

    if action_type not in ENDPOINT_ACTIONS:
        return {
            "status": "ENDPOINT_RESPONSE_REJECTED",
            "reason": (
                f"Unsupported endpoint action: "
                f"{action_type}"
            ),
            "mode": "LAB",
            "simulation_only": True,
            "real_containment": False,
        }

    definition = ENDPOINT_ACTIONS[action_type]

    return {
        "status": "ENDPOINT_RESPONSE_SIMULATED",
        "timestamp": utc_now(),
        "mode": "LAB",
        "simulation_only": True,
        "real_containment": False,
        "endpoint": {
            "action_type": action_type,
            "operation": definition["operation"],
            "target": target,
            "incident_id": incident_id,
            "analyst": analyst,
            "reason": reason,
            "state": definition["state"],
        },
    }
