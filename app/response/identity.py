from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


IDENTITY_ACTIONS = {
    "DISABLE_ACCOUNT": {
        "operation": "SIMULATED_ACCOUNT_DISABLE",
        "state": "ACCOUNT_DISABLED",
    },
    "REVOKE_SESSION": {
        "operation": "SIMULATED_SESSION_REVOCATION",
        "state": "SESSION_REVOKED",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def simulate_identity_response(
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
            "status": "IDENTITY_RESPONSE_REJECTED",
            "reason": "Identity target is required.",
            "mode": "LAB",
            "simulation_only": True,
            "real_containment": False,
        }

    if action_type not in IDENTITY_ACTIONS:
        return {
            "status": "IDENTITY_RESPONSE_REJECTED",
            "reason": f"Unsupported identity action: {action_type}",
            "mode": "LAB",
            "simulation_only": True,
            "real_containment": False,
        }

    definition = IDENTITY_ACTIONS[action_type]

    return {
        "status": "IDENTITY_RESPONSE_SIMULATED",
        "timestamp": utc_now(),
        "mode": "LAB",
        "simulation_only": True,
        "real_containment": False,
        "identity": {
            "action_type": action_type,
            "operation": definition["operation"],
            "target": target,
            "incident_id": incident_id,
            "analyst": analyst,
            "reason": reason,
            "state": definition["state"],
        },
    }
