from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.response.safety import validate_safety


LAB_MODE = True


SUPPORTED_ACTIONS = {
    "BLOCK_IP",
    "ISOLATE_ENDPOINT",
    "QUARANTINE_ENDPOINT",
    "DISABLE_ACCOUNT",
    "REVOKE_SESSION",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_response_action(
    action_type: str,
    target: str,
) -> dict[str, Any]:

    action_type = str(action_type).upper().strip()
    target = str(target).strip()

    if not LAB_MODE:
        raise RuntimeError(
            "Response actions are disabled outside LAB mode."
        )

    if action_type not in SUPPORTED_ACTIONS:
        return {
            "valid": False,
            "reason": "Unsupported response action.",
        }

    if not target:
        return {
            "valid": False,
            "reason": "Response target is required.",
        }

    return {
        "valid": True,
        "action_type": action_type,
        "target": target,
        "mode": "LAB",
        "simulation_only": True,
    }


def simulate_response_action(
    *,
    action_type: str,
    target: str,
    incident_id: int | None = None,
    analyst: str = "SOC_ANALYST",
    reason: str = "",
) -> dict[str, Any]:

    validation = validate_response_action(
        action_type,
        target,
    )

    safety = validate_safety(
        action_type,
        target,
    )

    if not safety["allowed"]:
        return {
            "status": "RESPONSE_BLOCKED",
            "timestamp": utc_now(),
            "mode": "LAB",
            "simulation_only": True,
            "real_containment": False,
            "safety": safety,
        }

    if not validation["valid"]:
        return {
            "status": "RESPONSE_REJECTED",
            "timestamp": utc_now(),
            "mode": "LAB",
            "simulation_only": True,
            "validation": validation,
        }

    action_type = validation["action_type"]

    descriptions = {
        "BLOCK_IP":
            f"Simulated network block for {target}.",

        "ISOLATE_ENDPOINT":
            f"Simulated endpoint isolation for {target}.",

        "QUARANTINE_ENDPOINT":
            f"Simulated endpoint quarantine for {target}.",

        "DISABLE_ACCOUNT":
            f"Simulated account disable for {target}.",

        "REVOKE_SESSION":
            f"Simulated session revocation for {target}.",
    }

    return {
        "status": "RESPONSE_SIMULATED",
        "timestamp": utc_now(),
        "mode": "LAB",
        "simulation_only": True,
        "real_containment": False,
        "action": {
            "type": action_type,
            "target": target,
            "incident_id": incident_id,
            "analyst": analyst,
            "reason": reason,
            "description": descriptions[action_type],
        },
    }
