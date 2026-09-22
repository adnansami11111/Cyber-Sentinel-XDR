from __future__ import annotations

from typing import Any

# =========================================================
# PHASE 8.9 — RESPONSE SAFETY CONTROLS
# =========================================================

LAB_MODE = True
REAL_CONTAINMENT_ENABLED = False

SAFETY_POLICY = {
    "mode": "LAB",
    "simulation_only": True,
    "real_containment_enabled": False,
    "destructive_actions_enabled": False,
}


def get_safety_status() -> dict[str, Any]:
    return {
        "status": "SAFE",
        "mode": "LAB",
        "simulation_only": True,
        "real_containment_enabled": False,
        "destructive_actions_enabled": False,
        "policy": SAFETY_POLICY.copy(),
    }


def validate_safety(
    action_type: str,
    target: str,
) -> dict[str, Any]:

    action_type = str(action_type).upper().strip()
    target = str(target).strip()

    if not LAB_MODE:
        return {
            "allowed": False,
            "reason": "Response actions are disabled outside LAB mode.",
            "mode": "NON_LAB",
            "simulation_only": False,
        }

    if REAL_CONTAINMENT_ENABLED:
        return {
            "allowed": False,
            "reason": "Real containment is explicitly disabled by Phase 8.9 safety policy.",
            "mode": "LAB",
            "simulation_only": True,
        }

    if not action_type:
        return {
            "allowed": False,
            "reason": "Action type is required.",
            "mode": "LAB",
            "simulation_only": True,
        }

    if not target:
        return {
            "allowed": False,
            "reason": "Response target is required.",
            "mode": "LAB",
            "simulation_only": True,
        }

    return {
        "allowed": True,
        "reason": "Action permitted as LAB simulation only.",
        "mode": "LAB",
        "simulation_only": True,
        "real_containment": False,
    }
