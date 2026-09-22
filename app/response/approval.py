from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


APPROVAL_STATES = {
    "PENDING",
    "APPROVED",
    "REJECTED",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_approval_request(
    *,
    action_type: str,
    target: str,
    incident_id: int | None = None,
    analyst: str = "SOC_ANALYST",
    reason: str = "",
) -> dict[str, Any]:

    return {
        "status": "PENDING_APPROVAL",
        "timestamp": utc_now(),
        "mode": "LAB",
        "simulation_only": True,
        "approval": {
            "state": "PENDING",
            "action_type": str(action_type).upper().strip(),
            "target": str(target).strip(),
            "incident_id": incident_id,
            "requested_by": analyst,
            "reason": reason,
        },
    }


def process_approval(
    *,
    decision: str,
    action_type: str,
    target: str,
    incident_id: int | None = None,
    analyst: str = "SOC_ANALYST",
    reason: str = "",
) -> dict[str, Any]:

    decision = str(decision).upper().strip()

    if decision not in {"APPROVE", "REJECT"}:
        return {
            "status": "APPROVAL_REJECTED",
            "reason": "Decision must be APPROVE or REJECT.",
            "mode": "LAB",
            "simulation_only": True,
        }

    state = (
        "APPROVED"
        if decision == "APPROVE"
        else "REJECTED"
    )

    return {
        "status": f"RESPONSE_{state}",
        "timestamp": utc_now(),
        "mode": "LAB",
        "simulation_only": True,
        "approval": {
            "state": state,
            "decision": decision,
            "action_type": str(action_type).upper().strip(),
            "target": str(target).strip(),
            "incident_id": incident_id,
            "analyst": analyst,
            "reason": reason,
        },
    }
