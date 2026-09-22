from __future__ import annotations

from typing import Any


def build_response_summary(
    response_actions: list[Any],
    incident_status: str | None,
) -> dict[str, Any]:
    actions = list(response_actions)

    action_types = sorted(
        {
            str(action.action_type)
            for action in actions
            if action.action_type
        }
    )

    statuses = sorted(
        {
            str(action.status)
            for action in actions
            if action.status
        }
    )

    targets = sorted(
        {
            str(action.target)
            for action in actions
            if action.target
        }
    )

    lab_only = all(
        str(action.mode or "LAB").upper() == "LAB"
        for action in actions
    )

    if not actions:
        summary = (
            "No response or containment actions have been recorded "
            "for this incident."
        )
        containment_status = "NO_ACTION_RECORDED"
    else:
        summary = (
            f"{len(actions)} response action(s) were recorded "
            f"for this incident."
        )
        containment_status = "ACTIONS_RECORDED"

    return {
        "containment_status": containment_status,
        "incident_status": incident_status,
        "action_count": len(actions),
        "action_types": action_types,
        "action_statuses": statuses,
        "targets": targets,
        "lab_only": lab_only,
        "simulation_only": True,
        "summary": summary,
    }
