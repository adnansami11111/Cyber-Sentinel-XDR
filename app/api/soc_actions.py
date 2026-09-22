from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Incident, ResponseAction


router = APIRouter(
    prefix="/api/soc/investigation",
    tags=["SOC Investigation Actions"],
)


ALLOWED_ACTIONS = {
    "ACKNOWLEDGE",
    "INVESTIGATE",
    "ESCALATE",
    "REQUEST_CONTAINMENT",
    "CLOSE",
    "ADD_NOTE",
}


class InvestigationActionRequest(BaseModel):
    action_type: str = Field(
        ...,
        min_length=3,
        max_length=100,
    )

    analyst: str = Field(
        default="SOC_ANALYST",
        min_length=1,
        max_length=255,
    )

    reason: str | None = Field(
        default=None,
        max_length=2000,
    )


def _normalize_action(action_type: str) -> str:
    return action_type.strip().upper().replace(" ", "_")


def _parse_incident_id(entity_id: str) -> int:
    if not entity_id.startswith("incident:"):
        raise HTTPException(
            status_code=400,
            detail=(
                "Investigation actions are currently "
                "supported for incidents only."
            ),
        )

    try:
        return int(
            entity_id.split(":", 1)[1]
        )
    except (ValueError, IndexError):
        raise HTTPException(
            status_code=400,
            detail="Invalid incident identifier.",
        )


@router.get(
    "/{entity_id}/actions"
)
async def get_investigation_actions(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
):
    incident_id = _parse_incident_id(
        entity_id
    )

    incident = await db.get(
        Incident,
        incident_id,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    result = await db.execute(
        select(ResponseAction)
        .where(
            ResponseAction.incident_id == incident_id
        )
        .order_by(
            ResponseAction.created_at.desc()
        )
    )

    actions = result.scalars().all()

    return {
        "status": "INVESTIGATION_ACTION_HISTORY_READY",
        "entity_id": entity_id,
        "incident_id": incident_id,
        "count": len(actions),
        "actions": [
            {
                "id": action.id,
                "incident_id": action.incident_id,
                "action_type": action.action_type,
                "target": action.target,
                "mode": action.mode,
                "status": action.status,
                "reason": action.reason,
                "created_at": (
                    action.created_at.isoformat()
                    if action.created_at
                    else None
                ),
            }
            for action in actions
        ],
    }


@router.post(
    "/{entity_id}/actions"
)
async def create_investigation_action(
    entity_id: str,
    payload: InvestigationActionRequest,
    db: AsyncSession = Depends(get_db),
):
    incident_id = _parse_incident_id(
        entity_id
    )

    action_type = _normalize_action(
        payload.action_type
    )

    if action_type not in ALLOWED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Unsupported investigation action.",
                "allowed_actions": sorted(
                    ALLOWED_ACTIONS
                ),
            },
        )

    incident = await db.get(
        Incident,
        incident_id,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    action_status = "RECORDED"

    if action_type == "REQUEST_CONTAINMENT":
        action_status = "REQUESTED"

    # LAB-safe state transitions.
    # These do not perform real-world containment.
    if action_type == "ACKNOWLEDGE":
        incident.status = "ACKNOWLEDGED"

    elif action_type == "INVESTIGATE":
        incident.status = "INVESTIGATING"

    elif action_type == "ESCALATE":
        incident.status = "ESCALATED"

    elif action_type == "CLOSE":
        incident.status = "CLOSED"

    incident.updated_at = datetime.utcnow()

    action = ResponseAction(
        incident_id=incident_id,
        action_type=action_type,
        target=f"incident:{incident_id}",
        mode="LAB",
        status=action_status,
        reason=payload.reason,
        created_at=datetime.utcnow(),
    )

    db.add(action)

    await db.commit()
    await db.refresh(action)

    return {
        "status": "INVESTIGATION_ACTION_RECORDED",
        "entity_id": entity_id,
        "incident_id": incident_id,
        "action": {
            "id": action.id,
            "action_type": action.action_type,
            "analyst": payload.analyst,
            "target": action.target,
            "mode": action.mode,
            "status": action.status,
            "reason": action.reason,
            "created_at": (
                action.created_at.isoformat()
                if action.created_at
                else None
            ),
        },
        "incident": {
            "id": incident.id,
            "status": incident.status,
            "risk_score": incident.risk_score,
            "updated_at": (
                incident.updated_at.isoformat()
                if incident.updated_at
                else None
            ),
        },
        "execution": {
            "mode": "LAB",
            "simulation_only": True,
            "real_containment": False,
        },
    }
