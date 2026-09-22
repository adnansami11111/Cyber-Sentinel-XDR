from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import ResponseAction

from app.response.engine import (
    SUPPORTED_ACTIONS,
    simulate_response_action,
)

from app.response.containment import (
    simulate_containment,
)

from app.response.endpoint import (
    simulate_endpoint_response,
)

from app.response.identity import (
    simulate_identity_response,
)

from app.response.approval import (
    create_approval_request,
    process_approval,
)
from app.response.safety import get_safety_status


router = APIRouter(
    prefix="/api/response",
    tags=["Response & Containment"],
)


class ResponseActionRequest(BaseModel):
    action_type: str = Field(
        ...,
        min_length=1,
    )

    target: str = Field(
        ...,
        min_length=1,
    )

    incident_id: int | None = None

    analyst: str = Field(
        default="SOC_ANALYST",
        min_length=1,
    )

    reason: str = ""


@router.get("/status")
async def response_status() -> dict[str, Any]:

    return {
        "status": "RESPONSE_ENGINE_READY",
        "mode": "LAB",
        "simulation_only": True,
        "real_containment": False,
        "supported_actions": sorted(
            SUPPORTED_ACTIONS
        ),
    }


@router.post("/simulate")
async def simulate_response(
    request: ResponseActionRequest,
) -> dict[str, Any]:

    result = simulate_response_action(
        action_type=request.action_type,
        target=request.target,
        incident_id=request.incident_id,
        analyst=request.analyst,
        reason=request.reason,
    )

    if result["status"] == "RESPONSE_REJECTED":
        raise HTTPException(
            status_code=400,
            detail=result,
        )

    return result


@router.post("/contain")
async def contain_response(
    request: ResponseActionRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    result = simulate_containment(
        action_type=request.action_type,
        target=request.target,
        incident_id=request.incident_id,
        analyst=request.analyst,
        reason=request.reason,
    )

    if result["status"] == "CONTAINMENT_REJECTED":
        raise HTTPException(
            status_code=400,
            detail=result,
        )

    containment = result["containment"]

    # ---------------------------------------------------------
    # PHASE 8.3 — RESPONSE AUDIT TRAIL
    # ---------------------------------------------------------

    if request.incident_id is not None:

        audit_record = ResponseAction(
            incident_id=request.incident_id,
            action_type=request.action_type.upper().strip(),
            target=request.target.strip(),
            mode="LAB",
            status="SIMULATED_CONTAINED",
            reason=(
                request.reason.strip()
                if request.reason
                else None
            ),
        )

        db.add(audit_record)

        await db.commit()

        await db.refresh(audit_record)

        result["audit"] = {
            "id": audit_record.id,
            "incident_id": audit_record.incident_id,
            "action_type": audit_record.action_type,
            "target": audit_record.target,
            "mode": audit_record.mode,
            "status": audit_record.status,
            "reason": audit_record.reason,
            "created_at": (
                audit_record.created_at.isoformat()
                if audit_record.created_at
                else None
            ),
        }

    else:

        result["audit"] = {
            "recorded": False,
            "reason": (
                "No incident_id supplied; "
                "containment was simulated but not "
                "persisted to incident response history."
            ),
        }

    return result



@router.post("/endpoint")
async def endpoint_response(
    request: ResponseActionRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    result = simulate_endpoint_response(
        action_type=request.action_type,
        target=request.target,
        incident_id=request.incident_id,
        analyst=request.analyst,
        reason=request.reason,
    )

    if result["status"] == "ENDPOINT_RESPONSE_REJECTED":
        raise HTTPException(
            status_code=400,
            detail=result,
        )

    if request.incident_id is not None:

        audit_record = ResponseAction(
            incident_id=request.incident_id,
            action_type=request.action_type.upper().strip(),
            target=request.target.strip(),
            mode="LAB",
            status=result["endpoint"]["state"],
            reason=(
                request.reason.strip()
                if request.reason
                else None
            ),
        )

        db.add(audit_record)
        await db.commit()
        await db.refresh(audit_record)

        result["audit"] = {
            "id": audit_record.id,
            "incident_id": audit_record.incident_id,
            "action_type": audit_record.action_type,
            "target": audit_record.target,
            "mode": audit_record.mode,
            "status": audit_record.status,
            "reason": audit_record.reason,
            "created_at": (
                audit_record.created_at.isoformat()
                if audit_record.created_at
                else None
            ),
        }

    return result



@router.post("/identity")
async def identity_response(
    request: ResponseActionRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    result = simulate_identity_response(
        action_type=request.action_type,
        target=request.target,
        incident_id=request.incident_id,
        analyst=request.analyst,
        reason=request.reason,
    )

    if result["status"] == "IDENTITY_RESPONSE_REJECTED":
        raise HTTPException(
            status_code=400,
            detail=result,
        )

    if request.incident_id is not None:

        audit_record = ResponseAction(
            incident_id=request.incident_id,
            action_type=request.action_type.upper().strip(),
            target=request.target.strip(),
            mode="LAB",
            status=result["identity"]["state"],
            reason=(
                request.reason.strip()
                if request.reason
                else None
            ),
        )

        db.add(audit_record)
        await db.commit()
        await db.refresh(audit_record)

        result["audit"] = {
            "id": audit_record.id,
            "incident_id": audit_record.incident_id,
            "action_type": audit_record.action_type,
            "target": audit_record.target,
            "mode": audit_record.mode,
            "status": audit_record.status,
            "reason": audit_record.reason,
            "created_at": (
                audit_record.created_at.isoformat()
                if audit_record.created_at
                else None
            ),
        }

    return result




@router.post("/approval/request")
async def request_approval(
    request: ResponseActionRequest,
) -> dict[str, Any]:

    return create_approval_request(
        action_type=request.action_type,
        target=request.target,
        incident_id=request.incident_id,
        analyst=request.analyst,
        reason=request.reason,
    )


@router.post("/approval/decision")
async def approval_decision(
    request: ResponseActionRequest,
) -> dict[str, Any]:

    decision = request.reason.upper().strip()

    if decision not in {"APPROVE", "REJECT"}:
        raise HTTPException(
            status_code=400,
            detail={
                "status": "APPROVAL_REJECTED",
                "reason": (
                    "Put APPROVE or REJECT "
                    "in the reason field for this "
                    "LAB workflow."
                ),
            },
        )

    return process_approval(
        decision=decision,
        action_type=request.action_type,
        target=request.target,
        incident_id=request.incident_id,
        analyst=request.analyst,
        reason=f"Analyst decision: {decision}",
    )


@router.get("/safety")
async def response_safety_status():
    """
    Phase 8.9 — Central response safety status.
    """
    return get_safety_status()


@router.get("/timeline/{incident_id}")
async def response_timeline(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    from sqlalchemy import select

    result = await db.execute(
        select(ResponseAction)
        .where(
            ResponseAction.incident_id == incident_id
        )
        .order_by(
            ResponseAction.created_at.asc()
        )
    )

    actions = result.scalars().all()

    timeline = []

    for index, action in enumerate(actions, start=1):

        action_type = action.action_type.upper()

        if action_type in {
            "BLOCK_IP",
        }:
            category = "NETWORK"

        elif action_type in {
            "ISOLATE_ENDPOINT",
            "QUARANTINE_ENDPOINT",
        }:
            category = "ENDPOINT"

        elif action_type in {
            "DISABLE_ACCOUNT",
            "REVOKE_SESSION",
        }:
            category = "IDENTITY"

        elif action_type in {
            "INVESTIGATE",
            "ACKNOWLEDGE",
            "ESCALATE",
            "ADD_NOTE",
            "REQUEST_CONTAINMENT",
        }:
            category = "CASE_WORKFLOW"

        else:
            category = "OTHER"

        timeline.append({
            "sequence": index,
            "timestamp": (
                action.created_at.isoformat()
                if action.created_at
                else None
            ),
            "category": category,
            "action_type": action.action_type,
            "target": action.target,
            "status": action.status,
            "mode": action.mode,
            "reason": action.reason,
        })

    return {
        "status": "RESPONSE_TIMELINE_READY",
        "mode": "LAB",
        "simulation_only": True,
        "incident_id": incident_id,
        "total_actions": len(timeline),
        "timeline": timeline,
    }


@router.get("/history/{incident_id}")
async def response_history(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    from sqlalchemy import select

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
        "status": "RESPONSE_HISTORY_READY",
        "mode": "LAB",
        "simulation_only": True,
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
