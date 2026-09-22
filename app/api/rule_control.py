from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    DetectionRule,
    DetectionRuleAudit,
)
from app.detection.registry import RULE_METADATA

router = APIRouter(
    prefix="/api/rules",
    tags=["Detection Rules"],
)


def _default_threshold(
    detection_name: str,
) -> int:
    thresholds = {
        "SSH Brute Force": 5,
        "Network Port Scan": 5,
        "Suspicious Network Utility": 1,
        "Suspicious Authentication Success": 1,
    }

    return thresholds.get(
        detection_name,
        1,
    )


async def ensure_rules_exist(
    db: AsyncSession,
):
    result = await db.scalars(
        select(DetectionRule)
    )

    existing = {
        rule.detection_name: rule
        for rule in result.all()
    }

    changed = False

    for name, metadata in RULE_METADATA.items():
        if name in existing:
            continue

        rule = DetectionRule(
            detection_name=name,
            rule_id=metadata["rule_id"],
            category=metadata["category"],
            confidence=metadata["confidence"],
            false_positive_risk=(
                metadata["false_positive_risk"]
            ),
            description=metadata["description"],
            enabled=True,
            threshold=_default_threshold(name),
            updated_at=datetime.utcnow(),
        )

        db.add(rule)
        changed = True

    if changed:
        await db.commit()


async def get_rule_record(
    db: AsyncSession,
    detection_name: str,
):
    await ensure_rules_exist(db)

    return await db.scalar(
        select(DetectionRule).where(
            DetectionRule.detection_name
            == detection_name
        )
    )


async def create_audit(
    db: AsyncSession,
    rule: DetectionRule,
    action: str,
    previous_value: str,
    new_value: str,
    reason: str | None = None,
):
    audit = DetectionRuleAudit(
        detection_rule_id=rule.id,
        detection_name=rule.detection_name,
        action=action,
        previous_value=previous_value,
        new_value=new_value,
        actor="SOC_ANALYST",
        reason=reason,
        changed_at=datetime.utcnow(),
    )

    db.add(audit)


# ---------------------------------------------------------
# STATIC AUDIT ROUTES MUST COME BEFORE /{detection_name}
# ---------------------------------------------------------

@router.get("/audit")
async def get_all_rule_audit(
    db: AsyncSession = Depends(get_db),
):
    await ensure_rules_exist(db)

    result = await db.scalars(
        select(DetectionRuleAudit).order_by(
            DetectionRuleAudit.changed_at.desc()
        )
    )

    audits = result.all()

    return {
        "count": len(audits),
        "audits": [
            {
                "id": audit.id,
                "detection_rule_id": (
                    audit.detection_rule_id
                ),
                "detection_name": (
                    audit.detection_name
                ),
                "action": audit.action,
                "previous_value": (
                    audit.previous_value
                ),
                "new_value": audit.new_value,
                "actor": audit.actor,
                "reason": audit.reason,
                "changed_at": (
                    audit.changed_at.isoformat()
                ),
            }
            for audit in audits
        ],
    }


@router.get("/{detection_name}/audit")
async def get_rule_audit(
    detection_name: str,
    db: AsyncSession = Depends(get_db),
):
    rule = await get_rule_record(
        db,
        detection_name,
    )

    if not rule:
        raise HTTPException(
            status_code=404,
            detail="Detection rule not found",
        )

    result = await db.scalars(
        select(DetectionRuleAudit)
        .where(
            DetectionRuleAudit.detection_rule_id
            == rule.id
        )
        .order_by(
            DetectionRuleAudit.changed_at.desc()
        )
    )

    audits = result.all()

    return {
        "detection_name": rule.detection_name,
        "rule_id": rule.rule_id,
        "count": len(audits),
        "audits": [
            {
                "id": audit.id,
                "action": audit.action,
                "previous_value": (
                    audit.previous_value
                ),
                "new_value": audit.new_value,
                "actor": audit.actor,
                "reason": audit.reason,
                "changed_at": (
                    audit.changed_at.isoformat()
                ),
            }
            for audit in audits
        ],
    }


@router.get("")
async def list_rules(
    db: AsyncSession = Depends(get_db),
):
    await ensure_rules_exist(db)

    result = await db.scalars(
        select(DetectionRule).order_by(
            DetectionRule.id
        )
    )

    rules = result.all()

    return {
        "count": len(rules),
        "persistent": True,
        "rules": [
            {
                "detection_name": rule.detection_name,
                "rule_id": rule.rule_id,
                "category": rule.category,
                "confidence": rule.confidence,
                "false_positive_risk": (
                    rule.false_positive_risk
                ),
                "description": rule.description,
                "enabled": rule.enabled,
                "threshold": rule.threshold,
                "updated_at": (
                    rule.updated_at.isoformat()
                    if rule.updated_at
                    else None
                ),
            }
            for rule in rules
        ],
    }


@router.get("/{detection_name}")
async def get_rule(
    detection_name: str,
    db: AsyncSession = Depends(get_db),
):
    rule = await get_rule_record(
        db,
        detection_name,
    )

    if not rule:
        raise HTTPException(
            status_code=404,
            detail="Detection rule not found",
        )

    return {
        "detection_name": rule.detection_name,
        "rule_id": rule.rule_id,
        "category": rule.category,
        "confidence": rule.confidence,
        "false_positive_risk": (
            rule.false_positive_risk
        ),
        "description": rule.description,
        "enabled": rule.enabled,
        "threshold": rule.threshold,
        "updated_at": (
            rule.updated_at.isoformat()
            if rule.updated_at
            else None
        ),
    }


@router.post("/{detection_name}/enable")
async def enable_rule(
    detection_name: str,
    db: AsyncSession = Depends(get_db),
):
    rule = await get_rule_record(
        db,
        detection_name,
    )

    if not rule:
        raise HTTPException(
            status_code=404,
            detail="Detection rule not found",
        )

    if rule.enabled:
        return {
            "detection_name": rule.detection_name,
            "enabled": True,
            "changed": False,
            "message": "Rule already enabled",
        }

    previous = str(rule.enabled)

    rule.enabled = True
    rule.updated_at = datetime.utcnow()

    await create_audit(
        db,
        rule,
        "ENABLE",
        previous,
        "True",
        "Rule enabled by SOC analyst",
    )

    await db.commit()

    return {
        "detection_name": rule.detection_name,
        "enabled": True,
        "changed": True,
        "message": "Rule enabled",
    }


@router.post("/{detection_name}/disable")
async def disable_rule(
    detection_name: str,
    db: AsyncSession = Depends(get_db),
):
    rule = await get_rule_record(
        db,
        detection_name,
    )

    if not rule:
        raise HTTPException(
            status_code=404,
            detail="Detection rule not found",
        )

    if not rule.enabled:
        return {
            "detection_name": rule.detection_name,
            "enabled": False,
            "changed": False,
            "message": "Rule already disabled",
        }

    previous = str(rule.enabled)

    rule.enabled = False
    rule.updated_at = datetime.utcnow()

    await create_audit(
        db,
        rule,
        "DISABLE",
        previous,
        "False",
        "Rule disabled by SOC analyst",
    )

    await db.commit()

    return {
        "detection_name": rule.detection_name,
        "enabled": False,
        "changed": True,
        "message": "Rule disabled",
    }


@router.post("/{detection_name}/threshold")
async def update_threshold(
    detection_name: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
):
    rule = await get_rule_record(
        db,
        detection_name,
    )

    if not rule:
        raise HTTPException(
            status_code=404,
            detail="Detection rule not found",
        )

    threshold = payload.get("threshold")

    if not isinstance(threshold, int):
        raise HTTPException(
            status_code=400,
            detail="threshold must be an integer",
        )

    if threshold < 1 or threshold > 1000:
        raise HTTPException(
            status_code=400,
            detail="threshold must be between 1 and 1000",
        )

    if rule.threshold == threshold:
        return {
            "detection_name": rule.detection_name,
            "threshold": rule.threshold,
            "changed": False,
            "message": (
                "Threshold already set "
                "to requested value"
            ),
        }

    previous = str(rule.threshold)

    rule.threshold = threshold
    rule.updated_at = datetime.utcnow()

    await create_audit(
        db,
        rule,
        "THRESHOLD_CHANGE",
        previous,
        str(threshold),
        "Detection threshold changed by SOC analyst",
    )

    await db.commit()

    return {
        "detection_name": rule.detection_name,
        "threshold": threshold,
        "changed": True,
        "message": "Threshold updated",
    }


async def is_rule_enabled(
    db: AsyncSession,
    detection_name: str,
) -> bool:
    rule = await get_rule_record(
        db,
        detection_name,
    )

    if not rule:
        return True

    return rule.enabled


async def get_rule_threshold(
    db: AsyncSession,
    detection_name: str,
) -> int:
    rule = await get_rule_record(
        db,
        detection_name,
    )

    if not rule:
        return 1

    return rule.threshold
