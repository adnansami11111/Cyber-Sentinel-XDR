from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Detection
from app.detection.registry import RULE_METADATA


router = APIRouter(
    prefix="/api/analytics",
    tags=["Analytics"],
)


@router.get("/detections")
async def detection_analytics(
    hours: int = Query(
        default=24,
        ge=1,
        le=720,
    ),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.utcnow() - timedelta(
        hours=hours
    )

    result = await db.execute(
        select(Detection)
        .where(
            Detection.created_at >= cutoff
        )
        .order_by(
            Detection.created_at.desc()
        )
    )

    detections = list(
        result.scalars().all()
    )

    total = len(detections)

    suppressed = sum(
        1
        for d in detections
        if d.status == "SUPPRESSED"
    )

    active = total - suppressed

    average_confidence = round(
        sum(
            d.confidence or 0
            for d in detections
        ) / total,
        2,
    ) if total else 0

    average_risk = round(
        sum(
            d.risk_score or 0
            for d in detections
        ) / total,
        2,
    ) if total else 0

    incident_result = await db.execute(
        select(func.count()).select_from(
            Detection
        ).where(
            Detection.created_at >= cutoff
        )
    )

    total_incident_window = (
        incident_result.scalar() or 0
    )

    rule_stats = {}

    for detection in detections:
        name = detection.detection_name

        if name not in rule_stats:
            rule_stats[name] = {
                "total": 0,
                "active": 0,
                "suppressed": 0,
                "average_risk": 0,
                "risk_values": [],
            }

        stats = rule_stats[name]

        stats["total"] += 1

        if detection.status == "SUPPRESSED":
            stats["suppressed"] += 1
        else:
            stats["active"] += 1

        stats["risk_values"].append(
            detection.risk_score or 0
        )

    for stats in rule_stats.values():
        values = stats.pop("risk_values")

        stats["average_risk"] = round(
            sum(values) / len(values),
            2,
        ) if values else 0

    highest_risk = sorted(
        detections,
        key=lambda d: d.risk_score or 0,
        reverse=True,
    )[:10]

    return {
        "status": "success",
        "period_hours": hours,
        "statistics": {
            "total": total,
            "active": active,
            "suppressed": suppressed,
            "average_confidence": (
                average_confidence
            ),
            "average_risk_score": (
                average_risk
            ),
            "detections_in_window": (
                total_incident_window
            ),
        },
        "rule_statistics": rule_stats,
        "highest_risk_detections": [
            {
                "id": d.id,
                "detection_name": (
                    d.detection_name
                ),
                "severity": d.severity,
                "risk_score": d.risk_score,
                "confidence": d.confidence,
                "source_ip": d.source_ip,
                "status": d.status,
                "created_at": (
                    d.created_at
                ),
            }
            for d in highest_risk
        ],
    }


@router.get(
    "/detections/{detection_name}"
)
async def detection_rule_analytics(
    detection_name: str,
    hours: int = Query(
        default=24,
        ge=1,
        le=720,
    ),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.utcnow() - timedelta(
        hours=hours
    )

    result = await db.execute(
        select(Detection)
        .where(
            Detection.detection_name
            == detection_name,
            Detection.created_at >= cutoff,
        )
        .order_by(
            Detection.created_at.desc()
        )
    )

    detections = list(
        result.scalars().all()
    )

    total = len(detections)

    suppressed = sum(
        1
        for d in detections
        if d.status == "SUPPRESSED"
    )

    active = total - suppressed

    average_confidence = round(
        sum(
            d.confidence or 0
            for d in detections
        ) / total,
        2,
    ) if total else 0

    average_risk = round(
        sum(
            d.risk_score or 0
            for d in detections
        ) / total,
        2,
    ) if total else 0

    unique_sources = sorted(
        {
            d.source_ip
            for d in detections
            if d.source_ip
        }
    )

    rule = RULE_METADATA.get(
        detection_name
    )

    rule_metadata = None

    if rule:
        rule_metadata = {
            "rule_id": rule.get(
                "rule_id"
            ),
            "category": rule.get(
                "category"
            ),
            "confidence": rule.get(
                "confidence"
            ),
            "false_positive_risk": rule.get(
                "false_positive_risk"
            ),
            "description": rule.get(
                "description"
            ),
        }

    return {
        "status": "success",
        "detection_name": detection_name,
        "rule": rule_metadata,
        "period_hours": hours,
        "statistics": {
            "total": total,
            "active": active,
            "suppressed": suppressed,
            "suppression_rate": round(
                (suppressed / total) * 100,
                2,
            ) if total else 0,
            "average_confidence": (
                average_confidence
            ),
            "average_risk_score": (
                average_risk
            ),
            "unique_source_ips": (
                len(unique_sources)
            ),
        },
        "source_ips": unique_sources,
    }


@router.get("/trends")
async def detection_trends(
    hours: int = Query(
        default=24,
        ge=1,
        le=720,
    ),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.utcnow() - timedelta(
        hours=hours
    )

    result = await db.execute(
        select(Detection)
        .where(
            Detection.created_at >= cutoff
        )
        .order_by(
            Detection.created_at.asc()
        )
    )

    detections = list(
        result.scalars().all()
    )

    hourly = {}

    for detection in detections:
        timestamp = detection.created_at

        if timestamp is None:
            continue

        hour_key = timestamp.replace(
            minute=0,
            second=0,
            microsecond=0,
        ).isoformat()

        if hour_key not in hourly:
            hourly[hour_key] = {
                "timestamp": hour_key,
                "total": 0,
                "active": 0,
                "suppressed": 0,
                "risk_scores": [],
                "severity": {
                    "LOW": 0,
                    "MEDIUM": 0,
                    "HIGH": 0,
                    "CRITICAL": 0,
                },
            }

        bucket = hourly[hour_key]

        bucket["total"] += 1

        if detection.status == "SUPPRESSED":
            bucket["suppressed"] += 1
        else:
            bucket["active"] += 1

        bucket["risk_scores"].append(
            detection.risk_score or 0
        )

        severity = (
            detection.severity or "LOW"
        ).upper()

        if severity not in bucket["severity"]:
            bucket["severity"][severity] = 0

        bucket["severity"][severity] += 1

    timeline = []

    for timestamp, bucket in sorted(
        hourly.items()
    ):
        scores = bucket.pop(
            "risk_scores"
        )

        bucket["average_risk_score"] = (
            round(
                sum(scores) / len(scores),
                2,
            )
            if scores
            else 0
        )

        timeline.append(bucket)

    severity_result = await db.execute(
        select(
            Detection.severity,
            func.count(Detection.id),
        )
        .where(
            Detection.created_at >= cutoff
        )
        .group_by(
            Detection.severity
        )
    )

    severity_distribution = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for severity, count in severity_result.all():
        key = (
            severity or "LOW"
        ).upper()

        severity_distribution[key] = count

    risk_distribution = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for detection in detections:
        score = detection.risk_score or 0

        if score >= 90:
            risk_distribution["CRITICAL"] += 1
        elif score >= 70:
            risk_distribution["HIGH"] += 1
        elif score >= 40:
            risk_distribution["MEDIUM"] += 1
        else:
            risk_distribution["LOW"] += 1

    peak_hour = None

    if timeline:
        peak_hour = max(
            timeline,
            key=lambda item: item["total"],
        )

    return {
        "status": "success",
        "period": {
            "hours": hours,
            "since": cutoff,
        },
        "summary": {
            "total_detections": len(
                detections
            ),
            "active_detections": sum(
                1
                for d in detections
                if d.status != "SUPPRESSED"
            ),
            "suppressed_detections": sum(
                1
                for d in detections
                if d.status == "SUPPRESSED"
            ),
            "peak_activity_hour": (
                peak_hour["timestamp"]
                if peak_hour
                else None
            ),
            "peak_activity_count": (
                peak_hour["total"]
                if peak_hour
                else 0
            ),
        },
        "severity_distribution": (
            severity_distribution
        ),
        "risk_distribution": (
            risk_distribution
        ),
        "timeline": timeline,
    }


@router.get("/coverage")
async def detection_coverage(
    hours: int = Query(
        default=24,
        ge=1,
        le=720,
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Detection coverage and rule-health analytics.

    Shows every registered detection rule,
    whether it is active, recent activity,
    event volume, suppression rate, risk,
    and coverage status.
    """

    cutoff = datetime.utcnow() - timedelta(
        hours=hours
    )

    result = await db.execute(
        select(Detection)
        .where(
            Detection.created_at >= cutoff
        )
        .order_by(
            Detection.created_at.desc()
        )
    )

    detections = list(
        result.scalars().all()
    )

    coverage = []

    observed_rules = set()

    for detection in detections:
        observed_rules.add(
            detection.detection_name
        )

    for rule_name, rule in RULE_METADATA.items():

        rule_detections = [
            d
            for d in detections
            if d.detection_name
            == rule_name
        ]

        total = len(rule_detections)

        active = sum(
            1
            for d in rule_detections
            if d.status != "SUPPRESSED"
        )

        suppressed = total - active

        average_risk = round(
            sum(
                d.risk_score or 0
                for d in rule_detections
            ) / total,
            2,
        ) if total else 0

        last_seen = None

        if rule_detections:
            last_seen = max(
                d.created_at
                for d in rule_detections
                if d.created_at
            )

        if total == 0:
            coverage_status = "NO_ACTIVITY"
        elif active == 0:
            coverage_status = "SUPPRESSED_ONLY"
        else:
            coverage_status = "ACTIVE"

        coverage.append(
            {
                "detection_name": rule_name,
                "rule_id": rule.get(
                    "rule_id"
                ),
                "category": rule.get(
                    "category"
                ),
                "confidence": rule.get(
                    "confidence"
                ),
                "false_positive_risk": rule.get(
                    "false_positive_risk"
                ),
                "total_detections": total,
                "active_detections": active,
                "suppressed_detections": (
                    suppressed
                ),
                "suppression_rate": round(
                    (suppressed / total) * 100,
                    2,
                ) if total else 0,
                "average_risk_score": (
                    average_risk
                ),
                "last_seen": last_seen,
                "coverage_status": (
                    coverage_status
                ),
            }
        )

    active_rules = sum(
        1
        for item in coverage
        if item["coverage_status"]
        == "ACTIVE"
    )

    no_activity_rules = sum(
        1
        for item in coverage
        if item["coverage_status"]
        == "NO_ACTIVITY"
    )

    suppressed_only_rules = sum(
        1
        for item in coverage
        if item["coverage_status"]
        == "SUPPRESSED_ONLY"
    )

    return {
        "status": "success",
        "period_hours": hours,
        "summary": {
            "registered_rules": len(
                coverage
            ),
            "rules_with_activity": (
                active_rules
            ),
            "rules_without_activity": (
                no_activity_rules
            ),
            "suppressed_only_rules": (
                suppressed_only_rules
            ),
            "coverage_percent": round(
                (
                    active_rules
                    / len(coverage)
                    * 100
                ),
                2,
            ) if coverage else 0,
        },
        "rules": coverage,
    }
