from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IOC
from app.intelligence.sources import normalize_source


ALLOWED_TYPES = {
    "ip",
    "domain",
    "url",
    "hash",
    "email",
}


ALLOWED_REPUTATIONS = {
    "MALICIOUS",
    "SUSPICIOUS",
    "BENIGN",
    "UNKNOWN",
}


def normalize_indicator_type(
    indicator_type: str | None,
) -> str:
    value = (
        indicator_type or ""
    ).strip().lower()

    aliases = {
        "ipv4": "ip",
        "ipv6": "ip",
        "ip_address": "ip",
        "hostname": "domain",
        "sha256": "hash",
        "sha1": "hash",
        "md5": "hash",
    }

    value = aliases.get(value, value)

    if value not in ALLOWED_TYPES:
        raise ValueError(
            f"Unsupported indicator type: {value}"
        )

    return value


def normalize_value(
    value: str,
) -> str:
    value = value.strip()

    if not value:
        raise ValueError(
            "IOC value cannot be empty"
        )

    return value


def normalize_reputation(
    reputation: str | None,
) -> str:
    value = (
        reputation or "UNKNOWN"
    ).strip().upper()

    if value not in ALLOWED_REPUTATIONS:
        return "UNKNOWN"

    return value


def normalize_confidence(
    confidence: float | int | None,
) -> float:
    try:
        value = float(
            confidence or 0.0
        )
    except (TypeError, ValueError):
        value = 0.0

    return round(
        max(0.0, min(value, 1.0)),
        4,
    )


def normalize_tags(
    tags: list[str] | None,
) -> list[str]:
    result = []

    for tag in tags or []:
        value = str(tag).strip().lower()

        if value and value not in result:
            result.append(value)

    return result


def normalize_record(
    record: dict[str, Any],
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)

    first_seen = record.get(
        "first_seen"
    )

    last_seen = record.get(
        "last_seen"
    )

    return {
        "indicator_type": normalize_indicator_type(
            record.get("indicator_type")
        ),
        "value": normalize_value(
            str(record.get("value", ""))
        ),
        "reputation": normalize_reputation(
            record.get("reputation")
        ),
        "confidence": normalize_confidence(
            record.get("confidence")
        ),
        "threat_type": (
            str(record["threat_type"]).strip()
            if record.get("threat_type")
            else None
        ),
        "source": normalize_source(
            record.get("source")
        ),
        "first_seen": first_seen or now,
        "last_seen": last_seen or now,
        "tags": normalize_tags(
            record.get("tags")
        ),
    }


async def ingest_ioc(
    db: AsyncSession,
    record: dict[str, Any],
) -> dict[str, Any]:
    normalized = normalize_record(record)

    result = await db.scalar(
        select(IOC).where(
            IOC.indicator_type
            == normalized["indicator_type"],
            IOC.value
            == normalized["value"],
        )
    )

    if result:
        existing = result

        existing.reputation = normalized[
            "reputation"
        ]

        existing.confidence = max(
            existing.confidence or 0.0,
            normalized["confidence"],
        )

        if normalized["threat_type"]:
            existing.threat_type = (
                normalized["threat_type"]
            )

        existing.source = normalized[
            "source"
        ]

        if normalized["first_seen"]:
            if (
                not existing.first_seen
                or normalized["first_seen"]
                < existing.first_seen
            ):
                existing.first_seen = (
                    normalized["first_seen"]
                )

        if normalized["last_seen"]:
            if (
                not existing.last_seen
                or normalized["last_seen"]
                > existing.last_seen
            ):
                existing.last_seen = (
                    normalized["last_seen"]
                )

        existing_tags = (
            existing.tags or []
        )

        merged_tags = existing_tags + [
            tag
            for tag in normalized["tags"]
            if tag not in existing_tags
        ]

        existing.tags = merged_tags

        await db.commit()
        await db.refresh(existing)

        return {
            "status": "updated",
            "created": False,
            "deduplicated": True,
            "ioc_id": existing.id,
            "indicator_type": existing.indicator_type,
            "value": existing.value,
        }

    ioc = IOC(
        indicator_type=normalized[
            "indicator_type"
        ],
        value=normalized["value"],
        reputation=normalized[
            "reputation"
        ],
        confidence=normalized[
            "confidence"
        ],
        threat_type=normalized[
            "threat_type"
        ],
        source=normalized["source"],
        first_seen=normalized[
            "first_seen"
        ],
        last_seen=normalized[
            "last_seen"
        ],
        tags=normalized["tags"],
        created_at=datetime.utcnow(),
    )

    db.add(ioc)

    await db.commit()
    await db.refresh(ioc)

    return {
        "status": "created",
        "created": True,
        "deduplicated": False,
        "ioc_id": ioc.id,
        "indicator_type": ioc.indicator_type,
        "value": ioc.value,
    }


async def ingest_batch(
    db: AsyncSession,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    created = 0
    updated = 0
    failed = 0

    results = []

    for index, record in enumerate(records):
        try:
            result = await ingest_ioc(
                db,
                record,
            )

            if result["created"]:
                created += 1
            else:
                updated += 1

            results.append(
                {
                    "index": index,
                    **result,
                }
            )

        except Exception as exc:
            failed += 1

            results.append(
                {
                    "index": index,
                    "status": "failed",
                    "error": str(exc),
                }
            )

    return {
        "total": len(records),
        "created": created,
        "updated": updated,
        "failed": failed,
        "results": results,
    }
