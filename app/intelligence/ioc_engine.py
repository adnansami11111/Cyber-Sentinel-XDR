from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IOC


async def lookup_ip(
    db: AsyncSession,
    ip_address: str,
):
    """
    Look up an IP address in the local IOC database.
    """

    if not ip_address:
        return None

    result = await db.scalar(
        select(IOC)
        .where(
            IOC.indicator_type == "ip",
            IOC.value == ip_address,
        )
        .order_by(
            IOC.created_at.desc()
        )
    )

    return result


async def enrich_ip(
    db: AsyncSession,
    ip_address: str,
):
    """
    Return normalized threat-intelligence information.
    """

    ioc = await lookup_ip(
        db,
        ip_address,
    )

    if not ioc:
        return {
            "ip": ip_address,
            "found": False,
            "reputation": "UNKNOWN",
            "confidence": 0.0,
            "threat_type": None,
            "source": None,
            "tags": [],
            "first_seen": None,
            "last_seen": None,
        }

    return {
        "ip": ip_address,
        "found": True,
        "reputation": ioc.reputation,
        "confidence": ioc.confidence,
        "threat_type": ioc.threat_type,
        "source": ioc.source,
        "tags": ioc.tags or [],
        "first_seen": (
            ioc.first_seen.isoformat()
            if ioc.first_seen
            else None
        ),
        "last_seen": (
            ioc.last_seen.isoformat()
            if ioc.last_seen
            else None
        ),
    }


async def build_ioc_evidence(
    db: AsyncSession,
    ip_address: str | None,
):
    """
    Build analyst-readable IOC evidence.
    """

    if not ip_address:
        return {
            "ioc_found": False,
            "reputation": "UNKNOWN",
            "confidence": 0.0,
            "source": None,
            "threat_type": None,
            "tags": [],
        }

    intelligence = await enrich_ip(
        db,
        ip_address,
    )

    return {
        "ioc_found": intelligence["found"],
        "ip": ip_address,
        "reputation": intelligence["reputation"],
        "confidence": intelligence["confidence"],
        "source": intelligence["source"],
        "threat_type": intelligence["threat_type"],
        "tags": intelligence["tags"],
        "first_seen": intelligence["first_seen"],
        "last_seen": intelligence["last_seen"],
    }
