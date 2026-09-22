from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Detection, Incident, IOC
from app.intelligence.ioc_engine import enrich_ip

from app.intelligence.detection_correlation import correlate_detection_with_cti
from app.intelligence.enrichment import enrich_detection
router = APIRouter(
    prefix="/api/intelligence",
    tags=["Threat Intelligence"],
)


def normalize_tags(tags):
    if tags is None:
        return []

    if isinstance(tags, list):
        return tags

    if isinstance(tags, str):
        value = tags.strip()

        if not value:
            return []

        try:
            import json

            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass

        return [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

    return [str(tags)]


def serialize_ioc(ioc: IOC) -> dict:
    return {
        "id": ioc.id,
        "indicator_type": ioc.indicator_type,
        "value": ioc.value,
        "reputation": ioc.reputation,
        "confidence": float(ioc.confidence or 0.0),
        "threat_type": ioc.threat_type,
        "source": ioc.source,
        "tags": normalize_tags(ioc.tags),
        "created_at": (
            ioc.created_at.isoformat()
            if ioc.created_at
            else None
        ),
    }


def serialize_detection(detection: Detection) -> dict:
    return {
        "id": detection.id,
        "detection_name": detection.detection_name,
        "severity": detection.severity,
        "confidence": float(detection.confidence or 0.0),
        "risk_score": detection.risk_score,
        "status": detection.status,
        "source_ip": detection.source_ip,
        "destination_ip": detection.destination_ip,
        "mitre_tactic": detection.mitre_tactic,
        "mitre_technique": detection.mitre_technique,
        "created_at": (
            detection.created_at.isoformat()
            if detection.created_at
            else None
        ),
    }


def serialize_incident(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "incident_key": incident.incident_key,
        "source_ip": incident.source_ip,
        "target_asset": incident.target_asset,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "attack_story": incident.attack_story,
        "mitre_techniques": incident.mitre_techniques,
        "created_at": (
            incident.created_at.isoformat()
            if incident.created_at
            else None
        ),
        "updated_at": (
            incident.updated_at.isoformat()
            if incident.updated_at
            else None
        ),
    }


async def calculate_intelligence(
    db: AsyncSession,
    ip_address: str,
) -> dict:
    ioc_result = await db.scalars(
        select(IOC)
        .where(IOC.value == ip_address)
        .order_by(IOC.id.desc())
    )
    ioc_matches = list(ioc_result)

    intelligence = {
        "matched": bool(ioc_matches),
        "reputation": "UNKNOWN",
        "confidence": 0.0,
        "threat_types": [],
        "sources": [],
        "tags": [],
    }

    for ioc in ioc_matches:
        reputation = (
            ioc.reputation.upper()
            if ioc.reputation
            else "UNKNOWN"
        )

        if reputation == "MALICIOUS":
            intelligence["reputation"] = "MALICIOUS"
        elif (
            reputation == "SUSPICIOUS"
            and intelligence["reputation"] != "MALICIOUS"
        ):
            intelligence["reputation"] = "SUSPICIOUS"
        elif (
            intelligence["reputation"] == "UNKNOWN"
            and reputation == "BENIGN"
        ):
            intelligence["reputation"] = "BENIGN"

        intelligence["confidence"] = max(
            intelligence["confidence"],
            float(ioc.confidence or 0.0),
        )

        if ioc.threat_type:
            if ioc.threat_type not in intelligence["threat_types"]:
                intelligence["threat_types"].append(
                    ioc.threat_type
                )

        if ioc.source:
            if ioc.source not in intelligence["sources"]:
                intelligence["sources"].append(
                    ioc.source
                )

        for tag in normalize_tags(ioc.tags):
            if tag not in intelligence["tags"]:
                intelligence["tags"].append(tag)

    return intelligence


@router.get("/ip/{ip_address}")
async def lookup_ip_intelligence(
    ip_address: str,
    db: AsyncSession = Depends(get_db),
):
    return await enrich_ip(db, ip_address)


@router.get("/iocs")
async def list_iocs(
    indicator_type: str | None = None,
    reputation: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(IOC).order_by(IOC.id.desc())

    if indicator_type:
        query = query.where(
            IOC.indicator_type == indicator_type
        )

    if reputation:
        query = query.where(
            IOC.reputation == reputation.upper()
        )

    result = await db.scalars(query)
    iocs = list(result)

    return {
        "count": len(iocs),
        "iocs": [
            serialize_ioc(ioc)
            for ioc in iocs
        ],
    }


@router.post("/iocs")
async def create_ioc(
    ioc_data: dict,
    db: AsyncSession = Depends(get_db),
):
    indicator_type = str(
        ioc_data.get("indicator_type", "")
    ).strip()

    value = str(
        ioc_data.get("value", "")
    ).strip()

    if not indicator_type:
        raise HTTPException(
            status_code=400,
            detail="indicator_type is required",
        )

    if not value:
        raise HTTPException(
            status_code=400,
            detail="value is required",
        )

    reputation = str(
        ioc_data.get(
            "reputation",
            "UNKNOWN",
        )
    ).upper()

    if reputation not in {
        "MALICIOUS",
        "SUSPICIOUS",
        "UNKNOWN",
        "BENIGN",
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                "reputation must be one of "
                "MALICIOUS, SUSPICIOUS, UNKNOWN, BENIGN"
            ),
        )

    try:
        confidence = float(
            ioc_data.get("confidence", 0.0)
        )
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="confidence must be numeric",
        )

    confidence = max(
        0.0,
        min(confidence, 1.0),
    )

    existing = await db.scalar(
        select(IOC)
        .where(
            IOC.indicator_type == indicator_type,
            IOC.value == value,
        )
        .order_by(IOC.id.desc())
    )

    if existing:
        existing.reputation = reputation
        existing.confidence = confidence
        existing.threat_type = ioc_data.get(
            "threat_type"
        )
        existing.source = ioc_data.get(
            "source",
            existing.source or "LOCAL_ANALYST",
        )

        tags = ioc_data.get("tags")
        if tags is not None:
            existing.tags = (
                tags
                if isinstance(tags, str)
                else str(tags)
            )

        await db.commit()
        await db.refresh(existing)

        return {
            "status": "updated",
            "ioc": serialize_ioc(existing),
        }

    tags = ioc_data.get("tags", [])

    ioc = IOC(
        indicator_type=indicator_type,
        value=value,
        reputation=reputation,
        confidence=confidence,
        threat_type=ioc_data.get("threat_type"),
        source=ioc_data.get(
            "source",
            "LOCAL_ANALYST",
        ),
        tags=(
            tags
            if isinstance(tags, str)
            else str(tags)
        ),
    )

    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)

    return {
        "status": "created",
        "ioc": serialize_ioc(ioc),
    }


@router.get("/correlate/ip/{ip_address}")
async def correlate_ip(
    ip_address: str,
    db: AsyncSession = Depends(get_db),
):
    intelligence = await calculate_intelligence(
        db,
        ip_address,
    )

    ioc_result = await db.scalars(
        select(IOC)
        .where(IOC.value == ip_address)
        .order_by(IOC.id.desc())
    )
    ioc_matches = list(ioc_result)

    detection_result = await db.scalars(
        select(Detection)
        .where(
            or_(
                Detection.source_ip == ip_address,
                Detection.destination_ip == ip_address,
            )
        )
        .order_by(Detection.created_at.desc())
    )
    detection_matches = list(detection_result)

    incident_result = await db.scalars(
        select(Incident)
        .where(Incident.source_ip == ip_address)
        .order_by(Incident.created_at.desc())
    )
    incident_matches = list(incident_result)

    malicious_ips = (
        1
        if intelligence["reputation"] == "MALICIOUS"
        else 0
    )

    suspicious_ips = (
        1
        if intelligence["reputation"] == "SUSPICIOUS"
        else 0
    )

    return {
        "status": "success",
        "ip_address": ip_address,
        "intelligence": intelligence,
        "ioc_matches": [
            serialize_ioc(ioc)
            for ioc in ioc_matches
        ],
        "detection_matches": [
            serialize_detection(detection)
            for detection in detection_matches
        ],
        "incident_matches": [
            serialize_incident(incident)
            for incident in incident_matches
        ],
        "correlation": {
            "ioc_match": bool(ioc_matches),
            "detection_match": bool(detection_matches),
            "incident_match": bool(incident_matches),
            "correlated": bool(
                ioc_matches
                or detection_matches
                or incident_matches
            ),
        },
        "summary": {
            "malicious_ips": malicious_ips,
            "suspicious_ips": suspicious_ips,
            "ioc_hits": len(ioc_matches),
            "detection_hits": len(detection_matches),
            "incident_hits": len(incident_matches),
        },
    }


@router.get("/incident/{incident_id}")
async def incident_intelligence(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
):
    incident = await db.scalar(
        select(Incident).where(
            Incident.id == incident_id
        )
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    correlated_ips = set()

    if incident.source_ip:
        correlated_ips.add(
            incident.source_ip
        )

    detection_result = await db.scalars(
        select(Detection).where(
            Detection.source_ip
            == incident.source_ip
        )
    )

    detections = list(detection_result)

    for detection in detections:
        if detection.source_ip:
            correlated_ips.add(
                detection.source_ip
            )

        if detection.destination_ip:
            correlated_ips.add(
                detection.destination_ip
            )

    ip_intelligence = []

    for ip_address in sorted(correlated_ips):
        intelligence = await calculate_intelligence(
            db,
            ip_address,
        )

        ioc_result = await db.scalars(
            select(IOC)
            .where(IOC.value == ip_address)
            .order_by(IOC.id.desc())
        )

        ioc_matches = list(ioc_result)

        ip_intelligence.append(
            {
                "ip_address": ip_address,
                "intelligence": intelligence,
                "ioc_matches": [
                    serialize_ioc(ioc)
                    for ioc in ioc_matches
                ],
            }
        )

    malicious_ips = sum(
        1
        for item in ip_intelligence
        if item["intelligence"]["reputation"]
        == "MALICIOUS"
    )

    suspicious_ips = sum(
        1
        for item in ip_intelligence
        if item["intelligence"]["reputation"]
        == "SUSPICIOUS"
    )

    ioc_hits = sum(
        len(item["ioc_matches"])
        for item in ip_intelligence
    )

    return {
        "status": "success",
        "incident_id": incident.id,
        "incident_key": incident.incident_key,
        "source_ip": incident.source_ip,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "status_value": incident.status,
        "summary": {
            "correlated_ips": len(
                ip_intelligence
            ),
            "malicious_ips": malicious_ips,
            "suspicious_ips": suspicious_ips,
            "ioc_hits": ioc_hits,
        },
        "ip_intelligence": ip_intelligence,
    }


@router.get("/ioc/{ioc_id}/profile")
async def ioc_intelligence_profile(
    ioc_id: int,
    db=Depends(get_db),
):
    from sqlalchemy import select
    from fastapi import HTTPException

    from app.db.models import IOC
    from app.intelligence.scoring import (
        build_intelligence_profile,
    )

    ioc = await db.scalar(
        select(IOC).where(
            IOC.id == ioc_id
        )
    )

    if not ioc:
        raise HTTPException(
            status_code=404,
            detail="IOC not found",
        )

    profile = build_intelligence_profile(
        reputation=ioc.reputation,
        confidence=ioc.confidence,
        source=ioc.source,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        threat_type=ioc.threat_type,
        tags=ioc.tags,
    )

    return {
        "status": "success",
        "ioc": {
            "id": ioc.id,
            "indicator_type": ioc.indicator_type,
            "value": ioc.value,
            "reputation": ioc.reputation,
            "confidence": ioc.confidence,
            "threat_type": ioc.threat_type,
            "source": ioc.source,
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
            "tags": ioc.tags or [],
        },
        "profile": profile,
    }


@router.get("/correlate/detection")
async def correlate_detection(
    source_ip: str | None = None,
    destination_ip: str | None = None,
    domain: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    domains = [domain] if domain else []

    return await correlate_detection_with_cti(
        db,
        source_ip=source_ip,
        destination_ip=destination_ip,
        domains=domains,
    )


@router.get("/enrich/detection")
async def enrich_detection_api(
    source_ip: str | None = None,
    destination_ip: str | None = None,
    domain: str | None = None,
    detection_name: str | None = None,
    detection_category: str | None = None,
    base_risk: int = 0,
    db: AsyncSession = Depends(get_db),
):
    return await enrich_detection(
        db,
        source_ip=source_ip,
        destination_ip=destination_ip,
        domain=domain,
        detection_name=detection_name,
        detection_category=detection_category,
        base_risk=base_risk,
    )
