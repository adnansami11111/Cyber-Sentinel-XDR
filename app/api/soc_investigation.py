from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Detection, Incident

from app.api.graph import (
    _incident_risk_seeds,
    _refresh_db_graph,
)
from app.graph.risk import propagate_risk


router = APIRouter(
    prefix="/api/soc",
    tags=["SOC Investigation"],
)


def _risk_level(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _graph_entity_context(entity):
    return {
        "id": str(entity.entity_id),
        "type": str(entity.entity_type),
        "label": str(entity.label),
        "properties": entity.properties or {},
    }


def _risk_for_entity(risk_data, entity_id: str) -> int:
    for item in risk_data.get("high_risk_entities", []):
        if not isinstance(item, dict):
            continue

        candidate_id = (
            item.get("entity_id")
            or item.get("id")
            or item.get("entity")
        )

        if str(candidate_id) == entity_id:
            return int(
                item.get(
                    "risk",
                    item.get(
                        "score",
                        item.get(
                            "risk_score",
                            0,
                        ),
                    ),
                )
                or 0
            )

    return 0


def _empty_risk():
    return {
        "max_risk": 0,
        "high_risk_entities": [],
    }


def _database_detection_context(
    detection: Detection,
):
    return {
        "id": f"detection:{detection.id}",
        "type": "DETECTION",
        "label": str(detection.detection_name),
        "properties": {
            "detection_id": detection.id,
            "detection_name": detection.detection_name,
            "severity": detection.severity,
            "confidence": detection.confidence,
            "source_ip": detection.source_ip,
            "created_at": (
                detection.created_at.isoformat()
                if detection.created_at
                else None
            ),
        },
    }


def _database_incident_context(
    incident: Incident,
):
    return {
        "id": f"incident:{incident.id}",
        "type": "INCIDENT",
        "label": str(incident.title),
        "properties": {
            "incident_id": incident.id,
            "incident_key": incident.incident_key,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "source_ip": incident.source_ip,
            "target_asset": incident.target_asset,
            "attack_story": incident.attack_story,
            "mitre_techniques":
                incident.mitre_techniques,
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
        },
    }


def _parse_mitre_techniques(value):
    if not value:
        return []

    if isinstance(value, list):
        return [str(item) for item in value]

    try:
        parsed = json.loads(value)

        if isinstance(parsed, list):
            return [str(item) for item in parsed]

    except (TypeError, json.JSONDecodeError):
        pass

    return []


def _build_evidence_correlation(
    incident: Incident,
    related_detections,
    mitre_entities,
    timeline,
):
    detection_evidence = []

    for detection in related_detections:
        detection_evidence.append({
            "entity_id":
                f"detection:{detection.id}",

            "detection_name":
                str(
                    detection.detection_name
                ),

            "severity":
                str(
                    detection.severity
                ),

            "confidence":
                float(
                    detection.confidence or 0
                ),

            "source_ip":
                detection.source_ip,

            "timestamp":
                (
                    detection.created_at.isoformat()
                    if detection.created_at
                    else None
                ),
        })

    mitre_evidence = []

    for technique in mitre_entities:
        mitre_evidence.append({
            "entity_id":
                technique.get("id"),

            "technique_id":
                technique.get("label")
                or technique.get("name")
                or technique.get("value")
                or technique.get("id"),

            "title":
                technique.get("label")
                or technique.get("name")
                or technique.get("value")
                or technique.get("id"),
        })

    source_ips = sorted({
        item.get("source_ip")
        for item in detection_evidence
        if item.get("source_ip")
    })

    detection_count = len(
        detection_evidence
    )

    mitre_count = len(
        mitre_evidence
    )

    timeline_count = len(
        timeline
    )

    correlation_signals = []

    if detection_count > 0:
        correlation_signals.append(
            "Detection evidence is associated with the incident."
        )

    if len(source_ips) == 1:
        correlation_signals.append(
            "Multiple detections originate from the same source IP."
        )

    if mitre_count > 0:
        correlation_signals.append(
            "MITRE ATT&CK techniques are mapped to the incident."
        )

    if timeline_count > 1:
        correlation_signals.append(
            "Multiple chronological investigation events are available."
        )

    if (
        incident.source_ip
        and len(source_ips) == 1
        and source_ips[0] == incident.source_ip
    ):
        correlation_signals.append(
            "Detection source IP matches the incident source IP."
        )

    evidence_strength = (
        "STRONG"
        if detection_count >= 2
        and (
            mitre_count > 0
            or timeline_count >= 3
        )
        else (
            "MODERATE"
            if detection_count > 0
            else "LIMITED"
        )
    )

    return {
        "evidence_strength":
            evidence_strength,

        "source_ip":
            incident.source_ip,

        "detection_count":
            detection_count,

        "mitre_count":
            mitre_count,

        "timeline_count":
            timeline_count,

        "detection_evidence":
            detection_evidence,

        "mitre_evidence":
            mitre_evidence,

        "correlation_signals":
            correlation_signals,
    }


def _build_incident_timeline(
    incident: Incident,
    related_detections,
):
    timeline = []

    for detection in related_detections:

        if detection.created_at is None:
            continue

        timeline.append({
            "timestamp":
                detection.created_at.isoformat(),

            "event_type":
                "DETECTION",

            "entity_id":
                f"detection:{detection.id}",

            "title":
                str(
                    detection.detection_name
                ),

            "description":
                (
                    f"{detection.detection_name} "
                    f"detected from "
                    f"{detection.source_ip}"
                ),

            "severity":
                str(
                    detection.severity
                ),

            "source_ip":
                detection.source_ip,

            "confidence":
                float(
                    detection.confidence or 0
                ),
        })

    if incident.created_at:

        timeline.append({
            "timestamp":
                incident.created_at.isoformat(),

            "event_type":
                "INCIDENT_CREATED",

            "entity_id":
                f"incident:{incident.id}",

            "title":
                "Incident created",

            "description":
                str(
                    incident.title
                ),

            "severity":
                str(
                    incident.severity
                ),

            "source_ip":
                incident.source_ip,

            "risk_score":
                int(
                    incident.risk_score or 0
                ),

            "confidence":
                1.0,
        })

    if (
        incident.updated_at
        and incident.updated_at
        != incident.created_at
    ):

        timeline.append({
            "timestamp":
                incident.updated_at.isoformat(),

            "event_type":
                "INCIDENT_UPDATED",

            "entity_id":
                f"incident:{incident.id}",

            "title":
                "Incident updated",

            "description":
                (
                    f"Incident status: "
                    f"{incident.status}"
                ),

            "severity":
                str(
                    incident.severity
                ),

            "source_ip":
                incident.source_ip,

            "risk_score":
                int(
                    incident.risk_score or 0
                ),

            "confidence":
                1.0,
        })

    timeline.sort(
        key=lambda item:
            item.get("timestamp") or ""
    )

    for index, event in enumerate(
        timeline,
        start=1,
    ):
        event["sequence"] = index

    return timeline


@router.get("/investigation/{entity_id:path}")
async def investigate_entity(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
):

    # =========================================================
    # REFRESH REAL DATABASE-BACKED GRAPH
    # =========================================================

    graph = await _refresh_db_graph(db)

    # =========================================================
    # GRAPH-BACKED ENTITY INVESTIGATION
    # =========================================================

    graph_entity = graph.entities.get(
        entity_id
    )

    if (
        graph_entity is not None
        and not entity_id.startswith("incident:")
    ):

        try:
            risk = propagate_risk(
                graph,
                seed_risks=_incident_risk_seeds(
                    graph
                ),
            )
        except Exception:
            risk = _empty_risk()

        entity_risk = _risk_for_entity(
            risk,
            entity_id,
        )

        # Incident risk is authoritative from DB.
        if (
            str(
                graph_entity.entity_type
            ).upper()
            == "INCIDENT"
        ):
            try:
                entity_risk = int(
                    graph_entity.properties.get(
                        "risk_score",
                        entity_risk,
                    )
                    or entity_risk
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        related_entities = []
        related_relationships = []
        seen_related = set()

        for relationship in graph.relationships:

            source_id = str(
                relationship.source_id
            )

            target_id = str(
                relationship.target_id
            )

            if (
                source_id != entity_id
                and target_id != entity_id
            ):
                continue

            related_relationships.append({
                "source":
                    source_id,

                "target":
                    target_id,

                "type":
                    str(
                        relationship.relationship_type
                    ),

                "confidence":
                    float(
                        getattr(
                            relationship,
                            "confidence",
                            1.0,
                        )
                        or 1.0
                    ),
            })

            other_id = (
                target_id
                if source_id == entity_id
                else source_id
            )

            if (
                other_id in seen_related
                or other_id == entity_id
            ):
                continue

            other = graph.entities.get(
                other_id
            )

            if other is None:
                continue

            seen_related.add(
                other_id
            )

            related_entities.append(
                _graph_entity_context(
                    other
                )
            )

        attack_chain = []

        for relationship in related_relationships:

            source = graph.entities.get(
                relationship["source"]
            )

            target = graph.entities.get(
                relationship["target"]
            )

            if source is None or target is None:
                continue

            attack_chain.append({
                "source": {
                    "id":
                        str(
                            source.entity_id
                        ),

                    "type":
                        str(
                            source.entity_type
                        ),

                    "label":
                        str(
                            source.label
                        ),
                },

                "relationship":
                    relationship["type"],

                "target": {
                    "id":
                        str(
                            target.entity_id
                        ),

                    "type":
                        str(
                            target.entity_type
                        ),

                    "label":
                        str(
                            target.label
                        ),
                },

                "confidence":
                    relationship["confidence"],
            })

        mitre_entities = [
            item
            for item in related_entities
            if str(
                item["type"]
            ).upper()
            == "MITRE_TECHNIQUE"
        ]

        ioc_entities = [
            item
            for item in related_entities
            if str(
                item["type"]
            ).upper() == "IOC"
        ]

        return {
            "status":
                "INVESTIGATION_WORKSPACE_READY",

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "entity": {
                **_graph_entity_context(
                    graph_entity
                ),

                "risk":
                    entity_risk,

                "risk_level":
                    _risk_level(
                        entity_risk
                    ),
            },

            "context": {
                "is_ioc":
                    str(
                        graph_entity.entity_type
                    ).upper() == "IOC",

                "is_ip":
                    str(
                        graph_entity.entity_type
                    ).upper() == "IP",

                "is_detection":
                    str(
                        graph_entity.entity_type
                    ).upper() == "DETECTION",

                "is_incident":
                    str(
                        graph_entity.entity_type
                    ).upper() == "INCIDENT",

                "is_mitre":
                    str(
                        graph_entity.entity_type
                    ).upper()
                    == "MITRE_TECHNIQUE",

                "is_asset":
                    str(
                        graph_entity.entity_type
                    ).upper() == "ASSET",

                "is_process":
                    str(
                        graph_entity.entity_type
                    ).upper() == "PROCESS",

                "is_domain":
                    str(
                        graph_entity.entity_type
                    ).upper() == "DOMAIN",
            },

            "related_entities":
                related_entities,

            "relationships":
                related_relationships,

            "attack_chain":
                attack_chain,

            "mitre":
                mitre_entities,

            "iocs":
                ioc_entities,

            "risk": {
                "entity_risk":
                    entity_risk,

                "entity_risk_level":
                    _risk_level(
                        entity_risk
                    ),

                "global_max_risk":
                    int(
                        risk.get(
                            "max_risk",
                            0,
                        )
                    ),
            },

            "investigation": {
                "related_entity_count":
                    len(
                        related_entities
                    ),

                "relationship_count":
                    len(
                        related_relationships
                    ),

                "attack_chain_count":
                    len(
                        attack_chain
                    ),

                "mitre_count":
                    len(
                        mitre_entities
                    ),

                "ioc_count":
                    len(
                        ioc_entities
                    ),

                "high_priority":
                    entity_risk >= 70,

                "recommended_action":
                    (
                        "ESCALATE"
                        if entity_risk >= 85
                        else
                        "INVESTIGATE"
                        if entity_risk >= 70
                        else
                        "MONITOR"
                    ),
            },
        }

    # =========================================================
    # REAL DATABASE DETECTION
    # =========================================================

    if entity_id.startswith(
        "detection:"
    ):

        try:
            detection_id = int(
                entity_id.split(
                    ":",
                    1,
                )[1]
            )
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid detection ID",
            )

        result = await db.execute(
            select(Detection).where(
                Detection.id
                == detection_id
            )
        )

        detection = (
            result.scalar_one_or_none()
        )

        if detection is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Detection not found: "
                    f"{detection_id}"
                ),
            )

        source_ip = detection.source_ip

        risk_score = 0

        severity = str(
            detection.severity
        ).upper()

        if severity == "CRITICAL":
            risk_score = 90
        elif severity == "HIGH":
            risk_score = 80
        elif severity == "MEDIUM":
            risk_score = 55
        elif severity == "LOW":
            risk_score = 30

        entity = (
            _database_detection_context(
                detection
            )
        )

        related_entities = []
        relationships = []
        attack_chain = []

        if source_ip:

            related_entities.append({
                "id":
                    f"ip:{source_ip}",

                "type":
                    "IP",

                "label":
                    str(source_ip),

                "properties": {
                    "source":
                        "detection",
                },
            })

            relationships.append({
                "source":
                    f"ip:{source_ip}",

                "target":
                    f"detection:{detection.id}",

                "type":
                    "SOURCE_OF",

                "confidence":
                    float(
                        detection.confidence
                        or 0
                    ),
            })

            attack_chain.append({
                "source": {
                    "id":
                        f"ip:{source_ip}",

                    "type":
                        "IP",

                    "label":
                        str(source_ip),
                },

                "relationship":
                    "SOURCE_OF",

                "target": {
                    "id":
                        f"detection:{detection.id}",

                    "type":
                        "DETECTION",

                    "label":
                        str(
                            detection.detection_name
                        ),
                },

                "confidence":
                    float(
                        detection.confidence
                        or 0
                    ),
            })

        return {
            "status":
                "INVESTIGATION_WORKSPACE_READY",

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "entity": {
                **entity,

                "risk":
                    risk_score,

                "risk_level":
                    _risk_level(
                        risk_score
                    ),
            },

            "context": {
                "is_ioc": False,
                "is_ip": False,
                "is_detection": True,
                "is_incident": False,
                "is_mitre": False,
                "is_asset": False,
                "is_process": False,
                "is_domain": False,
            },

            "related_entities":
                related_entities,

            "relationships":
                relationships,

            "attack_chain":
                attack_chain,

            "mitre": [],

            "iocs": [],

            "risk": {
                "entity_risk":
                    risk_score,

                "entity_risk_level":
                    _risk_level(
                        risk_score
                    ),

                "global_max_risk":
                    risk_score,
            },

            "investigation": {
                "related_entity_count":
                    len(
                        related_entities
                    ),

                "relationship_count":
                    len(
                        relationships
                    ),

                "attack_chain_count":
                    len(
                        attack_chain
                    ),

                "mitre_count":
                    0,

                "ioc_count":
                    0,

                "high_priority":
                    risk_score >= 70,

                "recommended_action":
                    (
                        "ESCALATE"
                        if risk_score >= 85
                        else
                        "INVESTIGATE"
                        if risk_score >= 70
                        else
                        "MONITOR"
                    ),
            },
        }

    # =========================================================
    # REAL DATABASE INCIDENT
    # =========================================================

    if entity_id.startswith(
        "incident:"
    ):

        try:
            incident_id = int(
                entity_id.split(
                    ":",
                    1,
                )[1]
            )
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid incident ID",
            )

        result = await db.execute(
            select(Incident).where(
                Incident.id
                == incident_id
            )
        )

        incident = (
            result.scalar_one_or_none()
        )

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Incident not found: "
                    f"{incident_id}"
                ),
            )

        risk_score = int(
            incident.risk_score or 0
        )

        entity = (
            _database_incident_context(
                incident
            )
        )

        related_entities = []
        relationships = []
        attack_chain = []

        # -----------------------------------------------------
        # SOURCE IP
        # -----------------------------------------------------

        if incident.source_ip:

            ip_id = (
                f"ip:{incident.source_ip}"
            )

            related_entities.append({
                "id":
                    ip_id,

                "type":
                    "IP",

                "label":
                    str(
                        incident.source_ip
                    ),

                "properties": {
                    "source":
                        "incident",
                },
            })

            relationships.append({
                "source":
                    ip_id,

                "target":
                    f"incident:{incident.id}",

                "type":
                    "INVOLVES",

                "confidence":
                    1.0,
            })

            attack_chain.append({
                "source": {
                    "id":
                        ip_id,

                    "type":
                        "IP",

                    "label":
                        str(
                            incident.source_ip
                        ),
                },

                "relationship":
                    "INVOLVES",

                "target": {
                    "id":
                        f"incident:{incident.id}",

                    "type":
                        "INCIDENT",

                    "label":
                        str(
                            incident.title
                        ),
                },

                "confidence":
                    1.0,
            })

        # -----------------------------------------------------
        # TARGET ASSET
        # -----------------------------------------------------

        if incident.target_asset:

            asset_id = (
                f"asset:{incident.target_asset}"
            )

            related_entities.append({
                "id":
                    asset_id,

                "type":
                    "ASSET",

                "label":
                    str(
                        incident.target_asset
                    ),

                "properties": {},
            })

            relationships.append({
                "source":
                    f"incident:{incident.id}",

                "target":
                    asset_id,

                "type":
                    "INVOLVES",

                "confidence":
                    1.0,
            })

            attack_chain.append({
                "source": {
                    "id":
                        f"incident:{incident.id}",

                    "type":
                        "INCIDENT",

                    "label":
                        str(
                            incident.title
                        ),
                },

                "relationship":
                    "TARGETS",

                "target": {
                    "id":
                        asset_id,

                    "type":
                        "ASSET",

                    "label":
                        str(
                            incident.target_asset
                        ),
                },

                "confidence":
                    1.0,
            })

        # -----------------------------------------------------
        # RELATED DETECTIONS
        # -----------------------------------------------------

        related_detections = []

        if incident.source_ip:

            detection_result = (
                await db.execute(
                    select(Detection)
                    .where(
                        Detection.source_ip
                        == incident.source_ip
                    )
                    .order_by(
                        Detection.created_at.asc()
                    )
                )
            )

            related_detections = (
                detection_result
                .scalars()
                .all()
            )

            for detection in related_detections:

                detection_entity = (
                    _database_detection_context(
                        detection
                    )
                )

                related_entities.append(
                    detection_entity
                )

                relationships.append({
                    "source":
                        f"detection:{detection.id}",

                    "target":
                        f"incident:{incident.id}",

                    "type":
                        "TRIGGERED",

                    "confidence":
                        float(
                            detection.confidence
                            or 0
                        ),
                })

                attack_chain.append({
                    "source": {
                        "id":
                            f"detection:{detection.id}",

                        "type":
                            "DETECTION",

                        "label":
                            str(
                                detection.detection_name
                            ),
                    },

                    "relationship":
                        "TRIGGERED",

                    "target": {
                        "id":
                            f"incident:{incident.id}",

                        "type":
                            "INCIDENT",

                        "label":
                            str(
                                incident.title
                            ),
                    },

                    "confidence":
                        float(
                            detection.confidence
                            or 0
                        ),
                })

        # -----------------------------------------------------
        # TIMELINE
        # -----------------------------------------------------

        timeline = (
            _build_incident_timeline(
                incident,
                related_detections,
            )
        )

        # -----------------------------------------------------
        # MITRE ATT&CK
        # -----------------------------------------------------

        mitre_ids = []

        # 1. Techniques explicitly stored on the incident.
        mitre_ids.extend(
            _parse_mitre_techniques(
                incident.mitre_techniques
            )
        )

        # 2. Techniques stored on correlated detections.
        for detection in related_detections:

            detection_mitre = getattr(
                detection,
                "mitre_technique",
                None,
            )

            if detection_mitre:
                mitre_ids.append(
                    str(detection_mitre)
                )

        # Remove duplicates while preserving order.
        mitre_ids = list(
            dict.fromkeys(
                str(item).strip()
                for item in mitre_ids
                if str(item).strip()
            )
        )

        mitre_entities = []

        for technique_id in mitre_ids:

            technique_entity = {
                "id":
                    f"mitre:{technique_id}",

                "type":
                    "MITRE_TECHNIQUE",

                "label":
                    technique_id,

                "properties": {
                    "source":
                        "incident_and_detections",

                    "incident_id":
                        incident.id,

                    "technique_id":
                        technique_id,
                },
            }

            mitre_entities.append(
                technique_entity
            )

            related_entities.append(
                technique_entity
            )

            relationships.append({
                "source":
                    f"incident:{incident.id}",

                "target":
                    f"mitre:{technique_id}",

                "type":
                    "MAPPED_TO",

                "confidence":
                    1.0,
            })

            attack_chain.append({
                "source": {
                    "id":
                        f"incident:{incident.id}",

                    "type":
                        "INCIDENT",

                    "label":
                        str(
                            incident.title
                        ),
                },

                "relationship":
                    "MAPPED_TO",

                "target": {
                    "id":
                        f"mitre:{technique_id}",

                    "type":
                        "MITRE_TECHNIQUE",

                    "label":
                        technique_id,
                },

                "confidence":
                    1.0,
            })

        # DEDUPLICATE RELATED ENTITIES
        # -----------------------------------------------------

        unique_entities = []
        seen_ids = set()

        for item in related_entities:

            item_id = str(
                item["id"]
            )

            if item_id in seen_ids:
                continue

            seen_ids.add(item_id)
            unique_entities.append(item)

        related_entities = unique_entities

        # -----------------------------------------------------
        # EVIDENCE CORRELATION
        # -----------------------------------------------------

        evidence_correlation = (
            _build_evidence_correlation(
                incident=incident,
                related_detections=related_detections,
                mitre_entities=mitre_entities,
                timeline=timeline,
            )
        )

        # -----------------------------------------------------
        # FINAL INCIDENT RESPONSE
        # -----------------------------------------------------

        return {
            "status":
                "INCIDENT_INVESTIGATION_READY",

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "entity": {
                **entity,

                "risk":
                    risk_score,

                "risk_level":
                    _risk_level(
                        risk_score
                    ),
            },

            "context": {
                "is_ioc": False,
                "is_ip": False,
                "is_detection": False,
                "is_incident": True,
                "is_mitre": False,
                "is_asset": False,
                "is_process": False,
                "is_domain": False,
            },

            "related_entities":
                related_entities,

            "relationships":
                relationships,

            "attack_chain":
                attack_chain,

            "mitre":
                mitre_entities,

            "iocs": [],

            "timeline":
                timeline,

            "evidence_correlation":
                evidence_correlation,

            "risk": {
                "entity_risk":
                    risk_score,

                "entity_risk_level":
                    _risk_level(
                        risk_score
                    ),

                "global_max_risk":
                    risk_score,
            },

            "investigation": {
                "related_entity_count":
                    len(
                        related_entities
                    ),

                "relationship_count":
                    len(
                        relationships
                    ),

                "attack_chain_count":
                    len(
                        attack_chain
                    ),

                "mitre_count":
                    len(
                        mitre_entities
                    ),

                "ioc_count":
                    0,

                "detection_count":
                    len(
                        related_detections
                    ),

                "timeline_count":
                    len(
                        timeline
                    ),

                "high_priority":
                    risk_score >= 70,

                "recommended_action":
                    (
                        "ESCALATE"
                        if risk_score >= 85
                        else
                        "INVESTIGATE"
                        if risk_score >= 70
                        else
                        "MONITOR"
                    ),
            },
        }

    # =========================================================
    # UNKNOWN ENTITY
    # =========================================================

    raise HTTPException(
        status_code=404,
        detail=f"Entity not found: {entity_id}",
    )


# =========================================================
# PHASE 7.9 — INVESTIGATION INTELLIGENCE
# =========================================================

@router.get("/investigation-intelligence/{entity_id:path}")
async def investigation_intelligence(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Build an analyst-oriented intelligence summary from
    the authoritative database investigation data.

    LAB / simulation only.
    """

    if not entity_id.startswith("incident:"):
        raise HTTPException(
            status_code=400,
            detail="Investigation intelligence currently supports incidents only.",
        )

    try:
        incident_id = int(
            entity_id.split(":", 1)[1]
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid incident ID",
        )

    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id
        )
    )

    incident = result.scalar_one_or_none()

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident not found: {incident_id}",
        )

    related_detections = []

    if incident.source_ip:
        detection_result = await db.execute(
            select(Detection)
            .where(
                Detection.source_ip
                == incident.source_ip
            )
            .order_by(
                Detection.created_at.asc()
            )
        )

        related_detections = (
            detection_result.scalars().all()
        )

    # -----------------------------------------------------
    # DETECTION INTELLIGENCE
    # -----------------------------------------------------

    detection_names = []
    detection_severities = []
    detection_confidences = []
    detection_ids = []

    for detection in related_detections:

        detection_ids.append(
            f"detection:{detection.id}"
        )

        if detection.detection_name:
            detection_names.append(
                str(detection.detection_name)
            )

        if detection.severity:
            detection_severities.append(
                str(detection.severity).upper()
            )

        try:
            detection_confidences.append(
                float(
                    detection.confidence or 0
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            pass

    detection_names = list(
        dict.fromkeys(
            detection_names
        )
    )

    detection_severities = list(
        dict.fromkeys(
            detection_severities
        )
    )

    # -----------------------------------------------------
    # MITRE INTELLIGENCE
    # -----------------------------------------------------

    mitre_ids = []

    mitre_ids.extend(
        _parse_mitre_techniques(
            incident.mitre_techniques
        )
    )

    for detection in related_detections:

        detection_mitre = getattr(
            detection,
            "mitre_technique",
            None,
        )

        if detection_mitre:
            mitre_ids.append(
                str(detection_mitre)
            )

    mitre_ids = list(
        dict.fromkeys(
            str(item).strip()
            for item in mitre_ids
            if str(item).strip()
        )
    )

    # -----------------------------------------------------
    # RISK INTELLIGENCE
    # -----------------------------------------------------

    risk_score = int(
        incident.risk_score or 0
    )

    risk_level = _risk_level(
        risk_score
    )

    if risk_score >= 85:
        risk_interpretation = (
            "The incident is in a critical risk range "
            "and requires immediate analyst attention."
        )
    elif risk_score >= 70:
        risk_interpretation = (
            "The incident is in a high risk range "
            "and requires active investigation."
        )
    elif risk_score >= 40:
        risk_interpretation = (
            "The incident is in a medium risk range "
            "and should remain under investigation."
        )
    else:
        risk_interpretation = (
            "The incident is currently in a lower "
            "risk range and should be monitored."
        )

    # -----------------------------------------------------
    # CORRELATION ANALYSIS
    # -----------------------------------------------------

    correlation_signals = []

    if incident.source_ip:
        correlation_signals.append(
            f"Incident source IP: {incident.source_ip}"
        )

    if incident.target_asset:
        correlation_signals.append(
            f"Target asset: {incident.target_asset}"
        )

    if len(related_detections) >= 2:
        correlation_signals.append(
            "Multiple detections are correlated to the same source IP."
        )
    elif len(related_detections) == 1:
        correlation_signals.append(
            "One detection is correlated to the incident source IP."
        )
    else:
        correlation_signals.append(
            "No detection records were correlated by source IP."
        )

    if len(mitre_ids) >= 2:
        correlation_signals.append(
            "Multiple MITRE ATT&CK techniques are associated with the activity."
        )
    elif len(mitre_ids) == 1:
        correlation_signals.append(
            "One MITRE ATT&CK technique is associated with the activity."
        )

    if incident.status:
        correlation_signals.append(
            f"Current incident status: {incident.status}."
        )

    # -----------------------------------------------------
    # EVIDENCE STRENGTH
    # -----------------------------------------------------

    evidence_points = 0

    if incident.source_ip:
        evidence_points += 1

    if incident.target_asset:
        evidence_points += 1

    if len(related_detections) >= 2:
        evidence_points += 2
    elif len(related_detections) == 1:
        evidence_points += 1

    if len(mitre_ids) >= 1:
        evidence_points += 1

    if incident.attack_story:
        evidence_points += 1

    if evidence_points >= 6:
        evidence_strength = "STRONG"
    elif evidence_points >= 3:
        evidence_strength = "MODERATE"
    else:
        evidence_strength = "LIMITED"

    # -----------------------------------------------------
    # CONFIDENCE
    # -----------------------------------------------------

    if detection_confidences:
        average_confidence = (
            sum(detection_confidences)
            / len(detection_confidences)
        )
    else:
        average_confidence = 0.0

    if (
        evidence_strength == "STRONG"
        and average_confidence >= 0.80
    ):
        investigation_confidence = "HIGH"
    elif (
        evidence_strength in {
            "STRONG",
            "MODERATE",
        }
        and average_confidence >= 0.50
    ):
        investigation_confidence = "MEDIUM"
    else:
        investigation_confidence = "LOW"

    # -----------------------------------------------------
    # KEY FINDINGS
    # -----------------------------------------------------

    key_findings = []

    key_findings.append(
        f"Incident {incident.id} has a risk score of {risk_score}."
    )

    if incident.source_ip:
        key_findings.append(
            f"Observed source: {incident.source_ip}."
        )

    if incident.target_asset:
        key_findings.append(
            f"Targeted asset: {incident.target_asset}."
        )

    if detection_names:
        key_findings.append(
            "Observed detections: "
            + ", ".join(detection_names)
            + "."
        )

    if mitre_ids:
        key_findings.append(
            "MITRE ATT&CK techniques: "
            + ", ".join(mitre_ids)
            + "."
        )

    if incident.attack_story:
        key_findings.append(
            f"Attack story: {incident.attack_story}"
        )

    # -----------------------------------------------------
    # ANALYST NEXT STEPS
    # -----------------------------------------------------

    analyst_next_steps = []

    if risk_score >= 85:
        analyst_next_steps.append(
            "Review the complete incident timeline immediately."
        )
        analyst_next_steps.append(
            "Validate the source IP and affected asset."
        )
        analyst_next_steps.append(
            "Review correlated detections and authentication activity."
        )
    elif risk_score >= 70:
        analyst_next_steps.append(
            "Continue investigation of the correlated detections."
        )
        analyst_next_steps.append(
            "Validate the source IP and target asset."
        )
    else:
        analyst_next_steps.append(
            "Continue monitoring the incident for additional evidence."
        )

    if mitre_ids:
        analyst_next_steps.append(
            "Review the mapped MITRE ATT&CK techniques for additional evidence."
        )

    if len(related_detections) >= 2:
        analyst_next_steps.append(
            "Compare detection timestamps to reconstruct the attack sequence."
        )

    analyst_next_steps.append(
        "Record analyst findings and disposition in the case workflow."
    )

    # -----------------------------------------------------
    # CONCLUSION
    # -----------------------------------------------------

    if (
        evidence_strength == "STRONG"
        and risk_score >= 85
    ):
        conclusion = (
            "The available telemetry provides strong correlated "
            "evidence for a high-priority security incident. "
            "The case should remain under active analyst investigation."
        )
    elif evidence_strength == "STRONG":
        conclusion = (
            "The available telemetry provides strong correlated "
            "evidence supporting the incident assessment."
        )
    elif evidence_strength == "MODERATE":
        conclusion = (
            "The available telemetry provides moderate evidence "
            "supporting the incident assessment. Additional validation "
            "would improve investigation confidence."
        )
    else:
        conclusion = (
            "The available telemetry is limited. Additional evidence "
            "should be collected before drawing a stronger conclusion."
        )

    return {
        "status":
            "INVESTIGATION_INTELLIGENCE_READY",

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "scope": {
            "mode": "LAB",
            "simulation_only": True,
            "entity_id": entity_id,
            "incident_id": incident.id,
        },

        "incident": {
            "id": incident.id,
            "incident_key": incident.incident_key,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "source_ip": incident.source_ip,
            "target_asset": incident.target_asset,
        },

        "risk": {
            "score": risk_score,
            "level": risk_level,
            "interpretation":
                risk_interpretation,
        },

        "evidence": {
            "strength":
                evidence_strength,

            "confidence":
                investigation_confidence,

            "evidence_points":
                evidence_points,

            "detection_count":
                len(related_detections),

            "detection_ids":
                detection_ids,

            "mitre_count":
                len(mitre_ids),

            "mitre_techniques":
                mitre_ids,

            "average_detection_confidence":
                round(
                    average_confidence,
                    3,
                ),
        },

        "correlation": {
            "source_ip":
                incident.source_ip,

            "target_asset":
                incident.target_asset,

            "detections":
                detection_names,

            "severities":
                detection_severities,

            "mitre_techniques":
                mitre_ids,

            "signals":
                correlation_signals,
        },

        "key_findings":
            key_findings,

        "analyst_next_steps":
            analyst_next_steps,

        "conclusion":
            conclusion,
    }
