from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Asset, Detection, Incident, IOC
from app.graph.attack_paths import (
    build_attack_path,
    enumerate_attack_paths,
)
from app.graph.entities import EntityGraph
from app.graph.incident import expand_incident_graph
from app.graph.risk import (
    get_high_risk_entities,
    propagate_risk,
)
from app.graph.relationships import relationship_summary


router = APIRouter(
    prefix="/api/graph",
    tags=["Entity Graph"],
)


GRAPH = EntityGraph()


async def _refresh_db_graph(
    db: AsyncSession,
) -> EntityGraph:
    """
    Rebuild the in-memory entity graph from the
    persistent Cyber Sentinel XDR database.

    The graph is intentionally rebuilt on each request
    so the SOC graph always reflects current DB state.
    """

    global GRAPH

    GRAPH = EntityGraph()

    incidents_result = await db.execute(
        select(Incident).order_by(Incident.id)
    )
    incidents = incidents_result.scalars().all()

    detections_result = await db.execute(
        select(Detection).order_by(Detection.id)
    )
    detections = detections_result.scalars().all()

    assets_result = await db.execute(
        select(Asset).order_by(Asset.id)
    )
    assets = assets_result.scalars().all()

    iocs_result = await db.execute(
        select(IOC).order_by(IOC.id)
    )
    iocs = iocs_result.scalars().all()

    asset_by_hostname = {
        asset.hostname: asset
        for asset in assets
        if asset.hostname
    }

    for incident in incidents:

        incident_asset = None

        if incident.target_asset:
            incident_asset = asset_by_hostname.get(
                incident.target_asset
            )

        incident_detections = [
            detection
            for detection in detections
            if (
                incident.source_ip
                and detection.source_ip
                and detection.source_ip
                == incident.source_ip
            )
        ]

        related_iocs = []

        for ioc in iocs:
            if (
                incident.source_ip
                and ioc.value
                and ioc.value
                == incident.source_ip
            ):
                related_iocs.append(ioc)

        assets_payload = []

        if incident_asset:
            assets_payload.append(
                {
                    "id": incident_asset.id,
                    "hostname": incident_asset.hostname,
                    "properties": {
                        "environment":
                            incident_asset.environment,
                        "asset_type":
                            incident_asset.asset_type,
                        "criticality":
                            incident_asset.criticality,
                        "ip_address":
                            incident_asset.ip_address,
                        "is_active":
                            incident_asset.is_active,
                    },
                }
            )

        if not incident_detections:
            expand_incident_graph(
                GRAPH,
                incident_id=incident.id,
                incident_title=incident.title,
                source_ips=(
                    [incident.source_ip]
                    if incident.source_ip
                    else []
                ),
                assets=assets_payload,
                incident_properties={
                    "severity": incident.severity,
                    "risk_score": incident.risk_score,
                    "status": incident.status,
                    "incident_key": incident.incident_key,
                },
            )
            continue

        for detection in incident_detections:

            mitre = []

            if detection.mitre_technique:
                mitre.append(
                    {
                        "id": detection.mitre_technique,
                        "name": detection.mitre_technique,
                    }
                )

            detection_iocs = [
                {
                    "id": ioc.id,
                    "value": ioc.value,
                    "indicator_type":
                        ioc.indicator_type,
                    "reputation":
                        ioc.reputation,
                    "confidence":
                        ioc.confidence,
                }
                for ioc in related_iocs
            ]

            expand_incident_graph(
                GRAPH,
                incident_id=incident.id,
                incident_title=incident.title,
                detection_id=detection.id,
                detection_name=detection.detection_name,
                source_ips=(
                    [detection.source_ip]
                    if detection.source_ip
                    else []
                ),
                destination_ips=(
                    [detection.destination_ip]
                    if detection.destination_ip
                    else []
                ),
                assets=assets_payload,
                mitre_techniques=mitre,
                iocs=detection_iocs,
                incident_properties={
                    "severity": incident.severity,
                    "risk_score": incident.risk_score,
                    "status": incident.status,
                    "incident_key": incident.incident_key,
                },
            )

    return GRAPH


def _incident_risk_seeds(
    graph: EntityGraph,
) -> dict[str, float]:
    seeds: dict[str, float] = {}

    for entity_id, entity in graph.entities.items():

        if entity.entity_type != "INCIDENT":
            continue

        risk_score = entity.properties.get(
            "risk_score",
            0,
        )

        try:
            risk_score = float(risk_score)
        except (TypeError, ValueError):
            risk_score = 0

        if risk_score > 0:
            seeds[str(entity_id)] = risk_score

    return seeds


@router.get("/summary")
async def graph_summary(
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    graph = await _refresh_db_graph(db)

    return {
        "status": "OPERATIONAL",
        "entity_count":
            len(graph.entities),
        "relationship_count":
            len(graph.relationships),
        "relationship_summary":
            relationship_summary(graph),
        "entities": [
            {
                "id": entity.entity_id,
                "type": entity.entity_type,
                "label": entity.label,
                "properties": entity.properties,
            }
            for entity in graph.entities.values()
        ],
    }


@router.get("/incident/{incident_id}")
async def incident_graph(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    graph = await _refresh_db_graph(db)

    incident_entity_id = (
        f"incident:{incident_id}"
    )

    if incident_entity_id not in graph.entities:
        raise HTTPException(
            status_code=404,
            detail="Incident graph not found",
        )

    incident = graph.entities[
        incident_entity_id
    ]

    connected_entities = set()

    for relationship in graph.relationships:

        if (
            relationship.source_id
            == incident_entity_id
        ):
            connected_entities.add(
                relationship.target_id
            )

        elif (
            relationship.target_id
            == incident_entity_id
        ):
            connected_entities.add(
                relationship.source_id
            )

    entities = [
        {
            "id": entity_id,
            "type":
                graph.entities[
                    entity_id
                ].entity_type,
            "label":
                graph.entities[
                    entity_id
                ].label,
            "properties":
                graph.entities[
                    entity_id
                ].properties,
        }
        for entity_id in connected_entities
        if entity_id in graph.entities
    ]

    relationships = [
        {
            "source":
                relationship.source_id,
            "target":
                relationship.target_id,
            "type":
                relationship.relationship_type,
            "confidence":
                relationship.confidence,
        }
        for relationship in graph.relationships
        if (
            relationship.source_id
            == incident_entity_id
            or relationship.target_id
            == incident_entity_id
        )
    ]

    return {
        "status": "INCIDENT_GRAPH_FOUND",
        "incident": {
            "id":
                incident.entity_id,
            "type":
                incident.entity_type,
            "label":
                incident.label,
            "properties":
                incident.properties,
        },
        "connected_entity_count":
            len(entities),
        "connected_entities":
            entities,
        "relationships":
            relationships,
    }


@router.get("/entity/{entity_id:path}")
async def entity_graph(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    graph = await _refresh_db_graph(db)

    if entity_id not in graph.entities:
        raise HTTPException(
            status_code=404,
            detail="Entity not found",
        )

    entity = graph.entities[entity_id]

    relationships = [
        {
            "source":
                relationship.source_id,
            "target":
                relationship.target_id,
            "type":
                relationship.relationship_type,
            "confidence":
                relationship.confidence,
        }
        for relationship in graph.relationships
        if (
            relationship.source_id == entity_id
            or relationship.target_id == entity_id
        )
    ]

    return {
        "status": "ENTITY_FOUND",
        "entity": {
            "id": entity.entity_id,
            "type": entity.entity_type,
            "label": entity.label,
            "properties": entity.properties,
        },
        "relationships": relationships,
    }


@router.get("/risk")
async def graph_risk(
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    graph = await _refresh_db_graph(db)

    risk = propagate_risk(
        graph,
        seed_risks=_incident_risk_seeds(graph),
    )

    return {
        "status": "RISK_ANALYSIS_COMPLETE",
        "threshold": 70,
        **risk,
    }


@router.get("/high-risk")
async def graph_high_risk(
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    graph = await _refresh_db_graph(db)

    risk = propagate_risk(
        graph,
        seed_risks=_incident_risk_seeds(graph),
    )

    return {
        "status": "HIGH_RISK_ANALYSIS_COMPLETE",
        "entities": get_high_risk_entities(
            risk
        ),
    }


@router.get("/attack-path")
async def graph_attack_path(
    source: str,
    target: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    graph = await _refresh_db_graph(db)

    return build_attack_path(
        graph,
        source,
        target,
    )


@router.get("/attack-paths")
async def graph_attack_paths(
    source: str,
    target: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:

    graph = await _refresh_db_graph(db)

    return enumerate_attack_paths(
        graph,
        source,
        target,
    )
