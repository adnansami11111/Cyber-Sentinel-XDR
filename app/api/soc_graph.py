from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.graph import (
    _incident_risk_seeds,
    _refresh_db_graph,
)
from app.db.database import get_db
from app.graph.risk import propagate_risk


router = APIRouter(
    prefix="/api/soc",
    tags=["SOC Graph"],
)


@router.get("/graph")
async def soc_graph(
    db: AsyncSession = Depends(get_db),
):
    graph = await _refresh_db_graph(db)

    entities = []

    for entity_id, entity in graph.entities.items():
        entities.append({
            "id": str(entity_id),
            "type": str(entity.entity_type),
            "label": str(entity.label),
            "properties": entity.properties or {},
        })

    relationships = []

    for relationship in graph.relationships:
        relationships.append({
            "source":
                str(relationship.source_id),
            "target":
                str(relationship.target_id),
            "type":
                str(relationship.relationship_type),
            "confidence": float(
                getattr(
                    relationship,
                    "confidence",
                    1.0,
                )
                or 1.0
            ),
        })

    risk = propagate_risk(
        graph,
        seed_risks=_incident_risk_seeds(graph),
    )

    risk_by_entity = {}

    for item in risk.get(
        "high_risk_entities",
        [],
    ):
        if not isinstance(item, dict):
            continue

        entity_id = (
            item.get("entity_id")
            or item.get("id")
            or item.get("entity")
        )

        if entity_id is None:
            continue

        risk_by_entity[str(entity_id)] = (
            item.get(
                "risk_score",
                item.get(
                    "risk",
                    item.get(
                        "score",
                        0,
                    ),
                ),
            )
        )

    return {
        "status": "SOC_GRAPH_READY",
        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),
        "summary": {
            "entities": len(entities),
            "relationships":
                len(relationships),
            "max_risk": int(
                risk.get(
                    "max_risk",
                    0,
                )
            ),
            "high_risk":
                len(
                    risk.get(
                        "high_risk_entities",
                        [],
                    )
                ),
        },
        "entities": entities,
        "relationships": relationships,
        "risk": risk,
        "risk_by_entity":
            risk_by_entity,
    }
