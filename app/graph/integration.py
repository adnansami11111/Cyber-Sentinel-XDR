from __future__ import annotations

from typing import Any

from app.graph.attack_paths import build_attack_path
from app.graph.entities import EntityGraph
from app.graph.extractor import extract_entities
from app.graph.risk import propagate_risk
from app.graph.relationships import (
    add_relationship,
    build_detection_relationships,
    relationship_summary,
)


def build_integrated_graph(
    *,
    incident_id: str | int,
    incident_title: str,
    detection_id: str | int,
    detection_name: str,
    source_ips: list[str] | None = None,
    destination_ips: list[str] | None = None,
    domains: list[str] | None = None,
    assets: list[dict[str, Any]] | None = None,
    processes: list[dict[str, Any]] | None = None,
    mitre_techniques: list[dict[str, str]] | None = None,
    iocs: list[dict[str, Any]] | None = None,
    incident_properties: dict[str, Any] | None = None,
    seed_risks: dict[str, int] | None = None,
) -> dict[str, Any]:

    graph = EntityGraph()

    source_ips = source_ips or []
    destination_ips = destination_ips or []
    domains = domains or []
    assets = assets or []
    processes = processes or []
    mitre_techniques = mitre_techniques or []
    iocs = iocs or []

    extracted_entities = extract_entities(
        ips=source_ips + destination_ips,
        domains=domains,
        detection={
            "id": detection_id,
            "name": detection_name,
            "properties": {},
        },
        incident={
            "id": incident_id,
            "title": incident_title,
            "properties": incident_properties or {},
        },
        mitre=mitre_techniques,
        assets=assets,
        processes=processes,
    )

    for entity in extracted_entities:
        graph.add_entity(entity)

    # Add IOC entities.
    for ioc in iocs:
        from app.graph.entities import GraphEntity

        entity_id = f"ioc:{ioc['id']}"

        graph.add_entity(
            GraphEntity(
                entity_id=entity_id,
                entity_type="IOC",
                label=ioc["value"],
                properties={
                    "indicator_type": ioc.get("indicator_type"),
                    "reputation": ioc.get(
                        "reputation",
                        "UNKNOWN",
                    ),
                    "confidence": ioc.get(
                        "confidence",
                        0,
                    ),
                },
            )
        )

    # Build normal detection relationships.
    build_detection_relationships(
        graph,
        source_ips=source_ips,
        destination_ips=destination_ips,
        domains=domains,
        detection_id=detection_id,
        incident_id=incident_id,
        mitre_techniques=[
            technique["id"]
            for technique in mitre_techniques
        ],
        asset_ids=[
            asset["id"]
            for asset in assets
        ],
        process_ids=[
            process["id"]
            for process in processes
        ],
    )

    # Connect IOCs to the incident.
    for ioc in iocs:
        add_relationship(
            graph,
            f"ioc:{ioc['id']}",
            f"incident:{incident_id}",
            "RELATED_TO",
            confidence=float(
                ioc.get("confidence", 0.80)
            ),
        )

    # Risk propagation.
    effective_seed_risks = seed_risks or {}

    risk_result = propagate_risk(
        graph,
        seed_risks=effective_seed_risks,
    )

    # Attack path.
    attack_path = build_attack_path(
        graph,
        source_ip=source_ips[0] if source_ips else "",
        incident_id=incident_id,
    )

    # Different attack-path implementations can expose
    # their result in slightly different shapes.
    # Normalize it here so the integration layer always
    # provides a stable "found" field.
    attack_path_found = bool(
        attack_path.get("found")
        or attack_path.get("path")
        or attack_path.get("nodes")
    )

    normalized_attack_path = dict(attack_path)
    normalized_attack_path["found"] = attack_path_found

    return {
        "status": "GRAPH_INTEGRATION_COMPLETE",

        "graph": {
            "entity_count": len(graph.entities),
            "relationship_count": len(
                graph.relationships
            ),
            "relationship_summary":
                relationship_summary(graph),
        },

        "entities": [
            {
                "id": entity.entity_id,
                "type": entity.entity_type,
                "label": entity.label,
                "properties": entity.properties,
            }
            for entity in graph.entities.values()
        ],

        "relationships": [
            {
                "source": relationship.source_id,
                "target": relationship.target_id,
                "type": relationship.relationship_type,
                "confidence": relationship.confidence,
            }
            for relationship in graph.relationships
        ],

        "attack_path": normalized_attack_path,

        "risk": risk_result,

        "validation": {
            "entities_present":
                len(graph.entities) > 0,

            "relationships_present":
                len(graph.relationships) > 0,

            "attack_path_found":
                attack_path_found,

            "risk_analysis_complete":
                bool(risk_result),
        },

        "_graph": graph,
    }
