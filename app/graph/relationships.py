from __future__ import annotations

from typing import Any

from app.graph.entities import (
    EntityGraph,
    GraphRelationship,
)


def add_relationship(
    graph: EntityGraph,
    source_id: str,
    target_id: str,
    relationship_type: str,
    confidence: float = 1.0,
    properties: dict[str, Any] | None = None,
) -> None:
    if source_id not in graph.entities:
        return

    if target_id not in graph.entities:
        return

    graph.add_relationship(
        GraphRelationship(
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type,
            confidence=confidence,
            properties=properties or {},
        )
    )


def build_detection_relationships(
    graph: EntityGraph,
    *,
    source_ips: list[str] | None = None,
    destination_ips: list[str] | None = None,
    domains: list[str] | None = None,
    detection_id: str | int | None = None,
    incident_id: str | int | None = None,
    mitre_techniques: list[str] | None = None,
    asset_ids: list[str | int] | None = None,
    process_ids: list[str | int] | None = None,
) -> dict[str, Any]:

    relationships_before = len(graph.relationships)

    detection_entity_id = (
        f"detection:{detection_id}"
        if detection_id is not None
        else None
    )

    incident_entity_id = (
        f"incident:{incident_id}"
        if incident_id is not None
        else None
    )

    # Source IP -> Detection
    for ip in source_ips or []:
        add_relationship(
            graph,
            f"ip:{ip.strip()}",
            detection_entity_id,
            "SOURCE_OF",
            confidence=0.95,
        )

    # Destination IP -> Detection
    for ip in destination_ips or []:
        add_relationship(
            graph,
            detection_entity_id,
            f"ip:{ip.strip()}",
            "TARGETS",
            confidence=0.90,
        )

    # Domain -> Detection
    for domain in domains or []:
        add_relationship(
            graph,
            f"domain:{domain.strip().lower()}",
            detection_entity_id,
            "ASSOCIATED_WITH",
            confidence=0.85,
        )

    # Detection -> Incident
    if detection_entity_id and incident_entity_id:
        add_relationship(
            graph,
            detection_entity_id,
            incident_entity_id,
            "TRIGGERED",
            confidence=0.90,
        )

    # Detection -> MITRE
    for technique_id in mitre_techniques or []:
        add_relationship(
            graph,
            detection_entity_id,
            f"mitre:{technique_id}",
            "MAPPED_TO",
            confidence=0.95,
        )

    # Detection -> Asset
    for asset_id in asset_ids or []:
        add_relationship(
            graph,
            detection_entity_id,
            f"asset:{asset_id}",
            "INVOLVES",
            confidence=0.90,
        )

    # Process -> Asset
    for process_id in process_ids or []:
        for asset_id in asset_ids or []:
            add_relationship(
                graph,
                f"process:{process_id}",
                f"asset:{asset_id}",
                "EXECUTED_ON",
                confidence=0.85,
            )

    # Incident -> Source IP
    for ip in source_ips or []:
        add_relationship(
            graph,
            incident_entity_id,
            f"ip:{ip.strip()}",
            "INVOLVES",
            confidence=0.90,
        )

    relationships_added = (
        len(graph.relationships) - relationships_before
    )

    return {
        "relationships_added": relationships_added,
        "total_relationships": len(graph.relationships),
    }


def build_domain_ip_relationships(
    graph: EntityGraph,
    domain_ip_map: dict[str, list[str]],
) -> int:

    relationships_before = len(graph.relationships)

    for domain, ips in domain_ip_map.items():
        domain_id = f"domain:{domain.strip().lower()}"

        for ip in ips:
            add_relationship(
                graph,
                domain_id,
                f"ip:{ip.strip()}",
                "ASSOCIATED_WITH",
                confidence=0.80,
            )

    return len(graph.relationships) - relationships_before


def relationship_summary(
    graph: EntityGraph,
) -> dict[str, Any]:

    counts: dict[str, int] = {}

    for relationship in graph.relationships:
        relationship_type = relationship.relationship_type

        counts[relationship_type] = (
            counts.get(relationship_type, 0) + 1
        )

    return {
        "total_relationships": len(graph.relationships),
        "by_type": counts,
    }
