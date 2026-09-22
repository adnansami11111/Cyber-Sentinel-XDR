from __future__ import annotations

from typing import Any

from app.graph.entities import EntityGraph, GraphEntity
from app.graph.relationships import build_detection_relationships


def expand_incident_graph(
    graph: EntityGraph,
    *,
    incident_id: str | int,
    incident_title: str,
    detection_id: str | int | None = None,
    detection_name: str | None = None,
    source_ips: list[str] | None = None,
    destination_ips: list[str] | None = None,
    domains: list[str] | None = None,
    assets: list[dict[str, Any]] | None = None,
    processes: list[dict[str, Any]] | None = None,
    mitre_techniques: list[dict[str, str]] | None = None,
    iocs: list[dict[str, Any]] | None = None,
    incident_properties: dict[str, Any] | None = None,
) -> dict[str, Any]:

    incident_entity_id = f"incident:{incident_id}"

    # --------------------------------
    # Incident
    # --------------------------------

    if incident_entity_id not in graph.entities:

        graph.add_entity(
            GraphEntity(
                entity_id=incident_entity_id,
                entity_type="INCIDENT",
                label=incident_title,
                properties=incident_properties or {},
            )
        )

    # --------------------------------
    # Detection
    # --------------------------------

    if (
        detection_id is not None
        and detection_name
    ):

        detection_entity_id = (
            f"detection:{detection_id}"
        )

        if detection_entity_id not in graph.entities:

            graph.add_entity(
                GraphEntity(
                    entity_id=detection_entity_id,
                    entity_type="DETECTION",
                    label=detection_name,
                )
            )

    # --------------------------------
    # Source IP entities
    # --------------------------------

    for ip in source_ips or []:

        entity_id = f"ip:{ip.strip()}"

        if entity_id not in graph.entities:

            graph.add_entity(
                GraphEntity(
                    entity_id=entity_id,
                    entity_type="IP",
                    label=ip.strip(),
                    properties={
                        "role": "SOURCE",
                    },
                )
            )

    # --------------------------------
    # Destination IP entities
    # --------------------------------

    for ip in destination_ips or []:

        entity_id = f"ip:{ip.strip()}"

        if entity_id not in graph.entities:

            graph.add_entity(
                GraphEntity(
                    entity_id=entity_id,
                    entity_type="IP",
                    label=ip.strip(),
                    properties={
                        "role": "DESTINATION",
                    },
                )
            )

    # --------------------------------
    # Domain entities
    # --------------------------------

    for domain in domains or []:

        normalized = domain.strip().lower()

        entity_id = f"domain:{normalized}"

        if entity_id not in graph.entities:

            graph.add_entity(
                GraphEntity(
                    entity_id=entity_id,
                    entity_type="DOMAIN",
                    label=normalized,
                )
            )

    # --------------------------------
    # Asset entities
    # --------------------------------

    asset_ids = []

    for asset in assets or []:

        asset_id = asset["id"]

        entity_id = f"asset:{asset_id}"

        asset_ids.append(asset_id)

        if entity_id not in graph.entities:

            graph.add_entity(
                GraphEntity(
                    entity_id=entity_id,
                    entity_type="ASSET",
                    label=asset["hostname"],
                    properties=asset.get(
                        "properties",
                        {},
                    ),
                )
            )

    # --------------------------------
    # Process entities
    # --------------------------------

    process_ids = []

    for process in processes or []:

        process_id = process["id"]

        entity_id = f"process:{process_id}"

        process_ids.append(process_id)

        if entity_id not in graph.entities:

            graph.add_entity(
                GraphEntity(
                    entity_id=entity_id,
                    entity_type="PROCESS",
                    label=process["name"],
                    properties=process.get(
                        "properties",
                        {},
                    ),
                )
            )

    # --------------------------------
    # MITRE entities
    # --------------------------------

    mitre_ids = []

    for technique in (
        mitre_techniques or []
    ):

        technique_id = technique["id"]

        entity_id = (
            f"mitre:{technique_id}"
        )

        mitre_ids.append(
            technique_id
        )

        if entity_id not in graph.entities:

            graph.add_entity(
                GraphEntity(
                    entity_id=entity_id,
                    entity_type="MITRE_TECHNIQUE",
                    label=technique["name"],
                    properties={
                        "technique_id":
                            technique_id,
                    },
                )
            )

    # --------------------------------
    # IOC entities
    # --------------------------------

    for ioc in iocs or []:

        ioc_id = ioc["id"]

        entity_id = f"ioc:{ioc_id}"

        if entity_id not in graph.entities:

            graph.add_entity(
                GraphEntity(
                    entity_id=entity_id,
                    entity_type="IOC",
                    label=ioc["value"],
                    properties={
                        "indicator_type":
                            ioc.get(
                                "indicator_type"
                            ),
                        "reputation":
                            ioc.get(
                                "reputation",
                                "UNKNOWN",
                            ),
                        "confidence":
                            ioc.get(
                                "confidence",
                                0,
                            ),
                    },
                )
            )

    # --------------------------------
    # Detection relationships
    # --------------------------------

    relationship_result = {
        "relationships_added": 0,
        "total_relationships":
            len(graph.relationships),
    }

    if detection_id is not None:

        relationship_result = (
            build_detection_relationships(
                graph,

                source_ips=source_ips,

                destination_ips=
                    destination_ips,

                domains=domains,

                detection_id=
                    detection_id,

                incident_id=
                    incident_id,

                mitre_techniques=
                    mitre_ids,

                asset_ids=
                    asset_ids,

                process_ids=
                    process_ids,
            )
        )

    # --------------------------------
    # IOC -> Incident relationships
    # --------------------------------

    ioc_relationships = 0

    for ioc in iocs or []:

        ioc_entity_id = (
            f"ioc:{ioc['id']}"
        )

        before = len(
            graph.relationships
        )

        if ioc_entity_id in graph.entities:

            from app.graph.relationships import (
                add_relationship,
            )

            add_relationship(
                graph,
                ioc_entity_id,
                incident_entity_id,
                "RELATED_TO",
                confidence=float(
                    ioc.get(
                        "confidence",
                        0.80,
                    )
                ),
            )

        ioc_relationships += (
            len(graph.relationships)
            - before
        )

    # --------------------------------
    # Summary
    # --------------------------------

    entity_counts: dict[str, int] = {}

    for entity in graph.entities.values():

        entity_counts[
            entity.entity_type
        ] = (
            entity_counts.get(
                entity.entity_type,
                0,
            )
            + 1
        )

    return {
        "status": "INCIDENT_GRAPH_EXPANDED",
        "incident_id": incident_id,
        "incident_entity":
            incident_entity_id,
        "entity_count":
            len(graph.entities),
        "relationship_count":
            len(graph.relationships),
        "entity_counts":
            entity_counts,
        "detection_relationships":
            relationship_result,
        "ioc_relationships":
            ioc_relationships,
    }
