from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from app.graph.entities import EntityGraph


def build_adjacency(
    graph: EntityGraph,
) -> dict[str, list[dict[str, Any]]]:

    adjacency: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for relationship in graph.relationships:
        adjacency[relationship.source_id].append(
            {
                "target": relationship.target_id,
                "type": relationship.relationship_type,
                "confidence": relationship.confidence,
            }
        )

    return dict(adjacency)


def find_attack_path(
    graph: EntityGraph,
    start_entity: str,
    target_entity: str,
    max_depth: int = 10,
) -> dict[str, Any]:

    if start_entity not in graph.entities:
        return {
            "found": False,
            "reason": f"Unknown start entity: {start_entity}",
            "path": [],
        }

    if target_entity not in graph.entities:
        return {
            "found": False,
            "reason": f"Unknown target entity: {target_entity}",
            "path": [],
        }

    adjacency = build_adjacency(graph)

    queue = deque(
        [
            (
                start_entity,
                [start_entity],
                [],
                [],
            )
        ]
    )

    visited = {
        start_entity,
    }

    while queue:

        current, path, relationships, confidences = queue.popleft()

        if current == target_entity:

            path_confidence = (
                min(confidences)
                if confidences
                else 1.0
            )

            return {
                "found": True,
                "start": start_entity,
                "target": target_entity,
                "depth": len(path) - 1,
                "path": path,
                "relationships": relationships,
                "confidence": round(
                    path_confidence,
                    4,
                ),
            }

        if len(path) - 1 >= max_depth:
            continue

        for edge in adjacency.get(current, []):

            target = edge["target"]

            if target in visited:
                continue

            visited.add(target)

            queue.append(
                (
                    target,
                    path + [target],
                    relationships
                    + [
                        edge["type"]
                    ],
                    confidences
                    + [
                        edge["confidence"]
                    ],
                )
            )

    return {
        "found": False,
        "start": start_entity,
        "target": target_entity,
        "depth": None,
        "path": [],
        "relationships": [],
        "confidence": 0.0,
    }


def build_attack_path(
    graph: EntityGraph,
    *,
    source_ip: str,
    incident_id: str | int,
    max_depth: int = 10,
) -> dict[str, Any]:

    start_entity = f"ip:{source_ip}"
    target_entity = f"incident:{incident_id}"

    result = find_attack_path(
        graph,
        start_entity,
        target_entity,
        max_depth=max_depth,
    )

    if not result["found"]:
        return {
            "status": "NO_ATTACK_PATH",
            **result,
        }

    entities = []

    for entity_id in result["path"]:

        entity = graph.entities.get(entity_id)

        if not entity:
            continue

        entities.append(
            {
                "id": entity.entity_id,
                "type": entity.entity_type,
                "label": entity.label,
            }
        )

    return {
        "status": "ATTACK_PATH_FOUND",
        "source": source_ip,
        "incident_id": incident_id,
        "depth": result["depth"],
        "confidence": result["confidence"],
        "entities": entities,
        "relationships": result[
            "relationships"
        ],
        "path": result["path"],
    }


def enumerate_attack_paths(
    graph: EntityGraph,
    *,
    start_entity: str,
    target_types: set[str],
    max_depth: int = 10,
) -> list[dict[str, Any]]:

    adjacency = build_adjacency(graph)

    results: list[dict[str, Any]] = []

    queue = deque(
        [
            (
                start_entity,
                [start_entity],
                [],
                [],
            )
        ]
    )

    visited_paths: set[
        tuple[str, ...]
    ] = set()

    while queue:

        current, path, relationships, confidences = queue.popleft()

        if len(path) - 1 > max_depth:
            continue

        if (
            current != start_entity
            and graph.entities[current].entity_type
            in target_types
        ):

            path_key = tuple(path)

            if path_key not in visited_paths:

                visited_paths.add(path_key)

                results.append(
                    {
                        "target": current,
                        "target_type": graph.entities[
                            current
                        ].entity_type,
                        "path": path,
                        "relationships": relationships,
                        "confidence": round(
                            min(confidences)
                            if confidences
                            else 1.0,
                            4,
                        ),
                        "depth": len(path) - 1,
                    }
                )

        for edge in adjacency.get(current, []):

            target = edge["target"]

            if target in path:
                continue

            queue.append(
                (
                    target,
                    path + [target],
                    relationships
                    + [
                        edge["type"]
                    ],
                    confidences
                    + [
                        edge["confidence"]
                    ],
                )
            )

    return results
