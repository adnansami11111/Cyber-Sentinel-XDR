from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.graph.entities import EntityGraph


ENTITY_BASE_RISK = {
    "IP": 60,
    "DOMAIN": 55,
    "IOC": 65,
    "DETECTION": 70,
    "INCIDENT": 80,
    "ASSET": 50,
    "PROCESS": 45,
    "USER": 40,
    "MITRE_TECHNIQUE": 30,
}


REPUTATION_RISK = {
    "MALICIOUS": 100,
    "SUSPICIOUS": 70,
    "BENIGN": 10,
    "UNKNOWN": 0,
}


def clamp_risk(value: float) -> int:
    return max(
        0,
        min(
            100,
            int(round(value)),
        ),
    )


def risk_level(score: int) -> str:
    if score >= 85:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "UNKNOWN"


def calculate_entity_base_risk(
    entity_type: str,
    properties: dict[str, Any] | None = None,
) -> int:

    properties = properties or {}

    risk = ENTITY_BASE_RISK.get(
        entity_type.upper(),
        30,
    )

    reputation = str(
        properties.get(
            "reputation",
            "UNKNOWN",
        )
    ).upper()

    if reputation in REPUTATION_RISK:
        reputation_score = REPUTATION_RISK[
            reputation
        ]

        risk = max(
            risk,
            reputation_score,
        )

    explicit_risk = properties.get(
        "risk_score"
    )

    if explicit_risk is not None:

        try:
            risk = max(
                risk,
                float(explicit_risk),
            )
        except (
            TypeError,
            ValueError,
        ):
            pass

    severity = str(
        properties.get(
            "severity",
            "",
        )
    ).upper()

    severity_bonus = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 5,
        "LOW": 0,
    }

    risk += severity_bonus.get(
        severity,
        0,
    )

    return clamp_risk(risk)


def build_risk_adjacency(
    graph: EntityGraph,
) -> dict[str, list[dict[str, Any]]]:

    adjacency: dict[
        str,
        list[dict[str, Any]]
    ] = defaultdict(list)

    for relationship in graph.relationships:

        adjacency[
            relationship.source_id
        ].append(
            {
                "target":
                    relationship.target_id,
                "type":
                    relationship.relationship_type,
                "confidence":
                    relationship.confidence,
            }
        )

        # Treat graph edges as traversable in
        # both directions for risk propagation.
        adjacency[
            relationship.target_id
        ].append(
            {
                "target":
                    relationship.source_id,
                "type":
                    relationship.relationship_type,
                "confidence":
                    relationship.confidence,
            }
        )

    return dict(adjacency)


def propagate_risk(
    graph: EntityGraph,
    *,
    seed_risks: dict[str, int] | None = None,
    max_depth: int = 5,
    decay: float = 0.75,
) -> dict[str, Any]:

    seed_risks = seed_risks or {}

    adjacency = build_risk_adjacency(
        graph
    )

    risks: dict[str, float] = {}

    sources: dict[
        str,
        list[dict[str, Any]]
    ] = defaultdict(list)

    # -----------------------------
    # Initial entity risk
    # -----------------------------

    for entity_id, entity in graph.entities.items():

        risks[entity_id] = (
            calculate_entity_base_risk(
                entity.entity_type,
                entity.properties,
            )
        )

    # -----------------------------
    # Explicit seed risk
    # -----------------------------

    for entity_id, score in seed_risks.items():

        if entity_id not in graph.entities:
            continue

        risks[entity_id] = max(
            risks[entity_id],
            clamp_risk(score),
        )

        sources[entity_id].append(
            {
                "source": entity_id,
                "score": clamp_risk(score),
                "depth": 0,
                "reason": "SEED_RISK",
            }
        )

    # -----------------------------
    # Propagation
    # -----------------------------

    frontier = []

    for entity_id, score in risks.items():

        if score <= 0:
            continue

        frontier.append(
            (
                entity_id,
                float(score),
                0,
                [entity_id],
            )
        )

    visited = set()

    while frontier:

        current, current_risk, depth, path = (
            frontier.pop(0)
        )

        if depth >= max_depth:
            continue

        for edge in adjacency.get(
            current,
            [],
        ):

            target = edge["target"]

            if target in path:
                continue

            confidence = float(
                edge["confidence"]
            )

            propagated = (
                current_risk
                * confidence
                * decay
            )

            if propagated < 5:
                continue

            old_risk = risks.get(
                target,
                0,
            )

            if propagated > old_risk:

                risks[target] = min(
                    100,
                    propagated,
                )

                sources[target].append(
                    {
                        "source": current,
                        "score": round(
                            propagated,
                            2,
                        ),
                        "depth": depth + 1,
                        "relationship":
                            edge["type"],
                        "confidence":
                            confidence,
                        "path":
                            path
                            + [target],
                    }
                )

                frontier.append(
                    (
                        target,
                        propagated,
                        depth + 1,
                        path + [target],
                    )
                )

    # -----------------------------
    # Build result
    # -----------------------------

    entities = []

    for entity_id, entity in graph.entities.items():

        score = clamp_risk(
            risks.get(
                entity_id,
                0,
            )
        )

        entities.append(
            {
                "id": entity_id,
                "type": entity.entity_type,
                "label": entity.label,
                "risk_score": score,
                "risk_level":
                    risk_level(score),
                "risk_sources":
                    sources.get(
                        entity_id,
                        [],
                    ),
            }
        )

    entities.sort(
        key=lambda item:
            item["risk_score"],
        reverse=True,
    )

    return {
        "entities": entities,
        "entity_count": len(entities),
        "max_risk": (
            entities[0]["risk_score"]
            if entities
            else 0
        ),
        "high_risk_entities": [
            entity
            for entity in entities
            if entity["risk_score"] >= 70
        ],
    }


def get_high_risk_entities(
    graph: EntityGraph,
    *,
    threshold: int = 70,
    seed_risks: dict[str, int] | None = None,
) -> list[dict[str, Any]]:

    result = propagate_risk(
        graph,
        seed_risks=seed_risks,
    )

    return [
        entity
        for entity in result["entities"]
        if entity["risk_score"]
        >= threshold
    ]
