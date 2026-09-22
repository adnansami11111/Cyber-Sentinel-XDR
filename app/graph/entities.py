from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


VALID_ENTITY_TYPES = {
    "ASSET",
    "IP",
    "DOMAIN",
    "IOC",
    "USER",
    "PROCESS",
    "DETECTION",
    "INCIDENT",
    "MITRE_TECHNIQUE",
}


VALID_RELATIONSHIP_TYPES = {
    "SOURCE_OF",
    "TARGETS",
    "ASSOCIATED_WITH",
    "TRIGGERED",
    "INVOLVES",
    "EXECUTED_ON",
    "MAPPED_TO",
    "RELATED_TO",
}


@dataclass
class GraphEntity:
    entity_id: str
    entity_type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.entity_type = self.entity_type.upper()

        if self.entity_type not in VALID_ENTITY_TYPES:
            raise ValueError(
                f"Unsupported entity type: {self.entity_type}"
            )


@dataclass
class GraphRelationship:
    source_id: str
    target_id: str
    relationship_type: str
    confidence: float = 1.0
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.relationship_type = self.relationship_type.upper()

        if self.relationship_type not in VALID_RELATIONSHIP_TYPES:
            raise ValueError(
                f"Unsupported relationship type: "
                f"{self.relationship_type}"
            )

        self.confidence = max(
            0.0,
            min(float(self.confidence), 1.0),
        )


@dataclass
class EntityGraph:
    entities: dict[str, GraphEntity] = field(default_factory=dict)
    relationships: list[GraphRelationship] = field(
        default_factory=list
    )

    def add_entity(self, entity: GraphEntity) -> None:
        self.entities[entity.entity_id] = entity

    def add_relationship(
        self,
        relationship: GraphRelationship,
    ) -> None:
        if relationship.source_id not in self.entities:
            raise ValueError(
                f"Unknown source entity: "
                f"{relationship.source_id}"
            )

        if relationship.target_id not in self.entities:
            raise ValueError(
                f"Unknown target entity: "
                f"{relationship.target_id}"
            )

        self.relationships.append(relationship)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": [
                {
                    "id": entity.entity_id,
                    "type": entity.entity_type,
                    "label": entity.label,
                    "properties": entity.properties,
                }
                for entity in self.entities.values()
            ],
            "relationships": [
                {
                    "source": relationship.source_id,
                    "target": relationship.target_id,
                    "type": relationship.relationship_type,
                    "confidence": relationship.confidence,
                    "properties": relationship.properties,
                }
                for relationship in self.relationships
            ],
            "entity_count": len(self.entities),
            "relationship_count": len(self.relationships),
        }
