from __future__ import annotations

import ipaddress
import re
from typing import Any

from app.graph.entities import GraphEntity


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def _entity_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{value}"


def extract_ip_entities(
    ips: list[str] | None,
) -> list[GraphEntity]:
    entities: list[GraphEntity] = []

    for value in ips or []:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue

        entities.append(
            GraphEntity(
                entity_id=_entity_id("ip", ip),
                entity_type="IP",
                label=str(ip),
                properties={
                    "version": ip.version,
                    "is_private": ip.is_private,
                    "is_global": ip.is_global,
                    "is_loopback": ip.is_loopback,
                },
            )
        )

    return entities


def extract_domain_entities(
    domains: list[str] | None,
) -> list[GraphEntity]:
    entities: list[GraphEntity] = []

    for domain in domains or []:
        domain = str(domain).strip().lower()

        if not DOMAIN_PATTERN.match(domain):
            continue

        entities.append(
            GraphEntity(
                entity_id=_entity_id(
                    "domain",
                    domain,
                ),
                entity_type="DOMAIN",
                label=domain,
                properties={},
            )
        )

    return entities


def extract_detection_entity(
    detection: dict[str, Any] | None,
) -> list[GraphEntity]:
    if not detection:
        return []

    detection_id = detection.get("id")
    name = detection.get(
        "name",
        f"Detection {detection_id}",
    )

    return [
        GraphEntity(
            entity_id=_entity_id(
                "detection",
                detection_id,
            ),
            entity_type="DETECTION",
            label=str(name),
            properties=detection.get(
                "properties",
                {},
            ),
        )
    ]


def extract_incident_entity(
    incident: dict[str, Any] | None,
) -> list[GraphEntity]:
    if not incident:
        return []

    incident_id = incident.get("id")
    title = incident.get(
        "title",
        f"Incident {incident_id}",
    )

    return [
        GraphEntity(
            entity_id=_entity_id(
                "incident",
                incident_id,
            ),
            entity_type="INCIDENT",
            label=str(title),
            properties=incident.get(
                "properties",
                {},
            ),
        )
    ]


def extract_mitre_entity(
    techniques: list[dict[str, Any]] | None,
) -> list[GraphEntity]:
    entities: list[GraphEntity] = []

    for technique in techniques or []:
        technique_id = technique.get("id")

        if not technique_id:
            continue

        entities.append(
            GraphEntity(
                entity_id=_entity_id(
                    "mitre",
                    technique_id,
                ),
                entity_type="MITRE_TECHNIQUE",
                label=str(
                    technique.get(
                        "name",
                        technique_id,
                    )
                ),
                properties={
                    "technique_id": technique_id,
                    "tactic": technique.get(
                        "tactic"
                    ),
                },
            )
        )

    return entities


def extract_asset_entity(
    assets: list[dict[str, Any]] | None,
) -> list[GraphEntity]:
    entities: list[GraphEntity] = []

    for asset in assets or []:
        asset_id = asset.get("id")

        if asset_id is None:
            continue

        # Accept multiple common asset schemas.
        hostname = asset.get("hostname")
        name = asset.get("name")
        asset_label = (
            hostname
            or name
            or f"Asset {asset_id}"
        )

        entities.append(
            GraphEntity(
                entity_id=_entity_id(
                    "asset",
                    asset_id,
                ),
                entity_type="ASSET",
                label=str(asset_label),
                properties={
                    "hostname": hostname,
                    "name": name,
                    "ip_address": asset.get(
                        "ip_address"
                    ),
                    "os": asset.get("os"),
                    "asset_type": asset.get(
                        "asset_type"
                    ),
                },
            )
        )

    return entities


def extract_process_entity(
    processes: list[dict[str, Any]] | None,
) -> list[GraphEntity]:
    entities: list[GraphEntity] = []

    for process in processes or []:
        process_id = process.get("id")

        if process_id is None:
            continue

        process_name = process.get(
            "name",
            process.get(
                "process_name",
                f"Process {process_id}",
            ),
        )

        entities.append(
            GraphEntity(
                entity_id=_entity_id(
                    "process",
                    process_id,
                ),
                entity_type="PROCESS",
                label=str(process_name),
                properties={
                    "pid": process.get("pid"),
                    "name": process_name,
                    "command_line": process.get(
                        "command_line"
                    ),
                    "user": process.get("user"),
                },
            )
        )

    return entities


def extract_entities(
    *,
    ips: list[str] | None = None,
    domains: list[str] | None = None,
    detection: dict[str, Any] | None = None,
    incident: dict[str, Any] | None = None,
    mitre: list[dict[str, Any]] | None = None,
    assets: list[dict[str, Any]] | None = None,
    processes: list[dict[str, Any]] | None = None,
) -> list[GraphEntity]:
    entities: list[GraphEntity] = []

    entities.extend(
        extract_ip_entities(ips)
    )

    entities.extend(
        extract_domain_entities(domains)
    )

    entities.extend(
        extract_detection_entity(detection)
    )

    entities.extend(
        extract_incident_entity(incident)
    )

    entities.extend(
        extract_mitre_entity(mitre)
    )

    entities.extend(
        extract_asset_entity(assets)
    )

    entities.extend(
        extract_process_entity(processes)
    )

    # Deduplicate by entity ID.
    unique: dict[str, GraphEntity] = {}

    for entity in entities:
        unique[entity.entity_id] = entity

    return list(unique.values())
