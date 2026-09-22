from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Detection,
    Incident,
    SecurityEvent,
)
from app.intelligence.ioc_engine import lookup_ip


async def build_entity_graph(
    db: AsyncSession,
    incident_id: int,
):
    """
    Build an investigation entity graph for an incident.

    The graph connects:
        source IP
        IOC
        security events
        users
        processes
        detections
        incident
    """

    incident = await db.scalar(
        select(Incident).where(
            Incident.id == incident_id
        )
    )

    if not incident:
        return None

    source_ip = incident.source_ip

    nodes = []
    edges = []

    node_ids = set()

    def add_node(
        node_id: str,
        node_type: str,
        label: str,
        data: dict | None = None,
    ):
        if node_id in node_ids:
            return

        node_ids.add(node_id)

        nodes.append(
            {
                "id": node_id,
                "type": node_type,
                "label": label,
                "data": data or {},
            }
        )

    def add_edge(
        source: str,
        target: str,
        relationship: str,
    ):
        edges.append(
            {
                "source": source,
                "target": target,
                "relationship": relationship,
            }
        )

    # ========================================================
    # INCIDENT NODE
    # ========================================================

    incident_node = f"incident:{incident.id}"

    add_node(
        incident_node,
        "incident",
        incident.title,
        {
            "id": incident.id,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
        },
    )

    # ========================================================
    # SOURCE IP NODE
    # ========================================================

    if source_ip:

        source_node = f"ip:{source_ip}"

        add_node(
            source_node,
            "source_ip",
            source_ip,
            {
                "ip": source_ip,
            },
        )

        add_edge(
            source_node,
            incident_node,
            "associated_with",
        )

    else:
        source_node = None

    # ========================================================
    # IOC NODE
    # ========================================================

    if source_ip:

        ioc = await lookup_ip(
            db,
            source_ip,
        )

        if ioc:

            ioc_node = f"ioc:{ioc.id}"

            add_node(
                ioc_node,
                "ioc",
                ioc.value,
                {
                    "id": ioc.id,
                    "indicator_type": ioc.indicator_type,
                    "reputation": ioc.reputation,
                    "confidence": ioc.confidence,
                    "threat_type": ioc.threat_type,
                    "source": ioc.source,
                    "tags": ioc.tags or [],
                },
            )

            if source_node:
                add_edge(
                    source_node,
                    ioc_node,
                    "matches_ioc",
                )

    # ========================================================
    # SECURITY EVENTS
    # ========================================================

    events_result = await db.scalars(
        select(SecurityEvent)
        .where(
            SecurityEvent.source_ip == source_ip
        )
        .order_by(
            SecurityEvent.timestamp.asc()
        )
    )

    events = list(events_result)

    for event in events:

        event_node = f"event:{event.id}"

        add_node(
            event_node,
            "event",
            event.event_type,
            {
                "id": event.id,
                "event_type": event.event_type,
                "timestamp": (
                    event.timestamp.isoformat()
                    if event.timestamp
                    else None
                ),
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "destination_port": (
                    event.destination_port
                ),
                "username": event.username,
                "process_name": event.process_name,
                "protocol": event.protocol,
            },
        )

        if source_node:
            add_edge(
                source_node,
                event_node,
                "generated_event",
            )

        # ====================================================
        # USER
        # ====================================================

        if event.username:

            user_node = (
                f"user:{event.username}"
            )

            add_node(
                user_node,
                "user",
                event.username,
                {
                    "username": event.username,
                },
            )

            add_edge(
                event_node,
                user_node,
                "involves_user",
            )

        # ====================================================
        # PROCESS
        # ====================================================

        if event.process_name:

            process_node = (
                f"process:{event.process_name}"
            )

            add_node(
                process_node,
                "process",
                event.process_name,
                {
                    "process_name": (
                        event.process_name
                    ),
                    "command_line": (
                        event.command_line
                    ),
                },
            )

            add_edge(
                event_node,
                process_node,
                "observed_process",
            )

    # ========================================================
    # DETECTIONS
    # ========================================================

    detections_result = await db.scalars(
        select(Detection)
        .where(
            Detection.source_ip == source_ip
        )
        .order_by(
            Detection.created_at.asc()
        )
    )

    detections = list(
        detections_result
    )

    for detection in detections:

        detection_node = (
            f"detection:{detection.id}"
        )

        add_node(
            detection_node,
            "detection",
            detection.detection_name,
            {
                "id": detection.id,
                "name": detection.detection_name,
                "severity": detection.severity,
                "risk_score": detection.risk_score,
                "confidence": detection.confidence,
                "mitre_tactic": (
                    detection.mitre_tactic
                ),
                "mitre_technique": (
                    detection.mitre_technique
                ),
                "status": detection.status,
            },
        )

        if source_node:
            add_edge(
                source_node,
                detection_node,
                "triggered_detection",
            )

        if detection.event_id:

            event_node = (
                f"event:{detection.event_id}"
            )

            if event_node in node_ids:

                add_edge(
                    event_node,
                    detection_node,
                    "triggered",
                )

        add_edge(
            detection_node,
            incident_node,
            "contributes_to",
        )

    return {
        "incident_id": incident.id,
        "incident_key": incident.incident_key,
        "source_ip": source_ip,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }
