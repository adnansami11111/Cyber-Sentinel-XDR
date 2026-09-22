from datetime import datetime, timedelta

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import SecurityEvent
from app.detection.registry import get_rules
from app.api.rule_control import (
    get_rule_threshold,
    is_rule_enabled,
)


EVENT_RULE_NAMES = {
    "authentication_failure": [
        "SSH Brute Force",
    ],
    "authentication_success": [
        "Suspicious Authentication Success",
    ],
    "network_connection": [
        "Network Port Scan",
    ],
    "process_start": [
        "Suspicious Network Utility",
    ],
}


async def _threshold_reached(
    db: AsyncSession,
    event: SecurityEvent,
    detection_name: str,
) -> bool:
    threshold = await get_rule_threshold(
        db,
        detection_name,
    )

    # A threshold of 1 means the current event
    # is sufficient to evaluate the detection.
    if threshold <= 1:
        return True

    if not event.source_ip:
        return False

    cutoff = datetime.utcnow() - timedelta(
        minutes=settings.CORRELATION_WINDOW_MINUTES
    )

    # --------------------------------------------------
    # SSH Brute Force
    # --------------------------------------------------
    if detection_name == "SSH Brute Force":
        result = await db.scalar(
            select(func.count(SecurityEvent.id))
            .where(
                SecurityEvent.event_type
                == "authentication_failure",
                SecurityEvent.source_ip
                == event.source_ip,
                SecurityEvent.created_at >= cutoff,
            )
        )

        count = result or 0

        return count >= threshold

    # --------------------------------------------------
    # Network Port Scan
    # --------------------------------------------------
    if detection_name == "Network Port Scan":
        result = await db.execute(
            select(
                distinct(
                    SecurityEvent.destination_port
                )
            )
            .where(
                SecurityEvent.event_type
                == "network_connection",
                SecurityEvent.source_ip
                == event.source_ip,
                SecurityEvent.destination_port.is_not(None),
                SecurityEvent.created_at >= cutoff,
            )
        )

        ports = {
            row[0]
            for row in result.all()
            if row[0] is not None
        }

        return len(ports) >= threshold

    # --------------------------------------------------
    # Suspicious Authentication Success
    #
    # Threshold represents the number of recent
    # authentication failures associated with the
    # successful authentication.
    # --------------------------------------------------
    if (
        detection_name
        == "Suspicious Authentication Success"
    ):
        result = await db.scalar(
            select(func.count(SecurityEvent.id))
            .where(
                SecurityEvent.event_type
                == "authentication_failure",
                SecurityEvent.source_ip
                == event.source_ip,
                SecurityEvent.created_at >= cutoff,
            )
        )

        count = result or 0

        return count >= threshold

    # --------------------------------------------------
    # Suspicious Network Utility
    # --------------------------------------------------
    if detection_name == "Suspicious Network Utility":
        result = await db.scalar(
            select(func.count(SecurityEvent.id))
            .where(
                SecurityEvent.event_type
                == "process_start",
                SecurityEvent.source_ip
                == event.source_ip,
                SecurityEvent.created_at >= cutoff,
            )
        )

        count = result or 0

        return count >= threshold

    return True


async def run_detection_rules(
    db: AsyncSession,
    event: SecurityEvent,
):
    rules = get_rules(
        event.event_type
    )

    rule_names = EVENT_RULE_NAMES.get(
        event.event_type,
        [],
    )

    detections = []

    for index, rule in enumerate(rules):

        detection_name = (
            rule_names[index]
            if index < len(rule_names)
            else None
        )

        if detection_name:

            # --------------------------------------------------
            # Persistent enable/disable control
            # --------------------------------------------------
            enabled = await is_rule_enabled(
                db,
                detection_name,
            )

            if not enabled:
                continue

            # --------------------------------------------------
            # Persistent runtime threshold control
            # --------------------------------------------------
            threshold_reached = (
                await _threshold_reached(
                    db,
                    event,
                    detection_name,
                )
            )

            if not threshold_reached:
                continue

        # ------------------------------------------------------
        # Execute detection rule
        # ------------------------------------------------------

        if event.event_type == (
            "authentication_failure"
        ):
            if not event.source_ip:
                continue

            detection = await rule(
                db,
                event.source_ip,
            )

        elif event.event_type == (
            "network_connection"
        ):
            if not event.source_ip:
                continue

            detection = await rule(
                db,
                event.source_ip,
            )

        elif event.event_type == (
            "authentication_success"
        ):
            detection = await rule(
                db,
                event,
            )

        else:
            detection = await rule(
                db,
                event,
            )

        if detection:
            detections.append(
                detection
            )

    return detections
