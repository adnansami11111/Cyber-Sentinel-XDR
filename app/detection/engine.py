from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import Detection, SecurityEvent
from app.detection.risk import calculate_risk_score
from app.intelligence.ioc_engine import lookup_ip


PORT_SCAN_WINDOW_MINUTES = 10

SUSPICIOUS_PROCESS_PATTERNS = {
    "nc": {
        "name": "Suspicious Network Utility",
        "severity": "HIGH",
        "tactic": "Command and Control",
        "technique": "T1059",
    },
    "ncat": {
        "name": "Suspicious Network Utility",
        "severity": "HIGH",
        "tactic": "Command and Control",
        "technique": "T1059",
    },
    "socat": {
        "name": "Suspicious Network Utility",
        "severity": "HIGH",
        "tactic": "Command and Control",
        "technique": "T1059",
    },
}


AUTH_ANOMALY_FAILURE_THRESHOLD = 3
AUTH_ANOMALY_WINDOW_MINUTES = 10


async def get_source_reputation(
    db: AsyncSession,
    source_ip: str | None,
) -> str:

    if not source_ip:
        return "UNKNOWN"

    ioc = await lookup_ip(
        db,
        source_ip,
    )

    if not ioc:
        return "UNKNOWN"

    return ioc.reputation


async def detect_brute_force(
    db: AsyncSession,
    source_ip: str,
):
    from app.api.rule_control import get_rule_threshold

    threshold = await get_rule_threshold(
        db,
        "SSH Brute Force",
    )

    window_start = datetime.utcnow() - timedelta(
        minutes=settings.CORRELATION_WINDOW_MINUTES
    )

    failure_count = await db.scalar(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.event_type
            == "authentication_failure",
            SecurityEvent.timestamp
            >= window_start,
        )
    )

    failure_count = failure_count or 0

    if failure_count < threshold:
        return None

    existing = await db.scalar(
        select(Detection)
        .where(
            Detection.detection_name
            == "SSH Brute Force",
            Detection.source_ip == source_ip,
            Detection.status == "NEW",
        )
        .order_by(
            Detection.created_at.desc()
        )
    )

    if existing:
        return existing

    reputation = await get_source_reputation(
        db,
        source_ip,
    )

    risk_score = calculate_risk_score(
        severity="HIGH",
        confidence=0.95,
        event_count=failure_count,
        source_reputation=reputation,
        asset_criticality="medium",
    )

    detection = Detection(
        detection_name="SSH Brute Force",
        description=(
            f"Detected {failure_count} authentication "
            f"failures from source {source_ip} "
            f"within "
            f"{settings.CORRELATION_WINDOW_MINUTES} "
            f"minutes. Runtime threshold: "
            f"{threshold}. IOC reputation: "
            f"{reputation}."
        ),
        severity="HIGH",
        risk_score=risk_score,
        confidence=0.95,
        mitre_tactic="Credential Access",
        mitre_technique="T1110",
        source_ip=source_ip,
        status="NEW",
    )

    db.add(detection)

    await db.commit()
    await db.refresh(detection)

    return detection


async def detect_port_scan(
    db: AsyncSession,
    source_ip: str,
):
    from app.api.rule_control import get_rule_threshold

    threshold = await get_rule_threshold(
        db,
        "Network Port Scan",
    )

    window_start = datetime.utcnow() - timedelta(
        minutes=PORT_SCAN_WINDOW_MINUTES
    )

    ports = await db.scalars(
        select(SecurityEvent.destination_port)
        .where(
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.event_type
            == "network_connection",
            SecurityEvent.timestamp
            >= window_start,
            SecurityEvent.destination_port.is_not(None),
        )
        .distinct()
    )

    unique_ports = list(ports)

    port_count = len(unique_ports)

    if port_count < threshold:
        return None

    existing = await db.scalar(
        select(Detection)
        .where(
            Detection.detection_name
            == "Network Port Scan",
            Detection.source_ip == source_ip,
            Detection.status == "NEW",
        )
        .order_by(
            Detection.created_at.desc()
        )
    )

    if existing:
        return existing

    reputation = await get_source_reputation(
        db,
        source_ip,
    )

    risk_score = calculate_risk_score(
        severity="MEDIUM",
        confidence=0.90,
        event_count=port_count,
        source_reputation=reputation,
        asset_criticality="medium",
    )

    detection = Detection(
        detection_name="Network Port Scan",
        description=(
            f"Detected connections to "
            f"{port_count} unique destination "
            f"ports from source {source_ip} "
            f"within {PORT_SCAN_WINDOW_MINUTES} "
            f"minutes. Runtime threshold: "
            f"{threshold}. IOC reputation: "
            f"{reputation}."
        ),
        severity="MEDIUM",
        risk_score=risk_score,
        confidence=0.90,
        mitre_tactic="Discovery",
        mitre_technique="T1046",
        source_ip=source_ip,
        status="NEW",
    )

    db.add(detection)

    await db.commit()
    await db.refresh(detection)

    return detection


async def detect_suspicious_process(
    db: AsyncSession,
    event: SecurityEvent,
):
    process_name = (
        event.process_name or ""
    ).lower().strip()

    if not process_name:
        return None

    matched = SUSPICIOUS_PROCESS_PATTERNS.get(
        process_name
    )

    if not matched:
        return None

    existing = await db.scalar(
        select(Detection)
        .where(
            Detection.detection_name
            == matched["name"],
            Detection.source_ip
            == event.source_ip,
            Detection.status == "NEW",
        )
        .order_by(
            Detection.created_at.desc()
        )
    )

    if existing:
        return existing

    reputation = await get_source_reputation(
        db,
        event.source_ip,
    )

    risk_score = calculate_risk_score(
        severity=matched["severity"],
        confidence=0.85,
        event_count=1,
        source_reputation=reputation,
        asset_criticality="medium",
    )

    detection = Detection(
        detection_name=matched["name"],
        description=(
            f"Suspicious process "
            f"'{event.process_name}' observed "
            f"on the monitored endpoint. "
            f"IOC reputation: {reputation}."
        ),
        severity=matched["severity"],
        risk_score=risk_score,
        confidence=0.85,
        mitre_tactic=matched["tactic"],
        mitre_technique=matched["technique"],
        source_ip=event.source_ip,
        status="NEW",
    )

    db.add(detection)

    await db.commit()
    await db.refresh(detection)

    return detection


async def detect_authentication_anomaly(
    db: AsyncSession,
    event: SecurityEvent,
):
    if event.event_type != "authentication_success":
        return None

    if not event.source_ip:
        return None

    window_start = datetime.utcnow() - timedelta(
        minutes=AUTH_ANOMALY_WINDOW_MINUTES
    )

    failure_count = await db.scalar(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.source_ip
            == event.source_ip,
            SecurityEvent.event_type
            == "authentication_failure",
            SecurityEvent.timestamp
            >= window_start,
        )
    )

    failure_count = failure_count or 0

    if failure_count < AUTH_ANOMALY_FAILURE_THRESHOLD:
        return None

    existing = await db.scalar(
        select(Detection)
        .where(
            Detection.detection_name
            == "Suspicious Authentication Success",
            Detection.source_ip
            == event.source_ip,
            Detection.status == "NEW",
        )
        .order_by(
            Detection.created_at.desc()
        )
    )

    if existing:
        return existing

    reputation = await get_source_reputation(
        db,
        event.source_ip,
    )

    risk_score = calculate_risk_score(
        severity="HIGH",
        confidence=0.90,
        event_count=failure_count + 1,
        source_reputation=reputation,
        asset_criticality="medium",
    )

    detection = Detection(
        detection_name=(
            "Suspicious Authentication Success"
        ),
        description=(
            f"Successful authentication from "
            f"{event.source_ip} followed "
            f"{failure_count} authentication "
            f"failures within "
            f"{AUTH_ANOMALY_WINDOW_MINUTES} "
            f"minutes. IOC reputation: "
            f"{reputation}."
        ),
        severity="HIGH",
        risk_score=risk_score,
        confidence=0.90,
        mitre_tactic="Credential Access",
        mitre_technique="T1078",
        source_ip=event.source_ip,
        status="NEW",
    )

    db.add(detection)

    await db.commit()
    await db.refresh(detection)

    return detection
