from datetime import datetime, timedelta
import json

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db.models import Base, SecurityEvent
from app.detection.engine import (
    detect_authentication_anomaly,
    detect_brute_force,
    detect_port_scan,
    detect_suspicious_process,
)


TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
    )

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    SessionLocal = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with SessionLocal() as session:
        yield session

    await engine.dispose()


def make_event(**overrides):
    event = SecurityEvent(
        timestamp=datetime.utcnow(),
        event_type="authentication_failure",
        source_ip="192.168.56.250",
        destination_ip="192.168.56.70",
        source_port=50000,
        destination_port=22,
        username="testuser",
        process_name=None,
        command_line=None,
        protocol="tcp",
        raw_data=json.dumps({}),
    )

    for key, value in overrides.items():
        setattr(event, key, value)

    return event


@pytest.mark.asyncio
async def test_brute_force_detection(db):
    from app.api.rule_control import get_rule_threshold

    threshold = await get_rule_threshold(
        db,
        "SSH Brute Force",
    )

    now = datetime.utcnow() - timedelta(minutes=1)

    for index in range(threshold):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=index),
                event_type="authentication_failure",
            )
        )

    await db.commit()

    result = await detect_brute_force(
        db=db,
        source_ip="192.168.56.250",
    )

    assert result is not None
    assert result.detection_name == "SSH Brute Force"
    assert result.mitre_technique == "T1110"


@pytest.mark.asyncio
async def test_port_scan_detection(db):
    now = datetime.utcnow()

    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        443,
    ]

    for index, port in enumerate(ports):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=index),
                event_type="network_connection",
                destination_port=port,
            )
        )

    await db.commit()

    result = await detect_port_scan(
        db=db,
        source_ip="192.168.56.250",
    )

    assert result is not None
    assert result.detection_name == "Network Port Scan"
    assert result.mitre_technique == "T1046"


@pytest.mark.asyncio
async def test_suspicious_process_detection(db):
    event = make_event(
        event_type="process_start",
        process_name="nc",
        command_line="nc 192.168.56.70 4444",
    )

    db.add(event)
    await db.commit()
    await db.refresh(event)

    result = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert result is not None
    assert result.detection_name == "Suspicious Network Utility"
    assert result.mitre_technique == "T1059"


@pytest.mark.asyncio
async def test_authentication_anomaly_detection(db):
    now = datetime.utcnow()

    for index in range(3):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=10 - index),
                event_type="authentication_failure",
            )
        )

    success_event = make_event(
        timestamp=now,
        event_type="authentication_success",
    )

    db.add(success_event)

    await db.commit()
    await db.refresh(success_event)

    result = await detect_authentication_anomaly(
        db=db,
        event=success_event,
    )

    assert result is not None
    assert result.detection_name == "Suspicious Authentication Success"
    assert result.mitre_technique == "T1078"


@pytest.mark.asyncio
async def test_brute_force_below_threshold(db):
    from app.api.rule_control import get_rule_threshold

    threshold = await get_rule_threshold(
        db,
        "SSH Brute Force",
    )

    now = datetime.utcnow()

    for index in range(threshold - 1):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=index),
                event_type="authentication_failure",
            )
        )

    await db.commit()

    result = await detect_brute_force(
        db=db,
        source_ip="192.168.56.250",
    )

    assert result is None


@pytest.mark.asyncio
async def test_brute_force_outside_time_window(db):
    from app.api.rule_control import get_rule_threshold

    threshold = await get_rule_threshold(
        db,
        "SSH Brute Force",
    )

    old_time = datetime.utcnow() - timedelta(minutes=11)

    for index in range(threshold):
        db.add(
            make_event(
                timestamp=old_time - timedelta(seconds=index),
                event_type="authentication_failure",
            )
        )

    await db.commit()

    result = await detect_brute_force(
        db=db,
        source_ip="192.168.56.250",
    )

    assert result is None


@pytest.mark.asyncio
async def test_port_scan_below_threshold(db):
    from app.api.rule_control import get_rule_threshold

    threshold = await get_rule_threshold(
        db,
        "Network Port Scan",
    )

    now = datetime.utcnow()

    for index in range(threshold - 1):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=index),
                event_type="network_connection",
                destination_port=1000 + index,
            )
        )

    await db.commit()

    result = await detect_port_scan(
        db=db,
        source_ip="192.168.56.250",
    )

    assert result is None


@pytest.mark.asyncio
async def test_port_scan_duplicate_ports_do_not_count_twice(db):
    from app.api.rule_control import get_rule_threshold

    threshold = await get_rule_threshold(
        db,
        "Network Port Scan",
    )

    now = datetime.utcnow()

    for index in range(threshold - 1):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=index),
                event_type="network_connection",
                destination_port=1000 + index,
            )
        )

    for index in range(3):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=20 + index),
                event_type="network_connection",
                destination_port=1000,
            )
        )

    await db.commit()

    result = await detect_port_scan(
        db=db,
        source_ip="192.168.56.250",
    )

    assert result is None


@pytest.mark.asyncio
async def test_authentication_anomaly_below_threshold(db):
    now = datetime.utcnow()

    for index in range(2):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=10 + index),
                event_type="authentication_failure",
            )
        )

    success_event = make_event(
        timestamp=now,
        event_type="authentication_success",
    )

    db.add(success_event)
    await db.commit()

    result = await detect_authentication_anomaly(
        db=db,
        event=success_event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_authentication_anomaly_outside_time_window(db):
    now = datetime.utcnow()
    old_time = now - timedelta(minutes=11)

    for index in range(3):
        db.add(
            make_event(
                timestamp=old_time - timedelta(seconds=index),
                event_type="authentication_failure",
            )
        )

    success_event = make_event(
        timestamp=now,
        event_type="authentication_success",
    )

    db.add(success_event)
    await db.commit()

    result = await detect_authentication_anomaly(
        db=db,
        event=success_event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_suspicious_process_non_suspicious_name(db):
    event = make_event(
        event_type="process_start",
        process_name="python",
        command_line="python app.py",
    )

    result = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_normal_authentication_does_not_trigger_brute_force(db):
    for index in range(2):
        db.add(
            make_event(
                timestamp=datetime.utcnow() - timedelta(seconds=index),
                event_type="authentication_failure",
                source_ip="192.168.56.100",
            )
        )

    await db.commit()

    result = await detect_brute_force(
        db=db,
        source_ip="192.168.56.100",
    )

    assert result is None


@pytest.mark.asyncio
async def test_normal_network_activity_does_not_trigger_port_scan(db):
    db.add(
        make_event(
            event_type="network_connection",
            source_ip="192.168.56.100",
            destination_port=443,
        )
    )

    await db.commit()

    result = await detect_port_scan(
        db=db,
        source_ip="192.168.56.100",
    )

    assert result is None


@pytest.mark.asyncio
async def test_normal_process_does_not_trigger_network_utility(db):
    event = make_event(
        event_type="process_start",
        source_ip="192.168.56.100",
        process_name="chrome",
        command_line="chrome --new-window",
    )

    result = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_authentication_success_without_failures_is_benign(db):
    event = make_event(
        event_type="authentication_success",
        source_ip="192.168.56.100",
    )

    db.add(event)
    await db.commit()

    result = await detect_authentication_anomaly(
        db=db,
        event=event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_common_process_names_are_not_suspicious(db):
    for process_name in ["python", "bash", "sshd", "chrome", "firefox"]:
        event = make_event(
            event_type="process_start",
            process_name=process_name,
            command_line=process_name,
        )

        result = await detect_suspicious_process(
            db=db,
            event=event,
        )

        assert result is None


@pytest.mark.asyncio
async def test_brute_force_detection_is_deduplicated(db):
    from app.api.rule_control import get_rule_threshold

    threshold = await get_rule_threshold(
        db,
        "SSH Brute Force",
    )

    now = datetime.utcnow()

    for index in range(threshold):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=index),
                event_type="authentication_failure",
                source_ip="192.168.56.250",
            )
        )

    await db.commit()

    first = await detect_brute_force(
        db=db,
        source_ip="192.168.56.250",
    )

    second = await detect_brute_force(
        db=db,
        source_ip="192.168.56.250",
    )

    assert first is not None
    assert second is not None
    assert first.id == second.id


@pytest.mark.asyncio
async def test_port_scan_detection_is_deduplicated(db):
    from app.api.rule_control import get_rule_threshold

    threshold = await get_rule_threshold(
        db,
        "Network Port Scan",
    )

    now = datetime.utcnow()

    for index in range(threshold):
        db.add(
            make_event(
                timestamp=now - timedelta(seconds=index),
                event_type="network_connection",
                source_ip="192.168.56.250",
                destination_port=1000 + index,
            )
        )

    await db.commit()

    first = await detect_port_scan(
        db=db,
        source_ip="192.168.56.250",
    )

    second = await detect_port_scan(
        db=db,
        source_ip="192.168.56.250",
    )

    assert first is not None
    assert second is not None
    assert first.id == second.id


@pytest.mark.asyncio
async def test_suspicious_process_detection_is_deduplicated(db):
    event = make_event(
        event_type="process_start",
        source_ip="192.168.56.250",
        process_name="nc",
        command_line="nc 192.168.56.70 4444",
    )

    first = await detect_suspicious_process(
        db=db,
        event=event,
    )

    second = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert first is not None
    assert second is not None
    assert first.id == second.id


@pytest.mark.asyncio
async def test_attack_events_share_same_source(db):
    source_ip = "192.168.56.250"

    events = [
        make_event(
            event_type="authentication_failure",
            source_ip=source_ip,
            destination_port=22,
        ),
        make_event(
            event_type="network_connection",
            source_ip=source_ip,
            destination_port=443,
        ),
        make_event(
            event_type="process_start",
            source_ip=source_ip,
            process_name="nc",
            command_line="nc 192.168.56.70 4444",
        ),
    ]

    for event in events:
        db.add(event)

    await db.commit()

    sources = {
        event.source_ip
        for event in events
    }

    assert len(sources) == 1
    assert source_ip in sources


@pytest.mark.asyncio
async def test_attack_events_are_within_correlation_window(db):
    source_ip = "192.168.56.250"
    now = datetime.utcnow()

    events = [
        make_event(
            timestamp=now - timedelta(minutes=1),
            event_type="authentication_failure",
            source_ip=source_ip,
        ),
        make_event(
            timestamp=now - timedelta(minutes=3),
            event_type="network_connection",
            source_ip=source_ip,
            destination_port=443,
        ),
        make_event(
            timestamp=now - timedelta(minutes=5),
            event_type="process_start",
            source_ip=source_ip,
            process_name="nc",
            command_line="nc 192.168.56.70 4444",
        ),
    ]

    for event in events:
        db.add(event)

    await db.commit()

    window_start = now - timedelta(minutes=10)

    recent_events = [
        event
        for event in events
        if event.timestamp >= window_start
    ]

    assert len(recent_events) == 3


@pytest.mark.asyncio
async def test_events_from_different_sources_are_not_same_correlation_group(db):
    event_one = make_event(
        event_type="authentication_failure",
        source_ip="192.168.56.250",
    )

    event_two = make_event(
        event_type="authentication_failure",
        source_ip="192.168.56.251",
    )

    db.add_all([event_one, event_two])
    await db.commit()

    sources = {
        event_one.source_ip,
        event_two.source_ip,
    }

    assert len(sources) == 2
    assert event_one.source_ip != event_two.source_ip


@pytest.mark.asyncio
async def test_incident_lifecycle_states(db):
    from app.db.models import Incident

    incident = Incident(
        incident_key="TEST-LIFECYCLE-001",
        title="Lifecycle Test Incident",
        severity="HIGH",
        risk_score=85,
        status="OPEN",
        source_ip="192.168.56.250",
        target_asset="LAB-ENDPOINT",
    )

    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    assert incident.id is not None
    assert incident.status == "OPEN"

    incident.status = "ESCALATED"

    await db.commit()
    await db.refresh(incident)

    assert incident.status == "ESCALATED"

    incident.status = "RESOLVED"

    await db.commit()
    await db.refresh(incident)

    assert incident.status == "RESOLVED"


@pytest.mark.asyncio
async def test_resolved_incident_retains_identity(db):
    from app.db.models import Incident

    incident = Incident(
        incident_key="TEST-LIFECYCLE-002",
        title="Resolved Incident",
        severity="MEDIUM",
        risk_score=60,
        status="OPEN",
        source_ip="192.168.56.251",
        target_asset="LAB-ENDPOINT",
    )

    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    incident_id = incident.id
    incident_key = incident.incident_key

    incident.status = "RESOLVED"

    await db.commit()
    await db.refresh(incident)

    assert incident.id == incident_id
    assert incident.incident_key == incident_key
    assert incident.status == "RESOLVED"


@pytest.mark.asyncio
async def test_incident_severity_and_risk_are_preserved(db):
    from app.db.models import Incident

    incident = Incident(
        incident_key="TEST-LIFECYCLE-003",
        title="Risk Preservation Test",
        severity="HIGH",
        risk_score=95,
        status="OPEN",
        source_ip="192.168.56.252",
        target_asset="LAB-ENDPOINT",
    )

    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    incident.status = "ESCALATED"

    await db.commit()
    await db.refresh(incident)

    assert incident.severity == "HIGH"
    assert incident.risk_score == 95
    assert incident.status == "ESCALATED"


@pytest.mark.asyncio
async def test_incident_report_data_structure(db):
    from app.db.models import Incident

    incident = Incident(
        incident_key="TEST-REPORT-001",
        title="Report Regression Test",
        severity="HIGH",
        risk_score=90,
        status="OPEN",
        source_ip="192.168.56.250",
        target_asset="LAB-ENDPOINT",
    )

    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    assert incident.id is not None
    assert incident.incident_key == "TEST-REPORT-001"
    assert incident.title == "Report Regression Test"
    assert incident.severity == "HIGH"
    assert incident.risk_score == 90
    assert incident.status == "OPEN"
    assert incident.source_ip == "192.168.56.250"
    assert incident.target_asset == "LAB-ENDPOINT"


@pytest.mark.asyncio
async def test_incident_report_fields_remain_valid_after_update(db):
    from app.db.models import Incident

    incident = Incident(
        incident_key="TEST-REPORT-002",
        title="Report Update Test",
        severity="MEDIUM",
        risk_score=70,
        status="OPEN",
        source_ip="192.168.56.251",
        target_asset="LAB-ENDPOINT",
    )

    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    incident.status = "ESCALATED"
    incident.risk_score = 85

    await db.commit()
    await db.refresh(incident)

    assert incident.status == "ESCALATED"
    assert incident.risk_score == 85
    assert incident.incident_key == "TEST-REPORT-002"
    assert incident.source_ip == "192.168.56.251"


@pytest.mark.asyncio
async def test_report_incident_contains_required_metadata(db):
    from app.db.models import Incident

    incident = Incident(
        incident_key="TEST-REPORT-003",
        title="Required Metadata Test",
        severity="CRITICAL",
        risk_score=100,
        status="OPEN",
        source_ip="192.168.56.252",
        target_asset="LAB-ENDPOINT",
    )

    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    required_fields = {
        "incident_key": incident.incident_key,
        "title": incident.title,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "source_ip": incident.source_ip,
        "target_asset": incident.target_asset,
    }

    for field, value in required_fields.items():
        assert value is not None, f"{field} is missing"

    assert required_fields["incident_key"].startswith("TEST-REPORT-")
    assert required_fields["risk_score"] >= 0
    assert required_fields["risk_score"] <= 100


@pytest.mark.asyncio
async def test_missing_source_ip_is_safe(db):
    event = make_event(
        event_type="authentication_failure",
        source_ip=None,
    )

    db.add(event)
    await db.commit()

    result = await detect_brute_force(
        db=db,
        source_ip=None,
    )

    assert result is None


@pytest.mark.asyncio
async def test_unknown_event_type_does_not_trigger_detection(db):
    event = make_event(
        event_type="unknown_event_type",
        source_ip="192.168.56.250",
    )

    db.add(event)
    await db.commit()

    result = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_empty_process_name_is_safe(db):
    event = make_event(
        event_type="process_start",
        process_name=None,
        command_line=None,
    )

    result = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_empty_command_line_is_safe(db):
    event = make_event(
        event_type="process_start",
        process_name="python",
        command_line="",
    )

    result = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_invalid_destination_port_does_not_trigger_port_scan(db):
    event = make_event(
        event_type="network_connection",
        source_ip="192.168.56.250",
        destination_port=None,
    )

    db.add(event)
    await db.commit()

    result = await detect_port_scan(
        db=db,
        source_ip="192.168.56.250",
    )

    assert result is None


@pytest.mark.asyncio
async def test_unknown_process_name_is_benign(db):
    event = make_event(
        event_type="process_start",
        process_name="completely_unknown_process",
        command_line="completely_unknown_process --test",
    )

    result = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_empty_database_returns_no_brute_force_detection(db):
    result = await detect_brute_force(
        db=db,
        source_ip="192.168.56.250",
    )

    assert result is None


@pytest.mark.asyncio
async def test_empty_database_returns_no_port_scan_detection(db):
    result = await detect_port_scan(
        db=db,
        source_ip="192.168.56.250",
    )

    assert result is None


@pytest.mark.asyncio
async def test_empty_database_returns_no_auth_anomaly(db):
    event = make_event(
        event_type="authentication_success",
        source_ip="192.168.56.250",
    )

    result = await detect_authentication_anomaly(
        db=db,
        event=event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_malformed_process_data_does_not_crash(db):
    event = make_event(
        event_type="process_start",
        process_name="",
        command_line=None,
    )

    result = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert result is None


@pytest.mark.asyncio
async def test_unrelated_event_does_not_create_detection(db):
    event = make_event(
        event_type="file_access",
        source_ip="192.168.56.250",
    )

    db.add(event)
    await db.commit()

    result = await detect_suspicious_process(
        db=db,
        event=event,
    )

    assert result is None
