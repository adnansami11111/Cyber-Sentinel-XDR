from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    ip_address: Mapped[str] = mapped_column(
        String(45),
        index=True,
        nullable=False,
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    asset_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    criticality: Mapped[str] = mapped_column(
        String(20),
        default="medium",
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    environment: Mapped[str | None] = mapped_column(
        String(100),
        default="LAB",
        nullable=True,
    )


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        index=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    source_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    process_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    command_line: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    protocol: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    raw_data: Mapped[str | dict | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        index=True,
    )


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    detection_name: Mapped[str] = mapped_column(
        String(255),
        index=True,
    )

    description: Mapped[str] = mapped_column(
        Text,
    )

    severity: Mapped[str] = mapped_column(
        String(30),
        index=True,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    mitre_tactic: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    mitre_technique: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="NEW",
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        index=True,
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    incident_key: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    target_asset: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    attack_story: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    severity: Mapped[str] = mapped_column(
        String(30),
        index=True,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="OPEN",
        index=True,
    )

    mitre_techniques: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        index=True,
    )


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(30),
        index=True,
    )

    value: Mapped[str] = mapped_column(
        String(500),
        index=True,
    )

    reputation: Mapped[str] = mapped_column(
        String(30),
        default="UNKNOWN",
        index=True,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        default=0.0,
    )

    threat_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    source: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    tags: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        index=True,
    )


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    incident_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("incidents.id"),
        index=True,
    )

    action_type: Mapped[str] = mapped_column(
        String(100),
        index=True,
    )

    target: Mapped[str] = mapped_column(
        String(500),
    )

    mode: Mapped[str] = mapped_column(
        String(30),
        default="LAB",
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="RECORDED",
        index=True,
    )

    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        index=True,
    )


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    detection_name: Mapped[str] = mapped_column(
        String(255),
        index=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String(100),
        index=True,
    )

    category: Mapped[str] = mapped_column(
        String(100),
        index=True,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
    )

    false_positive_risk: Mapped[str] = mapped_column(
        String(30),
    )

    description: Mapped[str] = mapped_column(
        Text,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )

    threshold: Mapped[int] = mapped_column(
        Integer,
        default=1,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class DetectionRuleAudit(Base):
    __tablename__ = "detection_rule_audits"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    detection_rule_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("detection_rules.id"),
        index=True,
    )

    detection_name: Mapped[str] = mapped_column(
        String(255),
        index=True,
    )

    action: Mapped[str] = mapped_column(
        String(50),
    )

    previous_value: Mapped[str] = mapped_column(
        Text,
    )

    new_value: Mapped[str] = mapped_column(
        Text,
    )

    actor: Mapped[str] = mapped_column(
        String(100),
    )

    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    changed_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        index=True,
    )
