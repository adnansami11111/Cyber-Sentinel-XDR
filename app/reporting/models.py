from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReportMetadata:
    report_id: str
    generated_at: str
    report_type: str = "INCIDENT_SECURITY_REPORT"
    format: str = "JSON"
    mode: str = "LAB"


@dataclass
class IncidentSummary:
    incident_id: int
    incident_key: str | None
    title: str | None
    severity: str | None
    risk_score: int | float | None
    status: str | None
    source_ip: str | None
    target_asset: str | None


@dataclass
class DetectionFinding:
    detection_id: int | None
    detection_name: str | None
    severity: str | None
    confidence: float | None
    risk_score: int | float | None
    status: str | None
    mitre_technique: str | None


@dataclass
class EvidenceItem:
    timestamp: str | None
    event_type: str | None
    source_ip: str | None
    destination_ip: str | None
    description: str | None
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class TimelineItem:
    timestamp: str | None
    event: str
    severity: str | None = None
    source: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponseActionItem:
    action_id: int | None
    action_type: str | None
    target: str | None
    mode: str | None
    status: str | None
    reason: str | None
    created_at: str | None


@dataclass
class SecurityReport:
    metadata: ReportMetadata
    executive_summary: str
    incident: IncidentSummary
    detections: list[DetectionFinding] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_mapping: list[dict[str, Any]] = field(default_factory=list)
    risk_assessment: dict[str, Any] = field(default_factory=dict)
    response_summary: dict[str, Any] = field(default_factory=dict)
    evidence: list[EvidenceItem] = field(default_factory=list)
    timeline: list[TimelineItem] = field(default_factory=list)
    response_actions: list[ResponseActionItem] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    indicators_of_compromise: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    report_status: str = "GENERATED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.__dict__,
            "executive_summary": self.executive_summary,
            "incident": self.incident.__dict__,
            "detections": [
                item.__dict__
                for item in self.detections
            ],
            "mitre_techniques": self.mitre_techniques,
            "mitre_mapping": self.mitre_mapping,
            "risk_assessment": self.risk_assessment,
            "response_summary": self.response_summary,
           "evidence": [
                item.__dict__
                for item in self.evidence
            ],
            "timeline": [
                item.__dict__
                for item in self.timeline
            ],
            "response_actions": [
                item.__dict__
                for item in self.response_actions
            ],
            "affected_assets": self.affected_assets,
            "indicators_of_compromise": self.indicators_of_compromise,
            "recommendations": self.recommendations,
            "report_status": self.report_status,
        }
