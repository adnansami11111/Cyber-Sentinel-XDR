from typing import Literal


Severity = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]


SEVERITY_BASE = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 70,
    "CRITICAL": 90,
}


REPUTATION_BONUS = {
    "MALICIOUS": 20,
    "SUSPICIOUS": 10,
    "UNKNOWN": 0,
    "BENIGN": -10,
}


CRITICALITY_BONUS = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 0,
}


MITRE_IMPACT_BONUS = {
    "credential_access": 8,
    "execution": 7,
    "persistence": 8,
    "privilege_escalation": 10,
    "defense_evasion": 7,
    "discovery": 4,
    "lateral_movement": 10,
    "collection": 6,
    "command_and_control": 9,
    "exfiltration": 10,
    "impact": 12,
}


def classify_risk(score: int) -> str:
    """
    Convert a numeric risk score into an operational
    risk band used by the XDR platform.
    """

    if score >= 90:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def calculate_risk_score(
    severity: str,
    confidence: float,
    event_count: int = 1,
    source_reputation: str = "UNKNOWN",
    asset_criticality: str = "medium",
    correlation_bonus: int = 0,
    mitre_impact: str | None = None,
) -> int:
    explanation = explain_risk_score(
        severity=severity,
        confidence=confidence,
        event_count=event_count,
        source_reputation=source_reputation,
        asset_criticality=asset_criticality,
        correlation_bonus=correlation_bonus,
        mitre_impact=mitre_impact,
    )

    return explanation["final_score"]


def explain_risk_score(
    severity: str,
    confidence: float,
    event_count: int = 1,
    source_reputation: str = "UNKNOWN",
    asset_criticality: str = "medium",
    correlation_bonus: int = 0,
    mitre_impact: str | None = None,
) -> dict:

    severity_key = severity.upper()
    reputation_key = source_reputation.upper()
    criticality_key = asset_criticality.lower()

    base_score = SEVERITY_BASE.get(
        severity_key,
        SEVERITY_BASE["LOW"],
    )

    confidence = max(
        0.0,
        min(confidence, 1.0),
    )

    confidence_adjustment = round(
        (confidence - 0.5) * 20
    )

    event_count = max(
        int(event_count),
        1,
    )

    repetition_bonus = min(
        max(event_count - 1, 0) * 5,
        15,
    )

    reputation_bonus = REPUTATION_BONUS.get(
        reputation_key,
        0,
    )

    criticality_bonus = CRITICALITY_BONUS.get(
        criticality_key,
        5,
    )

    normalized_mitre = (
        mitre_impact.lower().replace(" ", "_")
        if mitre_impact
        else None
    )

    mitre_bonus = MITRE_IMPACT_BONUS.get(
        normalized_mitre,
        0,
    )

    correlation_bonus = max(
        0,
        min(int(correlation_bonus), 15),
    )

    raw_score = (
        base_score
        + confidence_adjustment
        + repetition_bonus
        + reputation_bonus
        + criticality_bonus
        + correlation_bonus
        + mitre_bonus
    )

    final_score = max(
        0,
        min(100, raw_score),
    )

    risk_band = classify_risk(
        final_score
    )

    factors = [
        {
            "factor": "Severity",
            "value": severity_key,
            "impact": base_score,
            "description": (
                f"{severity_key} severity contributes "
                f"{base_score} points."
            ),
        },
        {
            "factor": "Confidence",
            "value": round(confidence, 2),
            "impact": confidence_adjustment,
            "description": (
                f"Detection confidence of "
                f"{round(confidence * 100)}% contributes "
                f"{confidence_adjustment:+d} points."
            ),
        },
        {
            "factor": "Repeated Activity",
            "value": event_count,
            "impact": repetition_bonus,
            "description": (
                f"{event_count} related event(s) contribute "
                f"{repetition_bonus} points."
            ),
        },
        {
            "factor": "Source Reputation",
            "value": reputation_key,
            "impact": reputation_bonus,
            "description": (
                f"Source reputation '{reputation_key}' "
                f"contributes {reputation_bonus:+d} points."
            ),
        },
        {
            "factor": "Asset Criticality",
            "value": criticality_key,
            "impact": criticality_bonus,
            "description": (
                f"Asset criticality '{criticality_key}' "
                f"contributes {criticality_bonus:+d} points."
            ),
        },
        {
            "factor": "Correlation",
            "value": correlation_bonus,
            "impact": correlation_bonus,
            "description": (
                f"Incident correlation contributes "
                f"{correlation_bonus} points."
            ),
        },
        {
            "factor": "MITRE Impact",
            "value": normalized_mitre,
            "impact": mitre_bonus,
            "description": (
                f"MITRE impact category "
                f"'{normalized_mitre or 'NONE'}' contributes "
                f"{mitre_bonus} points."
            ),
        },
    ]

    return {
        "final_score": final_score,
        "risk_band": risk_band,
        "raw_score": raw_score,
        "capped": raw_score != final_score,
        "severity": severity_key,
        "confidence": confidence,
        "event_count": event_count,
        "source_reputation": reputation_key,
        "asset_criticality": criticality_key,
        "correlation_bonus": correlation_bonus,
        "mitre_impact": normalized_mitre,
        "mitre_bonus": mitre_bonus,
        "factors": factors,
    }


def build_risk_profile(
    severity: str,
    confidence: float,
    event_count: int = 1,
    source_reputation: str = "UNKNOWN",
    asset_criticality: str = "medium",
    correlation_bonus: int = 0,
    mitre_impact: str | None = None,
) -> dict:
    """
    High-level risk profile intended for incident
    investigation, dashboards, and future response logic.
    """

    explanation = explain_risk_score(
        severity=severity,
        confidence=confidence,
        event_count=event_count,
        source_reputation=source_reputation,
        asset_criticality=asset_criticality,
        correlation_bonus=correlation_bonus,
        mitre_impact=mitre_impact,
    )

    score = explanation["final_score"]

    response_priority = {
        "CRITICAL": "IMMEDIATE",
        "HIGH": "URGENT",
        "MEDIUM": "STANDARD",
        "LOW": "MONITOR",
    }[explanation["risk_band"]]

    return {
        "score": score,
        "risk_band": explanation["risk_band"],
        "response_priority": response_priority,
        "requires_investigation": score >= 40,
        "requires_immediate_attention": score >= 90,
        "explanation": explanation,
    }
