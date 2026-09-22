from __future__ import annotations

from typing import Any


def calculate_risk_assessment(
    risk_score: int | float | None,
    severity: str | None,
    detection_count: int,
    mitre_count: int,
    ioc_count: int,
    response_action_count: int,
) -> dict[str, Any]:
    score = float(risk_score or 0)
    severity_value = str(severity or "UNKNOWN").upper()

    if score >= 90:
        risk_level = "CRITICAL"
    elif score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    factors: list[str] = []

    if score >= 70:
        factors.append("High incident risk score")

    if severity_value in {"HIGH", "CRITICAL"}:
        factors.append(f"{severity_value} incident severity")

    if detection_count > 0:
        factors.append(f"{detection_count} detection finding(s)")

    if mitre_count > 0:
        factors.append(f"{mitre_count} MITRE ATT&CK technique(s)")

    if ioc_count > 0:
        factors.append(f"{ioc_count} indicator(s) of compromise")

    if response_action_count > 0:
        factors.append(f"{response_action_count} response action(s) recorded")

    if not factors:
        factors.append("No significant risk factors identified")

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "severity": severity_value,
        "detection_count": detection_count,
        "mitre_technique_count": mitre_count,
        "ioc_count": ioc_count,
        "response_action_count": response_action_count,
        "risk_factors": factors,
    }
