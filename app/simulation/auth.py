from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# =========================================================
# PHASE 9.4 — SUSPICIOUS AUTHENTICATION SIMULATION
# =========================================================

DEFAULT_SOURCE_IP = "192.168.56.202"
DEFAULT_TARGET_IP = "192.168.56.10"
DEFAULT_USERNAME = "lab-user"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def simulate_suspicious_auth(
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    target_ip: str = DEFAULT_TARGET_IP,
    username: str = DEFAULT_USERNAME,
    failed_attempts: int = 5,
) -> dict[str, Any]:

    failed_attempts = max(
        1,
        min(int(failed_attempts), 20),
    )

    events = []

    # Simulated failed authentication sequence
    for attempt in range(1, failed_attempts + 1):
        events.append(
            {
                "event_type": "AUTHENTICATION_FAILURE",
                "timestamp": utc_now(),
                "source_ip": source_ip,
                "target_ip": target_ip,
                "username": username,
                "protocol": "SSH",
                "result": "FAILED",
                "attempt": attempt,
                "simulation": True,
                "mode": "LAB",
            }
        )

    # Simulated successful authentication
    events.append(
        {
            "event_type": "AUTHENTICATION_SUCCESS",
            "timestamp": utc_now(),
            "source_ip": source_ip,
            "target_ip": target_ip,
            "username": username,
            "protocol": "SSH",
            "result": "SUCCESS",
            "after_failed_attempts": failed_attempts,
            "simulation": True,
            "mode": "LAB",
        }
    )

    return {
        "status": "SUSPICIOUS_AUTH_SIMULATED",
        "mode": "LAB",
        "simulation_only": True,
        "real_attack": False,
        "scenario": "SUSPICIOUS_AUTH",
        "source_ip": source_ip,
        "target_ip": target_ip,
        "username": username,
        "failed_attempts": failed_attempts,
        "successful_authentication": True,
        "events_generated": len(events),
        "events": events,
    }
