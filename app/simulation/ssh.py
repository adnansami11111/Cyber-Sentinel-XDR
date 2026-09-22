from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# =========================================================
# PHASE 9.2 — SSH BRUTE-FORCE SIMULATION
# =========================================================

DEFAULT_SOURCE_IP = "192.168.56.200"
DEFAULT_TARGET_IP = "192.168.56.10"
DEFAULT_USERNAME = "lab-user"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def simulate_ssh_brute_force(
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    target_ip: str = DEFAULT_TARGET_IP,
    username: str = DEFAULT_USERNAME,
    attempts: int = 8,
) -> dict[str, Any]:

    attempts = max(1, min(int(attempts), 50))

    events = []

    for attempt in range(1, attempts + 1):
        events.append(
            {
                "event_type": "SSH_AUTH_FAILURE",
                "timestamp": utc_now(),
                "source_ip": source_ip,
                "target_ip": target_ip,
                "username": username,
                "protocol": "SSH",
                "port": 22,
                "result": "FAILED",
                "attempt": attempt,
                "simulation": True,
                "mode": "LAB",
            }
        )

    return {
        "status": "SSH_BRUTE_FORCE_SIMULATED",
        "mode": "LAB",
        "simulation_only": True,
        "real_attack": False,
        "scenario": "SSH_BRUTE_FORCE",
        "source_ip": source_ip,
        "target_ip": target_ip,
        "username": username,
        "attempts": attempts,
        "events_generated": len(events),
        "events": events,
    }
