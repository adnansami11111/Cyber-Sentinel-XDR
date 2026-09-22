from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# =========================================================
# PHASE 9 — ATTACK SIMULATION LAB
# PHASE 9.1 — SIMULATION ENGINE FOUNDATION
# =========================================================

LAB_MODE = True
REAL_ATTACKS_ENABLED = False


SUPPORTED_SCENARIOS = {
    "SSH_BRUTE_FORCE",
    "PORT_SCAN",
    "SUSPICIOUS_AUTH",
    "SUSPICIOUS_NETWORK_UTILITY",
    "MULTI_STAGE_ATTACK",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_simulation_status() -> dict[str, Any]:
    return {
        "status": "SIMULATION_READY",
        "mode": "LAB",
        "simulation_only": True,
        "real_attacks_enabled": False,
        "supported_scenarios": sorted(
            SUPPORTED_SCENARIOS
        ),
    }


def validate_simulation(
    scenario: str,
) -> dict[str, Any]:

    scenario = str(scenario).upper().strip()

    if not LAB_MODE:
        return {
            "allowed": False,
            "reason": "Attack simulation is disabled outside LAB mode.",
        }

    if REAL_ATTACKS_ENABLED:
        return {
            "allowed": False,
            "reason": "Real attack execution is permanently disabled.",
        }

    if scenario not in SUPPORTED_SCENARIOS:
        return {
            "allowed": False,
            "reason": "Unsupported simulation scenario.",
            "scenario": scenario,
        }

    return {
        "allowed": True,
        "scenario": scenario,
        "mode": "LAB",
        "simulation_only": True,
        "real_attack": False,
    }


def simulate_scenario(
    scenario: str,
    source_ip: str = "192.168.56.200",
    target_ip: str = "192.168.56.10",
) -> dict[str, Any]:

    validation = validate_simulation(
        scenario
    )

    if not validation["allowed"]:
        return {
            "status": "SIMULATION_REJECTED",
            "timestamp": utc_now(),
            "mode": "LAB",
            "simulation_only": True,
            "validation": validation,
        }

    return {
        "status": "SIMULATION_READY",
        "timestamp": utc_now(),
        "mode": "LAB",
        "simulation_only": True,
        "real_attack": False,
        "scenario": validation["scenario"],
        "source": {
            "ip": source_ip,
        },
        "target": {
            "ip": target_ip,
        },
    }
