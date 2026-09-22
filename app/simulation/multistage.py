from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.simulation.auth import simulate_suspicious_auth
from app.simulation.network_utility import (
    simulate_network_utility,
)
from app.simulation.portscan import simulate_port_scan
from app.simulation.ssh import simulate_ssh_brute_force


# =========================================================
# PHASE 9.6 — MULTI-STAGE ATTACK SIMULATION
# =========================================================

LAB_MODE = True
REAL_ATTACKS_ENABLED = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def simulate_multi_stage_attack(
    *,
    source_ip: str = "192.168.56.210",
    target_ip: str = "192.168.56.10",
    username: str = "lab-user",
) -> dict[str, Any]:

    if not LAB_MODE or REAL_ATTACKS_ENABLED:
        return {
            "status": "SIMULATION_REJECTED",
            "mode": "LAB",
            "simulation_only": True,
            "reason": "Multi-stage simulation is disabled.",
        }

    # -----------------------------------------------------
    # Stage 1 — Reconnaissance / Port Scan
    # -----------------------------------------------------

    stage_1 = simulate_port_scan(
        source_ip=source_ip,
        target_ip=target_ip,
    )

    # -----------------------------------------------------
    # Stage 2 — SSH Brute Force
    # -----------------------------------------------------

    stage_2 = simulate_ssh_brute_force(
        source_ip=source_ip,
        target_ip=target_ip,
        username=username,
        attempts=8,
    )

    # -----------------------------------------------------
    # Stage 3 — Suspicious Authentication
    # -----------------------------------------------------

    stage_3 = simulate_suspicious_auth(
        source_ip=source_ip,
        target_ip=target_ip,
        username=username,
        failed_attempts=5,
    )

    # -----------------------------------------------------
    # Stage 4 — Suspicious Network Utility
    # -----------------------------------------------------

    stage_4 = simulate_network_utility(
        source_ip=source_ip,
        target_ip=target_ip,
    )

    stages = [
        {
            "stage": 1,
            "name": "RECONNAISSANCE",
            "scenario": "PORT_SCAN",
            "status": stage_1["status"],
            "events": stage_1["events"],
        },
        {
            "stage": 2,
            "name": "CREDENTIAL_ATTACK",
            "scenario": "SSH_BRUTE_FORCE",
            "status": stage_2["status"],
            "events": stage_2["events"],
        },
        {
            "stage": 3,
            "name": "AUTHENTICATION_COMPROMISE",
            "scenario": "SUSPICIOUS_AUTH",
            "status": stage_3["status"],
            "events": stage_3["events"],
        },
        {
            "stage": 4,
            "name": "POST_AUTH_NETWORK_ACTIVITY",
            "scenario": "SUSPICIOUS_NETWORK_UTILITY",
            "status": stage_4["status"],
            "events": stage_4["events"],
        },
    ]

    total_events = sum(
        len(stage["events"])
        for stage in stages
    )

    return {
        "status": "MULTI_STAGE_ATTACK_SIMULATED",
        "timestamp": utc_now(),
        "mode": "LAB",
        "simulation_only": True,
        "real_attack": False,
        "scenario": "MULTI_STAGE_ATTACK",
        "source_ip": source_ip,
        "target_ip": target_ip,
        "username": username,
        "stage_count": len(stages),
        "total_events": total_events,
        "stages": stages,
    }
