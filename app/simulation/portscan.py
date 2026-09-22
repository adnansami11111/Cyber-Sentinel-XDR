from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# =========================================================
# PHASE 9.3 — PORT SCAN SIMULATION
# =========================================================

DEFAULT_SOURCE_IP = "192.168.56.201"
DEFAULT_TARGET_IP = "192.168.56.10"

DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    3389,
    8080,
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def simulate_port_scan(
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    target_ip: str = DEFAULT_TARGET_IP,
    ports: list[int] | None = None,
) -> dict[str, Any]:

    scan_ports = ports or DEFAULT_PORTS

    events = []

    for sequence, port in enumerate(scan_ports, start=1):
        events.append(
            {
                "event_type": "PORT_SCAN_ATTEMPT",
                "timestamp": utc_now(),
                "source_ip": source_ip,
                "target_ip": target_ip,
                "protocol": "TCP",
                "destination_port": int(port),
                "connection_result": "SIMULATED_PROBE",
                "sequence": sequence,
                "simulation": True,
                "mode": "LAB",
            }
        )

    return {
        "status": "PORT_SCAN_SIMULATED",
        "mode": "LAB",
        "simulation_only": True,
        "real_attack": False,
        "scenario": "PORT_SCAN",
        "source_ip": source_ip,
        "target_ip": target_ip,
        "ports_scanned": len(scan_ports),
        "events_generated": len(events),
        "events": events,
    }
