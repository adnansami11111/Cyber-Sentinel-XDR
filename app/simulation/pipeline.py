from __future__ import annotations

from typing import Any


def normalize_simulation_event(event: dict[str, Any]) -> dict[str, Any]:
    """
    Convert Phase 9 simulation events into the canonical
    telemetry format already consumed by Cyber Sentinel XDR.
    """

    event_type = str(
        event.get("event_type", "")
    ).strip().upper()

    normalized = dict(event)

    # ---------------------------------------------------------
    # SSH brute-force simulation
    # ---------------------------------------------------------
    if event_type == "SSH_AUTH_FAILURE":
        normalized["event_type"] = "authentication_failure"

    # ---------------------------------------------------------
    # Port-scan simulation
    # ---------------------------------------------------------
    elif event_type == "PORT_SCAN_ATTEMPT":
        normalized["event_type"] = "network_connection"

        if "destination_port" in event:
            normalized["destination_port"] = int(
                event["destination_port"]
            )

    # ---------------------------------------------------------
    # Suspicious authentication simulation
    # ---------------------------------------------------------
    elif event_type == "AUTHENTICATION_FAILURE":
        normalized["event_type"] = "authentication_failure"

    elif event_type == "AUTHENTICATION_SUCCESS":
        normalized["event_type"] = "authentication_success"

    # ---------------------------------------------------------
    # Suspicious network utility simulation
    # ---------------------------------------------------------
    elif event_type == "SUSPICIOUS_NETWORK_UTILITY":
        normalized["event_type"] = "process_start"

        command = str(
            event.get("command", "")
        ).strip()

        # Existing detection engine matches process_name
        # against nc / ncat / socat.
        if command:
            first_token = command.split()[0]
            normalized["process_name"] = (
                first_token.rsplit("/", 1)[-1]
            )

        normalized["command_line"] = command

    else:
        raise ValueError(
            f"Unsupported simulation event type: {event_type}"
        )

    # ---------------------------------------------------------
    # Explicitly mark this as simulation telemetry.
    # ---------------------------------------------------------
    normalized["simulation"] = True
    normalized["mode"] = "LAB"
    normalized["real_attack"] = False

    return normalized


def normalize_simulation_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        normalize_simulation_event(event)
        for event in events
    ]
