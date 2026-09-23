# Cyber Sentinel XDR — Demo Guide

## 1. Purpose

This guide provides a repeatable demonstration workflow for Cyber Sentinel XDR. The demonstration uses the controlled LAB environment and attack simulation framework. Real attacks and real containment actions are disabled.

## 2. Start the Application

```bash
cd ~/Cyber-Sentinel-XDR
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Application URL: `http://127.0.0.1:8000`

## 3. Verify System Health

```bash
curl http://127.0.0.1:8000/api/health
```

The expected response indicates that Cyber Sentinel XDR is operational and running in LAB mode.

## 4. Generate a Controlled Attack Simulation

Available scenarios:

- SSH_BRUTE_FORCE
- PORT_SCAN
- SUSPICIOUS_AUTH
- SUSPICIOUS_NETWORK_UTILITY
- MULTI_STAGE_ATTACK

Example:

```bash
python simulations/attack_simulator.py
```

The simulator sends controlled telemetry through the real detection and correlation pipeline.

## 5. Detection Pipeline

```text
Simulation
    ↓
Security Event
    ↓
Detection Engine
    ↓
Detection Rules
    ↓
Correlation
    ↓
Risk Assessment
    ↓
Incident
```

## 6. SOC Dashboard

Open `http://127.0.0.1:8000/soc`.

The dashboard provides visibility into security events, detections, incidents, risk, attack chains, entity relationships, and security posture.

## 7. Investigation

Select an incident from the SOC interface. The investigation workflow provides incident severity, risk score, source and target, detection findings, MITRE ATT&CK techniques, event timeline, attack story, related entities, and relationships.

## 8. Threat Intelligence

The Threat Intelligence functionality presents risk, evidence strength, confidence, detection findings, MITRE ATT&CK techniques, correlation signals, and analyst-oriented next steps.

## 9. Entity & Attack Graph

The graph represents relationships between IP addresses, assets, events, detections, incidents, and MITRE ATT&CK techniques.

## 10. Incident Reporting

Incident reports are available through:

```text
/api/reports/incident/{incident_id}
/api/reports/incident/{incident_id}/html
/api/reports/incident/{incident_id}/pdf
```

Reports contain incident details, detection findings, MITRE ATT&CK mappings, evidence, and timeline information.

## 11. API Demonstration

Important endpoints:

```text
/api/health
/api/events
/api/soc/overview
/api/soc/alerts
/api/soc/graph
/api/reports/incident/{incident_id}
/api/reports/incident/{incident_id}/html
/api/reports/incident/{incident_id}/pdf
```

## 12. Testing

Run:

```bash
pytest
```

Final validation: **45 tests passed**.

Testing covers database schema, detection rules, detection boundaries, false positives, deduplication, correlation, incident lifecycle, reports, input validation, error handling, and risk assessment.

## 13. Docker Demonstration

```bash
sudo docker-compose up -d --build
sudo docker-compose ps
curl http://127.0.0.1:8000/api/health
```

Application port: `8000`.

## 14. Recommended Interview Demo Flow

1. Explain the problem
2. Show architecture
3. Start the platform
4. Generate controlled attack simulation
5. Show detections
6. Show correlated incident
7. Open investigation
8. Show MITRE ATT&CK mapping
9. Show entity/attack graph
10. Generate incident report
11. Show automated tests
12. Explain Docker deployment

## 15. Safety Notice

Cyber Sentinel XDR is a defensive security laboratory project. Attack simulation is designed for controlled testing. Real attacks are disabled and response functionality is designed for LAB operation. Use the platform only in environments where you have authorization to perform security testing.
