# Cyber Sentinel XDR — Project Overview

## 1. Project Summary

Cyber Sentinel XDR is a defensive cybersecurity platform designed to demonstrate an end-to-end XDR/SOC workflow.

The platform collects security telemetry, applies detection rules, correlates related security activity, calculates risk, maps detections to MITRE ATT&CK techniques, manages incidents, supports investigation, provides threat-intelligence capabilities, and generates automated incident reports.

The project operates in a controlled LAB environment and includes an attack simulation framework for safely testing the detection and correlation pipeline.

---

## 2. Core Objectives

The project was designed to demonstrate:

- Security telemetry ingestion
- Detection engineering
- Threshold-based detection
- Event correlation
- Risk scoring
- Incident management
- MITRE ATT&CK mapping
- Threat intelligence analysis
- IOC analysis
- Entity and attack graph visualization
- SOC monitoring
- Investigation workflows
- Controlled response actions
- Attack simulation
- Automated security reporting
- Automated testing
- Containerized deployment

---

## 3. Detection Pipeline

The primary security-processing pipeline is:

```text
Telemetry
    ↓
Security Event
    ↓
Detection Rules
    ↓
Runtime Threshold
    ↓
Deduplication
    ↓
Correlation
    ↓
Risk Assessment
    ↓
Incident Creation
    ↓
Investigation / Reporting
