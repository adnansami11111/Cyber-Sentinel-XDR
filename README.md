# Cyber Sentinel XDR

[![Python](https://img.shields.io/badge/Python-3.13-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-API-green)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Tests-45%20Passed-brightgreen)](#testing)
[![Mode](https://img.shields.io/badge/Mode-LAB-orange)](#security-design)

A defensive, lab-focused Extended Detection and Response (XDR) platform for security monitoring, threat detection, threat intelligence, investigation, attack simulation, and incident reporting.

## Overview

Cyber Sentinel XDR is a Python/FastAPI-based cybersecurity platform designed as a controlled security operations lab.

It combines:

- Security telemetry ingestion
- Detection rules and runtime thresholds
- Event correlation and deduplication
- Risk scoring
- MITRE ATT&CK mapping
- Threat intelligence and IOC analysis
- Entity and attack graphs
- SOC dashboard
- Investigation workspace
- LAB-only response and containment
- Controlled attack simulation
- Automated incident reports
- Automated testing
- Docker deployment

> **Safety:** This project is designed for defensive security research and controlled laboratory environments. Attack simulation functionality is intentionally LAB-only and does not perform real-world attacks or containment.

---

## Architecture

```text
                    ┌──────────────────────┐
                    │   Security Telemetry │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Event Processing   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Detection Engine   │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
             ┌─────────────┐       ┌─────────────┐
             │ Correlation │       │ Risk Engine │
             └──────┬──────┘       └──────┬──────┘
                    │                     │
                    └──────────┬──────────┘
                               ▼
                    ┌──────────────────────┐
                    │ Incident Management  │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
      ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
      │ Threat Intel│   │ MITRE ATT&CK│   │ Attack Graph│
      └─────────────┘   └─────────────┘   └─────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │     SOC Dashboard    │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
      ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
      │Investigation│   │Response LAB │   │   Reports   │
      └─────────────┘   └─────────────┘   └─────────────┘

## SOC Dashboard

The SOC Command Center provides a centralized view of security activity, including incidents, alerts, threat activity, detection streams, risk distribution, suspicious sources, and MITRE ATT&CK activity.

![Cyber Sentinel XDR SOC Dashboard](docs/screenshots/soc-dashboard.png)


## Screenshots

### SOC Dashboard
![SOC Dashboard](docs/screenshots/soc-dashboard.png)

### Incident Report — Overview
![Incident Report Overview](docs/screenshots/incident-report-overview.png)

### Incident Report — Detection & MITRE ATT&CK
![Incident Report Detection and MITRE](docs/screenshots/incident-report-detection-mitre.png)
