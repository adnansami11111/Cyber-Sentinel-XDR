# Cyber Sentinel XDR — Architecture

## 1. System Overview

Cyber Sentinel XDR is a defensive, lab-focused Extended Detection and Response platform built around a FastAPI backend, asynchronous SQLAlchemy database layer, detection engine, threat intelligence modules, investigation workspace, SOC dashboard, simulation engine, response lab, and automated reporting.

The platform is designed to demonstrate how security telemetry can move through a complete detection and investigation lifecycle.

---

## 2. High-Level Architecture

```text
                         ┌─────────────────────────┐
                         │      Security Events    │
                         │                         │
                         │ Auth / Network / Process│
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │   Telemetry Ingestion   │
                         │       FastAPI API       │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │    Security Event DB    │
                         │     SQLite / SQLAlchemy │
                         └────────────┬────────────┘
                                      │
                                      ▼
                    ┌──────────────────────────────────┐
                    │       Detection Dispatcher       │
                    └───────────────┬──────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
       ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
       │ Brute Force │       │ Port Scan   │       │ Suspicious  │
       │ Detection   │       │ Detection   │       │ Process/Auth│
       └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    ▼
                         ┌─────────────────────────┐
                         │ Deduplication &         │
                         │ Correlation Engine      │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ Risk Scoring & MITRE    │
                         │ ATT&CK Mapping          │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ Incident Management     │
                         └────────────┬────────────┘
                                      │
             ┌────────────────────────┼────────────────────────┐
             ▼                        ▼                        ▼
      ┌─────────────┐        ┌────────────────┐        ┌─────────────┐
      │ SOC         │        │ Investigation  │        │ Threat Intel│
      │ Dashboard   │        │ Workspace      │        │ / IOC       │
      └─────────────┘        └────────────────┘        └─────────────┘
             │                        │                        │
             └────────────────────────┼────────────────────────┘
                                      ▼
                         ┌─────────────────────────┐
                         │ Response & Containment  │
                         │        LAB              │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ Automated Incident      │
                         │ Reports / HTML / PDF    │
                         └─────────────────────────┘
