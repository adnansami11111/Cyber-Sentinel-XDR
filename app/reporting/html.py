from __future__ import annotations

from html import escape
from typing import Any


def _safe(value: Any) -> str:
    if value is None:
        return "-"
    return escape(str(value))


def _table_rows(items: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    if not items:
        return '<tr><td colspan="99">No data available.</td></tr>'

    rows = []

    for item in items:
        cells = []
        for key, _ in columns:
            cells.append(f"<td>{_safe(item.get(key))}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")

    return "\n".join(rows)


def render_incident_report_html(report: dict[str, Any]) -> str:
    metadata = report.get("metadata", {})
    incident = report.get("incident", {})
    detections = report.get("detections", [])
    mitre_mapping = report.get("mitre_mapping", [])
    evidence = report.get("evidence", [])
    timeline = report.get("timeline", [])
    response_actions = report.get("response_actions", [])
    affected_assets = report.get("affected_assets", [])
    iocs = report.get("indicators_of_compromise", [])
    recommendations = report.get("recommendations", [])
    risk = report.get("risk_assessment", {})
    response = report.get("response_summary", {})

    detection_rows = _table_rows(
        detections,
        [
            ("detection_id", "ID"),
            ("detection_name", "Detection"),
            ("severity", "Severity"),
            ("confidence", "Confidence"),
            ("risk_score", "Risk"),
            ("status", "Status"),
            ("mitre_technique", "MITRE"),
        ],
    )

    mitre_rows = _table_rows(
        mitre_mapping,
        [
            ("technique_id", "Technique"),
            ("technique_name", "Name"),
            ("tactic", "Tactic"),
            ("description", "Description"),
        ],
    )

    evidence_rows = _table_rows(
        evidence,
        [
            ("timestamp", "Timestamp"),
            ("event_type", "Event"),
            ("source_ip", "Source"),
            ("destination_ip", "Destination"),
            ("description", "Description"),
        ],
    )

    timeline_rows = _table_rows(
        timeline,
        [
            ("timestamp", "Timestamp"),
            ("event", "Event"),
            ("severity", "Severity"),
            ("source", "Source"),
        ],
    )

    response_rows = _table_rows(
        response_actions,
        [
            ("action_id", "ID"),
            ("action_type", "Action"),
            ("target", "Target"),
            ("mode", "Mode"),
            ("status", "Status"),
            ("reason", "Reason"),
            ("created_at", "Created"),
        ],
    )

    asset_items = "".join(
        f"<li>{_safe(asset)}</li>" for asset in affected_assets
    ) or "<li>None</li>"

    ioc_items = "".join(
        f"<li><code>{_safe(ioc)}</code></li>" for ioc in iocs
    ) or "<li>None</li>"

    recommendation_items = "".join(
        f"<li>{_safe(item)}</li>" for item in recommendations
    ) or "<li>None</li>"

    risk_level = _safe(risk.get("risk_level", "UNKNOWN"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Incident Report - {_safe(incident.get("incident_id"))}</title>

<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #f4f6f8;
    color: #17202a;
}}

.container {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px;
}}

.header {{
    background: #111827;
    color: white;
    padding: 32px;
    border-radius: 14px;
    margin-bottom: 24px;
}}

.header h1 {{
    margin: 0 0 8px;
    font-size: 30px;
}}

.header p {{
    margin: 4px 0;
    color: #d1d5db;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}}

.card {{
    background: white;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.06);
}}

.card h3 {{
    margin-top: 0;
    color: #374151;
}}

.metric {{
    font-size: 28px;
    font-weight: bold;
}}

.section {{
    background: white;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.06);
}}

.section h2 {{
    margin-top: 0;
    border-bottom: 1px solid #e5e7eb;
    padding-bottom: 12px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}}

th, td {{
    text-align: left;
    padding: 10px;
    border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
}}

th {{
    background: #f9fafb;
    font-weight: 600;
}}

ul {{
    line-height: 1.8;
}}

code {{
    background: #f3f4f6;
    padding: 3px 6px;
    border-radius: 5px;
}}

.badge {{
    display: inline-block;
    padding: 5px 10px;
    border-radius: 999px;
    font-weight: bold;
    font-size: 13px;
    background: #e5e7eb;
}}

.footer {{
    text-align: center;
    color: #6b7280;
    padding: 20px;
    font-size: 13px;
}}

@media print {{
    body {{
        background: white;
    }}

    .container {{
        max-width: none;
        padding: 10px;
    }}

    .section, .card {{
        box-shadow: none;
        border: 1px solid #ddd;
    }}
}}
</style>
</head>

<body>
<div class="container">

<div class="header">
    <h1>Cyber Sentinel XDR</h1>
    <p>Automated Security Incident Report</p>
    <p>Report ID: {_safe(metadata.get("report_id"))}</p>
    <p>Generated: {_safe(metadata.get("generated_at"))}</p>
    <p>Mode: {_safe(metadata.get("mode"))}</p>
</div>

<div class="grid">
    <div class="card">
        <h3>Incident</h3>
        <div class="metric">{_safe(incident.get("incident_id"))}</div>
    </div>

    <div class="card">
        <h3>Severity</h3>
        <div class="metric">{_safe(incident.get("severity"))}</div>
    </div>

    <div class="card">
        <h3>Risk Score</h3>
        <div class="metric">{_safe(incident.get("risk_score"))}</div>
    </div>

    <div class="card">
        <h3>Risk Level</h3>
        <div class="metric">{risk_level}</div>
    </div>
</div>

<div class="section">
    <h2>Executive Summary</h2>
    <p>{_safe(report.get("executive_summary"))}</p>
</div>

<div class="section">
    <h2>Incident Details</h2>
    <table>
        <tr><th>Incident Key</th><td>{_safe(incident.get("incident_key"))}</td></tr>
        <tr><th>Title</th><td>{_safe(incident.get("title"))}</td></tr>
        <tr><th>Status</th><td>{_safe(incident.get("status"))}</td></tr>
        <tr><th>Severity</th><td>{_safe(incident.get("severity"))}</td></tr>
        <tr><th>Risk Score</th><td>{_safe(incident.get("risk_score"))}</td></tr>
        <tr><th>Source IP</th><td><code>{_safe(incident.get("source_ip"))}</code></td></tr>
        <tr><th>Target Asset</th><td>{_safe(incident.get("target_asset"))}</td></tr>
    </table>
</div>

<div class="section">
    <h2>Risk Assessment</h2>
    <table>
        <tr><th>Risk Level</th><td><span class="badge">{risk_level}</span></td></tr>
        <tr><th>Risk Score</th><td>{_safe(risk.get("risk_score"))}</td></tr>
        <tr><th>Detection Count</th><td>{_safe(risk.get("detection_count"))}</td></tr>
        <tr><th>MITRE Techniques</th><td>{_safe(risk.get("mitre_technique_count"))}</td></tr>
        <tr><th>IOC Count</th><td>{_safe(risk.get("ioc_count"))}</td></tr>
        <tr><th>Response Actions</th><td>{_safe(risk.get("response_action_count"))}</td></tr>
    </table>

    <h3>Risk Factors</h3>
    <ul>
        {''.join(f"<li>{_safe(x)}</li>" for x in risk.get("risk_factors", [])) or "<li>None</li>"}
    </ul>
</div>

<div class="section">
    <h2>Detection Findings</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Detection</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Risk</th>
                <th>Status</th>
                <th>MITRE</th>
            </tr>
        </thead>
        <tbody>
            {detection_rows}
        </tbody>
    </table>
</div>

<div class="section">
    <h2>MITRE ATT&CK Mapping</h2>
    <table>
        <thead>
            <tr>
                <th>Technique</th>
                <th>Name</th>
                <th>Tactic</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
            {mitre_rows}
        </tbody>
    </table>
</div>

<div class="section">
    <h2>Evidence</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Event</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
            {evidence_rows}
        </tbody>
    </table>
</div>

<div class="section">
    <h2>Event Timeline</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Event</th>
                <th>Severity</th>
                <th>Source</th>
            </tr>
        </thead>
        <tbody>
            {timeline_rows}
        </tbody>
    </table>
</div>

<div class="section">
    <h2>Response / Containment</h2>
    <p><strong>Status:</strong> {_safe(response.get("containment_status"))}</p>
    <p><strong>Summary:</strong> {_safe(response.get("summary"))}</p>
    <p><strong>Lab Only:</strong> {_safe(response.get("lab_only"))}</p>
    <p><strong>Simulation Only:</strong> {_safe(response.get("simulation_only"))}</p>

    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Action</th>
                <th>Target</th>
                <th>Mode</th>
                <th>Status</th>
                <th>Reason</th>
                <th>Created</th>
            </tr>
        </thead>
        <tbody>
            {response_rows}
        </tbody>
    </table>
</div>

<div class="section">
    <h2>Affected Assets</h2>
    <ul>{asset_items}</ul>
</div>

<div class="section">
    <h2>Indicators of Compromise</h2>
    <ul>{ioc_items}</ul>
</div>

<div class="section">
    <h2>Recommendations</h2>
    <ul>{recommendation_items}</ul>
</div>

<div class="footer">
    Cyber Sentinel XDR — Automated Security Reporting — LAB MODE
</div>

</div>
</body>
</html>
"""
