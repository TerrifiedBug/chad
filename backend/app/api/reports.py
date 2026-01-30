"""
Reports API - generates PDF and CSV reports for alerts and rules.

Provides:
- Alert Summary Report: alerts by severity, top rules, trends
- Rule Coverage Report: rules by status, ATT&CK coverage
"""

import csv
import io
from collections import Counter
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from opensearchpy import OpenSearch
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_opensearch_client_optional
from app.db.session import get_db
from app.models.rule import Rule
from app.models.user import User

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportFormat(str, Enum):
    PDF = "pdf"
    CSV = "csv"


class AlertSummaryRequest(BaseModel):
    format: ReportFormat = ReportFormat.CSV
    date_from: datetime | None = None
    date_to: datetime | None = None
    severity: list[str] | None = None
    index_pattern: str | None = None


class RuleCoverageRequest(BaseModel):
    format: ReportFormat = ReportFormat.CSV


def generate_alert_summary_csv(data: dict[str, Any]) -> io.StringIO:
    """Generate CSV for alert summary report."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header info
    writer.writerow(["CHAD Alert Summary Report"])
    writer.writerow([f"Generated: {datetime.now(UTC).isoformat()}"])
    writer.writerow([f"Date Range: {data['date_range']['from']} to {data['date_range']['to']}"])
    writer.writerow([])

    # Summary stats
    writer.writerow(["Summary Statistics"])
    writer.writerow(["Metric", "Value"])
    writer.writerow(["Total Alerts", data["total_alerts"]])
    for severity, count in data["by_severity"].items():
        writer.writerow([f"{severity.title()} Alerts", count])
    writer.writerow([])

    # Top triggered rules
    writer.writerow(["Top 10 Triggered Rules"])
    writer.writerow(["Rule Title", "Alert Count", "Severity"])
    for rule in data["top_rules"]:
        writer.writerow([rule["title"], rule["count"], rule["severity"]])
    writer.writerow([])

    # Alerts by day
    writer.writerow(["Alerts by Day"])
    writer.writerow(["Date", "Count"])
    for day in data["alerts_by_day"]:
        writer.writerow([day["date"], day["count"]])

    output.seek(0)
    return output


def generate_alert_summary_pdf(data: dict[str, Any]) -> io.BytesIO:
    """Generate PDF for alert summary report."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
    )
    elements.append(Paragraph("CHAD Alert Summary Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
    date_range_text = f"Date Range: {data['date_range']['from']} to {data['date_range']['to']}"
    elements.append(Paragraph(date_range_text, styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # Summary statistics
    elements.append(Paragraph("Summary Statistics", styles["Heading2"]))
    summary_data = [["Metric", "Value"]]
    summary_data.append(["Total Alerts", str(data["total_alerts"])])
    for severity, count in data["by_severity"].items():
        summary_data.append([f"{severity.title()} Alerts", str(count)])

    summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.3 * inch))

    # Top triggered rules
    elements.append(Paragraph("Top 10 Triggered Rules", styles["Heading2"]))
    if data["top_rules"]:
        rules_data = [["Rule Title", "Count", "Severity"]]
        for rule in data["top_rules"]:
            rules_data.append([rule["title"][:50], str(rule["count"]), rule["severity"]])

        rules_table = Table(rules_data, colWidths=[4 * inch, 1 * inch, 1.5 * inch])
        rules_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(rules_table)
    else:
        elements.append(Paragraph("No alerts in the selected period.", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # Alerts by day
    elements.append(Paragraph("Alerts by Day", styles["Heading2"]))
    if data["alerts_by_day"]:
        days_data = [["Date", "Count"]]
        for day in data["alerts_by_day"][:14]:  # Limit to 14 days in PDF
            days_data.append([day["date"], str(day["count"])])

        days_table = Table(days_data, colWidths=[2.5 * inch, 1.5 * inch])
        days_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(days_table)
    else:
        elements.append(Paragraph("No alerts in the selected period.", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer


def generate_rule_coverage_csv(data: dict[str, Any]) -> io.StringIO:
    """Generate CSV for rule coverage report."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header info
    writer.writerow(["CHAD Rule Coverage Report"])
    writer.writerow([f"Generated: {datetime.now(UTC).isoformat()}"])
    writer.writerow([])

    # Summary stats
    writer.writerow(["Summary Statistics"])
    writer.writerow(["Metric", "Value"])
    writer.writerow(["Total Rules", data["total_rules"]])
    writer.writerow(["Deployed Rules", data["deployed_rules"]])
    writer.writerow(["Undeployed Rules", data["undeployed_rules"]])
    writer.writerow(["Snoozed Rules", data["snoozed_rules"]])
    writer.writerow([])

    # Rules by severity
    writer.writerow(["Rules by Severity"])
    writer.writerow(["Severity", "Count"])
    for severity, count in data["by_severity"].items():
        writer.writerow([severity.title(), count])
    writer.writerow([])

    # ATT&CK coverage
    writer.writerow(["ATT&CK Technique Coverage"])
    writer.writerow(["Technique ID", "Technique Name", "Rules Count"])
    for technique in data["attack_coverage"]:
        writer.writerow([technique["id"], technique["name"], technique["rules_count"]])
    writer.writerow([])

    # Rule details
    writer.writerow(["Rule Details"])
    writer.writerow(["Title", "Severity", "Status", "Index Pattern", "ATT&CK Techniques"])
    for rule in data["rules"]:
        writer.writerow([
            rule["title"],
            rule["severity"],
            rule["status"],
            rule["index_pattern"],
            ", ".join(rule["attack_techniques"]),
        ])

    output.seek(0)
    return output


def generate_rule_coverage_pdf(data: dict[str, Any]) -> io.BytesIO:
    """Generate PDF for rule coverage report."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
    )
    elements.append(Paragraph("CHAD Rule Coverage Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # Summary statistics
    elements.append(Paragraph("Summary Statistics", styles["Heading2"]))
    summary_data = [
        ["Metric", "Value"],
        ["Total Rules", str(data["total_rules"])],
        ["Deployed Rules", str(data["deployed_rules"])],
        ["Undeployed Rules", str(data["undeployed_rules"])],
        ["Snoozed Rules", str(data["snoozed_rules"])],
    ]

    summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.3 * inch))

    # Rules by severity
    elements.append(Paragraph("Rules by Severity", styles["Heading2"]))
    severity_data = [["Severity", "Count"]]
    for severity, count in data["by_severity"].items():
        severity_data.append([severity.title(), str(count)])

    severity_table = Table(severity_data, colWidths=[2.5 * inch, 1.5 * inch])
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(severity_table)
    elements.append(Spacer(1, 0.3 * inch))

    # ATT&CK coverage (top 20)
    elements.append(Paragraph("ATT&CK Technique Coverage (Top 20)", styles["Heading2"]))
    if data["attack_coverage"]:
        attack_data = [["Technique ID", "Technique Name", "Rules"]]
        for technique in data["attack_coverage"][:20]:
            attack_data.append([
                technique["id"],
                technique["name"][:40],
                str(technique["rules_count"]),
            ])

        attack_table = Table(attack_data, colWidths=[1.5 * inch, 3.5 * inch, 1 * inch])
        attack_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(attack_table)
    else:
        elements.append(Paragraph("No ATT&CK techniques mapped to rules.", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer


@router.post("/alerts/summary")
async def generate_alert_summary_report(
    request: AlertSummaryRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    os_client: OpenSearch | None = Depends(get_opensearch_client_optional),
):
    """
    Generate an Alert Summary report.

    Returns PDF or CSV containing:
    - Total alerts by severity
    - Top 10 triggered rules
    - Alerts over time
    """
    if os_client is None:
        raise HTTPException(status_code=503, detail="OpenSearch not configured")

    # Set date range defaults
    date_to = request.date_to or datetime.now(UTC)
    date_from = request.date_from or (date_to - timedelta(days=30))

    # Build OpenSearch query
    must_clauses: list[dict] = [
        {"range": {"created_at": {"gte": date_from.isoformat(), "lte": date_to.isoformat()}}}
    ]

    if request.severity:
        must_clauses.append({"terms": {"severity": request.severity}})

    # Query alerts from OpenSearch
    index_pattern = request.index_pattern or "chad-alerts-*"
    try:
        # Get total count and severity breakdown
        agg_query = {
            "size": 0,
            "query": {"bool": {"must": must_clauses}},
            "aggs": {
                "by_severity": {"terms": {"field": "severity", "size": 10}},
                "by_rule": {
                    "terms": {"field": "rule_title.keyword", "size": 10},
                    "aggs": {"severity": {"terms": {"field": "severity", "size": 1}}},
                },
                "by_day": {
                    "date_histogram": {
                        "field": "created_at",
                        "calendar_interval": "day",
                        "format": "yyyy-MM-dd",
                    }
                },
            },
        }

        result = os_client.search(index=index_pattern, body=agg_query)

        total_alerts = result["hits"]["total"]["value"]
        aggs = result.get("aggregations", {})

        by_severity = {
            b["key"]: b["doc_count"]
            for b in aggs.get("by_severity", {}).get("buckets", [])
        }

        top_rules = [
            {
                "title": b["key"],
                "count": b["doc_count"],
                "severity": b.get("severity", {}).get("buckets", [{}])[0].get("key", "unknown"),
            }
            for b in aggs.get("by_rule", {}).get("buckets", [])
        ]

        alerts_by_day = [
            {"date": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs.get("by_day", {}).get("buckets", [])
        ]

    except Exception:
        # If index doesn't exist or query fails, return empty data
        total_alerts = 0
        by_severity = {}
        top_rules = []
        alerts_by_day = []

    # Build report data
    report_data = {
        "date_range": {
            "from": date_from.strftime("%Y-%m-%d"),
            "to": date_to.strftime("%Y-%m-%d"),
        },
        "total_alerts": total_alerts,
        "by_severity": by_severity,
        "top_rules": top_rules,
        "alerts_by_day": alerts_by_day,
    }

    # Generate output
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if request.format == ReportFormat.PDF:
        pdf_buffer = generate_alert_summary_pdf(report_data)
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="alert-summary-{timestamp}.pdf"'},
        )
    else:
        csv_buffer = generate_alert_summary_csv(report_data)
        return StreamingResponse(
            iter([csv_buffer.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="alert-summary-{timestamp}.csv"'},
        )


@router.post("/rules/coverage")
async def generate_rule_coverage_report(
    request: RuleCoverageRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Generate a Rule Coverage report.

    Returns PDF or CSV containing:
    - Rules by status (deployed/undeployed/snoozed)
    - Rules by severity
    - ATT&CK technique coverage
    """
    # Get all rules with their index patterns
    result = await db.execute(
        select(Rule).options()
    )
    rules = result.scalars().all()

    # Calculate statistics
    total_rules = len(rules)
    deployed_rules = sum(1 for r in rules if r.deployed_at is not None)
    snoozed_rules = sum(1 for r in rules if r.snooze_until is not None or r.snooze_indefinite)
    undeployed_rules = total_rules - deployed_rules

    # Helper function to extract tags from yaml_content
    def get_tags_from_yaml(yaml_content: str) -> list[str]:
        try:
            parsed = yaml.safe_load(yaml_content)
            if parsed and isinstance(parsed, dict):
                return parsed.get("tags", []) or []
        except Exception:
            pass
        return []

    # Severity distribution
    severity_counter: Counter = Counter()
    for rule in rules:
        severity_counter[rule.severity] += 1

    # ATT&CK technique coverage
    technique_counter: Counter = Counter()
    technique_names: dict[str, str] = {}

    for rule in rules:
        tags = get_tags_from_yaml(rule.yaml_content)
        for tag in tags:
            if isinstance(tag, str) and (tag.startswith("attack.t") or tag.startswith("attack.T")):
                # Extract technique ID
                technique_id = tag.replace("attack.", "").upper()
                technique_counter[technique_id] += 1
                if technique_id not in technique_names:
                    technique_names[technique_id] = technique_id  # Use ID as placeholder

    attack_coverage = [
        {"id": tid, "name": technique_names.get(tid, tid), "rules_count": count}
        for tid, count in technique_counter.most_common(50)
    ]

    # Rule details
    rule_details = []
    for rule in rules:
        status = "deployed" if rule.deployed_at else "undeployed"
        if rule.snooze_until or rule.snooze_indefinite:
            status = "snoozed"

        tags = get_tags_from_yaml(rule.yaml_content)
        attack_techniques = [
            tag.replace("attack.", "").upper()
            for tag in tags
            if isinstance(tag, str) and (tag.startswith("attack.t") or tag.startswith("attack.T"))
        ]

        rule_details.append({
            "title": rule.title,
            "severity": rule.severity,
            "status": status,
            "index_pattern": str(rule.index_pattern_id) if rule.index_pattern_id else "",
            "attack_techniques": attack_techniques,
        })

    # Build report data
    report_data = {
        "total_rules": total_rules,
        "deployed_rules": deployed_rules,
        "undeployed_rules": undeployed_rules,
        "snoozed_rules": snoozed_rules,
        "by_severity": dict(severity_counter),
        "attack_coverage": attack_coverage,
        "rules": rule_details,
    }

    # Generate output
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if request.format == ReportFormat.PDF:
        pdf_buffer = generate_rule_coverage_pdf(report_data)
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="rule-coverage-{timestamp}.pdf"'},
        )
    else:
        csv_buffer = generate_rule_coverage_csv(report_data)
        return StreamingResponse(
            iter([csv_buffer.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="rule-coverage-{timestamp}.csv"'},
        )
