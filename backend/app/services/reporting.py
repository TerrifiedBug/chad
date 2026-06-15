"""Scheduled reporting + compliance report builder (F5).

Builds detection-posture and compliance reports from data CHAD already holds
(ATT&CK coverage, rule hygiene, alert KPIs) and delivers them to a webhook. The
compliance report maps CHAD's controls to common frameworks (PCI-DSS, SOC 2,
ISO 27001, DORA) so an auditor sees which obligations the detection programme
addresses.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.attack_technique import RuleAttackMapping
from app.models.report_schedule import ReportCadence, ReportSchedule, ReportType
from app.models.rule import Rule, RuleStatus
from app.services.settings import get_setting

logger = logging.getLogger(__name__)

# Compliance frameworks → the control areas CHAD's detection programme supports.
COMPLIANCE_FRAMEWORKS: dict[str, dict[str, Any]] = {
    "pci_dss": {
        "name": "PCI-DSS v4.0",
        "controls": [
            ("10.2", "Audit trails of user actions", "audit_logging"),
            ("10.7", "Failures of critical security controls detected", "health_monitoring"),
            ("11.5", "Intrusion-detection techniques alert on compromise", "detection_rules"),
            ("8.4", "Multi-factor authentication enforced", "mfa"),
        ],
    },
    "soc2": {
        "name": "SOC 2 (CC series)",
        "controls": [
            ("CC7.2", "Anomalies and security events are detected", "detection_rules"),
            ("CC7.3", "Security incidents are evaluated", "case_management"),
            ("CC6.1", "Logical access — MFA", "mfa"),
            ("CC4.1", "Monitoring of controls", "audit_logging"),
        ],
    },
    "iso_27001": {
        "name": "ISO/IEC 27001:2022",
        "controls": [
            ("A.8.16", "Monitoring activities", "detection_rules"),
            ("A.8.15", "Logging", "audit_logging"),
            ("A.5.7", "Threat intelligence", "threat_intel"),
            ("A.8.5", "Secure authentication (MFA)", "mfa"),
        ],
    },
    "dora": {
        "name": "DORA (Digital Operational Resilience Act)",
        "controls": [
            ("Art.10", "Detection of anomalous activities", "detection_rules"),
            ("Art.11", "Response and recovery", "case_management"),
            ("Art.9", "Protection and prevention — logging", "audit_logging"),
        ],
    },
}


def compute_next_run(now: datetime, cadence: str) -> datetime:
    """Next run time for a cadence (simple fixed intervals)."""
    if cadence == ReportCadence.DAILY.value:
        return now + timedelta(days=1)
    if cadence == ReportCadence.MONTHLY.value:
        return now + timedelta(days=30)
    return now + timedelta(days=7)  # weekly default


async def _coverage_section(db: AsyncSession) -> dict[str, Any]:
    from app.services.attack_coverage import attack_coverage_service

    total = await attack_coverage_service.get_technique_count(db)
    covered = (
        await db.execute(
            select(func.count(func.distinct(RuleAttackMapping.technique_id)))
            .join(Rule, Rule.id == RuleAttackMapping.rule_id)
            .where(Rule.status == RuleStatus.DEPLOYED)
        )
    ).scalar() or 0
    pct = round(100 * covered / total, 1) if total else 0.0
    return {
        "title": "ATT&CK coverage",
        "techniques_total": total,
        "techniques_covered": covered,
        "coverage_pct": pct,
    }


async def _rule_health_section(db: AsyncSession) -> dict[str, Any]:
    rows = (
        await db.execute(select(Rule.status, func.count(Rule.id)).group_by(Rule.status))
    ).all()
    by_status = {str(getattr(s, "value", s)): c for s, c in rows}
    return {
        "title": "Rule hygiene",
        "deployed": by_status.get("deployed", 0),
        "undeployed": by_status.get("undeployed", 0),
        "snoozed": by_status.get("snoozed", 0),
        "total": sum(by_status.values()),
    }


def _kpi_section(os_client) -> dict[str, Any]:
    if os_client is None:
        return {"title": "Detection KPIs", "available": False,
                "note": "OpenSearch unavailable; alert KPIs skipped."}
    try:
        from app.services.alerts import AlertService

        counts = AlertService(os_client).get_alert_counts()
        by_status = getattr(counts, "by_status", None) or {}
        total = sum(by_status.values()) if by_status else 0
        fp = by_status.get("false_positive", 0)
        fp_rate = round(100 * fp / total, 1) if total else 0.0
        return {
            "title": "Detection KPIs",
            "available": True,
            "alerts_total": total,
            "false_positives": fp,
            "false_positive_rate_pct": fp_rate,
            "open": by_status.get("new", 0) + by_status.get("acknowledged", 0),
        }
    except Exception as e:
        logger.warning("KPI section failed: %s", e)
        return {"title": "Detection KPIs", "available": False, "note": str(e)}


async def _control_status(db: AsyncSession) -> dict[str, bool]:
    """Whether each CHAD control area is currently 'addressed' (config-driven)."""
    security = await get_setting(db, "security") or {}
    audit = await get_setting(db, "audit_hardening") or {}
    notif = await get_setting(db, "notification_settings") or {}
    rule_count = (await db.execute(select(func.count(Rule.id)))).scalar() or 0
    ti = await get_setting(db, "ti_config") or {}
    return {
        "audit_logging": True,  # always on (tamper-evident chain)
        "health_monitoring": True,
        "detection_rules": rule_count > 0,
        "mfa": bool(security.get("enforce_mfa")),
        "case_management": True,
        "threat_intel": bool(ti),
        "siem_forward": bool(audit.get("forward", {}).get("enabled")) or bool(notif),
    }


async def build_report(
    db: AsyncSession, os_client, report_type: str, framework: str | None = None
) -> dict[str, Any]:
    """Build a report payload of ``report_type`` (optionally framework-mapped)."""
    now = datetime.now(UTC)
    report: dict[str, Any] = {
        "generated_at": now.isoformat(),
        "type": report_type,
        "sections": [],
    }

    if report_type == ReportType.COVERAGE.value:
        report["sections"].append(await _coverage_section(db))
    elif report_type == ReportType.RULE_HEALTH.value:
        report["sections"].append(await _rule_health_section(db))
    elif report_type == ReportType.DETECTION_KPIS.value:
        report["sections"].append(_kpi_section(os_client))
    elif report_type == ReportType.COMPLIANCE.value:
        fw = COMPLIANCE_FRAMEWORKS.get(framework or "")
        if fw is None:
            raise ValueError(f"Unknown framework: {framework}")
        report["framework"] = framework
        report["framework_name"] = fw["name"]
        status = await _control_status(db)
        report["sections"] = [
            await _coverage_section(db),
            {
                "title": f"{fw['name']} control mapping",
                "controls": [
                    {"id": cid, "description": desc, "addressed": status.get(area, False)}
                    for cid, desc, area in fw["controls"]
                ],
            },
        ]
    else:
        raise ValueError(f"Unknown report type: {report_type}")

    return report


async def deliver_report(
    schedule: ReportSchedule, report: dict[str, Any], decrypt_header=None
) -> bool:
    """POST a built report to the schedule's webhook target. Returns success."""
    if schedule.delivery_type != "webhook" or not schedule.delivery_target:
        return False
    headers = {}
    if schedule.delivery_header_name and schedule.delivery_header_value:
        value = schedule.delivery_header_value
        if decrypt_header is not None:
            try:
                value = decrypt_header(value)
            except Exception:
                pass
        headers[schedule.delivery_header_name] = value
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                schedule.delivery_target,
                json={"report_name": schedule.name, "report": report},
                headers=headers,
            )
            resp.raise_for_status()
        return True
    except Exception as e:
        logger.warning("Report delivery failed for %s: %s", schedule.id, e)
        return False
