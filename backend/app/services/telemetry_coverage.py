"""
Telemetry-aware ATT&CK coverage grading.

Maps MITRE ATT&CK data-source names to candidate OpenSearch (ECS-style) field
names, then grades each technique into one of four states by crossing
rule-deployment with whether the technique's required telemetry actually exists
in the configured index patterns.

This module is pure (no DB / no network) so it is trivially unit-testable.
"""
from __future__ import annotations


class CoverageState:
    """The four telemetry-aware coverage states for an ATT&CK technique."""

    COVERED = "covered"          # deployed rule(s) AND telemetry present
    PARTIAL = "partial"          # rule(s) exist but undeployed, telemetry present
    NO_RULE = "no_rule"          # telemetry present but no detection rule
    NO_TELEMETRY = "no_telemetry"  # required telemetry fields are missing


# ATT&CK data-source name (lowercased) -> candidate OpenSearch field names.
# A data source is "satisfied" if ANY candidate field exists in the index. Field
# names follow Elastic Common Schema (ECS), the de-facto OpenSearch convention.
DATA_SOURCE_FIELD_MAP: dict[str, list[str]] = {
    "process: process creation": [
        "process.command_line",
        "process.name",
        "process.executable",
        "process.pid",
    ],
    "process: process termination": ["process.name", "process.pid", "process.end"],
    "process: os api execution": ["process.name", "process.command_line"],
    "command: command execution": ["process.command_line", "process.args"],
    "file: file creation": ["file.path", "file.name", "file.directory"],
    "file: file modification": ["file.path", "file.name", "file.mtime"],
    "file: file deletion": ["file.path", "file.name"],
    "file: file access": ["file.path", "file.name"],
    "network traffic: network connection creation": [
        "destination.ip",
        "source.ip",
        "network.transport",
        "destination.port",
    ],
    "network traffic: network traffic flow": [
        "network.bytes",
        "source.ip",
        "destination.ip",
    ],
    "network traffic: network traffic content": ["http.request.method", "url.full", "dns.question.name"],
    "logon session: logon session creation": [
        "winlog.event_id",
        "user.name",
        "event.action",
        "source.ip",
    ],
    "logon session: logon session metadata": ["user.name", "winlog.event_id"],
    "user account: user account creation": ["user.name", "winlog.event_id", "event.action"],
    "user account: user account modification": ["user.name", "event.action"],
    "windows registry: windows registry key creation": ["registry.path", "registry.key", "winlog.event_id"],
    "windows registry: windows registry key modification": ["registry.path", "registry.value", "winlog.event_id"],
    "module: module load": ["dll.path", "process.name", "winlog.event_id"],
    "scheduled job: scheduled job creation": ["winlog.event_id", "event.action", "process.command_line"],
    "service: service creation": ["winlog.event_id", "service.name", "event.action"],
    "service: service modification": ["service.name", "event.action"],
    "driver: driver load": ["dll.path", "winlog.event_id"],
    "script: script execution": ["process.command_line", "powershell.command.value"],
    "application log: application log content": ["message", "event.action", "event.code"],
    "cloud service: cloud service enumeration": ["cloud.provider", "event.action", "user.name"],
    "active directory: active directory object access": ["winlog.event_id", "user.name", "event.action"],
}


def data_sources_satisfied(
    data_sources: list[str] | None,
    available_fields: set[str],
) -> bool:
    """Return True if at least one of the technique's data sources is satisfied.

    A data source is satisfied when a mapped candidate field exists in
    ``available_fields``. For data sources with no map entry, fall back to a
    token match: the data source's leading category token (e.g. "process" from
    "Process: Process Creation") appearing as a dotted prefix in any field name.
    """
    if not data_sources:
        return False

    if not available_fields:
        return False

    for raw in data_sources:
        key = raw.strip().lower()
        candidates = DATA_SOURCE_FIELD_MAP.get(key)
        if candidates:
            if any(field in available_fields for field in candidates):
                return True
            continue

        # Fallback: match the leading category token against field prefixes.
        token = key.split(":", 1)[0].strip()
        if token and any(
            field == token or field.startswith(f"{token}.") for field in available_fields
        ):
            return True

    return False


def grade_cell(
    rule_deployed: bool,
    has_rule: bool,
    data_sources: list[str] | None,
    available_fields: set[str],
) -> str:
    """Grade a single technique cell into one of the four CoverageState values.

    Args:
        rule_deployed: At least one mapped rule for this technique is DEPLOYED.
        has_rule: At least one rule (any status) is mapped to this technique.
        data_sources: Technique's ATT&CK data sources (from the cached STIX data).
        available_fields: Union of fields available across configured index patterns.
    """
    has_telemetry = data_sources_satisfied(data_sources, available_fields)

    if not has_telemetry:
        return CoverageState.NO_TELEMETRY
    if rule_deployed:
        return CoverageState.COVERED
    if has_rule:
        return CoverageState.PARTIAL
    return CoverageState.NO_RULE
