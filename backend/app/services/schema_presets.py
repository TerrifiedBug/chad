"""Deterministic schema-preset field auto-mapper.

No LLM. A static dict of Sigma detection field -> ordered candidate target
field names per schema family (ECS / Sysmon / OCSF / winlogbeat), lifted from
the equivalence prose in the AI prompt (app/services/ai_mapping.py:37-45).

The resolver picks the first preset candidate that exists in the index's
available fields; if no candidate matches, it falls back to fuzzy matching via
find_similar_fields (app/services/opensearch.py:364).
"""

from app.services.opensearch import find_similar_fields

PRESET_FAMILIES: list[str] = ["ecs", "sysmon", "ocsf", "winlogbeat"]

# Sigma field -> ordered candidate target field names. Earlier = preferred.
SCHEMA_PRESETS: dict[str, dict[str, list[str]]] = {
    "ecs": {
        "SourceIp": ["source.ip", "src_ip", "client.ip"],
        "DestinationIp": ["destination.ip", "dst_ip", "server.ip"],
        "SourcePort": ["source.port", "src_port", "client.port"],
        "DestinationPort": ["destination.port", "dst_port", "server.port"],
        "User": ["user.name", "username", "acct"],
        "Image": ["process.executable", "process.name", "exe"],
        "CommandLine": ["process.command_line", "process.args", "command"],
        "ParentImage": ["process.parent.executable", "parent_exe"],
        "TargetFilename": ["file.path", "filepath", "target_path"],
    },
    "sysmon": {
        "SourceIp": ["SourceIp", "source.ip", "src_ip"],
        "DestinationIp": ["DestinationIp", "destination.ip", "dst_ip"],
        "SourcePort": ["SourcePort", "source.port", "src_port"],
        "DestinationPort": ["DestinationPort", "destination.port", "dst_port"],
        "User": ["User", "user.name", "username"],
        "Image": ["Image", "process.executable", "exe"],
        "CommandLine": ["CommandLine", "process.command_line", "cmdline"],
        "ParentImage": ["ParentImage", "process.parent.executable"],
        "TargetFilename": ["TargetFilename", "file.path", "target_path"],
    },
    "ocsf": {
        "SourceIp": ["src_endpoint.ip", "source.ip", "src_ip"],
        "DestinationIp": ["dst_endpoint.ip", "destination.ip", "dst_ip"],
        "SourcePort": ["src_endpoint.port", "source.port"],
        "DestinationPort": ["dst_endpoint.port", "destination.port"],
        "User": ["actor.user.name", "user.name", "username"],
        "Image": ["process.file.path", "process.name", "exe"],
        "CommandLine": ["process.cmd_line", "process.command_line"],
        "ParentImage": ["process.parent_process.file.path", "parent_exe"],
        "TargetFilename": ["file.path", "file.name", "target_path"],
    },
    "winlogbeat": {
        "SourceIp": ["winlog.event_data.SourceIp", "source.ip", "src_ip"],
        "DestinationIp": ["winlog.event_data.DestinationIp", "destination.ip"],
        "SourcePort": ["winlog.event_data.SourcePort", "source.port"],
        "DestinationPort": ["winlog.event_data.DestinationPort", "destination.port"],
        "User": ["winlog.event_data.User", "user.name", "username"],
        "Image": ["winlog.event_data.Image", "process.executable"],
        "CommandLine": ["winlog.event_data.CommandLine", "process.command_line"],
        "ParentImage": ["winlog.event_data.ParentImage", "process.parent.executable"],
        "TargetFilename": ["winlog.event_data.TargetFilename", "file.path"],
    },
}


def resolve_field(
    sigma_field: str,
    family: str,
    available_fields: set[str],
) -> tuple[str | None, str]:
    """Resolve a single Sigma field to a target field deterministically.

    Returns (target_field_or_None, method) where method is one of:
    - "preset": matched a preset candidate present in available_fields
    - "fuzzy": no preset candidate present; matched via find_similar_fields
    - "none":  unresolvable
    """
    candidates = SCHEMA_PRESETS.get(family, {}).get(sigma_field, [])
    for candidate in candidates:
        if candidate in available_fields:
            return candidate, "preset"

    similar = find_similar_fields(sigma_field, available_fields)
    if similar:
        return similar[0], "fuzzy"

    return None, "none"


def score_matchability(
    sigma_fields: list[str],
    family: str,
    available_fields: set[str],
) -> tuple[int, int]:
    """Return (resolvable_count, total_count) for a set of Sigma fields."""
    total = len(sigma_fields)
    resolvable = 0
    for field in sigma_fields:
        target, method = resolve_field(field, family, available_fields)
        if target is not None and method != "none":
            resolvable += 1
    return resolvable, total
