"""Tests for deterministic schema preset auto-mapper (no LLM, no OpenSearch)."""

from app.services.schema_presets import (
    PRESET_FAMILIES,
    SCHEMA_PRESETS,
    resolve_field,
    score_matchability,
)


class TestPresetTable:
    def test_families_present(self):
        assert PRESET_FAMILIES == ["ecs", "sysmon", "ocsf", "winlogbeat"]
        for family in PRESET_FAMILIES:
            assert family in SCHEMA_PRESETS

    def test_ecs_has_core_sigma_fields(self):
        ecs = SCHEMA_PRESETS["ecs"]
        assert "SourceIp" in ecs
        assert "source.ip" in ecs["SourceIp"]
        assert "process.executable" in ecs["Image"]
        assert "process.command_line" in ecs["CommandLine"]

    def test_candidates_are_ordered_lists(self):
        for family, mapping in SCHEMA_PRESETS.items():
            for sigma_field, candidates in mapping.items():
                assert isinstance(candidates, list)
                assert all(isinstance(c, str) for c in candidates)


class TestResolveField:
    def test_resolves_first_candidate_present(self):
        target, method = resolve_field(
            "SourceIp", "ecs", {"source.ip", "destination.ip", "timestamp"}
        )
        assert target == "source.ip"
        assert method == "preset"

    def test_picks_first_in_candidate_order(self):
        # ECS SourceIp candidate order is ["source.ip", "src_ip", "client.ip"].
        # When both src_ip and source.ip exist, source.ip wins (earlier).
        target, method = resolve_field(
            "SourceIp", "ecs", {"src_ip", "source.ip"}
        )
        assert target == "source.ip"
        assert method == "preset"

    def test_falls_back_to_fuzzy_when_no_preset_candidate(self):
        # No preset candidate present, but a field fuzzy-close to the Sigma
        # field name exists. find_similar_fields matches against the Sigma
        # field ("CommandLine"), so the close field must resemble that name.
        target, method = resolve_field(
            "CommandLine", "ecs", {"CommandLin", "unrelated.field"}
        )
        assert target == "CommandLin"
        assert method == "fuzzy"

    def test_returns_none_when_unresolvable(self):
        target, method = resolve_field(
            "SourceIp", "ecs", {"totally", "unrelated"}
        )
        assert target is None
        assert method == "none"

    def test_unknown_sigma_field_uses_fuzzy_only(self):
        target, method = resolve_field(
            "WeirdCustomField", "ecs", {"weirdcustomfield", "other"}
        )
        assert target == "weirdcustomfield"
        assert method == "fuzzy"

    def test_unknown_family_uses_fuzzy_only(self):
        target, method = resolve_field(
            "SourceIp", "nosuchfamily", {"source.ip"}
        )
        # No preset table for the family, so only fuzzy can match.
        assert method in ("fuzzy", "none")


class TestScoreMatchability:
    def test_counts_resolvable(self):
        resolvable, total = score_matchability(
            ["SourceIp", "User", "Image"],
            "ecs",
            {"source.ip", "user.name"},
        )
        assert total == 3
        assert resolvable == 2  # SourceIp + User resolvable, Image not

    def test_empty_fields(self):
        resolvable, total = score_matchability([], "ecs", {"source.ip"})
        assert (resolvable, total) == (0, 0)

    def test_all_resolvable(self):
        resolvable, total = score_matchability(
            ["SourceIp", "DestinationIp"],
            "ecs",
            {"source.ip", "destination.ip"},
        )
        assert (resolvable, total) == (2, 2)
