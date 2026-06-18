"""Unit tests for the telemetry-aware 4-state coverage grading."""
from app.services.telemetry_coverage import (
    DATA_SOURCE_FIELD_MAP,
    CoverageState,
    data_sources_satisfied,
    grade_cell,
)


class TestDataSourceFieldMap:
    def test_map_is_non_empty_and_lowercased_keys(self):
        assert DATA_SOURCE_FIELD_MAP
        for key, fields in DATA_SOURCE_FIELD_MAP.items():
            assert key == key.lower()
            assert isinstance(fields, list)
            assert fields

    def test_process_creation_maps_to_known_ecs_fields(self):
        fields = DATA_SOURCE_FIELD_MAP["process: process creation"]
        assert "process.command_line" in fields


class TestDataSourcesSatisfied:
    def test_none_data_sources_is_not_satisfied(self):
        assert data_sources_satisfied(None, {"process.command_line"}) is False

    def test_empty_data_sources_is_not_satisfied(self):
        assert data_sources_satisfied([], {"process.command_line"}) is False

    def test_matches_when_any_candidate_field_present(self):
        assert data_sources_satisfied(
            ["Process: Process Creation"], {"process.command_line", "host.name"}
        ) is True

    def test_unknown_data_source_falls_back_to_token_match(self):
        # "Foobar: Widget" has no map entry; token "foobar" appears in a field name
        assert data_sources_satisfied(["Foobar: Widget"], {"foobar.id"}) is True

    def test_not_satisfied_when_no_fields_match(self):
        assert data_sources_satisfied(
            ["Process: Process Creation"], {"unrelated.field"}
        ) is False


class TestGradeCell:
    FIELDS = {"process.command_line"}
    DS = ["Process: Process Creation"]

    def test_deployed_with_telemetry_is_covered(self):
        assert grade_cell(True, True, self.DS, self.FIELDS) == CoverageState.COVERED

    def test_rule_present_but_no_telemetry_is_no_telemetry(self):
        assert grade_cell(False, True, self.DS, set()) == CoverageState.NO_TELEMETRY

    def test_rule_present_not_deployed_with_telemetry_is_partial(self):
        assert grade_cell(False, True, self.DS, self.FIELDS) == CoverageState.PARTIAL

    def test_no_rule_with_telemetry_is_no_rule(self):
        assert grade_cell(False, False, self.DS, self.FIELDS) == CoverageState.NO_RULE

    def test_no_rule_no_telemetry_is_no_telemetry(self):
        assert grade_cell(False, False, self.DS, set()) == CoverageState.NO_TELEMETRY


class TestSchemaDefaults:
    def test_coverage_stats_defaults(self):
        from app.schemas.attack import TechniqueCoverageStats

        stats = TechniqueCoverageStats(total=0, deployed=0)
        assert stats.state == "no_rule"
        assert stats.has_telemetry is False

    def test_navigator_request_defaults(self):
        from app.schemas.attack import NavigatorExportRequest

        req = NavigatorExportRequest()
        assert req.deployed_only is False
        assert req.telemetry is False
        assert req.severity is None
        assert req.index_pattern_id is None
