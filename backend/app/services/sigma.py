"""Sigma rule parsing, validation, and translation service."""

from dataclasses import dataclass
from typing import Any

import yaml
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.base import Pipeline
from sigma.rule import SigmaRule


@dataclass
class ValidationError:
    """Represents a validation error in a Sigma rule."""

    type: str  # "syntax", "schema", "field"
    message: str
    line: int | None = None
    field: str | None = None


@dataclass
class TranslationResult:
    """Result of translating a Sigma rule to OpenSearch query."""

    success: bool
    query: dict[str, Any] | None = None
    errors: list[ValidationError] | None = None
    fields: set[str] | None = None


class SigmaService:
    """Service for parsing, validating, and translating Sigma rules."""

    def __init__(self) -> None:
        self._backend = OpensearchLuceneBackend()

    def parse_rule(self, yaml_content: str) -> SigmaRule | None:
        """
        Parse YAML content into a SigmaRule object.

        Args:
            yaml_content: Raw YAML string of the Sigma rule

        Returns:
            SigmaRule object if parsing succeeds, None otherwise

        Raises:
            ValueError: If YAML is invalid or not a valid Sigma rule
        """
        try:
            # First validate it's valid YAML
            parsed = yaml.safe_load(yaml_content)
            if not isinstance(parsed, dict):
                raise ValueError("Sigma rule must be a YAML mapping")

            # Parse as Sigma rule
            rule = SigmaRule.from_yaml(yaml_content)
            return rule
        except yaml.YAMLError as e:
            # Extract line number from YAML error if available
            line = None
            if hasattr(e, "problem_mark") and e.problem_mark:
                line = e.problem_mark.line + 1
            raise ValueError(f"Invalid YAML syntax: {e}") from e
        except SigmaError as e:
            raise ValueError(f"Invalid Sigma rule: {e}") from e

    def validate_rule(self, yaml_content: str) -> list[ValidationError]:
        """
        Validate a Sigma rule for syntax and schema errors.

        Args:
            yaml_content: Raw YAML string of the Sigma rule

        Returns:
            List of ValidationError objects (empty if valid)
        """
        errors: list[ValidationError] = []

        # Check YAML syntax
        try:
            parsed = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            line = None
            if hasattr(e, "problem_mark") and e.problem_mark:
                line = e.problem_mark.line + 1
            errors.append(
                ValidationError(
                    type="syntax",
                    message=f"Invalid YAML: {e}",
                    line=line,
                )
            )
            return errors

        if not isinstance(parsed, dict):
            errors.append(
                ValidationError(
                    type="syntax",
                    message="Sigma rule must be a YAML mapping",
                    line=1,
                )
            )
            return errors

        # Check required Sigma fields
        required_fields = ["title", "logsource", "detection"]
        for field in required_fields:
            if field not in parsed:
                errors.append(
                    ValidationError(
                        type="schema",
                        message=f"Missing required field: {field}",
                        field=field,
                    )
                )

        if errors:
            return errors

        # Try to parse as Sigma rule for deeper validation
        try:
            SigmaRule.from_yaml(yaml_content)
        except SigmaError as e:
            errors.append(
                ValidationError(
                    type="schema",
                    message=str(e),
                )
            )

        return errors

    def translate_to_opensearch(
        self, rule: SigmaRule, pipeline: Pipeline | None = None
    ) -> dict[str, Any]:
        """
        Convert a SigmaRule to OpenSearch percolator query DSL.

        Args:
            rule: Parsed SigmaRule object
            pipeline: Optional processing pipeline for field transformations

        Returns:
            OpenSearch query DSL as a dictionary
        """
        # Create a collection with single rule
        collection = SigmaCollection(init_rules=[rule])

        # Apply pipeline if provided
        if pipeline:
            collection = pipeline.apply(collection)

        # Convert to OpenSearch query
        queries = self._backend.convert(collection)

        if not queries:
            return {"query": {"match_none": {}}}

        # Backend returns list of query strings, we need the DSL
        # The OpensearchLuceneBackend returns Lucene query strings
        # We wrap it in a query_string query for percolator use
        query_string = queries[0]

        return {"query": {"query_string": {"query": query_string}}}

    def extract_fields(self, rule: SigmaRule) -> set[str]:
        """
        Extract all field names referenced in the rule detection logic.

        Args:
            rule: Parsed SigmaRule object

        Returns:
            Set of field names used in the rule
        """
        fields: set[str] = set()

        # rule.detection.detections is a dict of named detection items
        for detection_name, detection in rule.detection.detections.items():
            # Each detection has detection_items list
            for item in detection.detection_items:
                if hasattr(item, "field") and item.field:
                    fields.add(item.field)

        return fields

    def translate_and_validate(self, yaml_content: str) -> TranslationResult:
        """
        Parse, validate, and translate a Sigma rule in one operation.

        Args:
            yaml_content: Raw YAML string of the Sigma rule

        Returns:
            TranslationResult with query and any errors
        """
        # Validate first
        errors = self.validate_rule(yaml_content)
        if errors:
            return TranslationResult(success=False, errors=errors)

        # Parse and translate
        try:
            rule = self.parse_rule(yaml_content)
            if rule is None:
                return TranslationResult(
                    success=False,
                    errors=[
                        ValidationError(type="schema", message="Failed to parse rule")
                    ],
                )

            query = self.translate_to_opensearch(rule)
            fields = self.extract_fields(rule)

            return TranslationResult(success=True, query=query, fields=fields)
        except Exception as e:
            return TranslationResult(
                success=False,
                errors=[ValidationError(type="schema", message=str(e))],
            )

    def test_against_log(self, query: dict[str, Any], log: dict[str, Any]) -> bool:
        """
        Test if a log document matches an OpenSearch query.

        This is a simplified in-memory matching for sample log testing.
        It doesn't replicate full OpenSearch query semantics but handles
        common cases like query_string with field:value patterns.

        Args:
            query: OpenSearch query DSL
            log: Log document to test

        Returns:
            True if the log matches the query pattern
        """
        # Extract query string
        if "query" not in query:
            return False

        query_part = query["query"]

        if "query_string" in query_part:
            query_string = query_part["query_string"].get("query", "")
            return self._match_query_string(query_string, log)

        if "bool" in query_part:
            return self._match_bool_query(query_part["bool"], log)

        if "match_all" in query_part:
            return True

        if "match_none" in query_part:
            return False

        return False

    def _match_query_string(self, query_string: str, log: dict[str, Any]) -> bool:
        """
        Simple query string matching against a log document.

        Handles basic patterns like:
        - field:value
        - field:*value*
        - field:(value1 OR value2)
        """
        import re

        # Handle simple field:value patterns
        # This is a simplified matcher - not full Lucene query syntax
        pattern = r'(\w+(?:\.\w+)*):(?:"([^"]+)"|(\S+))'

        matches = re.findall(pattern, query_string)
        if not matches:
            # No field patterns found, check if any value exists in log
            return query_string.lower() in str(log).lower()

        for field, quoted_value, unquoted_value in matches:
            value = quoted_value or unquoted_value
            log_value = self._get_nested_value(log, field)

            if log_value is None:
                return False

            # Handle wildcard patterns
            if "*" in value:
                regex = value.replace("*", ".*")
                if not re.search(regex, str(log_value), re.IGNORECASE):
                    return False
            elif value.lower() not in str(log_value).lower():
                return False

        return True

    def _match_bool_query(
        self, bool_query: dict[str, Any], log: dict[str, Any]
    ) -> bool:
        """Match a bool query against a log document."""
        # Handle must clauses (AND)
        if "must" in bool_query:
            for clause in bool_query["must"]:
                if not self.test_against_log({"query": clause}, log):
                    return False

        # Handle should clauses (OR) - at least one must match
        if "should" in bool_query:
            if not any(
                self.test_against_log({"query": clause}, log)
                for clause in bool_query["should"]
            ):
                return False

        # Handle must_not clauses (NOT)
        if "must_not" in bool_query:
            for clause in bool_query["must_not"]:
                if self.test_against_log({"query": clause}, log):
                    return False

        return True

    def _get_nested_value(self, obj: dict[str, Any], path: str) -> Any:
        """Get a value from a nested dictionary using dot notation."""
        keys = path.split(".")
        current = obj

        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None

            if current is None:
                return None

        return current


# Singleton instance
sigma_service = SigmaService()
