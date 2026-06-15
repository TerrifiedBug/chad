"""Unit tests for app.utils.nested dotted-path helpers."""

from app.utils.nested import get_nested_value, set_nested_value


def test_get_nested_value_happy_path():
    assert get_nested_value({"a": {"b": 1}}, "a.b") == 1


def test_get_nested_value_missing_key():
    assert get_nested_value({"a": {"b": 1}}, "a.c") is None


def test_get_nested_value_non_dict_segment():
    assert get_nested_value({"a": 1}, "a.b") is None


def test_get_nested_value_single_key():
    assert get_nested_value({"a": 1}, "a") == 1


def test_set_nested_value_creates_parents():
    doc: dict = {}
    set_nested_value(doc, "a.b.c", 42)
    assert doc == {"a": {"b": {"c": 42}}}


def test_set_nested_value_existing_parent():
    doc = {"a": {"x": 1}}
    set_nested_value(doc, "a.y", 2)
    assert doc == {"a": {"x": 1, "y": 2}}


def test_set_nested_value_top_level():
    doc: dict = {}
    set_nested_value(doc, "a", 5)
    assert doc == {"a": 5}
