"""Tests for BaseJsonResource.jmespath().

Exercises the helper against synthetic content — the helper just delegates to
jmespath.search(expr, self.json), so we don't need a real API response.
"""

from polyswarm_api.core import BaseJsonResource
from polyswarm_api.resources import MetadataMapping


def _resource(content):
    return BaseJsonResource(content)


def test_jmespath_simple_field():
    r = _resource({"polyscore": 0.92})
    assert r.jmespath("polyscore") == 0.92


def test_jmespath_nested_dotted_path():
    r = _resource({"scan": {"latest_scan": {"polyscore": 0.92}}})
    assert r.jmespath("scan.latest_scan.polyscore") == 0.92


def test_jmespath_returns_none_for_missing_path():
    r = _resource({"a": {"b": 1}})
    assert r.jmespath("a.c.d") is None
    assert r.jmespath("nope") is None


def test_jmespath_array_projection():
    r = _resource({
        "engines": [
            {"name": "a"},
            {"name": "b"},
            {"name": "c"},
        ],
    })
    assert r.jmespath("engines[*].name") == ["a", "b", "c"]


def test_jmespath_filter_expression():
    r = _resource({
        "engines": [
            {"name": "a", "verdict": "malicious"},
            {"name": "b", "verdict": "benign"},
            {"name": "c", "verdict": "malicious"},
        ],
    })
    assert r.jmespath("engines[?verdict=='malicious'].name") == ["a", "c"]


def test_jmespath_keys_function():
    r = _resource({"foo": 1, "bar": 2, "baz": 3})
    assert sorted(r.jmespath("keys(@)")) == ["bar", "baz", "foo"]


def test_jmespath_length_function():
    r = _resource({"engines": [1, 2, 3, 4, 5]})
    assert r.jmespath("length(engines)") == 5


def test_jmespath_works_on_subclass():
    """Any BaseJsonResource subclass inherits .jmespath() automatically."""
    m = MetadataMapping({"artifact": {"sha256": {"description": "hash"}}})
    assert m.jmespath("artifact.sha256.description") == "hash"


def test_jmespath_pipe():
    """JMESPath pipe expressions work — | composes a sub-query on the previous result."""
    r = _resource({"engines": [{"name": "z"}, {"name": "a"}, {"name": "m"}]})
    assert r.jmespath("engines[*].name | sort(@)") == ["a", "m", "z"]