"""Tests for the `matched_strings` attribute on hunt-result resources.

Pure-unit: the resources parse a dict, so no HTTP and no stack are involved. The
point of these is the THREE-state contract (absent / empty / populated) documented
in specs/05-downstream-contract.md — the states are not interchangeable and a
consumer that collapses them loses the distinction between "we don't know" and
"the rule matched with no byte evidence".
"""

import pytest

from polyswarm_api.resources import (
    HistoricalHuntResult,
    HistoricalHuntResultList,
    LiveHuntResult,
    LiveHuntResultList,
)

_COMMON = {
    "id": 1,
    "instance_id": 2,
    "created": "2022-05-26T19:41:33.797898",
    "sha256": "f" * 64,
    "rule_name": "dos_stub_message",
    "tags": "{pe,stub}",
    "polyscore": 0.5,
    "malware_family": None,
    "detections": {"malicious": 1, "total": 1},
}

_STRINGS = [
    {"offset": 78, "identifier": "$stub", "length": 14,
     "data": "54 68 69 73 20 70 72 6F 67 72 61 6D 20 63", "truncated": False},
    {"offset": 0, "identifier": "$mz", "length": 512,
     "data": "4D 5A 90 00 ...", "truncated": True},
]

# Both concrete classes plus their `…List` subclasses, which inherit __init__ and must
# behave identically. NB the subclass does not imply the route: live_feed parses list
# rows as LiveHuntResult, and LiveHuntResultList is only ever a delete builder.
ALL_CLASSES = [
    LiveHuntResult, LiveHuntResultList,
    HistoricalHuntResult, HistoricalHuntResultList,
]


def _content(cls, **extra):
    content = dict(_COMMON, **extra)
    if issubclass(cls, LiveHuntResult):
        content["livescan_id"] = 3
    else:
        content["historicalscan_id"] = 3
    return content


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_absent_key_parses_as_none(cls):
    """A server predating the field omits the key; a subscript would raise here."""
    assert cls(_content(cls)).matched_strings is None


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_explicit_null_parses_as_none(cls):
    """List endpoints send the key with a null value rather than omitting it."""
    assert cls(_content(cls, matched_strings=None)).matched_strings is None


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_empty_list_is_preserved_and_is_not_none(cls):
    """`[]` means "matched, no byte evidence" — distinct from "not reported"."""
    result = cls(_content(cls, matched_strings=[]))
    assert result.matched_strings == []
    assert result.matched_strings is not None


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_populated_list_is_passed_through_verbatim(cls):
    """The SDK does not reshape entries — `data` in particular stays as yara rendered it."""
    result = cls(_content(cls, matched_strings=_STRINGS))
    assert result.matched_strings == _STRINGS
    assert result.matched_strings[0]["identifier"] == "$stub"
    assert result.matched_strings[1]["truncated"] is True


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_parsing_does_not_mutate_the_raw_json(cls):
    """`.json` is part of the contract: JSON-mode consumers read the server's payload
    unchanged, so parsing must not reshape or strip what it read.

    (Asserting `result.json[k] == content[k]` alone would be tautological -- __init__
    assigns `self.json = content` -- so this compares the parsed attributes against the
    raw dict instead, which is the property that would actually break.)
    """
    content = _content(cls, matched_strings=_STRINGS, matched_strings_dropped=19)
    result = cls(content)
    assert result.json is content
    assert result.matched_strings == content["matched_strings"]
    assert result.matched_strings_dropped == content["matched_strings_dropped"]
    assert set(content) <= set(result.json), "parsing must not drop keys from .json"


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_dropped_count_parses(cls):
    """The count that lets a consumer say "12 shown, 19 more"."""
    assert cls(_content(cls, matched_strings=_STRINGS, matched_strings_dropped=19)) \
        .matched_strings_dropped == 19


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_dropped_is_none_when_absent(cls):
    """Nothing dropped, and every result predating the budget -- same answer."""
    assert cls(_content(cls, matched_strings=_STRINGS)).matched_strings_dropped is None


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_a_populated_list_and_a_count_coexist(cls):
    """The normal shape for a verbose ruleset, and the pairing the contract turns on.

    A truncated list is still a list -- nothing marks it short from the inside -- so the
    count is the only thing that says so. Both must survive parsing together.
    """
    result = cls(_content(cls, matched_strings=_STRINGS, matched_strings_dropped=19))
    assert isinstance(result.matched_strings, list)
    assert len(result.matched_strings) == 2
    assert result.matched_strings_dropped == 19
