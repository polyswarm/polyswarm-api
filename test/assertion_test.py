"""Pure-unit tests for ``Assertion`` engine naming (no HTTP)."""
import pytest

from polyswarm_api import resources


def _content(engine):
    return {
        'author': '0x0000000000000000000000000000000000000001',
        'author_name': 'DefenseNet',
        'engine': engine,
        'bid': '500',
        'mask': True,
        'metadata': None,
        'verdict': True,
    }


class TestAssertionEngineNames:
    def test_display_name_is_exposed_next_to_the_stable_name(self):
        a = resources.Assertion(_content({'name': 'DefenseNet', 'display_name': 'DefenceNet'}))
        assert a.engine_name == 'DefenseNet'
        assert a.engine_display_name == 'DefenceNet'
        assert a.author_name == 'DefenseNet'

    def test_display_name_absent_falls_back_to_name(self):
        a = resources.Assertion(_content({'name': 'DefenseNet'}))
        assert a.engine_name == 'DefenseNet'
        assert a.engine_display_name == 'DefenseNet'

    @pytest.mark.parametrize('blank', [None, ''])
    def test_blank_display_name_falls_back_to_name(self, blank):
        a = resources.Assertion(_content({'name': 'DefenseNet', 'display_name': blank}))
        assert a.engine_display_name == 'DefenseNet'

    def test_raw_json_keeps_the_payload(self):
        a = resources.Assertion(_content({'name': 'DefenseNet', 'display_name': 'DefenceNet'}))
        assert a.json['engine'] == {'name': 'DefenseNet', 'display_name': 'DefenceNet'}
