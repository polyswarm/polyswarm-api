"""``window_days`` on historical hunts: request shape, pass-through on both clients, parse.

Builder and parse cases are pure-unit. The pass-through cases are respx because VCR does
not match bodies and the recorded cassettes predate the field, so only a mocked boundary
can see what the body carried. The live round trip is pending (specs/99-open-questions.md).
"""
import pytest

from polyswarm_api import resources
from test._client_harness import BASE_URL, COMMUNITY, ClientTestCase

_YARA = 'rule window_probe { condition: true }'
_HUNT_URL = f'{BASE_URL}/hunt/historical'


class _FakeApi:
    uri = 'https://api.example.test'
    community = 'gamma'


def _hunt(**extra):
    """A hunt row as the server returns it, without the optional fields."""
    return {
        'id': '7', 'created': '2026-10-01T12:00:00+00:00', 'status': 'PENDING',
        'progress': 0.0, 'results_csv_uri': None, **extra}


def _create(**kwargs):
    return resources.HistoricalHunt.create(_FakeApi(), community='gamma', **kwargs)


class TestHistoricalCreateBuilder:
    def test_window_rides_the_body_as_an_int(self):
        req = _create(yara=_YARA, window_days=30)
        assert req.method == 'POST'
        assert req.url == f'{_FakeApi.uri}/hunt/historical'
        assert req.input_json == {'yara': _YARA, 'window_days': 30, 'community': 'gamma'}
        assert req.params is None
        # A JSON number, not the string "30".
        assert type(req.input_json['window_days']) is int
        assert req.result_parser is resources.HistoricalHunt

    def test_no_window_leaves_the_key_out(self):
        req = _create(yara=_YARA, window_days=None)
        assert req.input_json == {'yara': _YARA, 'community': 'gamma'}

    def test_none_and_omitted_build_the_same_request(self):
        omitted, explicit = _create(yara=_YARA), _create(yara=_YARA, window_days=None)
        assert (explicit.method, explicit.url, explicit.params, explicit.input_json) == (
            omitted.method, omitted.url, omitted.params, omitted.input_json)

    def test_window_stays_an_int_beside_a_stored_rule_id(self):
        # core._params stringifies *_id keys only; the window is not one.
        req = _create(rule_id=5, window_days=90)
        assert req.input_json == {'rule_id': '5', 'window_days': 90, 'community': 'gamma'}

    def test_the_sdk_does_not_validate_the_value(self):
        # The server owns the enum and answers anything else with a 400.
        assert _create(yara=_YARA, window_days=45).input_json['window_days'] == 45


class HistoricalCreateWindowTestCase(ClientTestCase):
    """What ``historical_create`` puts on the wire, one body over both clients."""

    def setUp(self):
        super().setUp()
        self.mock.add('POST', _HUNT_URL, json={'status': 'OK', 'result': _hunt()})

    def test_window_reaches_the_body_as_an_int(self):
        self.api.historical_create(_YARA, window_days=30)
        assert self.mock.last_request_body == {
            'yara': _YARA, 'window_days': 30, 'community': COMMUNITY}

    def test_window_composes_with_a_stored_rule(self):
        self.api.historical_create(5, window_days=90)
        assert self.mock.last_request_body == {
            'rule_id': '5', 'window_days': 90, 'community': COMMUNITY}

    def test_no_window_sends_no_key(self):
        self.api.historical_create(_YARA)
        assert self.mock.last_request_body == {'yara': _YARA, 'community': COMMUNITY}

    def test_explicit_none_is_byte_identical_to_a_bare_call(self):
        self.api.historical_create(_YARA)
        self.api.historical_create(_YARA, window_days=None)
        bare, explicit = self.mock.requests
        assert explicit.content == bare.content


class TestHistoricalHuntWindowParse:
    @pytest.mark.parametrize('cls', [resources.HistoricalHunt, resources.HistoricalHuntList])
    def test_the_window_parses_as_the_int(self, cls):
        assert cls(_hunt(window_days=30), api=None).window_days == 30

    @pytest.mark.parametrize('cls', [resources.HistoricalHunt, resources.HistoricalHuntList])
    def test_an_explicit_null_is_none(self, cls):
        assert cls(_hunt(window_days=None), api=None).window_days is None

    @pytest.mark.parametrize('cls', [resources.HistoricalHunt, resources.HistoricalHuntList])
    def test_a_missing_key_is_none(self, cls):
        # A server predating the field omits the key altogether.
        assert 'window_days' not in _hunt()
        assert cls(_hunt(), api=None).window_days is None


class HistoricalWindowResponseTestCase(ClientTestCase):
    """The window on the create response, the single GET and the list, through the full
    pipeline. A fabricated envelope, standing in until a live round trip is recorded.
    """

    def test_create_returns_the_window(self):
        self.mock.add('POST', _HUNT_URL, json={'status': 'OK', 'result': _hunt(window_days=30)})
        assert self.api.historical_create(_YARA, window_days=30).window_days == 30

    def test_get_returns_the_window(self):
        self.mock.add('GET', f'{_HUNT_URL}?id=7&community={COMMUNITY}',
                      json={'status': 'OK', 'result': _hunt(window_days=60)})
        assert self.api.historical_get(7).window_days == 60

    def test_list_returns_the_window_on_every_hunt(self):
        rows = [_hunt(id='7', window_days=30), _hunt(id='8', window_days=None)]
        self.mock.add('GET', f'{_HUNT_URL}/list?community={COMMUNITY}', json={
            'status': 'OK', 'result': rows, 'has_more': False, 'limit': 50, 'offset': None})
        hunts = list(self.api.historical_list())
        assert [(h.id, h.window_days) for h in hunts] == [('7', 30), ('8', None)]
