"""``search_by_ioc(with_artifacts=True)`` — the reverse IOC search answering
artifact rows instead of bare sha256s — and the unchanged default request.

Three tiers (specs/04-testing.md):

* pure-unit builder tests for the request shape: the opt-in parameter rides
  the query as an int, the default request is byte-compatible with the
  pre-change contract, and the parser follows the flag;
* client-method pass-through tests on both transports, which fail if either
  signature stops forwarding the keyword; and
* a respx ``ClientTestCase`` body for the parse of a returned row. That one is
  a stand-in: the e2e stack does not serve ``with_artifacts`` yet, so a live
  VCR lifecycle test cannot be recorded (specs/99-open-questions.md). The
  default path stays covered live by ``test_search_by_ioc`` /
  ``test_async_search_by_ioc``.
"""
import asyncio

import pytest

from polyswarm_api import resources
from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api.api import PolyswarmAPI
from test._client_harness import BASE_URL, COMMUNITY, ClientTestCase

_SHA256 = '0285922fdd731d6905d5a6dc51d75e3bd504c5ac418b8c7b431063c6cee8d064'


def _artifact_row():
    """A metadata-search ``_source`` row holding exactly the server's include set
    for ``with_artifacts`` (``IOC_ARTIFACT_INCLUDES`` upstream)."""
    return {
        'artifact': {
            'created': '2026-06-05T19:01:38.104756+00:00',
            'id': '31542742786663251',
            'md5': '5d3bc3c626be6b6f59195afc4ab80fc8',
            'sha1': 'f1d73dcb1286cf42e707b5d7fcf918dd45290411',
            'sha256': _SHA256,
            'size': 89,
        },
        'scan': {
            'first_seen': '2026-06-04T10:00:00+00:00',
            'first_scan': {'created': '2026-06-04T10:00:00+00:00'},
            'last_seen': '2026-06-05T19:01:38.104756+00:00',
            'detections': {'benign': 0, 'malicious': 1, 'total': 1},
            'mimetype': {'extended': 'EICAR virus test files', 'mime': 'text/plain'},
            'latest_scan': {
                'polyscore': 0.97,
                'artifact_instance_id': '88272874449980049',
                'created': '2026-06-05T19:01:38.104756+00:00',
            },
            'filename': ['artifact'],
            'url': [],
        },
        'polyunite': {'malware_family': 'EICAR'},
        'hash': {'ssdeep': '3:a+JraNvsgzsVqSwHq9:tJuOgzsko', 'tlsh': 'T1A1B2C3'},
    }


class _FakeApi:
    uri = 'https://api.example.test'
    community = 'gamma'


class TestIocSearchBuilder:
    def test_default_request_is_unchanged(self):
        req = resources.IOC.ioc_search(_FakeApi(), ip='9.9.9.9')
        assert req.method == 'GET'
        assert req.url == f'{_FakeApi.uri}/ioc/search'
        assert req.params == {'community': 'gamma', 'ip': '9.9.9.9'}
        assert req.result_parser is resources.IOC

    def test_with_artifacts_rides_the_query_as_an_int_and_parses_metadata(self):
        req = resources.IOC.ioc_search(_FakeApi(), domain='evil.test', with_artifacts=True)
        assert req.params == {'community': 'gamma', 'domain': 'evil.test', 'with_artifacts': 1}
        # A bool would be rendered 'True' on the wire, which the server refuses.
        assert type(req.params['with_artifacts']) is int
        assert req.result_parser is resources.Metadata

    def test_with_artifacts_false_sends_nothing(self):
        req = resources.IOC.ioc_search(_FakeApi(), ttp='T1081', with_artifacts=False)
        assert 'with_artifacts' not in req.params
        assert req.result_parser is resources.IOC

    def test_a_bare_call_is_still_sent_as_before(self):
        # The SDK adds no client-side term check: a call with no term builds
        # the same request it always did and lets the server answer it.
        req = resources.IOC.ioc_search(_FakeApi())
        assert req.method == 'GET'
        assert req.url == f'{_FakeApi.uri}/ioc/search'
        assert req.params == {'community': 'gamma'}
        assert req.result_parser is resources.IOC

    @pytest.mark.parametrize('term', ['ip', 'domain', 'ttp', 'imphash'])
    def test_any_single_term_is_enough(self, term):
        req = resources.IOC.ioc_search(_FakeApi(), **{term: 'x'})
        assert req.params[term] == 'x'


class TestSearchByIocForwardsTheFlag:
    """Drive both CLIENT methods: dropping the keyword from either transport's
    signature or its pass-through fails here, which the builder tests cannot
    see. The sync one is the mirror the CLI calls."""

    @staticmethod
    def _sync_request(**kwargs):
        api = PolyswarmAPI.__new__(PolyswarmAPI)
        api.uri, api.community = _FakeApi.uri, _FakeApi.community
        api.refang_iocs = False  # the constructor's default
        captured = []

        def capture(request, *a, **kw):
            captured.append(request)
            return iter(())

        api._paginate = capture
        list(api.search_by_ioc(**kwargs))
        return captured[0]

    @staticmethod
    def _async_request(**kwargs):
        api = PolySwarmAsyncAPI.__new__(PolySwarmAsyncAPI)
        api.uri, api.community = _FakeApi.uri, _FakeApi.community
        api.refang_iocs = False  # the constructor's default
        captured = []

        async def paginate(request, *a, **kw):
            captured.append(request)
            return
            yield  # pragma: no cover — makes this an async generator

        api._paginate = paginate

        async def run():
            return [item async for item in api.search_by_ioc(**kwargs)]

        asyncio.run(run())
        return captured[0]

    @pytest.mark.parametrize('build', ['_sync_request', '_async_request'])
    def test_with_artifacts_reaches_the_request(self, build):
        req = getattr(self, build)(imphash='a' * 32, with_artifacts=True)
        assert req.params['with_artifacts'] == 1
        assert req.result_parser is resources.Metadata

    @pytest.mark.parametrize('build', ['_sync_request', '_async_request'])
    def test_a_bare_call_reaches_the_request_unchanged(self, build):
        req = getattr(self, build)()
        assert req.params == {'community': 'gamma'}
        assert req.result_parser is resources.IOC

    @pytest.mark.parametrize('build', ['_sync_request', '_async_request'])
    def test_default_sends_no_flag(self, build):
        req = getattr(self, build)(ip='9.9.9.9')
        assert 'with_artifacts' not in req.params
        assert req.result_parser is resources.IOC


class IocSearchWithArtifactsTestCase(ClientTestCase):
    """Full pipeline (session -> parse_response -> resource) on both
    transports, against a fabricated envelope — see the module docstring for
    why this is respx rather than a recorded cassette."""

    _URL = f'{BASE_URL}/ioc/search'

    def test_rows_parse_as_metadata(self):
        self.mock.add('GET', self._URL, json={
            'status': 'OK', 'result': [_artifact_row()],
            'has_more': False, 'limit': 50, 'offset': None})
        results = list(self.api.search_by_ioc(ip='9.9.9.9', with_artifacts=True))
        assert 'with_artifacts=1' in self.mock.last_request_url
        assert f'community={COMMUNITY}' in self.mock.last_request_url
        assert len(results) == 1
        row = results[0]
        assert isinstance(row, resources.Metadata)
        assert row.id == '31542742786663251'
        assert row.sha256 == _SHA256
        assert row.md5 == '5d3bc3c626be6b6f59195afc4ab80fc8'
        assert row.created is not None
        assert row.last_scanned is not None
        assert row.malicious == 1
        assert row.mimetype == 'text/plain'
        assert row.filenames == ['artifact']
        assert row.json['polyunite']['malware_family'] == 'EICAR'
        assert row.first_seen.isoformat() == '2026-06-04T10:00:00+00:00'
        assert row.ssdeep == '3:a+JraNvsgzsVqSwHq9:tJuOgzsko'
        assert row.tlsh == 'T1A1B2C3'
        # strings.* is outside the include set, so its attributes stay unset.
        assert row.domains is None
        assert row.ipv4 is None

    def test_default_rows_stay_sha256_strings(self):
        self.mock.add('GET', self._URL, json={
            'status': 'OK', 'result': [_SHA256],
            'has_more': False, 'limit': 50, 'offset': None})
        results = list(self.api.search_by_ioc(ip='9.9.9.9'))
        assert 'with_artifacts' not in self.mock.last_request_url
        assert [r.json for r in results] == [_SHA256]
        assert isinstance(results[0], resources.IOC)
