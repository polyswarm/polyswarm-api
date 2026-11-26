"""``analyze_url`` / ``wait_for_url_analysis`` / ``url_analysis`` and
``ArtifactInstance.ip_analysis``: the analysis-only ``POST /instance/url``
route, which runs only the server's ``ip`` analyzer (no engines, no quota).

Tiers (specs/04-testing.md):

* pure-unit builder test for the request shape (POST, ``url`` in the JSON
  body, ``community`` in the query string) and parse tests for
  ``ip_analysis`` (absent, then present);
* a dual-transport (``ClientTestCase``) respx suite for submit, the
  pending-then-done poll, the timeout, and refanging. Respx stands in for a
  live VCR lifecycle test because the ``ip`` analyzer does live DNS / RDAP /
  TLS lookups against the public internet, which the e2e stack does not do
  reproducibly (see ``99-open-questions.md``). The response bodies are trimmed
  copies of real prod responses (2026-11-26), not invented shapes.
"""
import copy
from unittest import mock

import httpx
import pytest

from polyswarm_api import exceptions, resources, settings
from test._client_harness import BASE_URL, COMMUNITY, ClientTestCase

_ID = '52770357625925130'

_IP_RESULT = {
    'target': 'wikipedia.org',
    'resolved_ip': '208.80.154.224',
    'ip_version': 'IPv4',
    'asn': 14907,
    'asn_org': 'WIKIMEDIA',
    'country_code': 'US',
    'country_name': 'United States',
    'city': None,
    'network_name': 'WIKIMEDIA',
    'range': '208.80.152.0 - 208.80.155.255',
    'cidrs': ['208.80.152.0/22'],
    'whois_server': 'whois.arin.net',
    'subject': 'CN=*.wikipedia.org',
    'issuer': "CN=YE2,O=Let's Encrypt,C=US",
    'redirects': [],
    'error': None,
}


_OLD = '2026-11-26T11:06:12.650306+00:00'
_NEW = '2026-11-26T13:44:26.690656+00:00'


def _instance(with_ip, updated=_OLD):
    metadata = [
        {'tool': 'hash', 'tool_metadata': {'sha256': 'a' * 64}},
    ]
    if with_ip:
        # A re-run rewrites this row in place: ``created`` stays, ``updated`` moves.
        metadata.append({'tool': 'ip', 'tool_metadata': copy.deepcopy(_IP_RESULT),
                         'created': '2026-11-26T11:05:52.182202+00:00', 'updated': updated})
    return {
        'id': _ID,
        'artifact_id': _ID,
        'sha256': 'a' * 64,
        'sha1': 'b' * 40,
        'md5': 'c' * 32,
        'mimetype': 'text/plain',
        'extended_type': 'ASCII text, with no line terminators',
        'size': 13,
        'filename': 'wikipedia.org',
        'type': 'URL',
        'community': COMMUNITY,
        'first_seen': '2020-01-06T02:37:11.683156+00:00',
        'created': '2026-11-26T11:05:52.000000+00:00',
        'upload_url': None,
        'assertions': [],
        'votes': [],
        'metadata': metadata,
        'failed': False,
        'window_closed': None,
        'polyscore': None,
    }


def _envelope(with_ip, updated=_OLD):
    return {'status': 'OK', 'result': _instance(with_ip, updated)}


class _FakeApi:
    uri = 'https://api.example.test'
    community = 'gamma'


class TestSubmitUrlAnalysisBuilder:
    def test_request_shape(self):
        req = resources.ArtifactInstance.submit_url_analysis(_FakeApi(), 'wikipedia.org')
        assert req.method == 'POST'
        assert req.url == f'{_FakeApi.uri}/instance/url'
        assert req.params == {'community': 'gamma'}
        assert req.input_json == {'url': 'wikipedia.org'}
        assert req.result_parser is resources.ArtifactInstance


class TestIpAnalysisParse:
    def test_absent_until_the_analyzer_has_run(self):
        assert resources.ArtifactInstance(_instance(with_ip=False)).ip_analysis is None

    def test_present_once_it_has(self):
        ip = resources.ArtifactInstance(_instance(with_ip=True)).ip_analysis
        assert ip['asn'] == 14907
        assert ip['resolved_ip'] == '208.80.154.224'

    def test_updated_timestamp(self):
        inst = resources.ArtifactInstance(_instance(with_ip=True, updated=_NEW))
        assert inst.ip_analysis_updated.isoformat() == _NEW
        assert resources.ArtifactInstance(_instance(with_ip=False)).ip_analysis_updated is None

    def test_a_null_tool_metadata_reads_as_not_run(self):
        content = _instance(with_ip=False)
        content['metadata'].append({'tool': 'ip', 'tool_metadata': None})
        assert resources.ArtifactInstance(content).ip_analysis is None


class UrlAnalysisTestCase(ClientTestCase):
    _SUBMIT = f'{BASE_URL}/instance/url'
    _LOOKUP = f'{BASE_URL}/consumer/submission/{COMMUNITY}/{_ID}'

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(settings, 'POLL_FREQUENCY', 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_analyze_url_posts_the_target(self):
        self.mock.add('POST', self._SUBMIT, json=_envelope(with_ip=False))
        instance = self.api.analyze_url('wikipedia.org')
        assert f'community={COMMUNITY}' in self.mock.last_request_url
        assert self.mock.last_request_body == {'url': 'wikipedia.org'}
        assert instance.id == _ID
        assert instance.type == 'URL'
        assert instance.ip_analysis is None

    def test_analyze_url_refangs_when_enabled(self):
        self.mock.add('POST', self._SUBMIT, json=_envelope(with_ip=False))
        api = self.api._api if hasattr(self.api, '_api') else self.api
        api.refang_iocs = True
        self.api.analyze_url('hxxps://wikipedia[.]org/')
        assert self.mock.last_request_body == {'url': 'https://wikipedia.org/'}

    def test_url_analysis_polls_until_the_ip_result_lands(self):
        self.mock.add('POST', self._SUBMIT, json=_envelope(with_ip=False))
        self.mock._router.route(method='GET', url=self._LOOKUP).mock(side_effect=[
            httpx.Response(200, json=_envelope(with_ip=False)),
            httpx.Response(200, json=_envelope(with_ip=True)),
        ])
        result = self.api.url_analysis('wikipedia.org')
        assert result.ip_analysis['asn_org'] == 'WIKIMEDIA'
        assert result.ip_analysis['country_code'] == 'US'
        lookups = [r for r in self.mock.requests if r.method == 'GET']
        assert len(lookups) == 2

    def test_resubmit_waits_for_the_rerun_by_default(self):
        # The submit response carries the previous result; fresh=True must not
        # return it, but wait for the row's ``updated`` to move.
        self.mock.add('POST', self._SUBMIT, json=_envelope(with_ip=True, updated=_OLD))
        self.mock._router.route(method='GET', url=self._LOOKUP).mock(side_effect=[
            httpx.Response(200, json=_envelope(with_ip=True, updated=_OLD)),
            httpx.Response(200, json=_envelope(with_ip=True, updated=_NEW)),
        ])
        result = self.api.url_analysis('wikipedia.org')
        assert result.ip_analysis_updated.isoformat() == _NEW
        assert [r.method for r in self.mock.requests] == ['POST', 'GET', 'GET']

    def test_resubmit_with_fresh_false_returns_the_previous_result(self):
        self.mock.add('POST', self._SUBMIT, json=_envelope(with_ip=True, updated=_OLD))
        result = self.api.url_analysis('wikipedia.org', fresh=False)
        assert result.ip_analysis['asn'] == 14907
        assert result.ip_analysis_updated.isoformat() == _OLD
        assert [r.method for r in self.mock.requests] == ['POST']

    def test_wait_accepts_a_bare_id(self):
        self.mock.add('GET', self._LOOKUP, json=_envelope(with_ip=True))
        result = self.api.wait_for_url_analysis(_ID)
        assert result.ip_analysis['resolved_ip'] == '208.80.154.224'

    def test_wait_times_out(self):
        self.mock.add('GET', self._LOOKUP, json=_envelope(with_ip=False))
        with mock.patch('time.time', side_effect=[0, 0, 10, 10, 10]), \
                pytest.raises(exceptions.TimeoutException):
            self.api.wait_for_url_analysis(_ID, timeout=5)
