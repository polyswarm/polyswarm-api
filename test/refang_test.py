"""Pure-unit tests for IoC refanging (``polyswarm_api.refang``) and for the
client methods that apply it before building a request.

No HTTP at all (the pure-unit tier — see specs/04-testing.md). This is input
normalization, not a new endpoint: the server contract is unchanged, so what
needs pinning is (a) the refang function itself and (b) the request shape each
client method builds — that the outgoing params/body carry the refanged value
when ``refang_iocs`` is on, and the raw value when it is off. The request is
captured at the ``_paginate`` / ``_single`` boundary, before any transport.
"""
import hashlib
import json
import pathlib

import pytest

from polyswarm_api import refang
from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api.api import PolyswarmAPI

# The case table is shared VERBATIM with the other PolySwarm clients that
# implement the same refang contract. Keep this file byte-identical across
# them: a change here is a change to the contract, and lands everywhere.
CASES_PATH = pathlib.Path(__file__).parent / 'fixtures' / 'refang_cases.json'
CASES = json.loads(CASES_PATH.read_text(encoding='utf-8'))

# Drift guard: the web UI pins the same digest over its copy, so editing the
# table here fails this suite until the other copy -- and both pins -- change
# together.
SHARED_CASES_SHA256 = '4bda4b2f8f0dacdd3fa80632fe2a6044b9d0ff5194402968cac9698605a72da8'


def test_contract_table_is_byte_identical_to_the_pinned_copy():
    assert hashlib.sha256(CASES_PATH.read_bytes()).hexdigest() == SHARED_CASES_SHA256


@pytest.mark.parametrize('case', CASES, ids=[c['why'] for c in CASES])
def test_refang_ioc_contract_table(case):
    assert refang.refang_ioc(case['input']) == case['expected']


class TestRefangIoc:
    def test_unchanged_input_is_returned_as_is_including_whitespace(self):
        # Nothing to refang: the caller gets its own value back, untrimmed.
        assert refang.refang_ioc('  evil.com  ') == '  evil.com  '

    def test_accept_can_veto_a_candidate(self):
        assert refang.refang_ioc('evil[.]com', accept=lambda c: False) == 'evil[.]com'

    def test_accept_sees_the_refanged_candidate(self):
        seen = []
        assert refang.refang_ioc('evil[.]com', accept=lambda c: seen.append(c) or True) == 'evil.com'
        assert seen == ['evil.com']

    def test_accept_is_not_consulted_when_nothing_is_defanged(self):
        def boom(_):
            raise AssertionError('accept must not run')
        assert refang.refang_ioc('evil.com', accept=boom) == 'evil.com'

    def test_non_string_values_pass_through(self):
        assert refang.refang_ioc(None) is None


class TestRefangText:
    def test_rewrites_without_gating_or_trimming(self):
        # The raw rewrite is ungated: it rewrites a non-IoC too.
        assert refang.refang_text(' hash[.]sha256 ') == ' hash.sha256 '

    def test_scheme_rules_are_anchored_at_the_start(self):
        assert refang.refang_text('see hxxp://evil.com') == 'see hxxp://evil.com'


class TestIsNetworkIoc:
    @pytest.mark.parametrize('value', [
        'evil.com', '127.0.0.1', 'https://evil.com/x?y#z', 'ftp://user@files.example.org:21/a',
        'http://[2001:db8::1]:8080/', 'xn--80ak6aa92e.com',
    ])
    def test_accepts(self, value):
        assert refang.is_network_ioc(value)

    @pytest.mark.parametrize('value', [
        '', 'evil', 'hash.sha256', '999.1.1.1', 'evil .com', 'a_b.com', 'hxxp://evil.com',
        # Python's ``$`` also matches before a trailing newline; a full match
        # must not, or this engine accepts what the others reject.
        'evil.com\n',
        # A case-insensitive flag would fold U+212A KELVIN SIGN onto ``k``.
        'evil.\u212aom',
    ])
    def test_rejects(self, value):
        assert not refang.is_network_ioc(value)


# ── Client integration: request shape at the transport boundary ────────────

class _Captured(Exception):
    """Raised by the fake boundary to stop a multi-step flow after its first
    request, which is the one carrying the IoC."""


def _sync_client(**kwargs):
    api = PolyswarmAPI(key='k' * 32, uri='https://api.example.test', community='gamma', **kwargs)
    captured = []

    def fake_paginate(request, *a, **kw):
        captured.append(api._to_request(request))
        return iter(())

    def fake_single(request, *a, **kw):
        captured.append(api._to_request(request, *a, **kw))
        raise _Captured()

    api._paginate = fake_paginate
    api._single = fake_single
    return api, captured


def _async_client(**kwargs):
    api = PolySwarmAsyncAPI(key='k' * 32, uri='https://api.example.test', community='gamma', **kwargs)
    captured = []

    async def fake_paginate(request, *a, **kw):
        captured.append(api._to_request(request))
        return
        yield  # pragma: no cover - makes this an async generator

    async def fake_single(request, *a, **kw):
        captured.append(api._to_request(request, *a, **kw))
        raise _Captured()

    api._paginate = fake_paginate
    api._single = fake_single
    return api, captured


def _params(request):
    """Normalise a request's params to a list of (key, value) pairs."""
    params = request.params
    if isinstance(params, dict):
        pairs = []
        for key, value in params.items():
            if isinstance(value, (list, tuple)):
                pairs.extend((key, v) for v in value)
            else:
                pairs.append((key, value))
        return pairs
    return list(params)


def _run_sync(api, method, *args, **kwargs):
    try:
        list(getattr(api, method)(*args, **kwargs))
    except _Captured:
        pass


async def _run_async(api, method, *args, **kwargs):
    try:
        result = getattr(api, method)(*args, **kwargs)
        if hasattr(result, '__aiter__'):
            async for _ in result:
                pass
        else:
            await result
    except _Captured:
        pass


# (method, args, kwargs, param key, expected refanged value, raw value)
SEARCH_CALLS = [
    ('search_url', ('hxxps[:]//evil[.]com',), {}, 'url', 'https://evil.com', 'hxxps[:]//evil[.]com'),
    ('search_by_metadata', ('strings.ips:*',), {'ips': ['127[.]0[.]0[.]1']}, 'ips', '127.0.0.1', '127[.]0[.]0[.]1'),
    ('search_by_metadata', ('strings.urls:*',), {'urls': ['hxxp://evil[.]com/x']}, 'urls', 'http://evil.com/x', 'hxxp://evil[.]com/x'),
    ('search_by_metadata', ('strings.domains:*',), {'domains': ['evil[dot]com']}, 'domains', 'evil.com', 'evil[dot]com'),
    ('search_by_ioc', (), {'ip': '10[.]0[.]0[.]1'}, 'ip', '10.0.0.1', '10[.]0[.]0[.]1'),
    ('search_by_ioc', (), {'domain': 'evil(.)com'}, 'domain', 'evil.com', 'evil(.)com'),
    ('check_known_hosts', (), {'ips': ['8[.]8[.]8[.]8']}, 'ip', '8.8.8.8', '8[.]8[.]8[.]8'),
    ('check_known_hosts', (), {'domains': ['good[.]example']}, 'domain', 'good.example', 'good[.]example'),
    # A bare string where a list is expected (``_refang_all``'s str branch).
    ('check_known_hosts', (), {'ips': '8[.]8[.]8[.]8'}, 'ip', '8.8.8.8', '8[.]8[.]8[.]8'),
    ('check_known_hosts', (), {'domains': 'good[.]example'}, 'domain', 'good.example', 'good[.]example'),
]


@pytest.mark.parametrize('method,args,kwargs,key,refanged,raw', SEARCH_CALLS)
class TestSearchMethodsRefang:
    def test_sync_sends_refanged_value(self, method, args, kwargs, key, refanged, raw):
        api, captured = _sync_client()
        _run_sync(api, method, *args, **kwargs)
        assert (key, refanged) in _params(captured[0])

    def test_sync_opt_out_sends_raw_value(self, method, args, kwargs, key, refanged, raw):
        api, captured = _sync_client(refang_iocs=False)
        _run_sync(api, method, *args, **kwargs)
        assert (key, raw) in _params(captured[0])

    async def test_async_sends_refanged_value(self, method, args, kwargs, key, refanged, raw):
        api, captured = _async_client()
        await _run_async(api, method, *args, **kwargs)
        assert (key, refanged) in _params(captured[0])

    async def test_async_opt_out_sends_raw_value(self, method, args, kwargs, key, refanged, raw):
        api, captured = _async_client(refang_iocs=False)
        await _run_async(api, method, *args, **kwargs)
        assert (key, raw) in _params(captured[0])


def test_metadata_free_form_query_is_never_refanged():
    api, captured = _sync_client()
    _run_sync(api, 'search_by_metadata', 'strings.domains:"evil[.]com"')
    assert ('query', 'strings.domains:"evil[.]com"') in _params(captured[0])


def test_live_values_are_sent_unchanged():
    api, captured = _sync_client()
    _run_sync(api, 'search_url', 'https://example.com/a[.]b')
    assert ('url', 'https://example.com/a[.]b') in _params(captured[0])


# (method, args, kwargs) — every URL submission path; the first request's JSON
# body carries the artifact name the server stores as the URL.
SUBMIT_CALLS = [
    ('submit', ('hxxps[:]//evil[.]com/x',), {'artifact_type': 'URL'}),
    ('sandbox_file', ('hxxps[:]//evil[.]com/x', 'provider', 'vm'), {'artifact_type': 'URL'}),
    ('sandbox_url', ('hxxps[:]//evil[.]com/x', 'provider', 'vm'), {}),
]


@pytest.mark.parametrize('method,args,kwargs', SUBMIT_CALLS)
class TestUrlSubmissionRefang:
    def test_sync_submits_refanged_url(self, method, args, kwargs):
        api, captured = _sync_client()
        _run_sync(api, method, *args, **kwargs)
        assert captured[0].input_json['artifact_name'] == 'https://evil.com/x'

    def test_sync_opt_out_submits_raw_url(self, method, args, kwargs):
        api, captured = _sync_client(refang_iocs=False)
        _run_sync(api, method, *args, **kwargs)
        assert captured[0].input_json['artifact_name'] == 'hxxps[:]//evil[.]com/x'

    async def test_async_submits_refanged_url(self, method, args, kwargs):
        api, captured = _async_client()
        await _run_async(api, method, *args, **kwargs)
        assert captured[0].input_json['artifact_name'] == 'https://evil.com/x'

    async def test_async_opt_out_submits_raw_url(self, method, args, kwargs):
        api, captured = _async_client(refang_iocs=False)
        await _run_async(api, method, *args, **kwargs)
        assert captured[0].input_json['artifact_name'] == 'hxxps[:]//evil[.]com/x'


def test_explicit_artifact_name_is_kept():
    api, captured = _sync_client()
    _run_sync(api, 'submit', 'hxxp://evil[.]com', artifact_type='URL', artifact_name='my label')
    assert captured[0].input_json['artifact_name'] == 'my label'


@pytest.mark.parametrize('method,args,kwargs', SUBMIT_CALLS)
def test_uploaded_url_content_is_refanged(monkeypatch, method, args, kwargs):
    # The server stores the uploaded content as the URL artifact, so the
    # content — not only the default artifact name — must be refanged.
    from polyswarm_api import resources
    contents = []
    original = resources.LocalArtifact.from_content.__func__

    def spy(cls, api, content, *a, **kw):
        contents.append(content)
        return original(cls, api, content, *a, **kw)

    monkeypatch.setattr(resources.LocalArtifact, 'from_content', classmethod(spy))
    api, _ = _sync_client()
    _run_sync(api, method, *args, **kwargs)
    assert contents == ['https://evil.com/x']


# (method, args) — known-host catalogue writes; the host rides the JSON body.
HOST_WRITE_CALLS = [
    ('add_known_good_host', ('domain', 'feed', 'good[.]example')),
    ('add_known_bad_host', ('domain', 'feed', 'good[.]example')),
    ('update_known_good_host', (7, 'domain', 'feed', 'good[.]example', True)),
]


@pytest.mark.parametrize('method,args', HOST_WRITE_CALLS)
class TestKnownHostWritesRefang:
    def test_sync_writes_refanged_host(self, method, args):
        api, captured = _sync_client()
        _run_sync(api, method, *args)
        assert captured[0].input_json['host'] == 'good.example'

    def test_sync_opt_out_writes_raw_host(self, method, args):
        api, captured = _sync_client(refang_iocs=False)
        _run_sync(api, method, *args)
        assert captured[0].input_json['host'] == 'good[.]example'

    async def test_async_writes_refanged_host(self, method, args):
        api, captured = _async_client()
        await _run_async(api, method, *args)
        assert captured[0].input_json['host'] == 'good.example'

    async def test_async_opt_out_writes_raw_host(self, method, args):
        api, captured = _async_client(refang_iocs=False)
        await _run_async(api, method, *args)
        assert captured[0].input_json['host'] == 'good[.]example'


# ── QR-code submissions: the argument is an image PATH, never a URL ────────
#
# ``qr[.]png`` refangs to ``qr.png``, which is shaped like a domain, so these
# fail if the QR branch ever runs the refang. ``submit`` reads the image with
# ``LocalArtifact.from_path``; ``sandbox_file`` hands the string to
# ``from_content`` (its URL branch has no path reader), so each is spied where
# the value actually lands.

QR_PREPROCESSING = {'type': 'qrcode'}


def _spy(monkeypatch, name):
    from polyswarm_api import resources
    seen = []

    def spy(cls, api, value, *a, **kw):
        seen.append(value)
        raise _Captured()

    monkeypatch.setattr(resources.LocalArtifact, name, classmethod(spy))
    return seen


def test_sync_submit_qrcode_path_is_never_refanged(monkeypatch):
    seen = _spy(monkeypatch, 'from_path')
    api, _ = _sync_client()
    _run_sync(api, 'submit', 'qr[.]png', artifact_type='URL', preprocessing=QR_PREPROCESSING)
    assert seen == ['qr[.]png']


async def test_async_submit_qrcode_path_is_never_refanged(monkeypatch):
    seen = _spy(monkeypatch, 'from_path')
    api, _ = _async_client()
    await _run_async(api, 'submit', 'qr[.]png', artifact_type='URL', preprocessing=QR_PREPROCESSING)
    assert seen == ['qr[.]png']


def test_sync_sandbox_file_qrcode_value_is_never_refanged(monkeypatch):
    seen = _spy(monkeypatch, 'from_content')
    api, _ = _sync_client()
    _run_sync(api, 'sandbox_file', 'qr[.]png', 'provider', 'vm', artifact_type='URL',
              preprocessing=QR_PREPROCESSING)
    assert seen == ['qr[.]png']


async def test_async_sandbox_file_qrcode_value_is_never_refanged(monkeypatch):
    seen = _spy(monkeypatch, 'from_content')
    api, _ = _async_client()
    await _run_async(api, 'sandbox_file', 'qr[.]png', 'provider', 'vm', artifact_type='URL',
                     preprocessing=QR_PREPROCESSING)
    assert seen == ['qr[.]png']
