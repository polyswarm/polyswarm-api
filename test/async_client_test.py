"""Tests for PolySwarmAsyncAPI (polyswarm_api.aio).

Most tests reuse the existing VCR cassettes from the sync test suite —
the HTTP interactions are identical; only the transport layer differs.
VCR is configured with ``match_on=['method', 'scheme', 'host', 'port',
'path', 'query']`` so query parameters compare as a set; this lets
cassettes survive httpx's different param-ordering from the
requests-recorded format.

Error-handling and lifecycle tests that have no pre-recorded cassette
use respx (the httpx mocking library).

Run with:
    pip install -e ".[tests]"
    pytest test/async_client_test.py -v
"""
import pytest
import httpx
import respx
import vcr as vcr_

from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api import exceptions


# ── VCR setup (mirrors client_scan_test.py, adds match_on for httpx compat) ──

vcr = vcr_.VCR(
    cassette_library_dir='test/vcr',
    path_transformer=vcr_.VCR.ensure_suffix('.vcr'),
    # Use default matchers minus 'uri' — that's literal string matching
    # which is order-sensitive on query parameters. The 'query' matcher
    # compares params as a set, so cassettes recorded with one param
    # order replay cleanly even if httpx serialises them differently.
    match_on=['method', 'scheme', 'host', 'port', 'path', 'query'],
)


# ── Shared constants ──────────────────────────────────────────────────────────

SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
SHA256_ALT = 'a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427'


class TestAsyncScanCase:
    """
    Async equivalents of ScanTestCaseV2, using the same VCR cassettes.

    With asyncio_mode = "auto" in pyproject.toml pytest-asyncio
    automatically drives all async def test_* methods as coroutines.
    """

    test_api_key = '11111111111111111111111111111111'
    api_version = 'v3'

    def _api(self, community='gamma'):
        return PolySwarmAsyncAPI(
            self.test_api_key,
            uri=f'http://localhost:9696/{self.api_version}',
            community=community,
        )

    # ── Submission ────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_submission(self):
        async with self._api() as api:
            result = await api.submit('test/malicious')
        assert result.failed is False
        assert result.result is None

    # ── Rescans ───────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_rescans(self):
        async with self._api() as api:
            result = await api.rescan(SHA256)
            assert result.failed is False
            assert result.result is None
            result = await api.rescan_id(result.id)
            assert result.failed is False
            assert result.result is None

    # ── Search ────────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_hash_search(self):
        async with self._api() as api:
            result = [r async for r in api.search(SHA256)]
        assert result[0].sha256 == SHA256

    @vcr.use_cassette()
    async def test_async_metadata_search(self):
        async with self._api() as api:
            result = [r async for r in api.search_by_metadata(f'artifact.sha256:{SHA256}')]
        assert result[0].sha256 == SHA256

    # ── IOCs ──────────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_iocs_by_hash(self):
        async with self._api() as api:
            await api.tool_metadata_create(
                '41782351738405672', 'cape_sandbox_v2',
                {'cape_sandbox_v2': {
                    'extracted_c2_ips': ['1.2.3.4'],
                    'extracted_c2_urls': ['www.virus.com'],
                    'ttp': ['T1081', 'T1060', 'T1069']
                }})
            iocs = [r async for r in api.iocs_by_hash('sha256', SHA256)]
        assert iocs[0].json['ips'] == ['1.2.3.4']
        assert iocs[0].json['ttps'] == ['T1081', 'T1060', 'T1069']

    @vcr.use_cassette()
    async def test_async_search_by_ioc(self):
        async with self._api() as api:
            await api.tool_metadata_create(
                '41782351738405672', 'cape_sandbox_v2',
                {'cape_sandbox_v2': {
                    'extracted_c2_ips': ['1.2.3.4'],
                    'extracted_c2_urls': ['www.virus.com'],
                    'ttp': ['T1081', 'T1060', 'T1069']
                }})
            iocs = [r async for r in api.search_by_ioc(ip='1.2.3.4')]
        assert iocs[0].json == SHA256

    # ── Known Hosts ───────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_add_known_good_host(self):
        async with self._api() as api:
            known = await api.add_known_good_host('domain', 'test', 'polyswarm.network')
        assert known.json['type'] == 'domain'
        assert known.json['host'] == 'polyswarm.network'

    @vcr.use_cassette()
    async def test_async_update_known_good_host(self):
        async with self._api() as api:
            known = await api.update_known_good_host(1, 'ip', 'test', '1.2.3.4', True)
        assert known.json['type'] == 'ip'
        assert known.json['host'] == '1.2.3.4'

    @vcr.use_cassette()
    async def test_async_delete_known_good_host(self):
        async with self._api() as api:
            known = await api.delete_known_good_host(1)
        assert known.json['type'] == 'ip'
        assert known.json['host'] == '1.2.3.4'

    @vcr.use_cassette()
    async def test_async_check_known_host(self):
        async with self._api() as api:
            known = [r async for r in api.check_known_hosts(ips=['1.2.3.4'])]
        assert known[0].json['host'] == '1.2.3.4'
        assert known[0].json['type'] == 'ip'

    # ── Sandbox ───────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_sandbox_providers(self):
        async with self._api() as api:
            response = await api.sandbox_providers()
        # Mirrors the sync shape (see test_sandbox_providers in
        # client_scan_test.py): ``.json['result']`` is keyed by provider slug.
        assert response.json['result']['cape']['slug'] == 'cape'
        assert response.json['result']['triage']['slug'] == 'triage'

    @vcr.use_cassette()
    async def test_async_sandboxtask_submit(self):
        async with self._api() as api:
            task = await api.sandbox('24135952517649903', 'cape', 'win-10-build-19041', True)
            assert task.json['config']['network_enabled'] is True
            task = await api.sandbox('24135952517649903', 'triage', 'win10-build-15063', False)
            assert task.sandbox == 'triage'
            assert task.json['config']['network_enabled'] is False

    @vcr.use_cassette()
    async def test_async_sandboxtask_latest(self):
        async with self._api() as api:
            latest_cape = await api.sandbox_task_latest(SHA256_ALT, 'cape')
            latest_triage = await api.sandbox_task_latest(SHA256_ALT, 'triage')
        assert latest_cape.sha256 == SHA256_ALT
        assert latest_cape.sandbox == 'cape'
        assert latest_triage.sha256 == SHA256_ALT
        assert latest_triage.sandbox == 'triage'

    @vcr.use_cassette()
    async def test_async_sandboxtask_list(self):
        async with self._api() as api:
            cape_tasks = [r async for r in api.sandbox_task_list(SHA256_ALT, sandbox='cape')]
            triage_tasks = [r async for r in api.sandbox_task_list(SHA256_ALT, sandbox='triage')]
            all_tasks = [r async for r in api.sandbox_task_list(SHA256_ALT)]
        assert len(cape_tasks) == 1
        assert cape_tasks[0].sandbox == 'cape'
        assert len(triage_tasks) == 1
        assert triage_tasks[0].sandbox == 'triage'
        assert len(all_tasks) == 2
        assert {t.sandbox for t in all_tasks} == {'cape', 'triage'}

    # ── Sample (aggregated view) ──────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_sample(self):
        async with self._api() as api:
            result = await api.sample(SHA256)
        assert isinstance(result.artifact_instance, dict)
        assert isinstance(result.sandbox, dict)
        assert {'cape', 'triage'} <= set(result.sandbox.keys())
        assert isinstance(result.tasks, dict)
        assert {'artifact_instance', 'llm_report', 'sandbox_cape', 'sandbox_triage'} <= set(result.tasks.keys())

    # ── YARA Rulesets ─────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_rules(self):
        async with self._api() as api:
            with open('test/eicar.yara') as f:
                contents = f.read()
            rule = await api.ruleset_create('test', contents)
            assert rule.name == 'test'
            assert rule.yara == contents

            rules = [r async for r in api.ruleset_list()]
            assert len(rules) == 1

            rule = await api.ruleset_get(rule.id)
            assert rule.name == 'test'

            rule = await api.ruleset_update(rule.id, name='test2', description='test')
            assert rule.name == 'test2'
            assert rule.description == 'test'

            await api.ruleset_delete(rule.id)
            with pytest.raises(exceptions.NoResultsException):
                _ = [r async for r in api.ruleset_list()]

    # ── Historical Hunting ────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_historical(self):
        async with self._api() as api:
            with open('test/eicar.yara') as f:
                historical_hunt = await api.historical_create(f.read())
            assert historical_hunt.status == 'PENDING'

            get_historical_hunt = await api.historical_get(historical_hunt.id)
            assert historical_hunt.id == get_historical_hunt.id

            deleted_historical_hunt = await api.historical_delete(get_historical_hunt.id)
            assert historical_hunt.id == deleted_historical_hunt.id

    @vcr.use_cassette()
    async def test_async_list_historical(self):
        async with self._api() as api:
            with open('test/eicar.yara') as f:
                yara_content = f.read()
            historical_ids = []
            for _ in range(5):
                historical = await api.historical_create(yara_content)
                historical_ids.append(historical.id)
            result = [r async for r in api.historical_list()]
            assert len(result) >= 4
            await api.historical_delete_list(historical_ids)

    @vcr.use_cassette()
    async def test_async_historical_results(self):
        async with self._api() as api:
            result = [r async for r in api.historical_results(hunt='48011760326110718')]
        assert len(result) == 6

    # ── Live Hunting ──────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_live(self):
        async with self._api() as api:
            with open('test/eicar.yara') as f:
                rule = await api.ruleset_create('eicar', f.read())
            rule = await api.live_start(rule_id=rule.id)
            assert rule.livescan_id

            await api.submit('test/malicious')

            feed = [r async for r in api.live_feed()]
            assert len(feed) > 1
            result = feed[0]
            result = await api.live_result(result.id)
            assert result.download_url

            await api.live_feed_delete([result.id])
            with pytest.raises(exceptions.NotFoundException):
                await api.live_result(result.id)

            rule = await api.live_stop(rule_id=rule.id)
            assert rule.livescan_id is None

    # ── Tool Metadata ─────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_tool_metadata(self):
        async with self._api() as api:
            await api.tool_metadata_create(41782351738405672, 'test_tool_1', {'key': 'value'})
            await api.tool_metadata_create(41782351738405672, 'test_tool_2', {'key2': 'value2'})
            metadata = [r async for r in api.tool_metadata_list(41782351738405672)]
        assert metadata[0].json['tool'] == 'test_tool_2'
        assert metadata[0].json['tool_metadata'] == {'key2': 'value2'}
        assert metadata[1].json['tool'] == 'test_tool_1'
        assert metadata[1].json['tool_metadata'] == {'key': 'value'}

    # ── Download ──────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_download_to_handle(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmp_dir:
            fpath = os.path.join(tmp_dir, 'out')
            with open(fpath, 'wb') as fh:
                async with self._api() as api:
                    await api.download_to_handle(SHA256, fh)
            with open(fpath, 'rb') as fh:
                assert fh.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


# ── Engine cache — no cassette, mirrors test_resolve_engine_name ──────────────

class TestAsyncEngineCache:
    """
    Tests for the engine cache use respx (httpx mocking library) to mock
    the engines-list endpoint without a VCR cassette.
    """
    test_api_key = '11111111111111111111111111111111'

    _engines_payload = [
        {
            'id': '8565030964589685', 'name': 'K7-Arbiter',
            'accountNumber': 181953637296, 'engineType': 'arbiter',
            'status': 'disabled', 'artifactTypes': ['file'], 'tags': ['arbiter'],
            'communities': ['pi'], 'mimeTypes': ['application/octet-stream'],
            'createdAt': '2019-04-24T22:36:51.000Z', 'modifiedAt': '2021-04-26T17:34:13.523Z',
            'archivedAt': None,
        },
        {
            'id': '9128037974787675', 'name': 'Test',
            'accountNumber': 191777777796, 'engineType': 'engine',
            'status': 'verified', 'artifactTypes': ['file'], 'tags': ['engine'],
            'communities': ['pi'], 'mimeTypes': None,
            'createdAt': '2019-04-24T22:36:51.000Z', 'modifiedAt': '2021-04-26T17:34:13.523Z',
            'archivedAt': None,
        },
        {
            'id': '84858992620316109', 'name': 'IRIS-H',
            'accountNumber': 181953637296, 'engineType': 'engine',
            'status': 'disabled', 'artifactTypes': ['file'], 'tags': ['engine'],
            'communities': ['pi', 'sigma'], 'mimeTypes': ['application/pdf'],
            'createdAt': '2019-04-24T22:44:40.000Z', 'modifiedAt': '2021-04-26T17:34:13.744Z',
            'archivedAt': None,
        },
        {
            'id': '49931709284165436', 'name': 'Intezer',
            'accountNumber': 181953637296, 'engineType': 'engine',
            'status': 'disabled', 'artifactTypes': ['file'], 'tags': ['engine'],
            'communities': ['pi', 'sigma'], 'mimeTypes': ['application/octet-stream'],
            'createdAt': '2019-08-29T19:51:38.000Z', 'modifiedAt': '2021-04-26T17:34:13.520Z',
            'archivedAt': None,
        },
    ]

    @respx.mock
    async def test_async_engine_cache(self):
        url = 'http://localhost:3000/api/v1/microengines/list'
        respx.get(url).mock(return_value=httpx.Response(200, json={
            'status': 'OK',
            'result': self._engines_payload,
            'has_more': False,
        }))
        api = PolySwarmAsyncAPI(self.test_api_key, uri='http://localhost:3000/api/v1', community='gamma')
        await api.refresh_engine_cache()
        assert {'Intezer', 'IRIS-H', 'Test', 'K7-Arbiter'} == {e.name for e in api._engines}
        assert {'K7-Arbiter'} == {e.name for e in api._engines if e.is_arbiter}
        await api.aclose()

    @respx.mock
    async def test_async_engine_cache_server_error_raises(self):
        url = 'http://localhost:3000/api/v1/microengines/list'
        respx.get(url).mock(return_value=httpx.Response(500, json={
            'status': 'error', 'result': 'server error',
        }))
        api = PolySwarmAsyncAPI(self.test_api_key, uri='http://localhost:3000/api/v1', community='gamma')
        with pytest.raises(exceptions.RequestException):
            await api.refresh_engine_cache()
        await api.aclose()

    @respx.mock
    async def test_async_engine_cache_empty_raises(self):
        url = 'http://localhost:3000/api/v1/microengines/list'
        respx.get(url).mock(return_value=httpx.Response(200, json={
            'status': 'OK', 'result': [], 'has_more': False,
        }))
        api = PolySwarmAsyncAPI(self.test_api_key, uri='http://localhost:3000/api/v1', community='gamma')
        with pytest.raises(exceptions.InvalidValueException):
            await api.refresh_engine_cache()
        await api.aclose()


# ── Error handling (no cassettes) — mirrors no-cassette sync tests ────────────

BASE_URL = 'http://localhost:9696/v3'
API_KEY = '11111111111111111111111111111111'


@respx.mock
async def test_async_not_found_raises():
    respx.get(f'{BASE_URL}/search/hash/sha256').mock(
        return_value=httpx.Response(404, json={'status': 'error', 'result': 'not found'})
    )
    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        with pytest.raises(exceptions.NotFoundException):
            _ = [r async for r in api.search(SHA256)]


@respx.mock
async def test_async_rate_limit_raises():
    respx.get(f'{BASE_URL}/search/hash/sha256').mock(
        return_value=httpx.Response(429, json={'status': 'error', 'result': 'rate limited'})
    )
    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        with pytest.raises(exceptions.UsageLimitsExceededException):
            _ = [r async for r in api.search(SHA256)]


@respx.mock
async def test_async_no_results_raises():
    respx.get(f'{BASE_URL}/hunt/rule/list').mock(return_value=httpx.Response(204))
    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        with pytest.raises(exceptions.NoResultsException):
            _ = [r async for r in api.ruleset_list()]


@respx.mock
async def test_async_session_drops_none_authorization_header():
    """``headers={'Authorization': None}`` must actually strip the
    session-level Authorization header from the outgoing request.

    Used by SDK callsites that hit third-party origins (engines list
    against an unauthenticated endpoint; pre-signed S3 URLs for archive
    / bundle / report downloads) — leaking the API key to those origins
    is a real exposure. requests honoured this; httpx does not natively,
    so the session implements the suppression manually.
    """
    from polyswarm_api.core import PolyswarmRequest

    target = 'https://s3.example.com/presigned-target'
    respx.get(target).mock(return_value=httpx.Response(200))

    api = PolySwarmAsyncAPI('secret-key-1234', uri=BASE_URL, community='gamma')
    try:
        await api.session.execute(PolyswarmRequest(
            api=api, method='GET', url=target, headers={'Authorization': None},
        ))
    finally:
        await api.aclose()

    assert 'Authorization' not in respx.calls[-1].request.headers


@respx.mock
async def test_async_session_keeps_authorization_header_by_default():
    """Sanity-check the inverse: when no suppression is requested the
    session-level Authorization header still ships, so the suppression
    code in the prior test isn't accidentally dropping it for every
    request.
    """
    target = f'{BASE_URL}/search/hash/sha256'
    respx.get(target).mock(return_value=httpx.Response(
        200,
        json={'status': 'OK', 'result': [], 'has_more': False},
    ))

    api = PolySwarmAsyncAPI('secret-key-1234', uri=BASE_URL, community='gamma')
    try:
        _ = [r async for r in api.search(SHA256)]
    finally:
        await api.aclose()

    assert respx.calls[-1].request.headers.get('Authorization') == 'secret-key-1234'


@respx.mock
async def test_async_no_parser_non_2xx_raises():
    """Endpoints whose request builder doesn't set a ``result_parser``
    (e.g. ``notification_webhook_test``) must still raise on non-2xx.

    parse_result was previously gating non-2xx exception mapping on
    result_parser being set, which silently swallowed server errors for
    fire-and-forget endpoints. Guard against the regression.
    """
    respx.post(f'{BASE_URL}/notification/webhook/test').mock(
        return_value=httpx.Response(500, json={
            'status': 'error', 'result': 'something went wrong',
        }),
    )
    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        with pytest.raises(exceptions.RequestException):
            await api.notification_webhook_test('webhook-123')


@respx.mock
async def test_async_upload_helper_strips_session_authorization():
    """``session.upload_file`` PUTs to a pre-signed S3 URL. The session-
    level ``Authorization`` header (the PolySwarm API key) must NOT
    ship to the object store — that would leak the API key to a
    third-party origin.
    """
    import io as _io

    presigned = 'https://s3.example.com/upload-target?sig=abc'
    put_route = respx.put(presigned).mock(return_value=httpx.Response(200))

    api = PolySwarmAsyncAPI('secret-key-1234', uri=BASE_URL, community='gamma')
    try:
        artifact = _io.BytesIO(b'sample-bytes')
        await api.session.upload_file(presigned, artifact)
    finally:
        await api.aclose()

    assert 'Authorization' not in put_route.calls[-1].request.headers


@respx.mock
async def test_async_download():
    """Single-step download: GET pre-signed URL, write into folder,
    close the local handle. Pins the simplest of the multi-statement
    canonical async methods.
    """
    import tempfile, os

    download_url = 'https://artifacts.example.com/eicar.bin'
    body = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    respx.get(
        f'{BASE_URL}/consumer/download/sha256/{SHA256}',
    ).mock(return_value=httpx.Response(
        200,
        content=body,
    ))

    api = PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma')
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = await api.download(tmp_dir, SHA256)
            assert result.handle.closed
            with open(os.path.join(tmp_dir, SHA256), 'rb') as f:
                assert f.read() == body
    finally:
        await api.aclose()


@respx.mock
async def test_async_sample_bundle_download_multistep():
    """``sample_bundle_download`` is a multi-step canonical async
    method: GET bundle task → state branch (PENDING / FAILED raise) →
    GET zip → close handle. Pins the full happy path against respx.
    """
    import tempfile, os

    bundle_id = '99'
    zip_url = 'https://s3.example.com/bundle.zip?sig=xyz'
    body = b'PK\x03\x04 fake zip bytes'

    respx.get(f'{BASE_URL}/bundle').mock(return_value=httpx.Response(
        200,
        json={
            'status': 'OK',
            'result': {
                'id': bundle_id,
                'community': 'gamma',
                'state': 'SUCCEEDED',
                'created': '2026-01-01T00:00:00',
                'instance_ids': [1, 2],
                'filename': 'bundle.zip',
                'preserve_filenames': False,
                'url': zip_url,
            },
        },
    ))
    respx.get(zip_url).mock(return_value=httpx.Response(200, content=body))

    api = PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma')
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = await api.sample_bundle_download(bundle_id, folder=tmp_dir)
            assert result.handle.closed
            written = os.path.join(tmp_dir, result.artifact_name)
            with open(written, 'rb') as f:
                assert f.read() == body
    finally:
        await api.aclose()


@respx.mock
async def test_async_report_download_multistep_handle_close():
    """``report_download`` is one of the multi-statement methods that
    motivated the codegen architecture: GET the report task → branch on
    state → second GET to fetch the rendered file → close the local
    handle. The post-``_single`` logic (``.state == 'PENDING'`` /
    ``result.handle.close()``) was the regression risk that the legacy
    polymorphic-return base class silently broke on async.

    This respx-driven test pins the full async flow against the new
    architecture: state-branch + second download + handle close, with
    no live e2e required.
    """
    import io as _io, tempfile, os
    from polyswarm_api import resources

    report_id = '42'
    download_url = 'https://s3.example.com/rendered-report.pdf'

    respx.get(f'{BASE_URL}/reports').mock(return_value=httpx.Response(200, json={
        'status': 'OK',
        'result': {
            'id': report_id,
            'type': 'scan',
            'format': 'pdf',
            'state': 'SUCCEEDED',
            'community': 'gamma',
            'created': '2026-01-01T00:00:00',
            'template_id': None,
            'template_metadata': {},
            'sandbox_task_id': None,
            'instance_id': '24135952517649903',
            'url': download_url,
        },
    }))
    body = b'%PDF-1.4 minimal'
    respx.get(download_url).mock(return_value=httpx.Response(
        200,
        content=body,
        headers={'Content-Type': 'application/pdf'},
    ))

    api = PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma')
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = await api.report_download(report_id, folder=tmp_dir)
            # post-_single step actually ran: handle is closed, file is on disk
            assert result.handle.closed
            written = os.path.join(tmp_dir, result.artifact_name)
            with open(written, 'rb') as f:
                assert f.read() == body
    finally:
        await api.aclose()


@respx.mock
async def test_async_report_template_logo_upload():
    """ReportTemplate.upload_logo previously passed the file-like via
    httpx ``data=``. Under httpx 0.27, ``data=`` is for Mapping
    form-encoded bodies; a raw byte payload must go through
    ``content=``. The fix reads the file into bytes and uses
    ``content=`` so the outbound PUT body is non-empty.

    Asserts the PUT actually carries the file bytes — the bot review
    flagged this as untested.
    """
    import io as _io
    from polyswarm_api import resources

    template_id = 'tpl-1'
    template_payload = {
        'id': template_id,
        'created': '2026-01-01T00:00:00',
        'template_name': 'test',
        'includes': None,
        'primary_color': None,
        'footer_text': None,
        'last_page_text': None,
        'is_default': False,
        'logo_content_length': None,
        'logo_content_type': None,
        'logo_height': None,
        'logo_width': None,
    }
    respx.get(f'{BASE_URL}/reports/templates').mock(return_value=httpx.Response(
        200, json={'status': 'OK', 'result': template_payload},
    ))
    upload_route = respx.put(f'{BASE_URL}/reports/templates/logo').mock(
        return_value=httpx.Response(
            200, json={'status': 'OK', 'result': template_payload},
        ),
    )

    api = PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma')
    try:
        logo_bytes = b'fake-png-bytes-for-test'
        await api.report_template_logo_upload(
            template_id, _io.BytesIO(logo_bytes), content_type='image/png',
        )
    finally:
        await api.aclose()

    put_request = upload_route.calls[-1].request
    assert put_request.content == logo_bytes
    assert put_request.headers.get('Content-Type') == 'image/png'


@respx.mock
async def test_async_instance_upload_to_presigned_url():
    """The 4.0 upload path: ``session.upload_file(url, artifact)``.

    Resources no longer carry an ``upload_file`` instance method — the
    transport is the session. Confirms a presigned PUT against an async
    api routes through the async client correctly.
    """
    from polyswarm_api import resources

    upload_url = 'https://s3.example.com/upload-target'
    respx.put(upload_url).mock(return_value=httpx.Response(200))

    api = PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma')
    try:
        instance = resources.ArtifactInstance(
            {
                'id': 1,
                'sha256': SHA256,
                'md5': '44d88612fea8a8f36de82e1278abb02f',
                'sha1': '3395856ce81f2b7382dee72602f798b642f14d8',
                'mimetype': 'text/plain',
                'size': 68,
                'extended_type': '',
                'first_seen': '2020-01-01T00:00:00',
                'upload_url': upload_url,
                'assertions': [],
                'votes': [],
                'failed': False,
                'window_closed': False,
                'polyscore': 0.0,
                'result': None,
                'metadata': [],
            },
            api=api,
        )
        import io as _io
        artifact = _io.BytesIO(b'eicar')
        response = await api.session.upload_file(instance.upload_url, artifact)
        assert response.status_code == 200
    finally:
        await api.aclose()


@respx.mock
async def test_async_context_manager():
    """Client cleans up correctly when used as an async context manager."""
    respx.get(f'{BASE_URL}/search/hash/sha256').mock(return_value=httpx.Response(200, json={
        'status': 'OK',
        'result': [{
            'sha256': SHA256, 'md5': '44d88612fea8a8f36de82e1278abb02f',
            'sha1': '3395856ce81f2b7382dee72602f798b642f14d8',
            'mimetype': 'text/plain', 'size': 68,
            'extended_type': 'EICAR virus test files',
            'first_seen': '2020-01-01T00:00:00', 'upload_url': '',
            'assertions': [], 'votes': [], 'failed': False,
            'window_closed': True, 'polyscore': 0.0, 'result': None, 'metadata': [],
        }],
        'has_more': False,
    }))
    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        result = [r async for r in api.search(SHA256)]
    assert result[0].sha256 == SHA256
