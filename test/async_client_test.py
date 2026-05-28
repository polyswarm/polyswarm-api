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
import asyncio
import pytest
import httpx
import respx
import vcr as vcr_

from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api import exceptions


async def _dispatch_sandbox(api, instance_id, sandbox_slug, vm_slug, network_enabled,
                            tries=30, delay=1):
    """Async counterpart of the sync test helper — retries through the
    storage-pointer-lag window after submit().
    """
    last = None
    for _ in range(tries):
        try:
            return await api.sandbox(instance_id, sandbox_slug, vm_slug, network_enabled)
        except exceptions.FailedInstanceException as e:
            last = e
            await asyncio.sleep(delay)
    raise last


async def _wait_for_sandbox_task(coro_factory, tries=30, delay=1):
    """Poll an async sandbox-task-search call (latest/list) until the
    SandboxTaskSearchHash index surfaces the just-created task. ``coro_factory``
    must be a callable returning a fresh coroutine each iteration (we can't
    await a coroutine twice).
    """
    last = None
    for _ in range(tries):
        try:
            return await coro_factory()
        except exceptions.NotFoundException as e:
            last = e
            await asyncio.sleep(delay)
    raise last


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
            # Provision: submit a fresh artifact so rescan has something to
            # rescan. The EICAR sha256 is deterministic for test/malicious.
            await api.submit('test/malicious')
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
            await api.submit('test/malicious')
            result = [r async for r in api.search(SHA256)]
        assert result[0].sha256 == SHA256

    @vcr.use_cassette()
    async def test_async_metadata_search(self):
        async with self._api() as api:
            await api.submit('test/malicious')
            result = [r async for r in api.search_by_metadata(f'artifact.sha256:{SHA256}')]
        assert result[0].sha256 == SHA256

    # ── IOCs ──────────────────────────────────────────────────────────────────

    @pytest.mark.skip(
        reason='Upstream artifact-index bug. The memoize cache is fine — '
               'direct in-process calls to get_fields_with_tag(IP_IOC) return '
               'all 17 tagged paths and extract_iocs() with the same '
               'tool_metadata shape returns the IP correctly. Something '
               'between the HTTP view and that function differs (likely '
               'last_scanned_instance resolution returning a different '
               'instance than the one carrying the cape_sandbox_v2 blob). '
               'Filed as a separate upstream follow-up.',
    )
    @vcr.use_cassette()
    async def test_async_iocs_by_hash(self):
        async with self._api() as api:
            instance = await api.submit('test/malicious')
            await api.tool_metadata_create(
                instance.id, 'cape_sandbox_v2', {
                    'extracted_c2_ips': ['1.2.3.4'],
                    'extracted_c2_urls': ['www.virus.com'],
                    'ttp': ['T1081', 'T1060', 'T1069'],
                })
            iocs = [r async for r in api.iocs_by_hash('sha256', SHA256)]
        assert iocs[0].json['ips'] == ['1.2.3.4']
        assert iocs[0].json['ttps'] == ['T1081', 'T1060', 'T1069']

    @pytest.mark.skip(
        reason='Upstream artifact-index bug. Likely shares the last_scanned_'
               'instance resolution issue with iocs_by_hash. Filed as a '
               'separate upstream follow-up.',
    )
    @vcr.use_cassette()
    async def test_async_search_by_ioc(self):
        async with self._api() as api:
            instance = await api.submit('test/malicious')
            await api.tool_metadata_create(
                instance.id, 'cape_sandbox_v2', {
                    'extracted_c2_ips': ['1.2.3.4'],
                    'extracted_c2_urls': ['www.virus.com'],
                    'ttp': ['T1081', 'T1060', 'T1069'],
                })
            iocs = [r async for r in api.search_by_ioc(ip='1.2.3.4')]
        assert iocs[0].json == SHA256

    # ── Known Hosts ───────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_add_known_good_host(self):
        async with self._api() as api:
            # Provision: drop residue, capture the real id from the add response.
            # ioc_cache divergence (see sync sibling) may leave stale entries;
            # tolerate 404 in cleanup.
            async for hit in api.check_known_hosts(domains=['polyswarm.network']):
                try:
                    await api.delete_known_good_host(hit.json['id'])
                except exceptions.NotFoundException:
                    pass
            known = await api.add_known_good_host('domain', 'test', 'polyswarm.network')
            try:
                assert known.json['type'] == 'domain'
                assert known.json['host'] == 'polyswarm.network'
            finally:
                try:
                    await api.delete_known_good_host(known.json['id'])
                except exceptions.NotFoundException:
                    pass

    @vcr.use_cassette()
    async def test_async_update_known_good_host(self):
        async with self._api() as api:
            added = await api.add_known_good_host('domain', 'test', 'polyswarm.network')
            try:
                known = await api.update_known_good_host(
                    added.json['id'], 'ip', 'test', '1.2.3.4', True,
                )
                assert known.json['type'] == 'ip'
                assert known.json['host'] == '1.2.3.4'
            finally:
                try:
                    await api.delete_known_good_host(added.json['id'])
                except exceptions.NotFoundException:
                    pass

    @vcr.use_cassette()
    async def test_async_delete_known_good_host(self):
        async with self._api() as api:
            added = await api.add_known_good_host('ip', 'test', '1.2.3.4')
            known = await api.delete_known_good_host(added.json['id'])
        assert known.json['type'] == 'ip'
        assert known.json['host'] == '1.2.3.4'

    @vcr.use_cassette()
    async def test_async_check_known_host(self):
        async with self._api() as api:
            async for hit in api.check_known_hosts(ips=['1.2.3.4']):
                try:
                    await api.delete_known_good_host(hit.json['id'])
                except exceptions.NotFoundException:
                    pass
            added = await api.add_known_good_host('ip', 'test', '1.2.3.4')
            try:
                known = [r async for r in api.check_known_hosts(ips=['1.2.3.4'])]
                assert any(h.json['host'] == '1.2.3.4' and h.json['type'] == 'ip' for h in known)
            finally:
                try:
                    await api.delete_known_good_host(added.json['id'])
                except exceptions.NotFoundException:
                    pass

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
            instance = await api.submit('test/malicious')
            task = await _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True)
            assert task.json['config']['network_enabled'] is True
            task = await _dispatch_sandbox(api, instance.id, 'triage', 'win10-build-15063', False)
            assert task.sandbox == 'triage'
            assert task.json['config']['network_enabled'] is False

    @pytest.mark.skip(
        reason='Requires sandbox workers to actually process queued tasks. '
               'sandbox_task_latest reads from SandboxTaskSearchHash which is '
               'only populated on SUCCEEDED tasks (see sync sibling for the '
               'full pointer). On a fresh e2e without cape/triage workers no '
               'task succeeds and latest returns 404.',
    )
    @vcr.use_cassette()
    async def test_async_sandboxtask_latest(self):
        async with self._api() as api:
            instance = await api.submit('test/malicious')
            await _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True)
            await _dispatch_sandbox(api, instance.id, 'triage', 'win10-build-15063', False)

            latest_cape = await _wait_for_sandbox_task(
                lambda: api.sandbox_task_latest(SHA256, 'cape'),
            )
            latest_triage = await _wait_for_sandbox_task(
                lambda: api.sandbox_task_latest(SHA256, 'triage'),
            )
        assert latest_cape.sha256 == SHA256
        assert latest_cape.sandbox == 'cape'
        assert latest_triage.sha256 == SHA256
        assert latest_triage.sandbox == 'triage'

    @vcr.use_cassette()
    async def test_async_sandboxtask_list(self):
        async with self._api() as api:
            instance = await api.submit('test/malicious')
            await _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True)
            await _dispatch_sandbox(api, instance.id, 'triage', 'win10-build-15063', False)

            # Poll until the SandboxTaskSearchHash index sees both tasks.
            for _ in range(30):
                try:
                    all_tasks = [r async for r in api.sandbox_task_list(SHA256)]
                    if {'cape', 'triage'} <= {t.sandbox for t in all_tasks}:
                        break
                except exceptions.NoResultsException:
                    pass
                await asyncio.sleep(1)

            cape_tasks = [r async for r in api.sandbox_task_list(SHA256, sandbox='cape')]
            triage_tasks = [r async for r in api.sandbox_task_list(SHA256, sandbox='triage')]
            all_tasks = [r async for r in api.sandbox_task_list(SHA256)]
        assert len(cape_tasks) >= 1
        assert all(t.sandbox == 'cape' for t in cape_tasks)
        assert len(triage_tasks) >= 1
        assert all(t.sandbox == 'triage' for t in triage_tasks)
        assert {'cape', 'triage'} <= {t.sandbox for t in all_tasks}

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
            try:
                # The e2e may carry leftover rulesets from prior runs; use
                # a presence assertion instead of an exact count.
                rules = [r async for r in api.ruleset_list()]
                assert any(r.id == rule.id for r in rules)

                got = await api.ruleset_get(rule.id)
                assert got.name == 'test'

                updated = await api.ruleset_update(rule.id, name='test2', description='test')
                assert updated.name == 'test2'
                assert updated.description == 'test'
            finally:
                await api.ruleset_delete(rule.id)
            remaining_ids = []
            try:
                remaining_ids = [r.id async for r in api.ruleset_list()]
            except exceptions.NoResultsException:
                pass
            assert rule.id not in remaining_ids

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
            # Provision: create a hunt; the corpus on a fresh e2e is empty
            # so we accept NoResultsException as a valid outcome.
            with open('test/eicar.yara') as yara:
                hunt = await api.historical_create(yara.read())
            try:
                try:
                    result = [r async for r in api.historical_results(hunt=hunt.id)]
                    for entry in result:
                        assert entry.sha256
                        assert entry.rule_name
                except (exceptions.NotFoundException, exceptions.NoResultsException):
                    pass
            finally:
                await api.historical_delete(hunt.id)

    # ── Live Hunting ──────────────────────────────────────────────────────────

    @pytest.mark.skip(
        reason='Requires the bounty / microengine pipeline locally so '
               'submitted artifacts produce assertions that show up in the '
               'live feed. The lifecycle (ruleset_create + live_start + '
               'live_stop) works without that pipeline but the feed-content '
               'and livescan_id assertions need microengines processing the '
               'submission. Re-record against an environment that has them.',
    )
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
            instance = await api.submit('test/malicious')
            await api.tool_metadata_create(instance.id, 'test_tool_1', {'key': 'value'})
            await api.tool_metadata_create(instance.id, 'test_tool_2', {'key2': 'value2'})
            # persist_external_metadata runs asynchronously via Celery; poll
            # the list endpoint until both tools land. The Celery roundtrip
            # can take ~5s when the queue is busy from neighbouring tests.
            tools = {}
            for _ in range(30):
                try:
                    metadata = [r async for r in api.tool_metadata_list(instance.id)]
                    tools = {m.json['tool']: m.json['tool_metadata'] for m in metadata}
                    if 'test_tool_1' in tools and 'test_tool_2' in tools:
                        break
                except exceptions.NoResultsException:
                    pass
                await asyncio.sleep(1)
        assert tools.get('test_tool_1') == {'key': 'value'}
        assert tools.get('test_tool_2') == {'key2': 'value2'}

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
async def test_async_report_template_logo_delete():
    """``report_template_logo_delete`` is a two-step flow: GET the
    template, then DELETE the logo. The cassette suite covers it but
    isn't refreshed; this respx test pins the wire shape so any drift
    in ``ReportTemplate.delete_logo()`` (wrong URL, missing id param,
    wrong method) fails fast.
    """
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
    delete_route = respx.delete(f'{BASE_URL}/reports/templates/logo').mock(
        return_value=httpx.Response(200, json={'status': 'OK', 'result': None}),
    )

    api = PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma')
    try:
        await api.report_template_logo_delete(template_id)
    finally:
        await api.aclose()

    delete_request = delete_route.calls[-1].request
    assert delete_request.url.params.get('id') == template_id


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
