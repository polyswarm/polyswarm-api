"""Tests for PolySwarmAsyncAPI (polyswarm_api.aio).

Most tests reuse the existing VCR cassettes from the sync test suite —
the HTTP interactions are identical; only the transport layer differs.
VCR is configured with match_on=['method', 'uri'] so the request headers
recorded by the requests library do not cause mismatches when httpx
replays the cassette.

Error-handling and lifecycle tests that have no pre-recorded cassette
use respx (the httpx equivalent of responses).

Run with:
    pip install -e ".[async,tests]"
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
    # Ignore request headers so cassettes recorded via requests replay cleanly
    # with the httpx-backed async client.
    match_on=['method', 'uri'],
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
            providers = [r async for r in api.sandbox_providers()]
        # SandboxProvider.parse_result returns a list-of-providers per slug
        # flatten to check slugs
        slugs = {p.slug for p in providers}
        assert 'cape' in slugs
        assert 'triage' in slugs

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
    Tests for the engine cache use respx (httpx equivalent of responses)
    because the sync suite uses @responses.activate for this test.
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
        await api.close()

    @respx.mock
    async def test_async_engine_cache_server_error_raises(self):
        url = 'http://localhost:3000/api/v1/microengines/list'
        respx.get(url).mock(return_value=httpx.Response(500, json={
            'status': 'error', 'result': 'server error',
        }))
        api = PolySwarmAsyncAPI(self.test_api_key, uri='http://localhost:3000/api/v1', community='gamma')
        with pytest.raises(exceptions.RequestException):
            await api.refresh_engine_cache()
        await api.close()

    @respx.mock
    async def test_async_engine_cache_empty_raises(self):
        url = 'http://localhost:3000/api/v1/microengines/list'
        respx.get(url).mock(return_value=httpx.Response(200, json={
            'status': 'OK', 'result': [], 'has_more': False,
        }))
        api = PolySwarmAsyncAPI(self.test_api_key, uri='http://localhost:3000/api/v1', community='gamma')
        with pytest.raises(exceptions.InvalidValueException):
            await api.refresh_engine_cache()
        await api.close()


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
