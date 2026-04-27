"""Tests for PolySwarmAsyncAPI (polyswarm_api.aio).

Uses respx to mock httpx HTTP calls — no network access required.
Each test creates its own PolySwarmAsyncAPI instance inside the
@respx.mock context to ensure the mock transport is active before
the httpx.AsyncClient is constructed.

Run with:
    pip install polyswarm_api[async] polyswarm_api[tests]
    pytest test/async_client_test.py -v
"""
import pytest
import httpx
import respx

from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api import exceptions

# ── Constants ─────────────────────────────────────────────────────────────────

API_KEY = '11111111111111111111111111111111'
BASE_URL = 'http://localhost:9696/v3'
COMMUNITY = 'gamma'

SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
SHA256_ALT = 'a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427'

# ── Shared fixture payloads ───────────────────────────────────────────────────

ARTIFACT_INSTANCE = {
    'sha256': SHA256,
    'md5': '44d88612fea8a8f36de82e1278abb02f',
    'sha1': '3395856ce81f2b7382dee72602f798b642f14d8',
    'mimetype': 'text/plain',
    'size': 68,
    'extended_type': 'EICAR virus test files',
    'first_seen': '2020-01-01T00:00:00',
    'upload_url': '',
    'id': '12345678901234567',
    'assertions': [],
    'votes': [],
    'failed': False,
    'window_closed': True,
    'polyscore': 0.0,
    'result': None,
    'metadata': [],
}

SANDBOX_TASK = {
    'id': '24135952517649903',
    'community': COMMUNITY,
    'sandbox': 'cape',
    'created': '2023-01-01T00:00:00',
    'expiration': '2023-01-08T00:00:00',
    'status': 'SUCCEEDED',
    'account_number': '123',
    'team_account_number': '456',
    'instance_id': '12345678901234567',
    'sha256': SHA256,
    'report': {},
    'upload_url': '',
    'config': {'network_enabled': True},
    'artifact': {},
}

YARA_RULESET = {
    'id': '99999999999999999',
    'name': 'test',
    'yara': 'rule test {}',
    'description': None,
    'created': '2023-01-01T00:00:00',
    'modified': '2023-01-01T00:00:00',
    'deleted': False,
    'livescan_id': None,
    'livescan_created': None,
}

HISTORICAL_HUNT = {
    'id': '48011760326110718',
    'created': '2023-01-01T00:00:00',
    'status': 'PENDING',
    'active': None,
    'ruleset_name': None,
    'yara': 'rule test {}',
    'summary': None,
    'progress': 0,
    'results_csv_uri': '',
    'communities': [COMMUNITY],
}

LIVE_HUNT_RESULT = {
    'id': '11111111111111111',
    'livescan_id': '22222222222222222',
    'instance_id': '12345678901234567',
    'created': '2023-01-01T00:00:00',
    'sha256': SHA256,
    'rule_name': 'test_rule',
    'tags': [],
    'polyscore': 0.9,
    'malware_family': 'EICAR',
    'detections': {'malicious': 1, 'benign': 0, 'total': 1},
    'download_url': 'https://s3.example.com/download',
    'community': COMMUNITY,
}

ENGINE = {
    'id': '8565030964589685',
    'name': 'TestEngine',
    'accountNumber': 181953637296,
    'engineType': 'microengine',
    'status': 'verified',
    'artifactTypes': ['file'],
    'tags': ['engine'],
    'communities': [COMMUNITY],
    'mimeTypes': ['application/octet-stream'],
    'createdAt': '2019-04-24T22:36:51.000Z',
    'modifiedAt': '2021-04-26T17:34:13.523Z',
    'archivedAt': None,
}

IOC_RESULT = {
    'ips': ['1.2.3.4'],
    'ttps': ['T1081', 'T1060', 'T1069'],
    'domains': [],
    'urls': [],
}

KNOWN_HOST_DOMAIN = {
    'id': 1,
    'type': 'domain',
    'host': 'polyswarm.network',
    'source': 'test',
    'good': True,
}

KNOWN_HOST_IP = {
    'id': 2,
    'type': 'ip',
    'host': '1.2.3.4',
    'source': 'test',
    'good': True,
}

TOOL_METADATA_1 = {
    'id': '111',
    'instance_id': '41782351738405672',
    'tool': 'test_tool_1',
    'tool_metadata': {'key': 'value'},
}

TOOL_METADATA_2 = {
    'id': '222',
    'instance_id': '41782351738405672',
    'tool': 'test_tool_2',
    'tool_metadata': {'key2': 'value2'},
}

METADATA_RESULT = {
    'artifact': {
        'sha256': SHA256,
        'sha1': '3395856ce81f2b7382dee72602f798b642f14d8',
        'md5': '44d88612fea8a8f36de82e1278abb02f',
        'id': '1',
        'created': '2023-01-01T00:00:00',
    },
    'hash': {},
    'scan': {},
    'strings': {},
    'exiftool': {},
    'lief': {},
    'pefile': {},
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def envelope(result, has_more=False):
    """Wrap a single resource in the standard API response envelope."""
    return {'status': 'OK', 'result': result, 'has_more': has_more}


def envelope_list(results, has_more=False):
    """Wrap a list of resources in the standard API response envelope."""
    return {'status': 'OK', 'result': results, 'has_more': has_more}


def make_api():
    """Create an unclosed PolySwarmAsyncAPI (must be called inside respx.mock)."""
    return PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community=COMMUNITY)


# ── Context manager / lifecycle ───────────────────────────────────────────────

@respx.mock
async def test_async_context_manager():
    """Client can be used as an async context manager."""
    respx.get(f'{BASE_URL}/search/hash/sha256').mock(
        return_value=httpx.Response(200, json=envelope_list([ARTIFACT_INSTANCE]))
    )
    async with make_api() as api:
        results = [r async for r in api.search(SHA256)]
    assert results[0].sha256 == SHA256


# ── Search & Lookup ───────────────────────────────────────────────────────────

@respx.mock
async def test_async_hash_search():
    respx.get(f'{BASE_URL}/search/hash/sha256').mock(
        return_value=httpx.Response(200, json=envelope_list([ARTIFACT_INSTANCE]))
    )
    async with make_api() as api:
        results = [r async for r in api.search(SHA256)]
    assert len(results) == 1
    assert results[0].sha256 == SHA256


@respx.mock
async def test_async_metadata_search():
    respx.get(f'{BASE_URL}/search/metadata/query').mock(
        return_value=httpx.Response(200, json=envelope_list([METADATA_RESULT]))
    )
    async with make_api() as api:
        results = [r async for r in api.search_by_metadata(f'artifact.sha256:{SHA256}')]
    assert len(results) == 1
    assert results[0].sha256 == SHA256


@respx.mock
async def test_async_exists_true():
    respx.head(f'{BASE_URL}/search/hash/sha256').mock(
        return_value=httpx.Response(200)
    )
    async with make_api() as api:
        result = await api.exists(SHA256)
    assert result is True


@respx.mock
async def test_async_exists_false():
    respx.head(f'{BASE_URL}/search/hash/sha256').mock(
        return_value=httpx.Response(404, json={'status': 'error', 'result': 'not found'})
    )
    async with make_api() as api:
        result = await api.exists(SHA256)
    assert result is False


# ── Rescans ───────────────────────────────────────────────────────────────────

@respx.mock
async def test_async_rescans():
    rescan_url = f'{BASE_URL}/consumer/submission/{COMMUNITY}/rescan/sha256/{SHA256}'
    rescan_id_url = f'{BASE_URL}/consumer/submission/{COMMUNITY}/rescan/12345678901234567'
    respx.post(rescan_url).mock(
        return_value=httpx.Response(200, json=envelope(ARTIFACT_INSTANCE))
    )
    respx.post(rescan_id_url).mock(
        return_value=httpx.Response(200, json=envelope(ARTIFACT_INSTANCE))
    )
    async with make_api() as api:
        result = await api.rescan(SHA256)
        assert result.failed is False

        result2 = await api.rescan_id(result.id)
        assert result2.failed is False


# ── IOCs ──────────────────────────────────────────────────────────────────────

@respx.mock
async def test_async_iocs_by_hash():
    respx.get(f'{BASE_URL}/ioc/sha256/{SHA256}').mock(
        return_value=httpx.Response(200, json=envelope_list([IOC_RESULT]))
    )
    async with make_api() as api:
        results = [r async for r in api.iocs_by_hash('sha256', SHA256)]
    assert len(results) == 1
    assert results[0].json['ips'] == ['1.2.3.4']
    assert results[0].json['ttps'] == ['T1081', 'T1060', 'T1069']


@respx.mock
async def test_async_search_by_ioc():
    respx.get(f'{BASE_URL}/ioc/search').mock(
        return_value=httpx.Response(200, json=envelope_list([SHA256]))
    )
    async with make_api() as api:
        results = [r async for r in api.search_by_ioc(ip='1.2.3.4')]
    assert results[0].json == SHA256


# ── Known Hosts ───────────────────────────────────────────────────────────────

@respx.mock
async def test_async_add_known_good_host():
    respx.post(f'{BASE_URL}/ioc/known').mock(
        return_value=httpx.Response(200, json=envelope(KNOWN_HOST_DOMAIN))
    )
    async with make_api() as api:
        result = await api.add_known_good_host('domain', 'test', 'polyswarm.network')
    assert result.json['type'] == 'domain'
    assert result.json['host'] == 'polyswarm.network'


@respx.mock
async def test_async_update_known_good_host():
    updated = {**KNOWN_HOST_IP, 'good': True}
    respx.put(f'{BASE_URL}/ioc/known').mock(
        return_value=httpx.Response(200, json=envelope(updated))
    )
    async with make_api() as api:
        result = await api.update_known_good_host(1, 'ip', 'test', '1.2.3.4', True)
    assert result.json['type'] == 'ip'
    assert result.json['host'] == '1.2.3.4'


@respx.mock
async def test_async_delete_known_good_host():
    respx.delete(f'{BASE_URL}/ioc/known').mock(
        return_value=httpx.Response(200, json=envelope(KNOWN_HOST_DOMAIN))
    )
    async with make_api() as api:
        result = await api.delete_known_good_host(1)
    assert result.json['type'] == 'domain'
    assert result.json['host'] == 'polyswarm.network'


@respx.mock
async def test_async_check_known_hosts():
    respx.get(f'{BASE_URL}/ioc/known').mock(
        return_value=httpx.Response(200, json=envelope_list([KNOWN_HOST_IP]))
    )
    async with make_api() as api:
        results = [r async for r in api.check_known_hosts(ips=['1.2.3.4'])]
    assert results[0].json['host'] == '1.2.3.4'
    assert results[0].json['type'] == 'ip'


# ── Sandbox Tasks ─────────────────────────────────────────────────────────────

@respx.mock
async def test_async_sandboxtask_submit():
    triage_task = {**SANDBOX_TASK, 'sandbox': 'triage', 'config': {'network_enabled': False}}
    call_count = [0]

    def dispatch(request):
        resp = SANDBOX_TASK if call_count[0] == 0 else triage_task
        call_count[0] += 1
        return httpx.Response(200, json=envelope(resp))

    respx.post(f'{BASE_URL}/sandbox/sandboxtask').mock(side_effect=dispatch)

    async with make_api() as api:
        task = await api.sandbox('24135952517649903', 'cape', 'win-10-build-19041', True)
        assert task.json['config']['network_enabled'] is True

        task2 = await api.sandbox('24135952517649903', 'triage', 'win10-build-15063', False)
        assert task2.sandbox == 'triage'
        assert task2.json['config']['network_enabled'] is False


@respx.mock
async def test_async_sandboxtask_latest():
    cape_task = {**SANDBOX_TASK, 'sha256': SHA256_ALT, 'sandbox': 'cape'}
    triage_task = {**SANDBOX_TASK, 'sha256': SHA256_ALT, 'sandbox': 'triage'}
    responses_seq = [
        httpx.Response(200, json=envelope(cape_task)),
        httpx.Response(200, json=envelope(triage_task)),
    ]
    call_idx = [0]

    def dispatch(request):
        resp = responses_seq[call_idx[0]]
        call_idx[0] += 1
        return resp

    respx.get(f'{BASE_URL}/sandbox/sandboxtask/latest').mock(side_effect=dispatch)

    async with make_api() as api:
        latest_cape = await api.sandbox_task_latest(SHA256_ALT, 'cape')
        latest_triage = await api.sandbox_task_latest(SHA256_ALT, 'triage')

    assert latest_cape.sha256 == SHA256_ALT
    assert latest_cape.sandbox == 'cape'
    assert latest_triage.sha256 == SHA256_ALT
    assert latest_triage.sandbox == 'triage'


@respx.mock
async def test_async_sandboxtask_list():
    cape_task = {**SANDBOX_TASK, 'sha256': SHA256_ALT, 'sandbox': 'cape'}
    triage_task = {**SANDBOX_TASK, 'sha256': SHA256_ALT, 'sandbox': 'triage'}

    def dispatch(request):
        url = str(request.url)
        if 'sandbox=cape' in url:
            return httpx.Response(200, json=envelope_list([cape_task]))
        elif 'sandbox=triage' in url:
            return httpx.Response(200, json=envelope_list([triage_task]))
        return httpx.Response(200, json=envelope_list([cape_task, triage_task]))

    respx.get(f'{BASE_URL}/sandbox/sandboxtask/list').mock(side_effect=dispatch)

    async with make_api() as api:
        cape_tasks = [r async for r in api.sandbox_task_list(SHA256_ALT, sandbox='cape')]
        triage_tasks = [r async for r in api.sandbox_task_list(SHA256_ALT, sandbox='triage')]
        all_tasks = [r async for r in api.sandbox_task_list(SHA256_ALT)]

    assert len(cape_tasks) == 1
    assert cape_tasks[0].sandbox == 'cape'
    assert len(triage_tasks) == 1
    assert triage_tasks[0].sandbox == 'triage'
    assert len(all_tasks) == 2
    assert {t.sandbox for t in all_tasks} == {'cape', 'triage'}


# ── YARA Rulesets ─────────────────────────────────────────────────────────────

@respx.mock
async def test_async_rules():
    ruleset_url = f'{BASE_URL}/hunt/rule'
    ruleset_list_url = f'{BASE_URL}/hunt/rule/list'
    updated = {**YARA_RULESET, 'name': 'test2', 'description': 'test'}

    respx.post(ruleset_url).mock(return_value=httpx.Response(200, json=envelope(YARA_RULESET)))
    respx.get(ruleset_list_url).mock(return_value=httpx.Response(200, json=envelope_list([YARA_RULESET])))
    respx.get(ruleset_url).mock(return_value=httpx.Response(200, json=envelope(YARA_RULESET)))
    respx.put(ruleset_url).mock(return_value=httpx.Response(200, json=envelope(updated)))
    respx.delete(ruleset_url).mock(return_value=httpx.Response(200, json=envelope(YARA_RULESET)))

    async with make_api() as api:
        rule = await api.ruleset_create('test', 'rule test {}')
        assert rule.name == 'test'
        assert rule.yara == 'rule test {}'

        rules = [r async for r in api.ruleset_list()]
        assert len(rules) == 1

        rule = await api.ruleset_get(rule.id)
        assert rule.name == 'test'

        rule = await api.ruleset_update(rule.id, name='test2', description='test')
        assert rule.name == 'test2'
        assert rule.description == 'test'

        deleted = await api.ruleset_delete(rule.id)
        assert deleted.id == YARA_RULESET['id']


# ── Historical Hunting ────────────────────────────────────────────────────────

@respx.mock
async def test_async_historical():
    hunt_url = f'{BASE_URL}/hunt/historical'

    respx.post(hunt_url).mock(return_value=httpx.Response(200, json=envelope(HISTORICAL_HUNT)))
    respx.get(hunt_url).mock(return_value=httpx.Response(200, json=envelope(HISTORICAL_HUNT)))
    respx.delete(hunt_url).mock(return_value=httpx.Response(200, json=envelope(HISTORICAL_HUNT)))

    async with make_api() as api:
        hunt = await api.historical_create('rule test {}')
        assert hunt.status == 'PENDING'

        fetched = await api.historical_get(hunt.id)
        assert fetched.id == hunt.id

        deleted = await api.historical_delete(hunt.id)
        assert deleted.id == hunt.id


@respx.mock
async def test_async_historical_results():
    hunt_id = '48011760326110718'
    results_data = [
        {
            'id': str(i),
            'historicalscan_id': hunt_id,
            'instance_id': '12345678901234567',
            'sha256': SHA256,
            'created': '2023-01-01T00:00:00',
            'rule_name': f'rule_{i}',
            'tags': [],
            'polyscore': 0.9,
            'malware_family': 'EICAR',
            'detections': {},
        }
        for i in range(6)
    ]
    respx.get(f'{BASE_URL}/hunt/historical/results/list').mock(
        return_value=httpx.Response(200, json=envelope_list(results_data))
    )
    async with make_api() as api:
        results = [r async for r in api.historical_results(hunt=hunt_id)]
    assert len(results) == 6


# ── Live Hunting ──────────────────────────────────────────────────────────────

@respx.mock
async def test_async_live():
    live_rule_url = f'{BASE_URL}/hunt/rule/live'
    live_list_url = f'{BASE_URL}/hunt/live/list'
    live_get_url = f'{BASE_URL}/hunt/live'

    active_rule = {**YARA_RULESET, 'livescan_id': '55555555555555555'}
    inactive_rule = {**YARA_RULESET, 'livescan_id': None}
    second_result = {**LIVE_HUNT_RESULT, 'id': '99999999999999999'}

    respx.post(live_rule_url).mock(return_value=httpx.Response(200, json=envelope(active_rule)))
    respx.delete(live_rule_url).mock(return_value=httpx.Response(200, json=envelope(inactive_rule)))
    respx.get(live_list_url).mock(
        return_value=httpx.Response(200, json=envelope_list([LIVE_HUNT_RESULT, second_result]))
    )
    respx.get(live_get_url).mock(return_value=httpx.Response(200, json=envelope(LIVE_HUNT_RESULT)))
    # live_feed_delete → DELETE /hunt/live/list, returns 204 → caught internally → None
    respx.delete(live_list_url).mock(return_value=httpx.Response(204))

    async with make_api() as api:
        rule = await api.live_start(rule_id='99999999999999999')
        assert rule.livescan_id == '55555555555555555'

        feed = [r async for r in api.live_feed()]
        assert len(feed) == 2

        result = await api.live_result(feed[0].id)
        assert result.download_url == 'https://s3.example.com/download'

        delete_result = await api.live_feed_delete([result.id])
        assert delete_result is None  # 204 → caught → returns None

        stopped_rule = await api.live_stop(rule_id='99999999999999999')
        assert stopped_rule.livescan_id is None


# ── Tool Metadata ─────────────────────────────────────────────────────────────

@respx.mock
async def test_async_tool_metadata():
    meta_url = f'{BASE_URL}/artifact/metadata'
    meta_list_url = f'{BASE_URL}/artifact/metadata/list'

    respx.post(meta_url).mock(return_value=httpx.Response(200, json=envelope(TOOL_METADATA_2)))
    respx.get(meta_list_url).mock(
        return_value=httpx.Response(200, json=envelope_list([TOOL_METADATA_2, TOOL_METADATA_1]))
    )

    async with make_api() as api:
        await api.tool_metadata_create(41782351738405672, 'test_tool_2', {'key2': 'value2'})
        metadata = [r async for r in api.tool_metadata_list(41782351738405672)]

    assert metadata[0].json['tool'] == 'test_tool_2'
    assert metadata[0].json['tool_metadata'] == {'key2': 'value2'}
    assert metadata[1].json['tool'] == 'test_tool_1'
    assert metadata[1].json['tool_metadata'] == {'key': 'value'}


# ── Engine Cache ──────────────────────────────────────────────────────────────

@respx.mock
async def test_async_engine_cache():
    second_engine = {**ENGINE, 'id': '9999999999999999', 'name': 'Other', 'engineType': 'arbiter'}
    respx.get(f'{BASE_URL}/microengines/list').mock(
        return_value=httpx.Response(200, json=envelope_list([ENGINE, second_engine]))
    )
    async with make_api() as api:
        await api.refresh_engine_cache()
        assert len(api._engines) == 2
        assert {e.name for e in api._engines} == {'TestEngine', 'Other'}
        # engines property always raises — use _engines directly for async clients
        with pytest.raises(AttributeError):
            _ = api.engines


@respx.mock
async def test_async_engine_cache_empty_raises():
    respx.get(f'{BASE_URL}/microengines/list').mock(
        return_value=httpx.Response(200, json=envelope_list([]))
    )
    async with make_api() as api:
        with pytest.raises(exceptions.InvalidValueException):
            await api.refresh_engine_cache()


@respx.mock
async def test_async_engine_cache_server_error_raises():
    respx.get(f'{BASE_URL}/microengines/list').mock(
        return_value=httpx.Response(500, json={'status': 'error', 'result': 'internal server error'})
    )
    async with make_api() as api:
        with pytest.raises(exceptions.RequestException):
            await api.refresh_engine_cache()


# ── Pagination ────────────────────────────────────────────────────────────────

@respx.mock
async def test_async_pagination():
    """Verify that paginated responses are consumed correctly."""
    page1 = {
        'status': 'OK',
        'result': [ARTIFACT_INSTANCE],
        'has_more': True,
        'offset': 10,
        'limit': 1,
    }
    page2 = {
        'status': 'OK',
        'result': [{**ARTIFACT_INSTANCE, 'id': '99999999999999999'}],
        'has_more': False,
        'offset': None,
        'limit': None,
    }
    responses_seq = [
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ]
    call_idx = [0]

    def dispatch(request):
        resp = responses_seq[call_idx[0]]
        call_idx[0] += 1
        return resp

    respx.get(f'{BASE_URL}/search/hash/sha256').mock(side_effect=dispatch)

    async with make_api() as api:
        results = [r async for r in api.search(SHA256)]

    assert len(results) == 2
    assert results[0].sha256 == SHA256
    assert results[1].sha256 == SHA256


# ── Error Handling ────────────────────────────────────────────────────────────

@respx.mock
async def test_async_not_found_raises():
    respx.get(f'{BASE_URL}/search/hash/sha256').mock(
        return_value=httpx.Response(404, json={'status': 'error', 'result': 'not found'})
    )
    async with make_api() as api:
        with pytest.raises(exceptions.NotFoundException):
            _ = [r async for r in api.search(SHA256)]


@respx.mock
async def test_async_rate_limit_raises():
    respx.get(f'{BASE_URL}/search/hash/sha256').mock(
        return_value=httpx.Response(429, json={'status': 'error', 'result': 'rate limited'})
    )
    async with make_api() as api:
        with pytest.raises(exceptions.UsageLimitsExceededException):
            _ = [r async for r in api.search(SHA256)]


@respx.mock
async def test_async_unprocessable_raises():
    respx.get(f'{BASE_URL}/search/hash/sha256').mock(
        return_value=httpx.Response(422, json={'status': 'error', 'result': 'unprocessable'})
    )
    async with make_api() as api:
        with pytest.raises(exceptions.FailedInstanceException):
            _ = [r async for r in api.search(SHA256)]


@respx.mock
async def test_async_no_results_raises():
    respx.get(f'{BASE_URL}/hunt/rule/list').mock(
        return_value=httpx.Response(204)
    )
    async with make_api() as api:
        with pytest.raises(exceptions.NoResultsException):
            _ = [r async for r in api.ruleset_list()]
