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
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
import pytest
import httpx
import respx
import vcr as vcr_

from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api import exceptions

from test._e2e_helpers import (
    EICAR_STRING, malicious_artifact, artifact_file, uid_ip, uid_host, uid_yara,
    assert_scanned, run_concurrently_async,
)


async def submit_and_scan(api, uid, wait=True):
    """Async counterpart of the sync ``submit_and_scan``: submit this test's
    unique EICAR artifact and, by default, wait for the scan to complete and
    assert it produced engine assertions and/or arbiter votes. ``wait=False``
    just submits (provisioning for a different flow). Returns ``(instance, sha)``.
    """
    content, sha = malicious_artifact(uid)
    with artifact_file(content) as fpath:
        instance = await api.submit(fpath)
    if wait:
        instance = await api.wait_for(instance)
        assert_scanned(instance)
    return instance, sha


async def rescan_and_scan(api, sha):
    """Async counterpart: rescan a sha (polling until the artifact is indexed),
    wait for the new scan to complete, and assert assertions/votes."""
    instance = None
    for _ in range(60):
        try:
            instance = await api.rescan(sha)
            break
        except (exceptions.NotFoundException, exceptions.NoResultsException):
            await asyncio.sleep(1)
    assert instance is not None, 'rescan should resolve once the artifact is indexed'
    instance = await api.wait_for(instance)
    assert_scanned(instance)
    return instance


@contextmanager
def _unique_artifact(content):
    """Write deterministic, test-unique bytes to a temp file and yield its
    path. The reverse IOC search keys off the ES metadata doc, which is built
    from the search row's last_scanned_instance and is overwritten by a real
    sandbox task — so a fresh sha (no sandbox task, sole instance) is required
    for a mock cape_sandbox_v2 to survive in it. Fixed content keeps the sha256
    (and the cassette) stable across runs.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = os.path.join(tmp_dir, 'artifact')
        with open(path, 'wb') as fh:
            fh.write(content)
        yield path


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


async def _poll_results(agen_factory, tries=30, delay=1):
    """Async counterpart of the sync ``_poll_results``: retry materialising an
    async generator until it yields results, riding out the cold-index latency
    a freshly-provisioned e2e shows. ``agen_factory`` returns a fresh async
    generator each call. Returns the list (possibly empty so the caller's
    assert still fires)."""
    res = []
    for _ in range(tries):
        try:
            res = [r async for r in agen_factory()]
            if res:
                return res
        except exceptions.NoResultsException:
            pass
        await asyncio.sleep(delay)
    return res


# ── Sandbox-task completion (standing in for the sandbox worker) ──────────────
# Async counterparts of the sync helpers in client_scan_test.py: with no
# cape/triage analysis VMs in e2e, replay the sandbox worker's HTTP calls to the
# sandbox service to drive a dispatched SandboxTask to SUCCEEDED (the only state
# that makes sandbox_task_latest resolve). Requires the e2e sandbox-service
# worker to be running.
SANDBOX_SERVICE_URI = 'http://sandbox:54110'


async def _post_sandbox_status(client, task_id, status):
    resp = await client.post(f'{SANDBOX_SERVICE_URI}/api/sandbox-task/',
                             json={'sandbox_task_id': task_id, 'status': status, 'errors': []})
    resp.raise_for_status()


async def _submit_sandbox_artifact(client, task_id, content, artifact_type, name,
                                   content_type='application/json',
                                   mimetype='application/json', extended_type='JSON text data'):
    if isinstance(content, (dict, list)):
        content = json.dumps(content).encode()
    resp = await client.post(
        f'{SANDBOX_SERVICE_URI}/api/sandbox-artifact/',
        json={'sandbox_task_id': task_id, 'name': name, 'artifact_type': artifact_type,
              'mimetype': mimetype, 'extended_type': extended_type,
              'sha256': hashlib.sha256(content).hexdigest(),
              'priority': 10, 'content_type': content_type})
    resp.raise_for_status()
    created = resp.json()
    (await client.put(created['upload_url'], content=content)).raise_for_status()
    (await client.patch(f'{SANDBOX_SERVICE_URI}/api/sandbox-artifact/{created["id"]}/')).raise_for_status()


async def _complete_sandbox_task(task_id, sandbox, tries=30, delay=1):
    """Drive a queued SandboxTask to SUCCEEDED without a real VM: STARTED -> a
    REPORT artifact (whose JSON the backend records as the sandbox tool's
    metadata, which lets the task complete) -> COLLECTING_DATA. triage also
    requires a RECORDING artifact first. Status codes: STARTED=1,
    COLLECTING_DATA=8. See client_scan_test.py for the full rationale.

    The opening STARTED post is retried: a just-dispatched task takes a moment to
    register on the sandbox service, so we wait (event-driven) for the service to
    accept the status instead of padding a fixed sleep before completing."""
    async with httpx.AsyncClient(timeout=60) as client:
        last = None
        for _ in range(tries):
            try:
                await _post_sandbox_status(client, task_id, 1)
                break
            except httpx.HTTPStatusError as e:
                last = e
                await asyncio.sleep(delay)
        else:
            raise last
        await _submit_sandbox_artifact(client, task_id, {'malscore': 5.0},
                                       'report', f'{sandbox}_report.json')
        if sandbox == 'triage':
            await _submit_sandbox_artifact(client, task_id, b'recording-data', 'recording',
                                           'recording.cast', content_type='application/octet-stream',
                                           mimetype='application/octet-stream', extended_type='data')
        # A real sandbox doesn't signal COLLECTING_DATA the instant it finishes
        # uploading its report — there's a natural gap. That gap is what lets the
        # backend's report-create task commit SandboxTask.artifact_metadata_id and
        # its delayed COLLECTING_DATA->SUCCEEDED transition fire (the replica-lag
        # safety net dispatched with eta=+DELAYED_IN_REPLICA_RETRY_LONG_DELAY — 1s
        # in e2e, 30s in prod). Posting status=8 back-to-back races that commit
        # under load (the report-create and the status transition land on the same
        # ai_sandbox_done queue with no ordering), so the search row may never be
        # written. The wait restores the real-world sequencing: by the time status=8
        # arrives the task is already SUCCEEDED, and status=8 is a no-op backstop.
        await asyncio.sleep(2)
        await _post_sandbox_status(client, task_id, 8)


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

# TESTS_VCR=off bypasses VCR entirely: `@vcr.use_cassette()` becomes a no-op so
# the suite runs against the live stack with no replay/record. Used by the e2e
# CI command. Default (unset/on) keeps the normal record-once/replay behaviour.
if os.getenv('TESTS_VCR', 'on').lower() == 'off':
    vcr.use_cassette = lambda *_a, **_k: (lambda _fn: _fn)


# ── Shared constants ──────────────────────────────────────────────────────────
# SHA256 is the EICAR fixture's sha, still used by the respx unit tests below
# (which mock fixed responses); the live data-creating tests derive their own
# unique shas via malicious_artifact(uid).

SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'


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
            uri=f'http://ai:9696/{self.api_version}',
            community=community,
        )

    # ── Submission ────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_submission(self, uid):
        # Canonical "a file goes in and gets scanned" path (async): submit_and_scan
        # waits for completion and asserts assertions/votes landed.
        async with self._api() as api:
            instance, sha = await submit_and_scan(api, uid)
        assert instance.sha256 == sha

    # ── Rescans ───────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_rescans(self, uid):
        async with self._api() as api:
            # Submit this test's own unique artifact, then rescan by hash and by
            # id; rescan_and_scan confirms each rescan actually re-runs the scan.
            _, sha = await submit_and_scan(api, uid, wait=False)
            rescanned = await rescan_and_scan(api, sha)
            assert_scanned(await api.wait_for(await api.rescan_id(rescanned.id)))

    # ── Search ────────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_hash_search(self, uid):
        async with self._api() as api:
            _, sha = await submit_and_scan(api, uid)
            result = await _poll_results(lambda: api.search(sha), tries=60)
        assert result and result[0].sha256 == sha

    @vcr.use_cassette()
    async def test_async_metadata_search(self, uid):
        async with self._api() as api:
            _, sha = await submit_and_scan(api, uid)
            result = await _poll_results(
                lambda: api.search_by_metadata(f'artifact.sha256:{sha}'), tries=90)
        assert result and result[0].sha256 == sha

    # ── IOCs ──────────────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_iocs_by_hash(self, uid):
        # Self-contained: the forward view needs a SandboxTaskSearchHash row for
        # the sha, created when a sandbox task is processed — so dispatch +
        # complete one for our own artifact, then attach the mock cape_sandbox_v2
        # IOC AFTER completion (so the task's report can't overwrite it). See the
        # sync test_iocs_by_hash for the full rationale.
        ioc_ip = uid_ip(uid)
        async with self._api() as api:
            instance, sha = await submit_and_scan(api, uid, wait=False)
            cape = await _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True)
            await _complete_sandbox_task(cape.id, 'cape')
            # Wait until the task is fully processed before attaching our mock IOC,
            # so ours is the last write and isn't clobbered under load.
            await _wait_for_sandbox_task(lambda: api.sandbox_task_latest(sha, 'cape'))
            await api.tool_metadata_create(
                instance.id, 'cape_sandbox_v2', {
                    'extracted_c2_ips': [ioc_ip],
                    'extracted_c2_urls': ['www.mock-ioc.test'],
                    'ttp': ['T1081', 'T1060', 'T1069'],
                })
            ips, ttps = [], []
            for _ in range(90):
                iocs = [r async for r in api.iocs_by_hash('sha256', sha)]
                if iocs:
                    ips = iocs[0].json.get('ips') or []
                    ttps = iocs[0].json.get('ttps') or []
                    if ioc_ip in ips:
                        break
                await asyncio.sleep(1)
        assert ioc_ip in ips
        assert set(['T1081', 'T1060', 'T1069']) <= set(ttps)

    @vcr.use_cassette()
    async def test_async_search_by_ioc(self, uid):
        # uid-unique IP -> the reverse ES search matches ONLY this test's one
        # artifact (single page), so it can't hang on multi-page accumulation the
        # way the old shared 9.42.0.x IPs did; iterate-and-break on our sha rather
        # than materialising the feed. See the sync test_search_by_ioc for the
        # cape_sandbox_v2 / fresh-sha rationale.
        ioc_ip = uid_ip(uid)
        async with self._api() as api:
            instance, sha = await submit_and_scan(api, uid, wait=False)
            await api.tool_metadata_create(
                instance.id, 'cape_sandbox_v2', {
                    'extracted_c2_ips': [ioc_ip],
                    'extracted_c2_urls': ['www.mock-ioc.test'],
                    'ttp': ['T1081', 'T1060', 'T1069'],
                })
            # persist_external_metadata (Celery) + the 5s ES flush; poll until
            # OUR sha resolves.
            # Unique IP => single-page result, so materialising is bounded; the
            # SDK's own pagination cap (see _consume_results) guards any caller
            # against a misbehaving multi-page server.
            found = False
            for _ in range(90):
                try:
                    iocs = [item.json async for item in api.search_by_ioc(ip=ioc_ip)]
                    if sha in iocs:
                        found = True
                        break
                except exceptions.NoResultsException:
                    pass
                await asyncio.sleep(1)
        assert found, 'search_by_ioc should surface our sha for our unique IP'

    # ── Known Hosts ───────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_add_known_good_host(self, uid):
        async with self._api() as api:
            host = uid_host(uid)
            known = await api.add_known_good_host('domain', 'test', host)
            assert known.json['type'] == 'domain'
            assert known.json['host'] == host

    @vcr.use_cassette()
    async def test_async_update_known_good_host(self, uid):
        async with self._api() as api:
            host = uid_host(uid)
            ip = uid_ip(uid)
            added = await api.add_known_good_host('domain', 'test', host)
            known = await api.update_known_good_host(
                added.json['id'], 'ip', 'test', ip, True,
            )
            assert known.json['type'] == 'ip'
            assert known.json['host'] == ip

    @vcr.use_cassette()
    async def test_async_delete_known_good_host(self, uid):
        async with self._api() as api:
            ip = uid_ip(uid)
            added = await api.add_known_good_host('ip', 'test', ip)
            known = await api.delete_known_good_host(added.json['id'])
        assert known.json['type'] == 'ip'
        assert known.json['host'] == ip

    @vcr.use_cassette()
    async def test_async_check_known_host(self, uid):
        async with self._api() as api:
            ip = uid_ip(uid)
            added = await api.add_known_good_host('ip', 'test', ip)
            known = [r async for r in api.check_known_hosts(ips=[ip])]
            assert any(h.json['host'] == ip and h.json['type'] == 'ip' for h in known)

    @vcr.use_cassette()
    async def test_async_known_good_lifecycle(self, uid):
        # Full create → extend → get → delete round-trip against the real
        # /known-good endpoint (internal-only; the e2e dev key is on the
        # internal plan). The sha comes from this test's unique EICAR variant
        # (same convention as the scan tests) => the create branch runs first;
        # the trailing delete keeps live re-runs deterministic.
        async with self._api() as api:
            _content, sha = malicious_artifact(uid)
            created = await api.known_good_create(
                sha256=sha, source='nsrl', filename='kg-sample.exe',
                metadata={'product': 'Example', 'version': '1.0'})
            assert created.sha256 == sha
            assert created.sources == ['nsrl']
            assert created.artifact_instance_id
            # The refusal on the async transport, against the real server. It reaches the
            # 404 arm by a different route than the sync parse path — the streaming
            # download raises from `aread()` → `_raise_for_status` — so both transports
            # need the live assertion, not just the fabricated respx one.
            with tempfile.TemporaryDirectory() as out_dir:
                with pytest.raises(exceptions.KnownGoodWithheldException) as ei:
                    await api.download(out_dir, sha)
                # A refused download leaves nothing behind — see the sync twin.
                assert os.listdir(out_dir) == []
            assert ei.value.sources == ['nsrl']
            # The existence probe on the async transport — see the sync twin for why these two
            # lines are the fleet's only live guard on a frozen status contract. Catalogued via
            # the CRUD: present plain (the reference instance is a real record), absent under
            # require_scan (nothing was ever scanned for it).
            # Polled — see the sync twin: known_good_create goes through the same async
            # search-row write, so an unpolled assertion flakes under TESTS_VCR=off.
            present = False
            for _ in range(30):
                present = await api.exists(sha, hash_type='sha256')
                if present:
                    break
                await asyncio.sleep(1)
            assert present is True
            assert await api.exists(sha, hash_type='sha256', require_scan=True) is False
            # A second feed flagging the same sha extends the same entry (no new row).
            extended = await api.known_good_create(sha256=sha, source='commercial')
            assert extended.id == created.id
            assert sorted(extended.sources) == ['commercial', 'nsrl']
            got = await api.known_good_get(sha256=sha)
            assert got.sha256 == sha
            assert sorted(got.sources) == ['commercial', 'nsrl']
            # Both feeds name themselves in the refusal once the entry is extended.
            with tempfile.TemporaryDirectory() as out_dir:
                with pytest.raises(exceptions.KnownGoodWithheldException) as ei:
                    await api.download(out_dir, sha)
            assert sorted(ei.value.sources) == ['commercial', 'nsrl']
            deleted = await api.known_good_delete(sha256=sha)
            assert deleted.sha256 == sha
            # A 404 with no known-good code must stay the BASE class — the subclass would
            # satisfy this raises() too, so the plain-miss half of the mapping needs its own
            # assertion against the real server.
            with pytest.raises(exceptions.NotFoundException) as ei:
                await api.known_good_get(sha256=sha)
            assert not isinstance(ei.value, exceptions.KnownGoodWithheldException)

    @vcr.use_cassette()
    async def test_async_hash_existence_probe_against_the_real_server(self, uid):
        # Async twin of the sync probe test — see it for why this is asserted against the
        # server rather than a mock: the probe is a HEAD with no result parser, so it has no
        # error channel and a server-side widening of "found" is a silent wrong boolean.
        async with self._api() as api:
            # Two distinct variants: one submitted below, one nothing ever submits — which is
            # what keeps this re-runnable against a reused stack.
            _absent_content, absent_sha = malicious_artifact(f'{uid}-never-submitted')
            _content, sha = malicious_artifact(uid)
            assert absent_sha != sha

            # ABSENT -> 204 -> False, in both forms.
            assert await api.exists(absent_sha, hash_type='sha256') is False
            assert await api.exists(absent_sha, hash_type='sha256', require_scan=True) is False

            # PRESENT: submit it and let the scan settle.
            instance, submitted_sha = await submit_and_scan(api, uid)
            assert submitted_sha == sha
            assert instance.window_closed

            # Poll the NARROWER form — require_scan can only become true at the same time or
            # later than the plain form, so polling the broad one and asserting the strict one
            # is a race. See the sync twin.
            scanned = False
            for _ in range(30):
                scanned = await api.exists(sha, hash_type='sha256', require_scan=True)
                if scanned:
                    break
                await asyncio.sleep(1)
            assert scanned is True
            assert await api.exists(sha, hash_type='sha256') is True

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
    async def test_async_sandboxtask_submit(self, uid):
        async with self._api() as api:
            instance, _ = await submit_and_scan(api, uid, wait=False)
            task = await _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True)
            assert task.json['config']['network_enabled'] is True
            task = await _dispatch_sandbox(api, instance.id, 'triage', 'windows11-21h2-x64', False)
            assert task.sandbox == 'triage'
            assert task.json['config']['network_enabled'] is False

    @vcr.use_cassette()
    async def test_async_sandboxtask_latest(self, uid):
        async with self._api() as api:
            instance, sha = await submit_and_scan(api, uid, wait=False)
            cape = await _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True)
            triage = await _dispatch_sandbox(api, instance.id, 'triage', 'windows11-21h2-x64', False)

            # No cape/triage VMs in e2e — drive each task to SUCCEEDED by replaying
            # the sandbox worker's HTTP calls. Completing a task creates its
            # SandboxTaskSearchHash row, which sandbox_task_latest reads.
            await _complete_sandbox_task(cape.id, 'cape')
            await _complete_sandbox_task(triage.id, 'triage')

            latest_cape = await _wait_for_sandbox_task(
                lambda: api.sandbox_task_latest(sha, 'cape'),
            )
            latest_triage = await _wait_for_sandbox_task(
                lambda: api.sandbox_task_latest(sha, 'triage'),
            )
        assert latest_cape.sha256 == sha
        assert latest_cape.sandbox == 'cape'
        assert latest_triage.sha256 == sha
        assert latest_triage.sandbox == 'triage'

    @vcr.use_cassette()
    async def test_async_sandboxtask_list(self, uid):
        async with self._api() as api:
            instance, sha = await submit_and_scan(api, uid, wait=False)
            # Dispatch cape + triage concurrently (distinct sandbox slugs, independent).
            await run_concurrently_async([
                _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True),
                _dispatch_sandbox(api, instance.id, 'triage', 'windows11-21h2-x64', False),
            ])

            # Poll until the SandboxTaskSearchHash index sees both tasks.
            for _ in range(30):
                try:
                    all_tasks = [r async for r in api.sandbox_task_list(sha)]
                    if {'cape', 'triage'} <= {t.sandbox for t in all_tasks}:
                        break
                except exceptions.NoResultsException:
                    pass
                await asyncio.sleep(1)

            cape_tasks = [r async for r in api.sandbox_task_list(sha, sandbox='cape')]
            triage_tasks = [r async for r in api.sandbox_task_list(sha, sandbox='triage')]
            all_tasks = [r async for r in api.sandbox_task_list(sha)]
        assert len(cape_tasks) >= 1
        assert all(t.sandbox == 'cape' for t in cape_tasks)
        assert len(triage_tasks) >= 1
        assert all(t.sandbox == 'triage' for t in triage_tasks)
        assert {'cape', 'triage'} <= {t.sandbox for t in all_tasks}

    # ── Sample (aggregated view) ──────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_sample(self, uid):
        # Self-contained: submit our own artifact, drive cape + triage to
        # COMPLETED, then poll the sample until it auto-triggers the LLM report.
        # The report can't COMPLETE in e2e (no OPENAI_API_KEY), and requested_id
        # stays null until a report renders, so we key off requested_status
        # (NOT_TRIGGERED/WAITING_FOR_OTHER_TASKS -> PENDING). See sync test_sample.
        async with self._api() as api:
            instance, sha = await submit_and_scan(api, uid, wait=False)
            cape = await _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True)
            triage = await _dispatch_sandbox(api, instance.id, 'triage', 'windows11-21h2-x64', False)
            await _complete_sandbox_task(cape.id, 'cape')
            await _complete_sandbox_task(triage.id, 'triage')

            # Poll until BOTH sandbox deps read COMPLETED *and* the LLM report was
            # auto-triggered — the exact postconditions asserted below, not a proxy.
            # Keying off llm_report alone raced: the report auto-triggers on *any
            # one* completed dep (the scan or a single sandbox), so a response can
            # show it triggered while sandbox_cape still projects NOT_TRIGGERED (the
            # per-task projection doesn't update atomically). This test drives both
            # sandboxes to SUCCEEDED, so both projections reach COMPLETED; waiting on
            # them directly closes the window. See sync test_sample.
            _PRE_TRIGGER = {None, 'NOT_TRIGGERED', 'WAITING_FOR_OTHER_TASKS'}
            result = await api.sample(sha)
            for _ in range(90):
                result = await api.sample(sha)
                tasks = result.tasks or {}
                sandboxes_completed = all(
                    tasks.get(f'sandbox_{s}', {}).get('requested_status') == 'COMPLETED'
                    for s in ('cape', 'triage')
                )
                llm_triggered = tasks.get('llm_report', {}).get('requested_status') not in _PRE_TRIGGER
                if sandboxes_completed and llm_triggered:
                    break
                await asyncio.sleep(1)
        assert isinstance(result.artifact_instance, dict)
        assert isinstance(result.sandbox, dict)
        assert {'cape', 'triage'} <= set(result.sandbox.keys())
        assert isinstance(result.tasks, dict)
        assert result.tasks['sandbox_cape']['requested_status'] == 'COMPLETED'
        assert result.tasks['sandbox_triage']['requested_status'] == 'COMPLETED'
        assert result.tasks['llm_report']['requested_status'] not in _PRE_TRIGGER

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
    async def test_async_historical(self, uid):
        async with self._api() as api:
            historical_hunt = await api.historical_create(uid_yara(uid))
            assert historical_hunt.status == 'PENDING'

            get_historical_hunt = await api.historical_get(historical_hunt.id)
            assert historical_hunt.id == get_historical_hunt.id

            deleted_historical_hunt = await api.historical_delete(get_historical_hunt.id)
            assert historical_hunt.id == deleted_historical_hunt.id

    @vcr.use_cassette()
    async def test_async_list_historical(self, uid):
        async with self._api() as api:
            yara_content = uid_yara(uid)
            historical_ids = []
            for _ in range(5):
                historical = await api.historical_create(yara_content)
                historical_ids.append(historical.id)
            listed_ids = {h.id async for h in api.historical_list()}
            assert set(historical_ids) <= listed_ids

    @vcr.use_cassette()
    async def test_async_historical_results(self, uid):
        async with self._api() as api:
            # Self-contained: our own unique hunt. The e2e historical scan is
            # asynchronous and doesn't reliably populate results within a test
            # window, so accept an empty set (end-to-end YARA matching is covered
            # by the live hunt in test_async_live); every entry is shape-checked.
            hunt = await api.historical_create(uid_yara(uid))
            try:
                async for entry in api.historical_results(hunt=hunt.id):
                    assert entry.sha256
                    assert entry.rule_name
            except (exceptions.NotFoundException, exceptions.NoResultsException):
                pass

    # ── Live Hunting ──────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_live(self, uid):
        async with self._api() as api:
            # Per-test ruleset whose YARA matches only this run's artifact, so
            # the live hunt surfaces just this submission (no cross-test feed).
            content, _ = malicious_artifact(uid)
            rule = await api.ruleset_create(f'sdk-{uid}', uid_yara(uid))
            rule_id = rule.id
            try:
                await api.live_start(rule_id=rule_id)
                # livescan_id is assigned asynchronously after engines pick up
                # the rule; the live_start response itself returns None.
                for _ in range(30):
                    await asyncio.sleep(1)
                    rule = await api.ruleset_get(rule_id)
                    if rule.livescan_id:
                        break
                assert rule.livescan_id, 'livescan_id should land after live_start'
                my_livescan_id = rule.livescan_id

                with artifact_file(content) as fpath:
                    await api.submit(fpath)

                # Bound the feed to this run's window (``since`` in seconds) so
                # the cassette stays small regardless of accumulated global feed
                # history; match on our livescan_id to anchor to this submission.
                my_results = []
                for _ in range(30):
                    await asyncio.sleep(1)
                    try:
                        feed = [r async for r in api.live_feed(since=600)]
                    except exceptions.NoResultsException:
                        continue
                    my_results = [
                        e for e in feed
                        if str(getattr(e, 'livescan_id', None)) == str(my_livescan_id)
                    ]
                    if my_results:
                        break
                assert my_results, 'live_feed should surface a hit for the submitted EICAR'
                result_id = my_results[0].id

                result = await api.live_result(result_id)
                for _ in range(20):
                    if result.download_url:
                        break
                    await asyncio.sleep(1)
                    result = await api.live_result(result_id)
                assert result.download_url

                # The list/detail split, pinned against the real server rather than prose.
                # The pure-unit tests exercise dict.get and would pass identically if the
                # server never grew the field; only a cassette shows what it actually sent.
                assert result.matched_strings, 'detail route should carry the yara evidence'
                assert my_results[0].matched_strings is None, \
                    'list rows do not carry the evidence -- it is a per-row blob fetch'
                # On .json, not the attribute: `is None` cannot tell a served null from an
                # absent key, and what needs pinning is that the server SENDS this field.
                assert 'matched_strings_dropped' in result.json, \
                    'server must serve the withheld-count field'
                assert result.matched_strings_dropped is None, \
                    'nothing withheld for a match this small'

                await api.live_feed_delete([result_id])
                with pytest.raises(exceptions.NotFoundException):
                    await api.live_result(result_id)

                await api.live_stop(rule_id=rule_id)
                stopped = await api.ruleset_get(rule_id)
                assert stopped.livescan_id is None
            finally:
                # Always tear the hunt down (see sync test_live): a leftover
                # active hunt captures every later EICAR submit and is what
                # accumulated 700+ stale feed rows. live_stop precedes delete.
                try:
                    await api.live_stop(rule_id=rule_id)
                except exceptions.PolyswarmException:
                    pass
                try:
                    await api.ruleset_delete(rule_id)
                except exceptions.PolyswarmException:
                    pass

    # ── Tool Metadata ─────────────────────────────────────────────────────────

    @vcr.use_cassette()
    async def test_async_tool_metadata(self, uid):
        async with self._api() as api:
            instance, _ = await submit_and_scan(api, uid, wait=False)
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
    async def test_async_download_to_handle(self, uid):
        import tempfile, os
        content, sha = malicious_artifact(uid)
        async with self._api() as api:
            with artifact_file(content) as fpath:
                await api.submit(fpath)
            with tempfile.TemporaryDirectory() as tmp_dir:
                out = os.path.join(tmp_dir, 'out')
                for _ in range(60):
                    try:
                        with open(out, 'wb') as fh:
                            await api.download_to_handle(sha, fh)
                        break
                    except (exceptions.NotFoundException, exceptions.NoResultsException):
                        await asyncio.sleep(1)
                with open(out, 'rb') as fh:
                    assert fh.read() == content


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
        engines = await api.engines()
        assert {'Intezer', 'IRIS-H', 'Test', 'K7-Arbiter'} == {e.name for e in engines}
        assert {'K7-Arbiter'} == {e.name for e in engines if e.is_arbiter}
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

BASE_URL = 'http://ai:9696/v3'
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
async def test_async_upload_file_retries_then_reraises_when_exhausted():
    """``upload_file`` retries up to ``attempts`` times on HTTP/transport errors
    and re-raises the last one when retries are exhausted — the failure path the
    happy-path/auth-strip tests don't exercise."""
    import io as _io
    presigned = 'https://s3.example.com/upload-target?sig=abc'
    put_route = respx.put(presigned).mock(return_value=httpx.Response(500))
    api = PolySwarmAsyncAPI('secret-key-1234', uri=BASE_URL, community='gamma')
    try:
        with pytest.raises(httpx.HTTPStatusError):
            await api.session.upload_file(presigned, _io.BytesIO(b'data'), attempts=3)
    finally:
        await api.aclose()
    assert put_route.call_count == 3      # all attempts burned before re-raising


async def test_async_upload_file_rejects_nonpositive_attempts():
    """``attempts < 1`` is rejected up front: otherwise the retry loop never runs
    and the final ``raise last_exc`` would be ``raise None`` (TypeError)."""
    import io as _io
    api = PolySwarmAsyncAPI('secret-key-1234', uri=BASE_URL, community='gamma')
    try:
        with pytest.raises(exceptions.InvalidValueException):
            await api.session.upload_file(
                'https://s3.example.com/x', _io.BytesIO(b'd'), attempts=0)
    finally:
        await api.aclose()


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
async def test_async_download_204_raises_no_results():
    """A 204 on a download means "no matching artifact" (the request worked but
    returned nothing), so the streaming path must raise ``NoResultsException``
    rather than write out a successful *empty* file — mirroring the shared
    ``parse_response`` 204 rule that the streaming path otherwise bypasses."""
    import tempfile, os

    respx.get(f'{BASE_URL}/consumer/download/sha256/{SHA256}').mock(
        return_value=httpx.Response(204))

    api = PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma')
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            with pytest.raises(exceptions.NoResultsException):
                await api.download(tmp_dir, SHA256)
            # No empty artifact file should have been left behind.
            assert os.listdir(tmp_dir) == []
    finally:
        await api.aclose()


@respx.mock
async def test_async_download_streams_in_chunks(monkeypatch):
    """Regression guard for the streaming-download fix: the body is consumed via
    the streaming API (``iter_bytes``) straight into the destination, not read
    whole and then chunked over a buffer. Shrink ``DOWNLOAD_CHUNK_SIZE`` and
    assert the handle received the body in multiple bounded writes — a single
    write would mean the body was materialised first (the 4.0 buffering
    regression this fix reverses)."""
    import io as _io
    import polyswarm_api.settings as _settings
    monkeypatch.setattr(_settings, 'DOWNLOAD_CHUNK_SIZE', 4)

    body = b'0123456789abcdef'  # 16 bytes -> 4 chunks at chunk size 4
    respx.get(f'{BASE_URL}/consumer/download/sha256/{SHA256}').mock(
        return_value=httpx.Response(200, content=body))

    writes = []

    class _CountingHandle(_io.BytesIO):
        def write(self, b):
            writes.append(bytes(b))
            return super().write(b)

    fh = _CountingHandle()
    api = PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma')
    try:
        await api.download_to_handle(SHA256, fh)
    finally:
        await api.aclose()

    assert fh.getvalue() == body
    assert len(writes) >= 2, f'expected chunked writes, got {len(writes)}: {writes}'
    assert all(len(w) <= 4 for w in writes), writes


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


# ── Pagination (no cassette) — multi-page walk + runaway safety bound ──────────

def _instance(sha):
    return {
        'sha256': sha, 'md5': '44d88612fea8a8f36de82e1278abb02f',
        'sha1': '3395856ce81f2b7382dee72602f798b642f14d8',
        'mimetype': 'text/plain', 'size': 68, 'extended_type': '',
        'first_seen': '2020-01-01T00:00:00', 'upload_url': '', 'assertions': [],
        'votes': [], 'failed': False, 'window_closed': True, 'polyscore': 0.0,
        'result': None, 'metadata': [],
    }


@respx.mock
async def test_async_pagination_walks_all_pages():
    """``_consume_results`` follows ``has_more`` + the returned offset to the
    next page until the server says it's done — the multi-page path the recorded
    IOC/search cassettes (all single-page) never exercise.
    """
    route = respx.get(f'{BASE_URL}/search/hash/sha256').mock(side_effect=[
        httpx.Response(200, json={
            'status': 'OK', 'has_more': True, 'offset': 'cursor-1',
            'result': [_instance(SHA256), _instance(SHA256)],
        }),
        httpx.Response(200, json={
            'status': 'OK', 'has_more': False,
            'result': [_instance(SHA256)],
        }),
    ])
    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        results = [r async for r in api.search(SHA256)]
    assert len(results) == 3            # both pages consumed
    assert route.call_count == 2        # advanced to page 2 via the offset
    assert 'cursor-1' in str(route.calls[-1].request.url)  # offset echoed back


@respx.mock
async def test_async_pagination_bounded_when_cursor_never_advances():
    """A pathological server that leaves ``has_more`` set with a non-advancing
    offset must NOT loop the client forever — the offset-repeat guard in
    ``_consume_results`` stops it. (This is the failure mode that, with the old
    shared-IP reverse-IOC search, hung CI.)
    """
    respx.get(f'{BASE_URL}/search/hash/sha256').mock(return_value=httpx.Response(
        200, json={
            'status': 'OK', 'has_more': True, 'offset': 'STUCK',
            'result': [_instance(SHA256)],
        },
    ))
    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        results = [r async for r in api.search(SHA256)]
    # Terminated with a bounded set instead of hanging.
    assert 0 < len(results) <= 5


@respx.mock
async def test_async_pagination_bounded_when_cursor_absent():
    """``has_more: true`` with **no** ``offset`` key (the live-feed envelope shape)
    leaves the client no cursor to advance — re-sending ``offset=None`` is
    byte-identical to the page just fetched, so ``_consume_results`` must stop
    after the current page rather than re-fetch it up to ``_MAX_PAGES``. This is
    the None/absent-cursor path the non-None stuck-cursor guard test above misses.
    """
    route = respx.get(f'{BASE_URL}/search/hash/sha256').mock(return_value=httpx.Response(
        200, json={
            'status': 'OK', 'has_more': True,   # deliberately no 'offset' key
            'result': [_instance(SHA256)],
        },
    ))
    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        results = [r async for r in api.search(SHA256)]
    assert len(results) == 1          # only page 1's item
    assert route.call_count == 1      # did NOT re-fetch the identical page


@respx.mock
async def test_async_pagination_resends_original_request_body():
    """``_next_page`` must re-send the *original* request body on page 2, not the
    parsed page-1 response. The send body lives in ``request.input_json`` and
    ``request.json`` holds the *response* after execution, so ``_next_page`` clones
    from ``input_json``. No shipped endpoint paginates with a JSON body (search uses
    query params), so this drives a hand-built body-carrying GET straight through
    the client's ``_paginate`` to exercise that.
    """
    from polyswarm_api.core import PolyswarmRequest
    from polyswarm_api import resources

    url = f'{BASE_URL}/search/hash/sha256'
    original_body = {'q': 'original-query', 'marker': 'keep-me'}
    route = respx.get(url).mock(side_effect=[
        httpx.Response(200, json={
            'status': 'OK', 'has_more': True, 'offset': 'cursor-2', 'limit': 50,
            'result': [_instance(SHA256)],
        }),
        httpx.Response(200, json={
            'status': 'OK', 'has_more': False,
            'result': [_instance(SHA256)],
        }),
    ])
    api = PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma')
    try:
        req = PolyswarmRequest(
            api=api, method='GET', url=url,
            json=dict(original_body), result_parser=resources.ArtifactInstance,
        )
        results = [r async for r in api._paginate(req)]
    finally:
        await api.aclose()
    assert len(results) == 2            # both pages consumed
    assert route.call_count == 2        # advanced to page 2
    page2 = route.calls[-1].request
    assert json.loads(page2.content) == original_body   # original body, not page-1 result
    assert 'cursor-2' in str(page2.url)                  # advanced via the returned cursor


# ── Sandbox finalize request shape (no cassette) — guards the finalize regression ──

def _sandbox_task_payload(task_id, community='gamma',
                          upload_url='https://s3.example.com/sb-upload?sig=x'):
    """Minimal valid SandboxTask response body for respx mocks."""
    return {
        'id': task_id, 'community': community, 'sandbox': 'cape',
        'created': '2026-01-01T00:00:00', 'expiration': '2026-01-02T00:00:00',
        'status': 'PENDING', 'account_number': 1, 'team_account_number': None,
        'instance_id': '999', 'sha256': '0' * 64, 'report': None,
        'upload_url': upload_url, 'config': {'network_enabled': True},
        'artifact': None, 'sandbox_artifacts': [],
    }


@respx.mock
async def test_async_sandbox_file_finalize_request_shape():
    """``sandbox_file`` finalize must PUT ``id=<task>`` in the query string and
    ``{"community": ...}`` in the body — the 3.x ``SandboxTask.update_file``
    contract. Regression guard for the dropped ``community`` body.
    """
    import io as _io
    upload_url = 'https://s3.example.com/sb-file-upload?sig=abc'
    respx.post(f'{BASE_URL}/sandbox/sandboxtask/instance').mock(
        return_value=httpx.Response(200, json={
            'status': 'OK', 'result': _sandbox_task_payload('555', upload_url=upload_url)}))
    respx.put(upload_url).mock(return_value=httpx.Response(200))
    finalize = respx.put(f'{BASE_URL}/sandbox/sandboxtask/instance').mock(
        return_value=httpx.Response(200, json={
            'status': 'OK', 'result': _sandbox_task_payload('555')}))

    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        await api.sandbox_file(_io.BytesIO(b'sample-bytes'), 'cape', 'win-10-build-19041')

    req = finalize.calls[-1].request
    assert req.url.params.get('id') == '555'
    assert 'sandbox_task_id' not in req.url.params
    assert json.loads(req.content) == {'community': 'gamma'}


@respx.mock
async def test_async_sandbox_url_create_and_finalize_request_shape():
    """``sandbox_url`` must (a) carry ``community`` in the create body and
    (b) finalize with ``id=<task>`` (not ``sandbox_task_id``) plus a
    ``{"community": ...}`` body — same contract as ``sandbox_file``. Guards both
    the create-body omission and the finalize param-name regression.
    """
    upload_url = 'https://s3.example.com/sb-url-upload?sig=abc'
    create = respx.post(f'{BASE_URL}/sandbox/sandboxtask/instance').mock(
        return_value=httpx.Response(200, json={
            'status': 'OK', 'result': _sandbox_task_payload('777', upload_url=upload_url)}))
    respx.put(upload_url).mock(return_value=httpx.Response(200))
    finalize = respx.put(f'{BASE_URL}/sandbox/sandboxtask/instance').mock(
        return_value=httpx.Response(200, json={
            'status': 'OK', 'result': _sandbox_task_payload('777')}))

    async with PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community='gamma') as api:
        await api.sandbox_url('http://malicious.example', 'cape', 'win-10-build-19041')

    create_body = json.loads(create.calls[-1].request.content)
    assert create_body.get('community') == 'gamma'

    req = finalize.calls[-1].request
    assert req.url.params.get('id') == '777'
    assert 'sandbox_task_id' not in req.url.params
    assert json.loads(req.content) == {'community': 'gamma'}
