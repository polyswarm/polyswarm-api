import hashlib
import json
import os
import shutil
import tempfile
import time
import httpx
import respx
import pytest
import tarfile
from contextlib import contextmanager

import vcr as vcr_

from polyswarm_api.api import PolyswarmAPI
from polyswarm_api import core
from polyswarm_api import exceptions

from test._e2e_helpers import (
    EICAR_STRING, malicious_artifact, artifact_file, uid_ip, uid_host, uid_yara,
    assert_scanned, run_concurrently,
)

from unittest import TestCase, mock


def submit_and_scan(api, uid, wait=True):
    """Submit this test's unique EICAR artifact.

    By default (``wait=True``) wait for the scan to complete and assert it
    produced engine assertions and/or arbiter votes — the canonical "a file goes
    in and gets scanned" path. With ``wait=False`` just submit, for tests that
    only need an instance to drive a different flow (sandbox / IOC / hunt /
    stream). Returns ``(instance, sha)`` — ``instance`` is the completed,
    window-closed scan result when ``wait=True``, else the submit response.
    """
    content, sha = malicious_artifact(uid)
    with artifact_file(content) as fpath:
        instance = api.submit(fpath)
    if wait:
        instance = api.wait_for(instance)
        assert_scanned(instance)
    return instance, sha


def rescan_and_scan(api, sha):
    """Rescan an existing sha (polling until the artifact is indexed), wait for
    the new scan to complete, and assert it produced assertions/votes."""
    instance = None
    for _ in range(60):
        try:
            instance = api.rescan(sha)
            break
        except (exceptions.NotFoundException, exceptions.NoResultsException):
            time.sleep(1)
    assert instance is not None, 'rescan should resolve once the artifact is indexed'
    instance = api.wait_for(instance)
    assert_scanned(instance)
    return instance


vcr = vcr_.VCR(cassette_library_dir='test/vcr',
               path_transformer=vcr_.VCR.ensure_suffix('.vcr'))

# TESTS_VCR=off bypasses VCR entirely: `@vcr.use_cassette()` becomes a no-op so
# the suite runs against the live stack with no replay/record. Used by the e2e
# CI command. Default (unset/on) keeps the normal record-once/replay behaviour.
if os.getenv('TESTS_VCR', 'on').lower() == 'off':
    vcr.use_cassette = lambda *_a, **_k: (lambda _fn: _fn)


@contextmanager
def temp_dir(files_dict):
    with tempfile.TemporaryDirectory() as tmp_dir:
        files = []
        for file_name, file_content in files_dict.items():
            mode = 'w' if isinstance(file_content, str) else 'wb'
            file_path = os.path.join(tmp_dir, file_name)
            open(file_path, mode=mode).write(file_content)
            files.append(file_path)
        yield tmp_dir, files


def _dispatch_sandbox(api, instance_id, sandbox_slug, vm_slug, network_enabled,
                      tries=30, delay=1):
    """Submit follow-on storage upload + finalize finishes asynchronously on
    the e2e — ``sandbox`` 422s with "Could not find storage path for instance"
    until the storage pointer is committed. Retry briefly to ride out the lag.
    """
    last = None
    for _ in range(tries):
        try:
            return api.sandbox(instance_id, sandbox_slug, vm_slug, network_enabled)
        except exceptions.FailedInstanceException as e:
            last = e
            time.sleep(delay)
    raise last


def _wait_for_sandbox_task(api, fn, *args, tries=30, delay=1, **kwargs):
    """The SandboxTaskSearchHash index that powers sandbox_task_latest /
    sandbox_task_list is populated asynchronously by a Celery worker. Retry
    a list/latest call until the task surfaces.
    """
    last = None
    for _ in range(tries):
        try:
            return fn(*args, **kwargs)
        except exceptions.NotFoundException as e:
            last = e
            time.sleep(delay)
    raise last


def _poll_results(call, tries=30, delay=1):
    """Retry a one-shot ``list(call())`` until it returns results, riding out
    the cold-index latency a freshly-provisioned e2e shows: a submission is
    accepted immediately but the ES / archive index that backs search /
    stream lags a few seconds behind. Returns the materialised list (possibly
    empty if it never populates within the window, so the caller's assert
    still fires)."""
    res = []
    for _ in range(tries):
        try:
            res = list(call())
            if res:
                return res
        except exceptions.NoResultsException:
            pass
        time.sleep(delay)
    return res


# ── Sandbox-task completion (standing in for the sandbox worker) ──────────────
# The e2e stack has no cape/triage analysis VMs, so a dispatched SandboxTask
# never produces the callbacks that move it to SUCCEEDED — the only state that
# makes sandbox_task_latest resolve (it reads a search index the backend
# populates when a task succeeds). These helpers replay the exact HTTP calls the
# sandbox worker makes to the sandbox service (POST api/sandbox-task/ for status;
# POST + PUT + PATCH api/sandbox-artifact/ for results), which drive the task to
# completion server-side. Requires the e2e sandbox-service worker to be running.
SANDBOX_SERVICE_URI = 'http://sandbox-service-e2e:54110'


def _post_sandbox_status(task_id, status):
    httpx.post(f'{SANDBOX_SERVICE_URI}/api/sandbox-task/',
               json={'sandbox_task_id': task_id, 'status': status, 'errors': []},
               timeout=30).raise_for_status()


def _submit_sandbox_artifact(task_id, content, artifact_type, name,
                             content_type='application/json',
                             mimetype='application/json', extended_type='JSON text data'):
    if isinstance(content, (dict, list)):
        content = json.dumps(content).encode()
    resp = httpx.post(
        f'{SANDBOX_SERVICE_URI}/api/sandbox-artifact/',
        json={'sandbox_task_id': task_id, 'name': name, 'artifact_type': artifact_type,
              'mimetype': mimetype, 'extended_type': extended_type,
              'sha256': hashlib.sha256(content).hexdigest(),
              'priority': 10, 'content_type': content_type},
        timeout=30)
    resp.raise_for_status()
    created = resp.json()
    httpx.put(created['upload_url'], content=content, timeout=60).raise_for_status()
    httpx.patch(f'{SANDBOX_SERVICE_URI}/api/sandbox-artifact/{created["id"]}/',
                timeout=30).raise_for_status()


def _complete_sandbox_task(task_id, sandbox, tries=30, delay=1):
    """Drive a queued SandboxTask to SUCCEEDED without a real VM: STARTED -> a
    REPORT artifact (whose JSON the backend records as the sandbox tool's
    metadata, which is what lets the task complete) -> COLLECTING_DATA. triage
    additionally requires a RECORDING artifact before it will complete, so submit
    one first. Status codes: STARTED=1, COLLECTING_DATA=8.

    The opening STARTED post is retried: a just-dispatched task takes a moment to
    register on the sandbox service, so we wait (event-driven) for the service to
    accept the status instead of padding a fixed sleep before completing."""
    last = None
    for _ in range(tries):
        try:
            _post_sandbox_status(task_id, 1)
            break
        except httpx.HTTPStatusError as e:
            last = e
            time.sleep(delay)
    else:
        raise last
    _submit_sandbox_artifact(task_id, {'malscore': 5.0}, 'report', f'{sandbox}_report.json')
    if sandbox == 'triage':
        _submit_sandbox_artifact(task_id, b'recording-data', 'recording', 'recording.cast',
                                 content_type='application/octet-stream',
                                 mimetype='application/octet-stream', extended_type='data')
    # A real sandbox doesn't signal COLLECTING_DATA the instant it finishes
    # uploading its report — there's a natural gap. That gap is what lets the
    # backend's report-create task commit SandboxTask.artifact_metadata_id and its
    # delayed COLLECTING_DATA->SUCCEEDED transition fire (the replica-lag safety net
    # dispatched with eta=+DELAYED_IN_REPLICA_RETRY_LONG_DELAY — 1s in e2e, 30s in
    # prod). Posting status=8 back-to-back races that commit under load (the
    # report-create and the status transition land on the same ai_sandbox_done queue
    # with no ordering), so the search row may never be written. The wait restores
    # the real-world sequencing: by the time status=8 arrives the task is already
    # SUCCEEDED, and status=8 is a no-op backstop.
    time.sleep(2)
    _post_sandbox_status(task_id, 8)


class JsonResourceTestCase(TestCase):
    def test_json_get(self):
        obj = core.BaseJsonResource({
            'path1': {
                'path2': [
                    {
                        'path3': 'value1',
                        'path4': 'value2'
                    },
                ],
            },
        })
        assert obj._get('path1.path2[0].path3') == 'value1'
        assert obj._get('path1.path2[0].path4') == 'value2'
        assert obj._get('path1.path2[1].path4') is None
        assert obj._get('path1.path3.path5') is None


class ScanTestCaseV2(TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_api_key = '11111111111111111111111111111111'
        self.api_version = 'v3'

    @vcr.use_cassette()
    def test_submission(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Canonical "a file goes in and gets scanned" path: submit_and_scan waits
        # for the scan to complete and asserts the entry carries assertions/votes.
        instance, sha = submit_and_scan(api, self._testMethodName)
        assert instance.sha256 == sha

    @vcr.use_cassette()
    def test_rescans(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Submit this test's own unique artifact, then rescan it by hash and by
        # id. rescan_and_scan confirms each rescan actually re-runs the scan
        # (assertions/votes land), not merely that the call was accepted.
        uid = self._testMethodName
        _, sha = submit_and_scan(api, uid, wait=False)
        rescanned = rescan_and_scan(api, sha)
        assert_scanned(api.wait_for(api.rescan_id(rescanned.id)))

    @vcr.use_cassette()
    def test_download(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Self-contained: submit this test's own artifact, then download ITS sha
        # and assert the bytes round-trip.
        content, sha = malicious_artifact(self._testMethodName)
        with artifact_file(content) as fpath:
            api.submit(fpath)
        with temp_dir({}) as (path, _):
            for _ in range(60):
                try:
                    api.download(path, sha)
                    break
                except (exceptions.NotFoundException, exceptions.NoResultsException):
                    time.sleep(1)
            with open(os.path.join(path, sha), 'rb') as result:
                assert result.read() == content

    @vcr.use_cassette()
    def test_download_to_handle(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        content, sha = malicious_artifact(self._testMethodName)
        with artifact_file(content) as fpath:
            api.submit(fpath)
        with temp_dir({}) as (path, _):
            for _ in range(60):
                try:
                    with open(os.path.join(path, 'temp_file_handle'), 'wb') as f:
                        api.download_to_handle(sha, f)
                    break
                except (exceptions.NotFoundException, exceptions.NoResultsException):
                    time.sleep(1)
            with open(os.path.join(path, 'temp_file_handle'), 'rb') as f:
                assert f.read() == content

    @vcr.use_cassette()
    def test_stream(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # The archiver batches submitted instances into a downloadable archive
        # once ARTIFACT_ARCHIVES_INSTANCE_COUNT (3 in e2e) is *exceeded*, after an
        # ARCHIVES_CREATION_DELAY. The batch is global, so we submit enough of OUR
        # OWN unique artifacts to cross the >3 threshold by ourselves, then walk
        # the feed (downloading each archive once) until every one of OUR shas has
        # turned up — ignoring whatever other artifacts share the archives.
        # The archiver batches in groups of >3 and leaves a trailing partial batch
        # pending until more submits arrive, so not every file we submit is
        # guaranteed to be archived in isolation. Submit a healthy batch of our
        # own unique artifacts and assert at least one full batch's worth (>3) of
        # OUR shas turns up in the recent archives — ignoring co-tenant artifacts.
        uid = self._testMethodName
        my = {}
        for i in range(8):
            content, sha = malicious_artifact(f'{uid}-{i}')
            my[sha] = content
        my_shas = set(my)

        # Submit our batch concurrently — the live run pays ~one round-trip
        # instead of eight serial submits. The submit responses are unused (each
        # sha is re-derived from local content), so submission order is irrelevant.
        def _submit(content):
            with artifact_file(content) as fpath:
                api.submit(fpath)

        run_concurrently([lambda c=c: _submit(c) for c in my.values()])
        found, seen = set(), set()
        with temp_dir({}) as (path, _):
            for _ in range(90):
                try:
                    # Bound to recent archives (this run), not the 2-day backlog.
                    for artifact_archive in api.stream(since=2):
                        # Dedup by the stable storage path; the presigned uri
                        # carries a fresh signature on every fetch.
                        key = artifact_archive.uri.split('?', 1)[0]
                        if key in seen:
                            continue
                        seen.add(key)
                        archive = api.download_archive(path, artifact_archive.uri)
                        with tarfile.open(os.path.join(path, archive.artifact_name), 'r:gz') as tar:
                            for member in tar.getmembers():
                                data = tar.extractfile(member).read()
                                found.add(hashlib.sha256(data).hexdigest())
                except exceptions.NoResultsException:
                    pass
                if len(my_shas & found) >= 4:
                    break
                time.sleep(1)
        assert len(my_shas & found) >= 4, \
            'a batch of our submitted artifacts should appear in the stream archives'

    @vcr.use_cassette()
    def test_hash_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Submit + scan this test's own artifact (confirms it scanned), then
        # search for ITS sha. The search index can lag the scan, so poll.
        _, sha = submit_and_scan(api, self._testMethodName)
        result = _poll_results(lambda: list(api.search(sha)), tries=60)
        assert result and result[0].sha256 == sha

    @vcr.use_cassette()
    def test_metadata_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Submit + scan this test's own artifact, then search the ES metadata
        # index for ITS sha (sha-scoped query). The metadata write can lag, so poll.
        _, sha = submit_and_scan(api, self._testMethodName)
        result = _poll_results(
            lambda: api.search_by_metadata(f'artifact.sha256:{sha}'), tries=90)
        assert result and result[0].sha256 == sha

    def test_resolve_engine_name(self):
        with respx.mock(assert_all_called=False) as router:
            ok_payload = {'results': [
        {
            "engineId": "8565030964589685",
            "vendorWebsite": "http://www.polyswarm.io",
            "accountNumber": 181953637296,
            "engineType": "arbiter",
            "artifactTypes": [ "file" ],
            "maxFileSize": "34603020",
            "createdAt": "2019-04-24T22:36:51.000Z",
            "modifiedAt": "2021-04-26T17:34:13.523Z",
            "archivedAt": None,
            "status": "disabled",
            "communities": [ "pi" ],
            "mimetypes": [ "application/octet-stream" ],
            "tags": [ "arbiter" ],
            "description": "K7 Arbiter Microengine",
            "name": "K7-Arbiter",
            "id": "8565030964589685"
        },
        {
            "engineId": "8565030964589685",
            "accountNumber": 191777777796,
            "engineType": "engine",
            "artifactTypes": [ "file" ],
            "createdAt": "2019-04-24T22:36:51.000Z",
            "modifiedAt": "2021-04-26T17:34:13.523Z",
            "archivedAt": None,
            "status": "verified",
            "communities": [ "pi" ],
            "tags": [ "engine" ],
            "description": "",
            "name": "Test",
            "id": "9128037974787675"
        },{
            "engineId": "84858992620316109",
            "vendorWebsite": "http://www.polyswarm.io",
            "accountNumber": 181953637296,
            "engineType": "engine",
            "artifactTypes": [ "file" ],
            "maxFileSize": "34603016",
            "createdAt": "2019-04-24T22:44:40.000Z",
            "modifiedAt": "2021-04-26T17:34:13.744Z",
            "archivedAt": None,
            "status": "disabled",
            "communities": [ "pi", "sigma" ],
            "mimetypes": [ "application/pdf", "application/vnd.ms-access" ],
            "tags": ["engine"],
            "description": "IRIS-H microengine",
            "name": "IRIS-H",
            "id": "84858992620316109"
            },
        {
            "engineId": "49931709284165436",
            "vendorWebsite": "http://www.polyswarm.io",
            "accountNumber": 181953637296,
            "engineType": "engine",
            "artifactTypes": [ "file" ],
            "maxFileSize": "34603015",
            "createdAt": "2019-08-29T19:51:38.000Z",
            "modifiedAt": "2021-04-26T17:34:13.520Z",
            "archivedAt": None,
            "status": "disabled",
            "communities": [ "pi", "sigma" ],
            "mimetypes": [ "application/octet-stream" ],
            "tags": [ "engine", "file" ],
            "description": "",
            "name": "Intezer",
            "id": "49931709284165436"
            }
        ]}
            url = 'http://localhost:3000/api/v1/microengines/list'
            route = router.get(url).mock(return_value=httpx.Response(200, json=ok_payload))

            # This still does not have a v2 path
            api = PolyswarmAPI(self.test_api_key, uri='http://localhost:3000/api/v1', community='gamma')
            assert {'Intezer', 'IRIS-H', 'Test', 'K7-Arbiter'} == {e.name for e in api.engines()}
            assert {'K7-Arbiter'} == {e.name for e in api.engines() if e.is_arbiter}

            # Verify handling of invalid responses
            route.mock(return_value=httpx.Response(500))
            with pytest.raises(exceptions.RequestException):
                api.refresh_engine_cache()

            route.mock(return_value=httpx.Response(200, json={"results": []}))
            with pytest.raises(exceptions.InvalidValueException):
                api.refresh_engine_cache()

            # Run tests after failed `refresh_engine_cache` to verify that we haven't cleared the cache
            assert len(set(api.engines())) == 4

    @vcr.use_cassette()
    def test_live(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Self-contained: a per-test ruleset whose YARA matches ONLY this test's
        # artifact (uid_yara keys on the uid embedded by malicious_artifact), so
        # the live hunt surfaces just this run's submission — no cross-test feed
        # pollution. The pipeline assigns livescan_id asynchronously.
        uid = self._testMethodName
        content, _ = malicious_artifact(uid)
        rule = api.ruleset_create(f'sdk-{uid}', uid_yara(uid))
        rule_id = rule.id
        try:
            api.live_start(rule_id=rule_id)
            for _ in range(30):
                time.sleep(1)
                rule = api.ruleset_get(rule_id)
                if rule.livescan_id:
                    break
            assert rule.livescan_id, 'livescan_id should land after live_start'
            my_livescan_id = rule.livescan_id

            with artifact_file(content) as fpath:
                api.submit(fpath)

            # Bound the feed to this run's window (``since`` is in seconds) so
            # the cassette stays small regardless of how much global feed
            # history has accumulated, and match on our livescan_id to anchor
            # to the artifact this test submitted.
            my_results = []
            for _ in range(30):
                time.sleep(1)
                try:
                    feed = list(api.live_feed(since=600))
                except exceptions.NoResultsException:
                    continue
                my_results = [e for e in feed
                              if str(getattr(e, 'livescan_id', None)) == str(my_livescan_id)]
                if my_results:
                    break
            assert my_results, 'live_feed should surface a hit for the submitted EICAR'
            result_id = my_results[0].id

            # download_url is rendered after the engines complete + the
            # artifact is stored. Poll live_result until it lands.
            result = api.live_result(result_id)
            for _ in range(20):
                if result.download_url:
                    break
                time.sleep(1)
                result = api.live_result(result_id)
            assert result.download_url

            api.live_feed_delete([result_id])
            with pytest.raises(exceptions.NotFoundException):
                api.live_result(result_id)

            # Stop returns the just-stopped livescan_id; the ruleset's stored
            # livescan_id flips back to None on the next read.
            api.live_stop(rule_id=rule_id)
            stopped = api.ruleset_get(rule_id)
            assert stopped.livescan_id is None
        finally:
            # Always tear the hunt down, even on a mid-test failure: a left-
            # over active live hunt captures every later EICAR submission in
            # the suite, which is exactly how the global feed accumulated to
            # 700+ stale LiveResult rows. live_stop must precede ruleset_delete
            # ("can not delete a ruleset with an active live hunt"). Both are
            # tolerant — on the happy path the hunt is already stopped.
            try:
                api.live_stop(rule_id=rule_id)
            except exceptions.PolyswarmException:
                pass
            try:
                api.ruleset_delete(rule_id)
            except exceptions.PolyswarmException:
                pass

    @vcr.use_cassette()
    def test_historical(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        historical_hunt = api.historical_create(uid_yara(self._testMethodName))
        assert historical_hunt.status == 'PENDING'
        get_historical_hunt = api.historical_get(historical_hunt.id)
        assert historical_hunt.id == get_historical_hunt.id
        deleted_historical_hunt = api.historical_delete(get_historical_hunt.id)
        assert historical_hunt.id == deleted_historical_hunt.id

    @vcr.use_cassette()
    def test_list_historical(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Create this test's own hunts and assert each created id is present in
        # the list (subset check is isolation-safe: other tests' hunts may also
        # be listed on the shared stack).
        yara_content = uid_yara(self._testMethodName)
        historical_ids = []
        for _ in range(5):
            historical = api.historical_create(yara_content)
            historical_ids.append(historical.id)
        listed_ids = {h.id for h in api.historical_list()}
        assert set(historical_ids) <= listed_ids

    @vcr.use_cassette()
    def test_historical_results(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Self-contained: our own unique hunt (uid_yara). The e2e historical scan
        # is asynchronous and does not reliably populate results within a test
        # window, so accept an empty result set — end-to-end YARA matching is
        # exercised by the live hunt in test_live. Every returned entry is still
        # shape-checked, and the hunt is this test's own (no shared state).
        hunt = api.historical_create(uid_yara(self._testMethodName))
        try:
            for entry in api.historical_results(hunt=hunt.id):
                assert entry.sha256
                assert entry.rule_name
        except (exceptions.NotFoundException, exceptions.NoResultsException):
            pass

    @vcr.use_cassette()
    def test_rules(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # creating
        with open('test/eicar.yara') as rule:
            contents = rule.read()
            rule = api.ruleset_create('test', contents)
        assert rule.name == 'test'
        assert rule.yara == contents
        try:
            # listing — the created rule must be in the list; the e2e may carry
            # other rulesets from earlier runs, so use a presence assertion
            # rather than an exact count.
            rules = list(api.ruleset_list())
            assert any(r.id == rule.id for r in rules)
            # getting
            got = api.ruleset_get(rule.id)
            assert got.name == 'test'
            # updating
            updated = api.ruleset_update(rule.id, name='test2', description='test')
            assert updated.name == 'test2'
            assert updated.description == 'test'
        finally:
            # deleting — the created rule disappears from the list.
            api.ruleset_delete(rule.id)
        remaining_ids = []
        try:
            remaining_ids = [r.id for r in api.ruleset_list()]
        except exceptions.NoResultsException:
            pass
        assert rule.id not in remaining_ids

    @vcr.use_cassette()
    def test_tool_metadata(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Self-contained: submit this test's own artifact and attach two tool
        # blobs. Tool metadata is instance-scoped, so the tool names need no
        # namespacing — they can't collide across tests' distinct instances.
        instance, _ = submit_and_scan(api, self._testMethodName, wait=False)
        api.tool_metadata_create(instance.id, 'test_tool_1', {'key': 'value'})
        api.tool_metadata_create(instance.id, 'test_tool_2', {'key2': 'value2'})
        # persist_external_metadata runs asynchronously via Celery; poll the
        # list endpoint until both tools land. The Celery roundtrip can take
        # ~5s when the queue is busy from neighbouring tests.
        for _ in range(30):
            try:
                metadata = list(api.tool_metadata_list(instance.id))
                tools = {m.json['tool']: m.json['tool_metadata'] for m in metadata}
                if 'test_tool_1' in tools and 'test_tool_2' in tools:
                    break
            except exceptions.NoResultsException:
                pass
            time.sleep(1)
        assert tools.get('test_tool_1') == {'key': 'value'}
        assert tools.get('test_tool_2') == {'key2': 'value2'}

    @vcr.use_cassette()
    def test_iocs_by_hash(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Forward IOC lookup: /v3/ioc-beta/sha256/<sha> resolves the sha via
        # SandboxTaskSearchHash (seeded for the EICAR fixture in e2e) and reads
        # the resulting instance's metadata. We don't need a live sandbox:
        # tool_metadata_create attaches an artificial cape_sandbox_v2 blob that
        # extract_iocs reads straight off the instance. Use the shared EICAR
        # fixture because the forward view requires a SandboxTaskSearchHash row,
        # which only the provisioned EICAR sha has.
        #
        # Self-contained: the forward view needs a SandboxTaskSearchHash row for
        # the sha (its lookup key), which the backend creates when a sandbox task
        # is processed — so we dispatch + complete one for our own fresh artifact
        # rather than depending on the seeded EICAR sha. The mock cape_sandbox_v2
        # IOC blob is attached AFTER completion so the task's own report metadata
        # can't overwrite it. uid-unique IP (public, survives filter_known_good).
        uid = self._testMethodName
        ioc_ip = uid_ip(uid)
        instance, sha = submit_and_scan(api, uid, wait=False)
        cape = _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True)
        _complete_sandbox_task(cape.id, 'cape')
        # Wait until the task is fully processed (SandboxTaskSearchHash populated
        # and the completion's own async metadata write settled) BEFORE attaching
        # our mock IOC, so ours is the last write and isn't clobbered under load.
        _wait_for_sandbox_task(api, api.sandbox_task_latest, sha, 'cape')
        api.tool_metadata_create(instance.id, 'cape_sandbox_v2', {
            'extracted_c2_ips': [ioc_ip],
            'extracted_c2_urls': ['www.mock-ioc.test'],
            'ttp': ['T1081', 'T1060', 'T1069'],
        })

        # persist_external_metadata + ES update runs async via Celery; poll the
        # IOC view until the ioc_ip surfaces (generous window for full-suite load).
        ips, ttps = [], []
        for _ in range(90):
            iocs = list(api.iocs_by_hash('sha256', sha))
            if iocs:
                ips = iocs[0].json.get('ips') or []
                ttps = iocs[0].json.get('ttps') or []
                if ioc_ip in ips:
                    break
            time.sleep(1)
        assert ioc_ip in ips
        assert set(['T1081', 'T1060', 'T1069']) <= set(ttps)

    @vcr.use_cassette()
    def test_search_by_ioc(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Reverse IOC search (/v3/ioc/search?ip=): given an IOC, find the sha256
        # that reported it. Same artificial cape_sandbox_v2 trick as the forward
        # test_iocs_by_hash (no live sandbox needed), but the reverse view reads
        # Elasticsearch rather than the DB, which forces two requirements the
        # forward test doesn't have:
        #
        #   1. A UNIQUE artifact, not the shared EICAR fixture. The EICAR sha has
        #      a seeded cape sandbox task, and _shape_es_metadata OVERWRITES the
        #      doc's cape_sandbox_v2 with that task's metadata — discarding our
        #      mock IOC. A fresh sha has no sandbox task (overwrite skipped) and
        #      is its own search row's last_scanned_instance, so our mock cape is
        #      folded into the doc verbatim. Deterministic content keeps the sha
        #      (hence the cassette) stable; distinct IP so other docs can't match.
        #   2. Hash the bytes ourselves — the submit response returns
        #      sha256=None for a brand-new artifact (it's computed server-side).
        #
        # The ES doc sat behind the 600s production flush, which is why this was
        # skipped; e2e now runs ELASTICSEARCH_FLUSH_INTERVAL=5s so it resolves in
        # ~15-30s.
        #
        # uid-unique IP: the reverse search then matches ONLY this test's one
        # artifact, so it's a single page regardless of how much the (shared,
        # though ephemeral) stack accumulated — this is what kept the old shared
        # 9.42.0.x IPs returning multi-page results and hanging the suite. We also
        # iterate-and-break on our sha rather than materialising the whole feed.
        uid = self._testMethodName
        ioc_ip = uid_ip(uid)
        instance, sha = submit_and_scan(api, uid, wait=False)
        api.tool_metadata_create(instance.id, 'cape_sandbox_v2', {
            'extracted_c2_ips': [ioc_ip],
            'extracted_c2_urls': ['www.mock-ioc.test'],
            'ttp': ['T1081', 'T1060', 'T1069'],
        })
        # persist_external_metadata (Celery) + the 5s ES flush; poll until OUR
        # sha resolves. Unique IP => single-page result, so materialising is
        # bounded; the SDK's own pagination cap (see _consume_results) guards any
        # caller against a misbehaving multi-page server.
        found = False
        for _ in range(90):
            try:
                iocs = [item.json for item in api.search_by_ioc(ip=ioc_ip)]
                if sha in iocs:
                    found = True
                    break
            except exceptions.NoResultsException:
                pass
            time.sleep(1)
        assert found, 'search_by_ioc should surface our sha for our unique IP'

    @vcr.use_cassette()
    def test_add_known_good_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://ai:9696/v3', community='gamma')
        # Unique per-test host on the ephemeral stack => the create branch with
        # no prior cleanup needed.
        host = uid_host(self._testMethodName)
        known = v3api.add_known_good_host("domain", "test", host)
        assert known.json['type'] == "domain"
        assert known.json['host'] == host

    @vcr.use_cassette()
    def test_update_known_good_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://ai:9696/v3', community='gamma')
        # Add a unique host, capture its real id, then update it to a unique IP.
        host = uid_host(self._testMethodName)
        ip = uid_ip(self._testMethodName)
        added = v3api.add_known_good_host("domain", "test", host)
        known = v3api.update_known_good_host(added.json['id'], "ip", "test", ip, True)
        assert known.json['type'] == "ip"
        assert known.json['host'] == ip

    @vcr.use_cassette()
    def test_delete_known_good_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://ai:9696/v3', community='gamma')
        host = uid_host(self._testMethodName)
        added = v3api.add_known_good_host("domain", "test", host)
        known = v3api.delete_known_good_host(added.json['id'])
        assert known.json['type'] == "domain"
        assert known.json['host'] == host

    @vcr.use_cassette()
    def test_check_known_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://ai:9696/v3', community='gamma')
        # Add a unique known-good IP and list it back.
        ip = uid_ip(self._testMethodName)
        added = v3api.add_known_good_host('ip', 'test', ip)
        known = list(v3api.check_known_hosts(ips=[ip]))
        assert any(h.json['host'] == ip and h.json['type'] == 'ip' for h in known)

    @vcr.use_cassette()
    def test_known_good_lifecycle(self):
        # Full create → extend → get → delete round-trip against the real
        # /known-good endpoint (internal-only; the e2e dev key is on the
        # internal plan). The sha comes from this test's unique EICAR variant
        # (same convention as the scan tests) => the create branch runs first;
        # the trailing delete keeps live re-runs deterministic.
        v3api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        _content, sha = malicious_artifact(self._testMethodName)
        created = v3api.known_good_create(
            sha256=sha, source='nsrl', filename='kg-sample.exe',
            metadata={'product': 'Example', 'version': '1.0'})
        assert created.sha256 == sha
        assert created.sources == ['nsrl']
        assert created.artifact_instance_id
        # The refusal, against the real server. Every other assertion about the error
        # envelope reads a body this repo fabricated, which pins what we *think* the server
        # sends — a rename of the code string on the server side would leave those green.
        # Here the caller-visible outcome IS the contract: the typed exception and its feeds.
        with tempfile.TemporaryDirectory() as out_dir:
            with pytest.raises(exceptions.KnownGoodWithheldException) as ei:
                v3api.download(out_dir, sha)
            # A refused download leaves nothing behind. `_execute_download` checks the
            # status before it calls `open_destination`, and this pins that ordering: invert
            # it and a refusal would leave an empty file, which to a caller is
            # indistinguishable from a download that worked.
            assert os.listdir(out_dir) == []
        assert ei.value.sources == ['nsrl']
        # The existence probe, against the real server — and the only LIVE coverage of it in
        # the fleet. Its status codes are a frozen contract (artifact-index
        # specs/09-hash-search-head-contract.md): 200 = found, 204 = not found. The probe
        # carries no result parser, so a non-2xx never raises and every non-200 collapses to
        # False — which means a server-side widening produces a wrong boolean with no error and
        # no log line. That is exactly the 4.0 inversion this SDK shipped in 4.0.0/4.1.0.
        # Everything else asserting these semantics is respx-mocked, so it pins the SDK's
        # mapping and would stay green through such a flip. These two lines would not.
        #
        # Catalogued via the CRUD, which builds a searchable reference instance:
        #   plain          -> present, because that reference IS a real record
        #   require_scan   -> absent, because nothing was ever scanned for it
        # Polled: known_good_create returns an artifact_instance_id, so it goes through the
        # same async search-row write as a submission — asserting it unpolled is a flake under
        # TESTS_VCR=off, by the same reasoning as the probe test below.
        present = False
        for _ in range(30):
            present = v3api.exists(sha, hash_type='sha256')
            if present:
                break
            time.sleep(1)
        assert present is True
        assert v3api.exists(sha, hash_type='sha256', require_scan=True) is False
        # A second feed flagging the same sha extends the same entry (no new row).
        extended = v3api.known_good_create(sha256=sha, source='commercial')
        assert extended.id == created.id
        assert sorted(extended.sources) == ['commercial', 'nsrl']
        got = v3api.known_good_get(sha256=sha)
        assert got.sha256 == sha
        assert sorted(got.sources) == ['commercial', 'nsrl']
        # Both feeds now name themselves in the refusal — the exception's .sources tracks
        # the catalogue rather than being a snapshot from the first flagging.
        with tempfile.TemporaryDirectory() as out_dir:
            with pytest.raises(exceptions.KnownGoodWithheldException) as ei:
                v3api.download(out_dir, sha)
        assert sorted(ei.value.sources) == ['commercial', 'nsrl']
        deleted = v3api.known_good_delete(sha256=sha)
        assert deleted.sha256 == sha
        # A 404 with no known-good code must stay the BASE class: the subclass satisfies
        # `pytest.raises(NotFoundException)` too, so without this the one place the real
        # server returns a plain miss never checks that it wasn't mapped to the subclass.
        with pytest.raises(exceptions.NotFoundException) as ei:
            v3api.known_good_get(sha256=sha)
        assert not isinstance(ei.value, exceptions.KnownGoodWithheldException)

    @vcr.use_cassette()
    def test_hash_existence_probe_against_the_real_server(self):
        # The hash existence probe, end to end, on resources this test provisions itself.
        #
        # Its status codes are a frozen contract — artifact-index
        # specs/09-hash-search-head-contract.md: 200 = found, 204 = not found. The SDK sends
        # this with no result parser AND as a HEAD, so parse_response short-circuits before the
        # non-2xx mapping and hands `exists()` a bare status code. There is no error channel:
        # a server-side widening of "found" produces a wrong boolean, silently. That is the
        # shape of the inversion this SDK shipped in 4.0.0/4.1.0 — `int(result) // 100 == 2`
        # made every artifact the index had never seen report present, and the suite stayed
        # green because its probe coverage was entirely mocked.
        #
        # So this asserts the server's behaviour rather than the SDK's mapping, on both sides
        # of the 200/204 boundary, using the ordinary provisioning path.
        v3api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Two distinct EICAR variants, both deterministic: one this test submits, and one
        # NOTHING ever submits. Deriving the absent case from its own uid is what keeps this
        # test re-runnable against a reused stack — probing the sha we are about to submit
        # would pass only on a freshly booted one.
        _absent_content, absent_sha = malicious_artifact(f'{self._testMethodName}-never-submitted')
        _content, sha = malicious_artifact(self._testMethodName)
        assert absent_sha != sha

        # ABSENT -> 204 -> False, in both forms.
        assert v3api.exists(absent_sha, hash_type='sha256') is False
        assert v3api.exists(absent_sha, hash_type='sha256', require_scan=True) is False

        # PRESENT: submit the same sha and let the scan settle, so `last_scanned` lands in a
        # scan state and both forms answer 200 -> True.
        instance, submitted_sha = submit_and_scan(v3api, self._testMethodName)
        assert submitted_sha == sha, 'the probe must be asked about the sha we just submitted'
        assert instance.window_closed

        # The search row and its last_scanned state are written by async tasks, so allow for
        # index lag — but poll on the NARROWER condition. require_scan filters on the scan
        # state of the row that the plain form only needs to exist, so it can only become true
        # at the same time or later; polling the broad form and then asserting the narrow one
        # is a race. Assert both once the strict one holds.
        scanned = False
        for _ in range(30):
            scanned = v3api.exists(sha, hash_type='sha256', require_scan=True)
            if scanned:
                break
            time.sleep(1)
        assert scanned is True
        assert v3api.exists(sha, hash_type='sha256') is True

    @vcr.use_cassette()
    def test_sandbox_providers(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://ai:9696/v3', community='gamma')
        response = v3api.sandbox_providers()
        assert response.json['result']['cape']['slug'] == 'cape'
        assert response.json['result']['triage']['slug'] == 'triage'

    @vcr.use_cassette()
    def test_sandboxtask_submit(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://ai:9696/v3', community='gamma')
        # Self-contained: submit this test's own artifact and dispatch sandbox
        # tasks against ITS instance id. The submit response carries the real id.
        instance, _ = submit_and_scan(v3api, self._testMethodName, wait=False)

        task = _dispatch_sandbox(v3api, instance.id, 'cape', 'win-10-build-19041', True)
        assert task.json['config']['network_enabled'] is True
        task = _dispatch_sandbox(v3api, instance.id, 'triage', 'windows11-21h2-x64', False)
        assert task.sandbox == 'triage'
        assert task.json['config']['network_enabled'] is False

    @vcr.use_cassette()
    def test_sandboxtask_latest(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://ai:9696/v3', community='gamma')
        # Self-contained: submit our own artifact and drive cape + triage to
        # SUCCEEDED by replaying the sandbox worker's HTTP calls (no analysis VMs
        # in e2e). Completing a task creates its SandboxTaskSearchHash row, which
        # is what sandbox_task_latest reads.
        instance, sha256 = submit_and_scan(v3api, self._testMethodName, wait=False)
        cape = _dispatch_sandbox(v3api, instance.id, 'cape', 'win-10-build-19041', True)
        triage = _dispatch_sandbox(v3api, instance.id, 'triage', 'windows11-21h2-x64', False)

        # _complete_sandbox_task waits (event-driven) for the sandbox service to
        # register each just-dispatched task before driving it to SUCCEEDED.
        _complete_sandbox_task(cape.id, 'cape')
        _complete_sandbox_task(triage.id, 'triage')

        latest_cape = _wait_for_sandbox_task(v3api, v3api.sandbox_task_latest, sha256, 'cape')
        latest_triage = _wait_for_sandbox_task(v3api, v3api.sandbox_task_latest, sha256, 'triage')

        assert latest_cape.sha256 == sha256
        assert latest_cape.sandbox == 'cape'
        assert latest_triage.sha256 == sha256
        assert latest_triage.sandbox == 'triage'

    @vcr.use_cassette()
    def test_sandboxtask_list(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://ai:9696/v3', community='gamma')
        # Self-contained: submit our own artifact and queue cape + triage for ITS
        # sha. Assertions are scoped to our sha, so they're exact for this run.
        instance, sha256 = submit_and_scan(v3api, self._testMethodName, wait=False)
        # Dispatch cape + triage concurrently (distinct sandbox slugs, independent).
        run_concurrently([
            lambda: _dispatch_sandbox(v3api, instance.id, 'cape', 'win-10-build-19041', True),
            lambda: _dispatch_sandbox(v3api, instance.id, 'triage', 'windows11-21h2-x64', False),
        ])

        # Poll until the SandboxTaskSearchHash index sees both tasks.
        for _ in range(30):
            try:
                tasks = list(v3api.sandbox_task_list(sha256))
                sandboxes = {t.sandbox for t in tasks}
                if {'cape', 'triage'} <= sandboxes:
                    break
            except exceptions.NoResultsException:
                pass
            time.sleep(1)

        cape_tasks = list(v3api.sandbox_task_list(sha256, sandbox='cape'))
        triage_tasks = list(v3api.sandbox_task_list(sha256, sandbox='triage'))

        assert len(cape_tasks) >= 1
        assert all(t.sandbox == 'cape' for t in cape_tasks)
        assert len(triage_tasks) >= 1
        assert all(t.sandbox == 'triage' for t in triage_tasks)

        tasks = list(v3api.sandbox_task_list(sha256))
        sandboxes = {t.sandbox for t in tasks}
        assert {'cape', 'triage'} <= sandboxes

    @vcr.use_cassette()
    def test_sample(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://ai:9696/{self.api_version}', community='gamma')
        # Self-contained: submit our own artifact and drive cape + triage to
        # COMPLETED, then GET the aggregated sample for OUR sha. Reaching the
        # sample with a completed sandbox dep auto-triggers an LLM report; it
        # cannot COMPLETE in e2e (no OPENAI_API_KEY), so we assert it was
        # *triggered* (PENDING/etc.), not finished.
        uid = self._testMethodName
        instance, sha = submit_and_scan(api, uid, wait=False)
        cape = _dispatch_sandbox(api, instance.id, 'cape', 'win-10-build-19041', True)
        triage = _dispatch_sandbox(api, instance.id, 'triage', 'windows11-21h2-x64', False)
        _complete_sandbox_task(cape.id, 'cape')
        _complete_sandbox_task(triage.id, 'triage')

        # Poll the sample until BOTH sandbox deps read COMPLETED *and* the LLM
        # report has been auto-triggered — i.e. wait on the exact postconditions
        # asserted below, not a proxy for them. The report's requested_status moves
        # NOT_TRIGGERED/WAITING_FOR_OTHER_TASKS -> PENDING (then FAILED here, since
        # e2e has no OPENAI_API_KEY); requested_id stays null until a report
        # actually renders (impossible without an LLM), so requested_status is the
        # trigger signal.
        #
        # Keying the loop off llm_report alone raced: the report auto-triggers as
        # soon as *any one* dependency completes (the scan or a single sandbox), so
        # a response can show it triggered while sandbox_cape still projects
        # NOT_TRIGGERED — the delayed COLLECTING_DATA->SUCCEEDED transition (see
        # _complete_sandbox_task) not yet folded into the per-task projection, which
        # doesn't update atomically. That mismatch was the flake. This test drives
        # BOTH sandboxes to SUCCEEDED before polling, so both projections do reach
        # COMPLETED; waiting on them directly (not on the report as a proxy) closes
        # the window. A 90x1s timeout here therefore means a dependency never
        # settled — the scan's bounty window or a sandbox — not this loop.
        _PRE_TRIGGER = {None, 'NOT_TRIGGERED', 'WAITING_FOR_OTHER_TASKS'}
        result = api.sample(sha)
        for _ in range(90):
            result = api.sample(sha)
            tasks = result.tasks or {}
            sandboxes_completed = all(
                tasks.get(f'sandbox_{s}', {}).get('requested_status') == 'COMPLETED'
                for s in ('cape', 'triage')
            )
            llm_triggered = tasks.get('llm_report', {}).get('requested_status') not in _PRE_TRIGGER
            if sandboxes_completed and llm_triggered:
                break
            time.sleep(1)
        assert isinstance(result.artifact_instance, dict)
        assert isinstance(result.sandbox, dict)
        assert {'cape', 'triage'} <= set(result.sandbox.keys())
        assert isinstance(result.tasks, dict)
        assert result.tasks['sandbox_cape']['requested_status'] == 'COMPLETED'
        assert result.tasks['sandbox_triage']['requested_status'] == 'COMPLETED'
        # llm_report auto-triggered (PENDING -> ...); it cannot reach COMPLETED in
        # e2e (no LLM), so assert it was triggered, not finished.
        assert result.tasks['llm_report']['requested_status'] not in _PRE_TRIGGER

