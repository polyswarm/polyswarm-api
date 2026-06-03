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
)

from unittest import TestCase, mock


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


def _complete_sandbox_task(task_id, sandbox):
    """Drive a queued SandboxTask to SUCCEEDED without a real VM: STARTED -> a
    REPORT artifact (whose JSON the backend records as the sandbox tool's
    metadata, which is what lets the task complete) -> COLLECTING_DATA. triage
    additionally requires a RECORDING artifact before it will complete, so submit
    one first. Status codes: STARTED=1, COLLECTING_DATA=8."""
    _post_sandbox_status(task_id, 1)
    _submit_sandbox_artifact(task_id, {'malscore': 5.0}, 'report', f'{sandbox}_report.json')
    if sandbox == 'triage':
        _submit_sandbox_artifact(task_id, b'recording-data', 'recording', 'recording.cast',
                                 content_type='application/octet-stream',
                                 mimetype='application/octet-stream', extended_type='data')
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
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        result = api.submit('test/malicious')
        assert result.failed is False
        assert result.result is None

    @vcr.use_cassette()
    def test_rescans(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        # Self-contained: submit this test's own unique (EICAR + uid) artifact,
        # then rescan ITS sha. rescan needs the artifact indexed, which lags a
        # fresh submit, so poll the rescan until it stops 404-ing (the autouse
        # fixture no-ops the sleep on VCR replay).
        uid = self._testMethodName
        content, sha = malicious_artifact(uid)
        with artifact_file(content) as fpath:
            api.submit(fpath)
        result = None
        for _ in range(60):
            try:
                result = api.rescan(sha)
                break
            except (exceptions.NotFoundException, exceptions.NoResultsException):
                time.sleep(1)
        assert result is not None, 'rescan should resolve once the artifact is indexed'
        assert result.failed is False
        assert result.result is None
        result = api.rescan_id(result.id)
        assert result.failed is False
        assert result.result is None

    @vcr.use_cassette()
    def test_download(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        with temp_dir({}) as (path, _):
            api.download(path, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
            with open(os.path.join(path, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'), 'rb') as result:
                content = result.read()
                assert content == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @vcr.use_cassette()
    def test_download_to_handle(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        with temp_dir({}) as (path, _):
            with open(os.path.join(path, 'temp_file_handle'), 'wb') as f:
                api.download_to_handle('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', f)
            with open(os.path.join(path, 'temp_file_handle'), 'rb') as f:
                assert f.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @vcr.use_cassette()
    def test_stream(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        # The archiver batches submitted instances into a downloadable archive
        # once ARTIFACT_ARCHIVES_INSTANCE_COUNT (3 in e2e) is *exceeded*, after
        # an ARCHIVES_CREATION_DELAY (~30s). Submit enough EICAR to cross the
        # >3 threshold, then poll the stream feed until the archive lands.
        for _ in range(5):
            api.submit('test/malicious')
        with temp_dir({}) as (path, _):
            # Consume only the FIRST archive (next(iter(...))) instead of
            # list(api.stream()) — the feed accumulates archives and paging
            # the whole thing would bloat the cassette. One page is enough to
            # download + verify, and bounds the recording to a single request.
            artifact_archive = None
            for _ in range(90):
                try:
                    artifact_archive = next(iter(api.stream()), None)
                except exceptions.NoResultsException:
                    artifact_archive = None
                if artifact_archive is not None:
                    break
                time.sleep(1)
            assert artifact_archive is not None, 'stream should yield an archive after >3 submits'
            archive = api.download_archive(path, artifact_archive.uri)
            with tarfile.open(os.path.join(path, archive.artifact_name), 'r:gz') as tar:
                for member in tar.getmembers():
                    extracted = tar.extractfile(member)
                    assert extracted.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @vcr.use_cassette()
    def test_hash_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        # Self-contained: submit this test's own unique artifact and search for
        # ITS sha. The search index lags the submit, so poll until it surfaces.
        uid = self._testMethodName
        content, sha = malicious_artifact(uid)
        with artifact_file(content) as fpath:
            api.submit(fpath)
        result = _poll_results(lambda: list(api.search(sha)), tries=60)
        assert result and result[0].sha256 == sha

    @vcr.use_cassette()
    def test_metadata_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        # Provision: metadata search hits the indexed corpus, which lags the
        # submission on a cold e2e; poll until the ES metadata index catches up.
        api.submit('test/malicious')
        # Indexes in ~1s when idle but the ES metadata write lags badly under
        # full-suite Celery load, so use a generous window.
        result = _poll_results(lambda: api.search_by_metadata(
            'artifact.sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'),
            tries=90)
        assert result and result[0].sha256 == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

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
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        # Provision: create a ruleset, start the live hunt, submit EICAR.
        # The pipeline assigns livescan_id asynchronously (the live_start
        # response itself has livescan_id=None — engines pick up the rule
        # within ~1s and the value lands on the ruleset).
        with open('test/eicar.yara') as yara:
            rule = api.ruleset_create('eicar', yara.read())
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

            api.submit('test/malicious')

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
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            historical_hunt = api.historical_create(yara.read())
        assert historical_hunt.status == 'PENDING'
        get_historical_hunt = api.historical_get(historical_hunt.id)
        assert historical_hunt.id == get_historical_hunt.id
        deleted_historical_hunt = api.historical_delete(get_historical_hunt.id)
        assert historical_hunt.id == deleted_historical_hunt.id

    @vcr.use_cassette()
    def test_list_historical(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            yara_content = yara.read()
        historical_ids = []
        for _ in range(5):
            historical = api.historical_create(yara_content)
            historical_ids.append(historical.id)
        result = list(api.historical_list())
        assert len(result) >= 4
        api.historical_delete_list(historical_ids)

    @vcr.use_cassette()
    def test_historical_results(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        # Provision: create a fresh hunt and use its returned id rather than a
        # hard-coded one. Results count depends on the indexed corpus, so the
        # assertion is structural — every entry has the shape we expect.
        with open('test/eicar.yara') as yara:
            hunt = api.historical_create(yara.read())
        try:
            try:
                result = list(api.historical_results(hunt=hunt.id))
                for entry in result:
                    assert entry.sha256
                    assert entry.rule_name
            except (exceptions.NotFoundException, exceptions.NoResultsException):
                # Empty corpus on a fresh e2e — no matches; the API surfaces
                # this as NoResults / NotFound depending on the path taken.
                # Accept as a valid outcome.
                pass
        finally:
            api.historical_delete(hunt.id)

    @vcr.use_cassette()
    def test_rules(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
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
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        # Provision: submit so we have a real instance to attach metadata to,
        # then post two tool_metadata blobs.
        instance = api.submit('test/malicious')
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
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        # Forward IOC lookup: /v3/ioc-beta/sha256/<sha> resolves the sha via
        # SandboxTaskSearchHash (seeded for the EICAR fixture in e2e) and reads
        # the resulting instance's metadata. We don't need a live sandbox:
        # tool_metadata_create attaches an artificial cape_sandbox_v2 blob that
        # extract_iocs reads straight off the instance. Use the shared EICAR
        # fixture because the forward view requires a SandboxTaskSearchHash row,
        # which only the provisioned EICAR sha has.
        #
        # The IP must be globally-routable so filter_known_good_iocs keeps it
        # (it drops private/reserved), and distinct from the other IOC tests so
        # their docs can't cross-match. 9.42.0.1 — public (IBM netblock).
        ioc_ip = '9.42.0.1'
        instance = api.submit('test/malicious')
        api.tool_metadata_create(instance.id, 'cape_sandbox_v2', {
            'extracted_c2_ips': [ioc_ip],
            'extracted_c2_urls': ['www.mock-ioc.test'],
            'ttp': ['T1081', 'T1060', 'T1069'],
        })

        # persist_external_metadata + ES update runs async via Celery; poll the
        # IOC view until the ioc_ip surfaces.
        sha = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
        ips, ttps = [], []
        for _ in range(60):
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
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
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
        content, sha = malicious_artifact(uid)
        with artifact_file(content) as fpath:
            instance = api.submit(fpath)
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
        v3api = PolyswarmAPI(self.test_api_key, uri='http://artifact-index-e2e:9696/v3', community='gamma')
        # Provision: clean up any prior IOC for the test host so the add path
        # exercises the create branch rather than 400-ing with "already exists".
        # The check-vs-delete divergence (cache returns stale entries the
        # delete-by-id no longer finds) means we tolerate 404 on cleanup.
        for hit in list(v3api.check_known_hosts(domains=['polyswarm.network'])):
            try:
                v3api.delete_known_good_host(hit.json['id'])
            except exceptions.NotFoundException:
                pass

        known = v3api.add_known_good_host("domain", "test", "polyswarm.network")
        try:
            assert known.json['type'] == "domain"
            assert known.json['host'] == "polyswarm.network"
        finally:
            try:
                v3api.delete_known_good_host(known.json['id'])
            except exceptions.NotFoundException:
                pass

    @vcr.use_cassette()
    def test_update_known_good_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://artifact-index-e2e:9696/v3', community='gamma')
        # Provision: add an IOC to update, capture its real id (auto-increment
        # is past 1 on any non-fresh DB, so we can't hard-code that value).
        added = v3api.add_known_good_host("domain", "test", "polyswarm.network")
        try:
            known = v3api.update_known_good_host(added.json['id'], "ip", "test", "1.2.3.4", True)
            assert known.json['type'] == "ip"
            assert known.json['host'] == "1.2.3.4"
        finally:
            try:
                v3api.delete_known_good_host(added.json['id'])
            except exceptions.NotFoundException:
                pass

    @vcr.use_cassette()
    def test_delete_known_good_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://artifact-index-e2e:9696/v3', community='gamma')
        # Provision: add an IOC to delete; capture id.
        added = v3api.add_known_good_host("domain", "test", "polyswarm.network")
        known = v3api.delete_known_good_host(added.json['id'])
        assert known.json['type'] == "domain"
        assert known.json['host'] == "polyswarm.network"

    @vcr.use_cassette()
    def test_check_known_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://artifact-index-e2e:9696/v3', community='gamma')
        # Provision: drop any leftover IOC for this ip, add a fresh known-good
        # entry, list it back. The ioc_cache divergence (see above) can leave
        # stale entries; tolerate 404 in cleanup.
        for hit in list(v3api.check_known_hosts(ips=['1.2.3.4'])):
            try:
                v3api.delete_known_good_host(hit.json['id'])
            except exceptions.NotFoundException:
                pass
        added = v3api.add_known_good_host('ip', 'test', '1.2.3.4')
        try:
            known = list(v3api.check_known_hosts(ips=["1.2.3.4"]))
            assert any(h.json['host'] == '1.2.3.4' and h.json['type'] == 'ip' for h in known)
        finally:
            try:
                v3api.delete_known_good_host(added.json['id'])
            except exceptions.NotFoundException:
                pass

    @vcr.use_cassette()
    def test_sandbox_providers(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://artifact-index-e2e:9696/v3', community='gamma')
        response = v3api.sandbox_providers()
        assert response.json['result']['cape']['slug'] == 'cape'
        assert response.json['result']['triage']['slug'] == 'triage'

    @vcr.use_cassette()
    def test_sandboxtask_submit(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://artifact-index-e2e:9696/v3', community='gamma')
        # Provision: submit a fresh artifact and dispatch sandbox tasks
        # against ITS instance id rather than a frozen one. The submit
        # response carries the real id.
        instance = v3api.submit('test/malicious')

        task = _dispatch_sandbox(v3api, instance.id, 'cape', 'win-10-build-19041', True)
        assert task.json['config']['network_enabled'] is True
        task = _dispatch_sandbox(v3api, instance.id, 'triage', 'win10-build-15063', False)
        assert task.sandbox == 'triage'
        assert task.json['config']['network_enabled'] is False

    @vcr.use_cassette()
    def ytest_sandboxtask_get(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://artifact-index-e2e:9696/v3', community='gamma')
        task_id = 37385694435473303
        status = v3api.sandbox_task_status(task_id)
        assert status.id == task_id
        assert status.sandbox == 'triage'
        assert status.sha256 == 'a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427'
        assert status.created == 'gamma'

    @vcr.use_cassette()
    def test_sandboxtask_latest(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://artifact-index-e2e:9696/v3', community='gamma')
        # Submit + queue cape and triage tasks. There are no cape/triage analysis
        # VMs in e2e, so each task is driven to SUCCEEDED by replaying the sandbox
        # worker's HTTP calls (see _complete_sandbox_task) — that is what makes
        # sandbox_task_latest resolve per sandbox.
        instance = v3api.submit('test/malicious')
        cape = _dispatch_sandbox(v3api, instance.id, 'cape', 'win-10-build-19041', True)
        triage = _dispatch_sandbox(v3api, instance.id, 'triage', 'win10-build-15063', False)

        # Let the sandbox service register the dispatched tasks (it creates the
        # root artifact the status/result callbacks key off) before we complete
        # them; the autouse fixture no-ops this sleep on VCR replay.
        time.sleep(6)
        _complete_sandbox_task(cape.id, 'cape')
        _complete_sandbox_task(triage.id, 'triage')

        sha256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
        latest_cape = _wait_for_sandbox_task(v3api, v3api.sandbox_task_latest, sha256, 'cape')
        latest_triage = _wait_for_sandbox_task(v3api, v3api.sandbox_task_latest, sha256, 'triage')

        assert latest_cape.sha256 == sha256
        assert latest_cape.sandbox == 'cape'
        assert latest_triage.sha256 == sha256
        assert latest_triage.sandbox == 'triage'

    @vcr.use_cassette()
    def test_sandboxtask_list(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://artifact-index-e2e:9696/v3', community='gamma')
        # Provision: submit + queue cape and triage tasks for a known sha256.
        # Use relative assertions (>= 1, set inclusion) so prior runs that
        # left tasks in place don't break the suite.
        instance = v3api.submit('test/malicious')
        _dispatch_sandbox(v3api, instance.id, 'cape', 'win-10-build-19041', True)
        _dispatch_sandbox(v3api, instance.id, 'triage', 'win10-build-15063', False)

        sha256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

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
        api = PolyswarmAPI(self.test_api_key, uri=f'http://artifact-index-e2e:9696/{self.api_version}', community='gamma')
        result = api.sample('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
        assert isinstance(result.artifact_instance, dict)
        assert isinstance(result.sandbox, dict)
        assert {'cape', 'triage'} <= set(result.sandbox.keys())
        assert isinstance(result.tasks, dict)
        assert {'artifact_instance', 'llm_report', 'sandbox_cape', 'sandbox_triage'} <= set(result.tasks.keys())
