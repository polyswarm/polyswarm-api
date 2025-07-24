import os
import shutil
import tempfile
import responses
import pytest
import tarfile
from contextlib import contextmanager

import vcr as vcr_

from polyswarm_api.api import PolyswarmAPI
from polyswarm_api import core
from polyswarm_api import exceptions

from unittest import TestCase, mock


vcr = vcr_.VCR(cassette_library_dir='test/vcr',
               path_transformer=vcr_.VCR.ensure_suffix('.vcr'))


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
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = api.submit('test/malicious')
        assert result.failed is False
        assert result.result is None

    @vcr.use_cassette()
    def test_rescans(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = api.rescan('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
        assert result.failed is False
        assert result.result is None
        result = api.rescan_id(result.id)
        assert result.failed is False
        assert result.result is None

    @vcr.use_cassette()
    def test_download(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with temp_dir({}) as (path, _):
            api.download(path, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
            with open(os.path.join(path, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'), 'rb') as result:
                content = result.read()
                assert content == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @vcr.use_cassette()
    def test_download_to_handle(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with temp_dir({}) as (path, _):
            with open(os.path.join(path, 'temp_file_handle'), 'wb') as f:
                api.download_to_handle('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', f)
            with open(os.path.join(path, 'temp_file_handle'), 'rb') as f:
                assert f.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @vcr.use_cassette()
    def test_stream(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with temp_dir({}) as (path, _):
            result = list(api.stream())
            artifact_archive = result[0]
            archive = api.download_archive(path, artifact_archive.uri)
            with tarfile.open(os.path.join(path, archive.artifact_name), 'r:gz') as tar:
                for member in tar.getmembers():
                    result = tar.extractfile(member)
                    assert result.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @vcr.use_cassette()
    def test_hash_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.search('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].sha256 == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @vcr.use_cassette()
    def test_metadata_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.search_by_metadata('artifact.sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].sha256 == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @responses.activate
    def test_resolve_engine_name(self):
        responses.add(responses.GET, 'http://localhost:3000/api/v1/microengines/list', json={'results': [
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
        ]})
        # This still does not have a v2 path
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:3000/api/v1', community='gamma')
        assert {'Intezer', 'IRIS-H', 'Test', 'K7-Arbiter'} == {e.name for e in api.engines}
        assert {'K7-Arbiter'} == {e.name for e in api.engines if e.is_arbiter}

        # Verify handling of invalid responses
        responses.replace(responses.GET, 'http://localhost:3000/api/v1/microengines/list', status=500)
        with pytest.raises(exceptions.RequestException):
            api.refresh_engine_cache()

        responses.replace(responses.GET, 'http://localhost:3000/api/v1/microengines/list', json={"results": []})
        with pytest.raises(exceptions.InvalidValueException):
            api.refresh_engine_cache()

        # Run tests after failed `refresh_engine_cache` to verify that we haven't cleared `api.engines`
        assert len(set(api.engines)) == 4

    @vcr.use_cassette()
    def test_live(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            rule = api.ruleset_create('eicar', yara.read())
        rule = api.live_start(rule_id=rule.id)
        assert rule.livescan_id
        api.submit('test/malicious')
        # add a break point at the line below and
        # wait for the bounty to finish when generating the vcr
        feed = list(api.live_feed())
        assert len(feed) > 1
        result = feed[0]
        result = api.live_result(result.id)
        assert result.download_url
        api.live_feed_delete([result.id])
        with pytest.raises(exceptions.NotFoundException):
            api.live_result(result.id)
        rule = api.live_stop(rule_id=rule.id)
        assert rule.livescan_id is None

    @vcr.use_cassette()
    def test_historical(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            historical_hunt = api.historical_create(yara.read())
        assert historical_hunt.status == 'PENDING'
        get_historical_hunt = api.historical_get(historical_hunt.id)
        assert historical_hunt.id == get_historical_hunt.id
        deleted_historical_hunt = api.historical_delete(get_historical_hunt.id)
        assert historical_hunt.id == deleted_historical_hunt.id

    @vcr.use_cassette()
    def test_list_historical(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
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
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.historical_results(hunt='48011760326110718'))
        assert len(result) == 6

    @vcr.use_cassette()
    def test_rules(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        # creating
        with open('test/eicar.yara') as rule:
            contents = rule.read()
            rule = api.ruleset_create('test', contents)
        assert rule.name == 'test'
        assert rule.yara == contents
        # listing
        rules = list(api.ruleset_list())
        assert len(rules) == 1
        # getting
        rule = api.ruleset_get(rule.id)
        assert rule.name == 'test'
        # updating
        rule = api.ruleset_update(rule.id, name='test2', description='test')
        assert rule.name == 'test2'
        assert rule.description == 'test'
        # deleting
        api.ruleset_delete(rule.id)
        with pytest.raises(exceptions.NoResultsException):
            list(api.ruleset_list())

    @vcr.use_cassette()
    def test_tool_metadata(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        api.tool_metadata_create(41782351738405672, 'test_tool_1', {'key': 'value'})
        api.tool_metadata_create(41782351738405672, 'test_tool_2', {'key2': 'value2'})
        metadata = list(api.tool_metadata_list(41782351738405672))
        assert metadata[0].json['tool'] == 'test_tool_2'
        assert metadata[0].json['tool_metadata'] == {'key2': 'value2'}
        assert metadata[1].json['tool'] == 'test_tool_1'
        assert metadata[1].json['tool_metadata'] == {'key': 'value'}

    @vcr.use_cassette()
    def test_iocs_by_hash(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        api.tool_metadata_create(
            '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'cape_sandbox_v2', {'cape_sandbox_v2': {
                'extracted_c2_ips': ['1.2.3.4'],
                'extracted_c2_urls': ['www.virus.com'],
                'ttp': ['T1081', 'T1060', 'T1069']
             }})

        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')
        iocs = list(v3api.iocs_by_hash('sha256', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert iocs[0].json['ips'] == ['1.2.3.4']
        assert iocs[0].json['ttps'] == ['T1081', 'T1060', 'T1069']

    @vcr.use_cassette()
    def test_search_by_ioc(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        api.tool_metadata_create(
            '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'cape_sandbox_v2', {'cape_sandbox_v2': {
                'extracted_c2_ips': ['1.2.3.4'],
                'extracted_c2_urls': ['www.virus.com'],
                'ttp': ['T1081', 'T1060', 'T1069']
             }})

        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')
        iocs = list(v3api.search_by_ioc(ip="1.2.3.4"))
        assert iocs[0].json == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @vcr.use_cassette()
    def test_add_known_good_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')
        known = v3api.add_known_good_host("domain", "test", "polyswarm.network")
        assert known.json['type'] == "domain"
        assert known.json['host'] == "polyswarm.network"

    @vcr.use_cassette()
    def test_update_known_good_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')
        known = v3api.update_known_good_host(1, "ip", "test", "1.2.3.4", True)
        assert known.json['type'] == "ip"
        assert known.json['host'] == "1.2.3.4"

    @vcr.use_cassette()
    def test_delete_known_good_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')
        known = v3api.delete_known_good_host(1)
        assert known.json['type'] == "domain"
        assert known.json['host'] == "polyswarm.network"

    @vcr.use_cassette()
    def test_check_known_host(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')
        known = v3api.check_known_hosts(ips=["1.2.3.4"])
        assert known[0].json['host'] == "1.2.3.4"
        assert known[0].json['type'] == "ip"

    @vcr.use_cassette()
    def test_sandbox_providers(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')
        response = v3api.sandbox_providers()
        assert response.json['result']['cape']['slug'] == 'cape'
        assert response.json['result']['triage']['slug'] == 'triage'

    @vcr.use_cassette()
    def test_sandboxtask_submit(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')
        task = v3api.sandbox('24135952517649903', 'cape', 'win-10-build-19041', True)
        assert task.json['config']['network_enabled'] is True
        task = v3api.sandbox('24135952517649903', 'triage', 'win10-build-15063', False)
        assert task.sandbox == 'triage'
        assert task.json['config']['network_enabled'] is False

    @vcr.use_cassette()
    def ytest_sandboxtask_get(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')
        task_id = 37385694435473303
        status = v3api.sandbox_task_status(task_id)
        assert status.id == task_id
        assert status.sandbox == 'triage'
        assert status.sha256 == 'a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427'
        assert status.created == 'gamma'

    @vcr.use_cassette()
    def test_sandboxtask_latest(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')

        sha256 = 'a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427'
        latest_cape = v3api.sandbox_task_latest(sha256, 'cape')
        latest_triage = v3api.sandbox_task_latest(sha256, 'triage')

        assert latest_cape.sha256 == sha256
        assert latest_cape.sandbox == 'cape'
        assert latest_triage.sha256 == sha256
        assert latest_triage.sandbox == 'triage'

    @vcr.use_cassette()
    def test_sandboxtask_list(self):
        v3api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v3', community='gamma')

        cape_tasks = list(v3api.sandbox_task_list('a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427',
                                                  sandbox='cape'))
        triage_tasks = list(v3api.sandbox_task_list('a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427',
                                                    sandbox='triage'))

        assert len(cape_tasks) == 1
        assert cape_tasks[0].sandbox == 'cape'
        assert len(triage_tasks) == 1
        assert triage_tasks[0].sandbox == 'triage'

        tasks = list(v3api.sandbox_task_list('a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427'))

        assert len(tasks) == 2
        assert set(t.sandbox for t in tasks) == {'cape', 'triage'}
