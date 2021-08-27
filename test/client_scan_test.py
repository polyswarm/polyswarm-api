import os
import shutil
import tempfile
import responses
import pytest
import tarfile
from contextlib import contextmanager

import vcr as vcr_
from future.utils import string_types

from polyswarm_api.api import PolyswarmAPI
from polyswarm_api import core
from polyswarm_api import exceptions

try:
    from unittest import TestCase, mock
except ImportError:
    import mock


vcr = vcr_.VCR(cassette_library_dir='test/vcr',
               path_transformer=vcr_.VCR.ensure_suffix('.vcr'))


# TODO: the day we drop python 2.7 support we can use python 3 version of this
@contextmanager
def TemporaryDirectory():
    name = tempfile.mkdtemp()
    try:
        yield name
    finally:
        shutil.rmtree(name)


@contextmanager
def temp_dir(files_dict):
    with TemporaryDirectory() as tmp_dir:
        files = []
        for file_name, file_content in files_dict.items():
            mode = 'w' if isinstance(file_content, string_types) else 'wb'
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
        super(ScanTestCaseV2, self).__init__(*args, **kwargs)
        self.test_api_key = '11111111111111111111111111111111'
        self.api_version = 'v2'

    @vcr.use_cassette()
    def test_submission(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        result = api.submit('test/malicious')
        assert result.failed is False
        assert result.result is None

    @vcr.use_cassette()
    def test_rescan(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        result = api.rescan('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
        assert result.failed is False
        assert result.result is None

    @vcr.use_cassette()
    def test_rescanid(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        result = api.rescan_id('84294676590305175')
        assert result.failed is False
        assert result.result is None

    @vcr.use_cassette()
    def test_download(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}/consumer'.format(self.api_version), community='gamma')
        with temp_dir({}) as (path, _):
            api.download(path, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
            result = open(os.path.join(path, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'), 'rb')
            assert result.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @vcr.use_cassette()
    def test_download_to_handle(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}/consumer'.format(self.api_version), community='gamma')
        with temp_dir({}) as (path, _):
            with open(os.path.join(path, 'temp_file_handle'), 'wb') as f:
                api.download_to_handle('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', f)
            with open(os.path.join(path, 'temp_file_handle'), 'rb') as f:
                assert f.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @vcr.use_cassette()
    def test_stream(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
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
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        result = list(api.search('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].sha256 == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @vcr.use_cassette()
    def test_metadata_search(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        result = list(api.search_by_metadata('artifact.sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].sha256 == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @responses.activate
    def test_resolve_engine_name(self):
        responses.add(responses.GET, 'http://localhost:3000/api/v1/microengines/list', json={'results': [
        {
            "address": "0x2A1EEEe60A652961a4B6981b6103CDcb63efBD6b",
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
            "address": None,
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
            "address": "84858992620316109",
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
            "address": "0x73653AAAfa73EC3CEBb9c0500d81f94B1153ecDF",
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
        assert {
            'Intezer': '0x73653aaafa73ec3cebb9c0500d81f94b1153ecdf',
            'IRIS-H': '84858992620316109',
            'K7-Arbiter': '0x2a1eeee60a652961a4b6981b6103cdcb63efbd6b',
            'Test': None,
        } == {e.name: e.address for e in api.engines}
        assert len(set(api.engines)) == 4

    @vcr.use_cassette()
    def test_live(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        with open('test/eicar.yara') as yara:
            live_hunt = api.live_create(yara.read())
        assert live_hunt.active
        assert live_hunt.status == 'SUCCESS'
        api.live_update(False, hunt=live_hunt.id)
        updated_live_hunt = api.live_get(live_hunt.id)
        assert not updated_live_hunt.active
        deleted_live_hunt = api.live_delete(live_hunt.id)
        assert live_hunt.id == deleted_live_hunt.id

    @vcr.use_cassette()
    def test_live_results(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        result = list(api.live_results(hunt='1876773693834725'))
        assert len(result) == 20

    @vcr.use_cassette()
    def test_list_live(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        result = list(api.live_list(all_=True))
        assert len(result) >= 15

    @vcr.use_cassette()
    def test_historical(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        with open('test/eicar.yara') as yara:
            historical_hunt = api.historical_create(yara.read())
        assert historical_hunt.status == 'PENDING'
        get_historical_hunt = api.historical_get(historical_hunt.id)
        assert historical_hunt.id == get_historical_hunt.id
        deleted_historical_hunt = api.historical_delete(get_historical_hunt.id)
        assert historical_hunt.id == deleted_historical_hunt.id

    @vcr.use_cassette()
    def test_list_historical(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        with open('test/eicar.yara') as yara:
            yara_content = yara.read()
        for _ in range(101):
            api.historical_create(yara_content)
        result = list(api.historical_list())
        assert len(result) >= 100

    @vcr.use_cassette()
    def test_historical_results(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        result = list(api.historical_results(hunt='37414793702930975'))
        assert len(result) == 18

    @vcr.use_cassette()
    def test_rules(self):
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
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
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/{}'.format(self.api_version), community='gamma')
        api.tool_metadata_create(
            '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'test_tool_1', {'key': 'value'})
        api.tool_metadata_create(
            '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'test_tool_2', {'key2': 'value2'})
        metadata = list(api.tool_metadata_list('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert metadata[0].json['tool'] == 'test_tool_2'
        assert metadata[0].json['tool_metadata'] == {'key2': 'value2'}
        assert metadata[1].json['tool'] == 'test_tool_1'
        assert metadata[1].json['tool_metadata'] == {'key': 'value'}
