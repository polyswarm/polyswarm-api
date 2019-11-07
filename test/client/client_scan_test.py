import os
import shutil
import tempfile
from contextlib import contextmanager

import pytest
import responses
from polyswarm_api.api import PolyswarmAPI

try:
    from unittest import TestCase, mock
except ImportError:
    import mock


@contextmanager
def TemporaryDirectory():
    """The day we drop python 2.7 support we can use python 3 version of this"""
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
            mode = 'w' if isinstance(file_content, str) else 'wb'
            file_path = os.path.join(tmp_dir, file_name)
            open(file_path, mode=mode).write(file_content)
            files.append(file_path)
        yield tmp_dir, files


class ScanTestCaseV2(TestCase):
    def __init__(self, *args, **kwargs):
        super(ScanTestCaseV2, self).__init__(*args, **kwargs)
        self.test_api_key = '11111111111111111111111111111111'
        self.api_version = 'v2'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_submission(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.scan('test/malicious'))
        assert result[0].status == 'Bounty Awaiting Arbitration'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_rescan(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.rescan('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].status == 'Bounty Awaiting Arbitration'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_hash_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.search('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].sha256 == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_metadata_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.search_by_metadata('hash.sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].sha256 == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'


@pytest.mark.skip(reason="deprecating tests for v1")
class ScanTestCase(TestCase):
    def __init__(self, *args, **kwargs):
        super(ScanTestCase, self).__init__(*args, **kwargs)
        self.test_api_key = '11111111111111111111111111111111'
        self.api_version = 'v1'

    def test_everything_is_ok(self):
        pass

    @responses.activate
    def test_submission(self):
        responses.add(responses.Response(responses.POST, f'http://localhost:9696/{self.api_version}/consumer/gamma',
                                         json={'result': '00000000-0000-0000-0000-000000000000', 'status': 'OK'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/consumer/gamma/uuid/00000000-0000-0000-0000-000000000000',
                                         json={'result': {'files': [{'assertions': [], 'bounty_guid': None, 'bounty_status': 'Created', 'failed': False, 'filename': 'malicious', 'hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'id': '36695034110833257', 'result': None, 'size': 68, 'submission_guid': '00000000-0000-0000-0000-000000000000', 'type': 'FILE', 'votes': [], 'window_closed': False}], 'status': 'Bounty Running', 'uuid': '00000000-0000-0000-0000-000000000000'}, 'status': 'OK'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/consumer/gamma/uuid/00000000-0000-0000-0000-000000000000',
                                         json={'result': {'files': [{'assertions': [{'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'author_name': 'eicar', 'bid': '1000000000000000000', 'engine': {'description': 'eicar', 'name': 'eicar', 'tags': []}, 'mask': True, 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}, 'verdict': True}], 'bounty_guid': '843014e7-96da-4513-97cb-3ded3584ab0c', 'bounty_status': 'Awaiting arbitration.', 'failed': False, 'filename': 'malicious', 'hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'id': '36695034110833257', 'result': None, 'size': 68, 'submission_guid': '00000000-0000-0000-0000-000000000000', 'type': 'FILE', 'votes': [], 'window_closed': True}], 'status': 'Bounty Awaiting Arbitration', 'uuid': '00000000-0000-0000-0000-000000000000'}, 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.scan('test/malicious'))
        assert result[0].json['result']['status'] == 'Bounty Awaiting Arbitration'

    @responses.activate
    def test_rescan(self):
        responses.add(responses.Response(responses.POST, f'http://localhost:9696/{self.api_version}/consumer/gamma/rescan/sha256/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
                                         json={'result': '00000000-0000-0000-0000-000000000000', 'status': 'OK'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/consumer/gamma/uuid/00000000-0000-0000-0000-000000000000',
                                         json={'result': {'files': [{'assertions': [], 'bounty_guid': None, 'bounty_status': 'Created', 'failed': False, 'filename': 'malicious', 'hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'id': '36695034110833257', 'result': None, 'size': 68, 'submission_guid': '00000000-0000-0000-0000-000000000000', 'type': 'FILE', 'votes': [], 'window_closed': False}], 'status': 'Bounty Running', 'uuid': '00000000-0000-0000-0000-000000000000'}, 'status': 'OK'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/consumer/gamma/uuid/00000000-0000-0000-0000-000000000000',
                                         json={'result': {'files': [{'assertions': [{'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'author_name': 'eicar', 'bid': '1000000000000000000', 'engine': {'description': 'eicar', 'name': 'eicar', 'tags': []}, 'mask': True, 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}, 'verdict': True}], 'bounty_guid': '843014e7-96da-4513-97cb-3ded3584ab0c', 'bounty_status': 'Awaiting arbitration.', 'failed': False, 'filename': 'malicious', 'hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'id': '36695034110833257', 'result': None, 'size': 68, 'submission_guid': '00000000-0000-0000-0000-000000000000', 'type': 'FILE', 'votes': [], 'window_closed': True}], 'status': 'Bounty Awaiting Arbitration', 'uuid': '00000000-0000-0000-0000-000000000000'}, 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.rescan('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].json['result']['status'] == 'Bounty Awaiting Arbitration'

    @responses.activate
    def test_download(self):
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/consumer/download/sha256/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
                                         body=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}/consumer', community='gamma')
        with temp_dir({}) as (path, _):
            result = list(api.download(path, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
            with result[0].result.file_handle as f:
                assert f.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @responses.activate
    def test_stream(self):
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/consumer/download/stream?since=2880',
                                         json={'result': {'stream': ['https://s3folder/malicious', 'https://s3folder/non-malicious']}, 'status': 'OK'}))
        responses.add(responses.Response(responses.GET, 'https://s3folder/malicious',
                                         body=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'))
        responses.add(responses.Response(responses.GET, 'https://s3folder/non-malicious',
                                         body=b'Non malicious'))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with temp_dir({}) as (path, _):
            result = list(api.stream(path))
            with result[0].result.file_handle as f:
                assert f.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            with result[1].result.file_handle as f:
                assert f.read() == b'Non malicious'

    @responses.activate
    def test_hash_search(self):
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/search?type=sha256&hash=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f&with_instances=1&with_metadata=1',
                                         json={'result': [{'artifact_instances': [{'artifact_id': '68527603077936897', 'assertions': [{'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'author_name': 'eicar', 'bid': '1000000000000000000', 'engine': {'description': 'eicar', 'name': 'eicar', 'tags': []}, 'mask': True, 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}, 'verdict': True}], 'bounty_id': '73493387430431', 'bounty_result': {'artifact_type': 'FILE', 'files': [{'assertions': [{'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'author_name': 'eicar', 'bid': '1000000000000000000', 'engine': {'description': 'eicar', 'name': 'eicar', 'tags': []}, 'mask': True, 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}, 'verdict': True}], 'bounty_guid': '843014e7-96da-4513-97cb-3ded3584ab0c', 'bounty_status': 'Bounty Settled', 'failed': False, 'filename': 'malicious', 'hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'id': '36695034110833257', 'result': True, 'size': 68, 'submission_guid': '3dea7f89-18af-4d4c-b7a1-d4dcc981a5fc', 'type': 'FILE', 'votes': [{'arbiter': '0xF870491ea0F53F67846Eecb57855284D8270284D', 'engine': {}, 'vote': True}], 'window_closed': True}], 'status': 'Bounty Settled'}, 'community': 'gamma', 'consumer_guid': None, 'country': '', 'failed': False, 'id': '36695034110833257', 'name': 'malicious', 'result': True, 'submission_uuid': '3dea7f89-18af-4d4c-b7a1-d4dcc981a5fc', 'submitted': 'Fri, 01 Nov 2019 16:33:54 GMT', 'type': 'FILE', 'votes': [{'arbiter': '0xF870491ea0F53F67846Eecb57855284D8270284D', 'engine': {}, 'vote': True}], 'window_closed': True}], 'artifact_metadata': {'hash': {'md5': '44d88612fea8a8f36de82e1278abb02f', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'sha3_256': '8b4c4e204a8a039198e292d2291f4c451d80e4c38bf0cc04ad3841fea8755bd8', 'sha3_512': 'a20290c6ebf01dc5182bb57718250f61ab11b418466714632a7d1474a02849641f7b78e4093e19ad12fdbedbe02f3bec4ca3ec3235557e82ab5ac02d061e7007', 'sha512': 'cc805d5fab1fd71a4ab352a9c533e65fb2d5b885518f4e565e68847223b8e6b85cb48f3afad842726d99239c9e36505c64b0dc9a061d9e507d833277ada336ab', 'ssdeep': '3:a+JraNvsgzsVqSwHq9:tJuOgzsko', 'tlsh': '41a022003b0eee2ba20b00200032e8b00808020e2ce00a3820a020b8c83308803ec228'}, 'scan': {'countries': [], 'detections': {'malicious': 1, 'total': 1}, 'filename': ['malicious'], 'first_scan': {'0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8': {'assertion': 'malicious', 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}}}, 'first_seen': '2019-10-30T22:14:41.035934+00:00', 'last_seen': '2019-10-30T22:14:41.035934+00:00', 'latest_scan': {'0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8': {'assertion': 'malicious', 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}}}, 'mimetype': {'extended': 'EICAR virus test files', 'mime': 'text/plain'}}, 'strings': {'domains': [], 'ipv4': [], 'ipv6': [], 'urls': []}}, 'extended_type': 'EICAR virus test files', 'first_seen': 'Wed, 30 Oct 2019 22:14:41 GMT', 'id': '68527603077936897', 'last_seen': 'Fri, 01 Nov 2019 13:33:54 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}], 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.search('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].result[0].hash.hash == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @responses.activate
    def test_metadata_search(self):
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/search?type=metadata&with_instances=1&with_metadata=1',
                                         json={'result': [{'artifact_instances': [{'artifact_id': '11611818710765483', 'assertions': [{'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'author_name': 'eicar', 'bid': '1000000000000000000', 'engine': {'description': 'eicar', 'name': 'eicar', 'tags': []}, 'mask': True, 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}, 'verdict': True}], 'bounty_id': '27929274698946641', 'bounty_result': {'artifact_type': 'FILE', 'files': [{'assertions': [{'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'author_name': 'eicar', 'bid': '1000000000000000000', 'engine': {'description': 'eicar', 'name': 'eicar', 'tags': []}, 'mask': True, 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}, 'verdict': True}], 'bounty_guid': 'b767ae23-7908-41c7-93dc-b609e4b531b7', 'bounty_status': 'Bounty Settled', 'failed': False, 'filename': 'malicious', 'hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'id': '75963548741299164', 'result': True, 'size': 68, 'submission_guid': 'e2a8542e-196b-41cd-8056-b65a28bb2e3e', 'type': 'FILE', 'votes': [{'arbiter': '0xF870491ea0F53F67846Eecb57855284D8270284D', 'engine': {}, 'vote': True}], 'window_closed': True}], 'status': 'Bounty Settled'}, 'community': 'gamma', 'consumer_guid': None, 'country': '', 'failed': False, 'id': '75963548741299164', 'name': 'malicious', 'result': True, 'submission_uuid': 'e2a8542e-196b-41cd-8056-b65a28bb2e3e', 'submitted': 'Fri, 01 Nov 2019 21:33:53 GMT', 'type': 'FILE', 'votes': [{'arbiter': '0xF870491ea0F53F67846Eecb57855284D8270284D', 'engine': {}, 'vote': True}], 'window_closed': True}], 'artifact_metadata': {'hash': {'md5': '44d88612fea8a8f36de82e1278abb02f', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'sha3_256': '8b4c4e204a8a039198e292d2291f4c451d80e4c38bf0cc04ad3841fea8755bd8', 'sha3_512': 'a20290c6ebf01dc5182bb57718250f61ab11b418466714632a7d1474a02849641f7b78e4093e19ad12fdbedbe02f3bec4ca3ec3235557e82ab5ac02d061e7007', 'sha512': 'cc805d5fab1fd71a4ab352a9c533e65fb2d5b885518f4e565e68847223b8e6b85cb48f3afad842726d99239c9e36505c64b0dc9a061d9e507d833277ada336ab', 'ssdeep': '3:a+JraNvsgzsVqSwHq9:tJuOgzsko', 'tlsh': '41a022003b0eee2ba20b00200032e8b00808020e2ce00a3820a020b8c83308803ec228'}, 'scan': {'countries': [], 'detections': {'malicious': 1, 'total': 1}, 'filename': ['malicious'], 'first_scan': {'0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8': {'assertion': 'malicious', 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}}}, 'first_seen': '2019-11-01T21:33:53.292099+00:00', 'last_seen': '2019-11-01T21:33:53.292099+00:00', 'latest_scan': {'0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8': {'assertion': 'malicious', 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}}}, 'mimetype': {'extended': 'EICAR virus test files', 'mime': 'text/plain'}}, 'strings': {'domains': [], 'ipv4': [], 'ipv6': [], 'urls': []}}, 'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 's3_file_name': 'testing/files/27/5a/02/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}], 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.search_by_metadata('hash.sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].result[0].hash.hash == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @responses.activate
    def test_resolve_engine_name(self):
        responses.add(responses.Response(responses.GET, 'http:/f/localhost:3000/api/{self.api_version}/microengines/list',
                                         json={'results': [{'id': 1, 'createdAt': '2019-11-01T21:27:47.109Z', 'modifiedAt': '2019-11-01T21:27:47.109Z', 'archivedAt': None, 'name': 'eicar', 'description': 'eicar', 'address': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'userId': 1, 'verificationStatus': 'verified', 'tags': []}]}))
        api = PolyswarmAPI(self.test_api_key, uri='http:/f/localhost:3000/api/{self.api_version}', community='gamma')
        result = api._resolve_engine_name('0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8')
        assert result == 'eicar'

    @responses.activate
    def test_live(self):
        responses.add(responses.Response(responses.POST, f'http://localhost:9696/{self.api_version}/hunt/live',
                                         json={'result': {'hunt_id': '0000000000000000'}, 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            result = api.live(yara.read())
        assert result.result.hunt_id == '0000000000000000'

    @responses.activate
    def test_live_results(self):
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/live/results?with_bounty_results=&with_metadata=&limit=3&offset=0&since=0',
                                         json={'result': {'active': True, 'created': 'Mon, 04 Nov 2019 16:03:18 GMT', 'id': '63433636835291189', 'results': [{'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:21 GMT', 'rule_name': 'eicar_substring_test', 'tags': ''}, {'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:21 GMT', 'rule_name': 'eicar_av_test', 'tags': ''}, {'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:18 GMT', 'rule_name': 'eicar_substring_test', 'tags': ''}], 'ruleset_name': None, 'status': 'RUNNING', 'total': 10}, 'status': 'RUNNING'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/live/results?with_bounty_results=&with_metadata=&limit=3&offset=3&since=0',
                                         json={'result': {'active': True, 'created': 'Mon, 04 Nov 2019 16:03:18 GMT', 'id': '63433636835291189', 'results': [{'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:18 GMT', 'rule_name': 'eicar_av_test', 'tags': ''}, {'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:15 GMT', 'rule_name': 'eicar_substring_test', 'tags': ''}, {'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:15 GMT', 'rule_name': 'eicar_av_test', 'tags': ''}], 'ruleset_name': None, 'status': 'RUNNING', 'total': 10}, 'status': 'RUNNING'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/live/results?with_bounty_results=&with_metadata=&limit=3&offset=6&since=0',
                                         json={'result': {'active': True, 'created': 'Mon, 04 Nov 2019 16:03:18 GMT', 'id': '63433636835291189', 'results': [{'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:13 GMT', 'rule_name': 'eicar_substring_test', 'tags': ''}, {'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:13 GMT', 'rule_name': 'eicar_av_test', 'tags': ''}, {'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:01 GMT', 'rule_name': 'eicar_substring_test', 'tags': ''}], 'ruleset_name': None, 'status': 'RUNNING', 'total': 10}, 'status': 'RUNNING'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/live/results?with_bounty_results=&with_metadata=&limit=3&offset=9&since=0',
                                         json={'result': {'active': True, 'created': 'Mon, 04 Nov 2019 16:03:18 GMT', 'id': '63433636835291189', 'results': [{'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 16:08:01 GMT', 'rule_name': 'eicar_av_test', 'tags': ''}], 'ruleset_name': None, 'status': 'RUNNING', 'total': 10}, 'status': 'RUNNING'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/live/results?with_bounty_results=&with_metadata=&limit=3&offset=12&since=0',
                                         json={'result': {'active': True, 'created': 'Mon, 04 Nov 2019 16:03:18 GMT', 'id': '63433636835291189', 'results': [], 'ruleset_name': None, 'status': 'RUNNING', 'total': 10}, 'status': 'RUNNING'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = api.live_results(with_bounty_results=False, with_metadata=False, limit=3)
        assert len(result.result.results) == 10

    @responses.activate
    def test_historical(self):
        responses.add(responses.Response(responses.POST, f'http://localhost:9696/{self.api_version}/hunt/historical',
                                         json={'result': {'hunt_id': '0000000000000000'}, 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            result = api.historical(yara.read())
        assert result.result.hunt_id == '0000000000000000'

    @responses.activate
    def test_historical_results(self):
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/historical/results?with_bounty_results=&with_metadata=&limit=1&offset=0&since=0',
                                         json={'result': {'created': 'Mon, 04 Nov 2019 19:11:37 GMT', 'id': '87727805741550630', 'results': [{'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 19:11:37 GMT', 'rule_name': 'eicar_substring_test', 'tags': ''}], 'ruleset_name': None, 'status': 'SUCCESS', 'total': 2}, 'status': 'SUCCESS'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/historical/results?with_bounty_results=&with_metadata=&limit=1&offset=1&since=0',
                                         json={'result': {'created': 'Mon, 04 Nov 2019 19:11:37 GMT', 'id': '87727805741550630', 'results': [{'artifact': {'extended_type': 'EICAR virus test files', 'first_seen': 'Fri, 01 Nov 2019 21:33:53 GMT', 'id': '11611818710765483', 'last_seen': 'Mon, 04 Nov 2019 13:08:21 GMT', 'md5': '44d88612fea8a8f36de82e1278abb02f', 'mimetype': 'text/plain', 'sha1': '3395856ce81f2b7382dee72602f798b642f14140', 'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}, 'created': 'Mon, 04 Nov 2019 19:11:37 GMT', 'rule_name': 'eicar_av_test', 'tags': ''}], 'ruleset_name': None, 'status': 'SUCCESS', 'total': 2}, 'status': 'SUCCESS'}))
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/historical/results?with_bounty_results=&with_metadata=&limit=1&offset=2&since=0',
                                         json={'result': {'created': 'Mon, 04 Nov 2019 19:11:37 GMT', 'id': '87727805741550630', 'results': [], 'ruleset_name': None, 'status': 'SUCCESS', 'total': 2}, 'status': 'SUCCESS'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = api.historical_results(with_bounty_results=False, with_metadata=False, limit=1)
        assert len(result.result.results) == 2

    @responses.activate
    def test_delete_live(self):
        responses.add(responses.Response(responses.DELETE, f'http://localhost:9696/{self.api_version}/hunt/live?hunt_id=00000000000000000',
                                         json={'result': {'hunt_id': '00000000000000000'}, 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = api.live_delete('00000000000000000')
        assert result.result == '00000000000000000'

    @responses.activate
    def test_delete_live(self):
        responses.add(responses.Response(responses.DELETE, f'http://localhost:9696/{self.api_version}/hunt/historical?hunt_id=00000000000000000',
                                         json={'result': {'hunt_id': '00000000000000000'}, 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = api.historical_delete('00000000000000000')
        assert result.result == '00000000000000000'

    @responses.activate
    def test_list_live(self):
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/live?all=true',
                                         json={'result': [{'active': True, 'created': 'Mon, 04 Nov 2019 16:03:18 GMT', 'id': '63433636835291189', 'results': None, 'ruleset_name': None, 'status': 'RUNNING', 'total': 10}, {'active': False, 'created': 'Fri, 01 Nov 2019 22:37:38 GMT', 'id': '30278416219087863', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'active': False, 'created': 'Fri, 01 Nov 2019 22:35:33 GMT', 'id': '3704780491120403', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'active': False, 'created': 'Fri, 01 Nov 2019 22:34:19 GMT', 'id': '27135338495759590', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'active': False, 'created': 'Fri, 01 Nov 2019 22:33:37 GMT', 'id': '54592556430064812', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}], 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = api.live_list()
        assert len(result.result) == 5

    @responses.activate
    def test_list_historical(self):
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/hunt/historical?all=true',
                                         json={'result': [{'created': 'Mon, 04 Nov 2019 19:11:37 GMT', 'id': '87727805741550630', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 2}, {'created': 'Mon, 04 Nov 2019 18:40:00 GMT', 'id': '47190397989086018', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 34}, {'created': 'Mon, 04 Nov 2019 18:37:43 GMT', 'id': '86866921610782572', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'created': 'Mon, 04 Nov 2019 18:31:07 GMT', 'id': '16122797615766244', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'created': 'Mon, 04 Nov 2019 18:05:10 GMT', 'id': '81709619298806644', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'created': 'Mon, 04 Nov 2019 17:45:14 GMT', 'id': '49537000409407578', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'created': 'Mon, 04 Nov 2019 17:36:03 GMT', 'id': '92075141711091536', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'created': 'Mon, 04 Nov 2019 17:34:50 GMT', 'id': '16213998657109226', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'created': 'Mon, 04 Nov 2019 17:34:25 GMT', 'id': '46124705929143681', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'created': 'Mon, 04 Nov 2019 17:34:17 GMT', 'id': '17264462171967388', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}, {'created': 'Mon, 04 Nov 2019 17:33:40 GMT', 'id': '13903550507680813', 'results': None, 'ruleset_name': None, 'status': 'SUCCESS', 'total': 0}], 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = api.historical_list()
        assert len(result.result) == 11

    @responses.activate
    def test_list_historical(self):
        responses.add(responses.Response(responses.GET, f'http://localhost:9696/{self.api_version}/consumer/submission/6eadcabe-9f9e-4301-8e60-c9e58504c325/polyscore',
                                         json={'result': {'scores': {'77090327141458166': 0.9999682631387563}}, 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.score('6eadcabe-9f9e-4301-8e60-c9e58504c325'))
        assert result[0].result.scores['77090327141458166'] == 0.9999682631387563
