import os
import tempfile
from contextlib import contextmanager

import responses
from polyswarm_api.api import PolyswarmAPI

try:
    from unittest import TestCase, mock
except ImportError:
    import mock

FILE_SUBMISSION_RESULT = {
    'files': [
        {
            'assertions': [
                {
                    'author': '0x0000000000000000000000000000000000000000',
                    'bid': 500000000000000000,
                    'engine': '0x0000000000000000000000000000000000000000',
                    'mask': True,
                    'metadata': {'malware_family': '',
                                 'scanner': {'environment': {'architecture': 'x86_64',
                                                             'operating_system': 'Linux'}}},
                    'verdict': False
                }
            ],
            'bounty_guid': '00000000-0000-0000-0000-000000000001',
            'bounty_status': 'Awaiting arbitration.',
            'failed': False,
            'filename': 'test1',
            'hash': '0000000000000000000000000000000000000000000000000000000000000000',
            'result': None,
            'size': 3,
            'submission_guid': '00000000-0000-0000-0000-000000000000',
            'votes': [],
            'window_closed': True
        },
        {'assertions': [
            {
                'author': '0x0000000000000000000000000000000000000000',
                'bid': 500000000000000000,
                'engine': '0x0000000000000000000000000000000000000000',
                'mask': True,
                'metadata': {'malware_family': 'Test File',
                             'scanner': {'environment': {'architecture': 'x86_64',
                                                         'operating_system': 'Linux'}}},
                'verdict': True
            }
        ],
            'bounty_guid': '00000000-0000-0000-0000-000000000002',
            'bounty_status': 'Awaiting arbitration.',
            'failed': False,
            'filename': 'test2',
            'hash': '0000000000000000000000000000000000000000000000000000000000000000',
            'result': None,
            'size': 3,
            'submission_guid': '00000000-0000-0000-0000-000000000000',
            'votes': [],
            'window_closed': True
        }
    ],
    'forced': True,
    'permalink': 'https://polyswarm.network/scan/results/00000000-0000-0000-0000-000000000000',
    'status': 'OK',
    'uuid': '00000000-0000-0000-0000-000000000000'
}

URL_SUBMISSION_RESULT = FILE_SUBMISSION_RESULT


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


class ScanTestCase(TestCase):
    def __init__(self, *args, **kwargs):
        super(ScanTestCase, self).__init__(*args, **kwargs)
        self.test_api_key = '11111111111111111111111111111111'

    def test_everything_is_ok(self):
        pass

    @responses.activate
    def test_submission(self):
        responses.add(responses.Response(responses.POST, 'http://localhost:9696/v1/consumer/gamma',
                                         json={'result': '00000000-0000-0000-0000-000000000000', 'status': 'OK'}))
        responses.add(responses.Response(responses.GET, 'http://localhost:9696/v1/consumer/gamma/uuid/00000000-0000-0000-0000-000000000000',
                                         json={'result': {'files': [{'assertions': [], 'bounty_guid': None, 'bounty_status': 'Created', 'failed': False, 'filename': 'malicious', 'hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'id': '36695034110833257', 'result': None, 'size': 68, 'submission_guid': '00000000-0000-0000-0000-000000000000', 'type': 'FILE', 'votes': [], 'window_closed': False}], 'status': 'Bounty Running', 'uuid': '00000000-0000-0000-0000-000000000000'}, 'status': 'OK'}))
        responses.add(responses.Response(responses.GET, 'http://localhost:9696/v1/consumer/gamma/uuid/00000000-0000-0000-0000-000000000000',
                                         json={'result': {'files': [{'assertions': [{'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'author_name': 'eicar', 'bid': '1000000000000000000', 'engine': {'description': 'eicar', 'name': 'eicar', 'tags': []}, 'mask': True, 'metadata': {'malware_family': 'Eicar Test File', 'scanner': {'environment': {'architecture': 'x86_64', 'operating_system': 'Linux'}}}, 'verdict': True}], 'bounty_guid': '843014e7-96da-4513-97cb-3ded3584ab0c', 'bounty_status': 'Awaiting arbitration.', 'failed': False, 'filename': 'malicious', 'hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'id': '36695034110833257', 'result': None, 'size': 68, 'submission_guid': '00000000-0000-0000-0000-000000000000', 'type': 'FILE', 'votes': [], 'window_closed': True}], 'status': 'Bounty Awaiting Arbitration', 'uuid': '00000000-0000-0000-0000-000000000000'}, 'status': 'OK'}))
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v1', community='gamma')
        result = list(api.scan('test/malicious'))
        assert result[0].json['result']['status'] == 'Bounty Awaiting Arbitration'

    @responses.activate
    def test_download(self):
        responses.add(responses.Response(responses.GET, 'http://localhost:9696/v1/consumer/download/sha256/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
                                         body=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'))
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v1/consumer', community='gamma')
        with temp_dir({}) as (path, _):
            result = list(api.download(path, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
            with result[0].result.file_handle as f:
                assert f.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @responses.activate
    def test_stream(self):
        responses.add(responses.Response(responses.GET, 'http://localhost:9696/v1/consumer/download/stream?since=1440',
                                         json={'result': {'stream': ['https://s3folder/malicious', 'https://s3folder/non-malicious']}, 'status': 'OK'}))
        responses.add(responses.Response(responses.GET, 'https://s3folder/malicious',
                                         body=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'))
        responses.add(responses.Response(responses.GET, 'https://s3folder/non-malicious',
                                         body=b'Non malicious'))
        api = PolyswarmAPI(self.test_api_key, uri='http://localhost:9696/v1', community='gamma')
        with temp_dir({}) as (path, _):
            result = list(api.stream(path))
            with result[0].result.file_handle as f:
                assert f.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            with result[1].result.file_handle as f:
                assert f.read() == b'Non malicious'


    # def test_url_request_failed_exception(self):
    #     client = PolyswarmAPI(self.test_api_key)
    #     urls = ['google.com', 'polyswarm.io']
    #     error_msg = ', '.join(urls)
    #     with mock.patch('polyswarm_api.PolyswarmAsyncAPI._post_artifacts',
    #                     side_effect=exceptions.RequestFailedException(error_msg)):
    #         results = client.scan_urls(urls)
    #         assert results == {'filename': error_msg, 'files': [], 'result': 'error', 'status': 'error'}
    #
    # def test_file_request_failed_exception(self):
    #     client = PolyswarmAPI(self.test_api_key)
    #     with temp_dir({'test1': '123', 'test2': '456'}) as (_, files):
    #         error_msg = ', '.join(files)
    #         with mock.patch('polyswarm_api.PolyswarmAsyncAPI._post_artifacts',
    #                         side_effect=exceptions.RequestFailedException(error_msg)):
    #             results = client.scan(files)
    #             assert results == {'filename': error_msg, 'files': [], 'result': 'error', 'status': 'error'}
    #
    # def test_file_request_successful(self):
    #     client = PolyswarmAPI(self.test_api_key)
    #     with temp_dir({'test1': '123', 'test2': '456'}) as (_, files):
    #         with mock.patch(
    #                 'polyswarm_api.PolyswarmAsyncAPI._post_artifacts',
    #                 return_value={
    #                     'status': 'OK',
    #                     'result': '00000000-0000-0000-0000-000000000000'}
    #         ), mock.patch(
    #             'polyswarm_api.PolyswarmAsyncAPI.lookup_uuid',
    #             return_value=FILE_SUBMISSION_RESULT
    #         ):
    #             results = client.scan(files)
    #             assert results == [FILE_SUBMISSION_RESULT]
    #
    # def test_url_request_successful(self):
    #     client = PolyswarmAPI(self.test_api_key)
    #     urls = ['google.com', 'polyswarm.io']
    #     with mock.patch(
    #             'polyswarm_api.PolyswarmAsyncAPI._post_artifacts',
    #             return_value=async_return({
    #                 'status': 'OK',
    #                 'result': '00000000-0000-0000-0000-000000000000'})
    #     ), mock.patch(
    #         'polyswarm_api.PolyswarmAsyncAPI.lookup_uuid',
    #         return_value=URL_SUBMISSION_RESULT
    #     ):
    #         results = client.scan_urls(urls)
    #         assert results == [URL_SUBMISSION_RESULT]
