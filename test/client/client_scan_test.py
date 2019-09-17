import os
import tempfile
from contextlib import contextmanager
import asyncio

from polyswarm_api import PolyswarmAPI
from polyswarm_api import exceptions
from unittest import TestCase, mock

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


def async_return(result):
    f = asyncio.Future()
    f.set_result(result)
    return f


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
        self.test_api_key = '00000000000000000000000000000000'

    def test_url_request_failed_exception(self):
        client = PolyswarmAPI(self.test_api_key)
        urls = ['google.com', 'polyswarm.io']
        error_msg = ', '.join(urls)
        with mock.patch('polyswarm_api.PolyswarmAsyncAPI._post_artifacts',
                        side_effect=exceptions.RequestFailedException(error_msg)):
            results = client.scan_urls(urls)
            assert results == {'filename': error_msg, 'files': [], 'result': 'error', 'status': 'error'}

    def test_file_request_failed_exception(self):
        client = PolyswarmAPI(self.test_api_key)
        with temp_dir({'test1': '123', 'test2': '456'}) as (_, files):
            error_msg = ', '.join(files)
            with mock.patch('polyswarm_api.PolyswarmAsyncAPI._post_artifacts',
                            side_effect=exceptions.RequestFailedException(error_msg)):
                results = client.scan_files(files)
                assert results == {'filename': error_msg, 'files': [], 'result': 'error', 'status': 'error'}

    def test_file_request_successful(self):
        client = PolyswarmAPI(self.test_api_key)
        with temp_dir({'test1': '123', 'test2': '456'}) as (_, files):
            with mock.patch(
                    'polyswarm_api.PolyswarmAsyncAPI._post_artifacts',
                    return_value=async_return({
                        'status': 'OK',
                        'result': '00000000-0000-0000-0000-000000000000'})
            ), mock.patch(
                'polyswarm_api.PolyswarmAsyncAPI.lookup_uuid',
                return_value=async_return(FILE_SUBMISSION_RESULT)
            ):
                results = client.scan_files(files)
                assert results == [FILE_SUBMISSION_RESULT]

    def test_url_request_successful(self):
        client = PolyswarmAPI(self.test_api_key)
        urls = ['google.com', 'polyswarm.io']
        with mock.patch(
                'polyswarm_api.PolyswarmAsyncAPI._post_artifacts',
                return_value=async_return({
                    'status': 'OK',
                    'result': '00000000-0000-0000-0000-000000000000'})
        ), mock.patch(
            'polyswarm_api.PolyswarmAsyncAPI.lookup_uuid',
            return_value=async_return(URL_SUBMISSION_RESULT)
        ):
            results = client.scan_urls(urls)
            assert results == [URL_SUBMISSION_RESULT]
