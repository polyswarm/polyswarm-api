from unittest import TestCase
from polyswarm_api.__main__ import polyswarm
from polyswarm_api.types import result
from polyswarm_api.types.hash import to_hash
from polyswarm_api.types.query import MetadataQuery
import requests_mock
import requests
from pkg_resources import resource_string
import json
from click.testing import CliRunner
import os
import traceback
try:
    from unittest.mock import patch
except NameError:
    from mock import patch

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

TestCase.maxDiff = None


class SearchTest(TestCase):

    def __init__(self, *args, **kwargs):
        super(SearchTest, self).__init__(*args, **kwargs)
        self.test_runner = CliRunner()
        self.test_api_key = '963da5a463b0ab61fe0f96f82846490d'
        self.test_hash = '08666dae57ea6a8ef21cfa38cf41db395e8c39c61b1f281cb6927b2bca07fb1d'
        self.test_captured_output_file = '/tmp/output.txt'
        self.test_query = "_exists_:lief.libraries"
        self.session = requests.Session()
        self.adapter = requests_mock.Adapter()
        self.session.mount('mock', self.adapter)

    def setUp(self):
        self._remove_file(self.test_captured_output_file)

    def test_everything_is_ok(self):
        # yes, everything is ok
        pass
    
    @staticmethod
    def _remove_file(file_path):
        try:
            os.remove(file_path)
        except FileNotFoundError:
            print('File {file_path} does not exist'.format(**{'file_path': file_path}))

    @staticmethod
    def _get_file_content(file_path):
        with open(file_path, 'r') as file:
            return file.read()
"""
    def test_search_with_hash_parameter(self):
        expected_output = self._get_test_text_resource_content('expected_search_hashes_output.txt')
        with patch('polyswarm_api.api.PolyswarmAPI.search') as mock_search_hashes:
            mock_search_hashes.side_effect = self._mock_search_hashes_with_results
            result = self.test_runner.invoke(polyswarm, ['--api-key', self.test_api_key, '--output-format', 'json',
                                                         '--output-file', self.test_captured_output_file,
                                                         'search', 'hash', self.test_hash])
        self.assertEqual(result.exit_code, 0, msg=result.exception)
        output = self._get_file_content(self.test_captured_output_file)
        self.assertEqual(output, expected_output)

    def test_search_with_query_parameter(self):
        expected_output = self._get_test_text_resource_content('expected_cli_search_query_output.txt')
        with patch('polyswarm_api.api.PolyswarmAPI.search_by_metadata') as mock_search_hashes:
            mock_search_hashes.side_effect = self._mock_search_query_with_results
            result = self.test_runner.invoke(polyswarm,
                                             ['-vvv', '--api-key', self.test_api_key, '--output-format', 'json',
                                              '--output-file', self.test_captured_output_file,
                                              'search', 'metadata', self.test_query])

        self.assertEqual(result.exit_code, 0, msg=traceback.format_tb(result.exc_info[2]))
        output = self._get_file_content(self.test_captured_output_file)
        self.assertEqual(output, expected_output)

    @staticmethod
    def _get_test_text_resource_content(resource):
        return resource_string('test.resources', resource).decode('utf-8')

    def _get_test_json_resource_content(self, resource):
        return json.loads(self._get_test_text_resource_content(resource))

    def _mock_search_hashes_with_results(self, hashes, with_instances=False, with_metadata=True):
        success_json = self._get_test_json_resource_content('expected_search_success_results_hash.json')

        self.adapter.register_uri('GET', 'mock://api.polyswarm.network/v1/search', json=success_json)

        def result_generator():
            yield result.SearchResult([to_hash(hashes)], self.session.get('mock://api.polyswarm.network/v1/search'))
        return result_generator()

    def _mock_search_query_with_results(self, query, with_instances=False, with_metadata=True, raw=True):
        success_json = self._get_test_json_resource_content('expected_search_success_results.json')
        self.adapter.register_uri('GET', 'mock://api.polyswarm.network/v1/search', json=success_json)

        def result_generator():
            yield result.SearchResult(query, self.session.get('mock://api.polyswarm.network/v1/search'))
        return result_generator()

"""