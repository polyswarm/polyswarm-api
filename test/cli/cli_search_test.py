from unittest import TestCase
from polyswarm_api.__main__ import polyswarm
from pkg_resources import resource_string
import json
from click.testing import CliRunner
import os

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

    def setUp(self):
        self._remove_file(self.test_captured_output_file)

    def test_search_with_hash_parameter(self):
        expected_output = self._get_test_text_resource_content('expected_search_hashes_output.txt')
        with patch('polyswarm_api.PolyswarmAPI.search_hashes') as mock_search_hashes:
            mock_search_hashes.side_effect = self._mock_search_hashes_with_results
            result = self.test_runner.invoke(polyswarm, ['--api-key', self.test_api_key, '--output-format', 'json',
                                                         '--output-file', self.test_captured_output_file,
                                                         'search', 'hash', self.test_hash])
        self.assertEqual(result.exit_code, 0)
        output = self._get_file_content(self.test_captured_output_file)
        self.assertEqual(output, expected_output)

    def test_search_with_query_parameter(self):
        expected_output = self._get_test_text_resource_content('expected_cli_search_query_output.txt')
        with patch('polyswarm_api.PolyswarmAPI.search_query') as mock_search_hashes:
            mock_search_hashes.side_effect = self._mock_search_query_with_results
            result = self.test_runner.invoke(polyswarm,
                                             ['-vvv', '--api-key', self.test_api_key, '--output-format', 'json',
                                              '--output-file', self.test_captured_output_file,
                                              'search', 'metadata', self.test_query])

        self.assertEqual(result.exit_code, 0, msg=result.exception)
        output = self._get_file_content(self.test_captured_output_file)
        self.assertEqual(output, expected_output)

    @staticmethod
    def _get_test_text_resource_content(resource):
        return resource_string('test.resources', resource).decode('utf-8')

    def _get_test_json_resource_content(self, resource):
        return json.loads(self._get_test_text_resource_content(resource))

    def _mock_search_hashes_with_results(self, hashes, hash_type):
        del hashes, hash_type
        return self._get_test_json_resource_content('expected_search_success_results_hash.json')

    def _mock_search_query_with_results(self, query, raw=True):
        del query
        return self._get_test_json_resource_content('expected_search_success_results.json')

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
