from polyswarm_api.api import PolyswarmAPI
from test.utils import PolyApiBaseTestCase

try:
    from unittest.mock import patch
except NameError:
    from mock import patch

"""
class SearchQueryTestCase(PolyApiBaseTestCase):

    def get_application(self):
        def success_response(request):
            del request
            response = self._get_test_text_resource('search_query_server_success_response.json')
            return web.Response(text=response, content_type='application/json')

        def non_json_response(request):
            del request
            return web.Response(text='Definitely NOT JSON')

        def not_found_response(request):
            del request
            response = self._get_test_text_resource('search_query_server_success_empty_response.json')
            return web.Response(text=response, content_type='application/json')

        def invalid_query_response(request):
            del request
            return web.Response(text='Search query is not valid', status=400)

        app = web.Application()
        app.router.add_get('/v1/search', success_response)
        app.router.add_get('/v2/search', not_found_response)
        app.router.add_get('/v3/search', invalid_query_response)
        app.router.add_get('/v4/search', non_json_response)
        return app

    def test_search_query(self):
        test_uri = 'http://localhost:{}/v1'.format(self.server.port)
        test_client = PolyswarmAPI(self.test_api_key, uri=test_uri)
        expected_results = self._get_test_json_resource('expected_search_success_results.json')
        results = test_client.search(self.test_query)
        self.assertDictEqual(results, expected_results)

    def test_search_query_not_found_from_server(self):
        test_uri = 'http://localhost:{}/v2'.format(self.server.port)
        test_client = PolyswarmAPI(self.test_api_key, uri=test_uri)
        expected_results = self._get_test_json_resource('expected_search_query_not_found_results.json')
        results = test_client.search(self.test_query)
        self.assertDictEqual(results, expected_results)

    def test_search_query_invalid_query_from_server(self):
        test_uri = 'http://localhost:{}/v3'.format(self.server.port)
        test_client = PolyswarmAPI(self.test_api_key, uri=test_uri)

        with patch('polyswarm_api.logger.error') as mock_logger_error:
            test_client.search(self.test_query)
        self.assertEqual(mock_logger_error.call_args[0][0], 'Server request failed: %s')
        self.assertEqual(str(mock_logger_error.call_args[0][1]),
                         'Received non-json response from PolySwarm API: Search query is not valid')

    def test_search_query_non_json_response_from_server(self):
        test_uri = 'http://localhost:{}/v4'.format(self.server.port)
        test_client = PolyswarmAPI(self.test_api_key, uri=test_uri)
        expected_results = self._get_test_json_resource('expected_search_query_non_json_results.json')
        with patch('polyswarm_api.logger.error') as mock_logger_error:
            results = test_client.search(self.test_query)
        self.assertEqual(mock_logger_error.call_args[0][0], 'Server request failed: %s')
        self.assertEqual(str(mock_logger_error.call_args[0][1]),
                         'Received non-json response from PolySwarm API: Definitely NOT JSON')
        self.assertDictEqual(results, expected_results)
"""