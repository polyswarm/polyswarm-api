from aiohttp import web
from polyswarm_api import PolyswarmAPI
from test.utils import PolyApiBaseTestCase
from unittest.mock import patch
from urllib import parse
import json


class SearchQueryTestCase(PolyApiBaseTestCase):

    async def get_application(self):
        async def success_response(request):
            del request
            response = self._get_test_text_resource('search_query_server_success_response.json')
            return web.Response(text=response, content_type='application/json')

        async def non_json_response(request):
            del request
            return web.Response(text='Definitely NOT JSON')

        async def not_found_response(request):
            del request
            return web.Response(text='Search query didn\'t return any results', status=404)

        async def invalid_query_response(request):
            del request
            return web.Response(text='Search query is not valid', status=400)

        app = web.Application()
        query = parse.quote(json.dumps(self.test_query))
        app.router.add_get('/v1/search/query/{}'.format(query), success_response)
        app.router.add_get('/v2/search/query/{}'.format(query), not_found_response)
        app.router.add_get('/v3/search/query/{}'.format(query), invalid_query_response)
        app.router.add_get('/v4/search/query/{}'.format(query), non_json_response)
        return app

    def test_search_query(self):
        test_uri = 'http://localhost:{}/v1'.format(self.server.port)
        test_client = PolyswarmAPI(self.test_api_key, uri=test_uri)
        expected_results = self._get_test_json_resource('expected_search_success_results.json')
        results = test_client.search_query(self.test_query)
        self.assertDictEqual(results, expected_results)

    def test_search_query_not_found_from_server(self):
        test_uri = 'http://localhost:{}/v2'.format(self.server.port)
        test_client = PolyswarmAPI(self.test_api_key, uri=test_uri)
        expected_results = self._get_test_json_resource('expected_search_query_not_found_results.json')
        results = test_client.search_query(self.test_query)
        self.assertDictEqual(results, expected_results)


    def test_search_query_invalid_query_from_server(self):
        test_uri = 'http://localhost:{}/v3'.format(self.server.port)
        test_client = PolyswarmAPI(self.test_api_key, uri=test_uri)

        with patch('polyswarm_api.logger.error') as mock_logger_error:
            test_client.search_query(self.test_query)

        self.assertEqual(str(mock_logger_error.call_args[0][0]),
                         'Error reading from PolySwarm API: Search query is not valid')

    def test_search_query_non_json_response_from_server(self):
        test_uri = 'http://localhost:{}/v4'.format(self.server.port)
        test_client = PolyswarmAPI(self.test_api_key, uri=test_uri)
        expected_results = self._get_test_json_resource('expected_search_query_non_json_results.json')
        with patch('polyswarm_api.logger.error') as mock_logger_error:
            results = test_client.search_query(self.test_query)

        print(mock_logger_error.call_args[0][0])

        self.assertEqual(str(mock_logger_error.call_args[0][0]),
                         'Received non-json response from PolySwarm API: Definitely NOT JSON')
