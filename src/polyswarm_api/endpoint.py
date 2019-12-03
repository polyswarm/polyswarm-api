import logging
import json
from future.utils import raise_from
from concurrent import futures
from copy import deepcopy

from . import const
from . import http
from . import exceptions
from .types import resources

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


logger = logging.getLogger(__name__)


class RequestParamsEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            return json.JSONEncoder.default(self, obj)
        except Exception:
            return str(obj)


class PolyswarmRequest(object):
    """This class holds a requests-compatible dictionary and extra information we need to parse the response."""
    def __init__(self, api_instance, request_parameters, key=None, result_parser=None, json_response=True, **kwargs):
        self.api_instance = api_instance
        # we should not access the api_instance session directly, but provide as a
        # parameter in the constructor, but this will do for the moment
        self.session = self.api_instance.session or http.PolyswarmHTTP(key, retries=const.DEFAULT_RETRIES)
        self.request_parameters = request_parameters
        self.result_parser = result_parser
        self.json_response = json_response
        self.raw_result = None
        self.status_code = None
        self.status = None
        self.result = None
        self.errors = None
        self.total = None
        self.limit = None
        self.offset = None
        self.order_by = None
        self.direction = None
        self.parser_kwargs = kwargs
        self._exception = None

    def execute(self):
        self.raw_result = self.session.request(**self.request_parameters)
        if self.result_parser is not None:
            self.parse_result(self.raw_result)
        return self

    def _bad_status_message(self):
        return "Request:\n{}\n" \
               "Got unexpected result code: {}\n" \
               "Message: {}".format(json.dumps(self.request_parameters, indent=4,
                                               sort_keys=True, cls=RequestParamsEncoder),
                                    self.status_code,
                                    self.result)

    def _extract_json_body(self, result):
        self.json = result.json()
        self.result = self.json.get('result')
        self.status = self.json.get('status')
        self.errors = self.json.get('errors')

    def parse_result(self, result):
        self.status_code = result.status_code
        try:
            if self.status_code // 100 != 2:
                self._extract_json_body(result)
                if self.status_code == 429:
                    raise exceptions.UsageLimitsExceededException(self, const.USAGE_EXCEEDED_MESSAGE)
                if self.status_code == 404:
                    raise exceptions.NotFoundException(self, self.result)
                raise exceptions.RequestFailedException(self, self._bad_status_message())
            else:
                if self.json_response:
                    self._extract_json_body(result)
                    self.total = self.json.get('total')
                    self.limit = self.json.get('limit')
                    self.offset = self.json.get('offset')
                    self.order_by = self.json.get('order_by')
                    self.direction = self.json.get('direction')
                    if 'result' in self.json:
                        result = self.json['result']
                    elif 'results' in self.json:
                        result = self.json['results']
                    else:
                        raise exceptions.RequestFailedException(
                            self,
                            'The response standard must contain either the "result" or "results" key.'
                        )
                    if isinstance(result, list):
                        self.result = self.result_parser.parse_result_list(self.api_instance, result, **self.parser_kwargs)
                    else:
                        self.result = self.result_parser.parse_result(self.api_instance, result, **self.parser_kwargs)
                else:
                    self.result = self.result_parser.parse_result(self.api_instance, result, **self.parser_kwargs)
        except JSONDecodeError as e:
            if self.status_code == 404:
                raise raise_from(exceptions.NotFoundException(self, 'The requested endpoint does not exist.'), e)
            else:
                raise raise_from(exceptions.RequestFailedException(self, 'Server returned non-JSON response.'), e)

    def __iter__(self):
        return self.consume_results()

    def consume_results(self):
        request = self
        while True:
            # consume items items from list if iterable
            # of yield the single result if not
            try:
                for result in request.result:
                    yield result
            except TypeError:
                yield request.result

            # StopIteration is deprecated
            # As per https://www.python.org/dev/peps/pep-0479/
            # We simply return upon termination condition
            if request._exception is not None:
                return
            # if the result is not a list, there is not next page
            if not isinstance(request.result, list):
                return
            # if the list does not fill the page, stop
            if len(request.result) < request.limit:
                return

            # try to get the next page and execute the request
            request = request.next_page().execute()

    def next_page(self):
        new_parameters = deepcopy(self.request_parameters)
        new_parameters.setdefault('params', {})['offset'] = self.offset
        new_parameters.setdefault('params', {})['limit'] = self.limit
        new_parameters['params']['offset'] += new_parameters['params']['limit']
        return PolyswarmRequest(
            self.api_instance,
            new_parameters,
            result_parser=self.result_parser,
        )


class PolyswarmRequestGenerator(object):
    """ This class will return PolyswarmRequests"""
    def __init__(self, api_instance):
        self.api_instance = api_instance
        self.uri = api_instance.uri
        self.community = api_instance.community

    def download(self, hash_value, hash_type, output_file, create=False):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/download/{}/{}'.format(self.uri, hash_type, hash_value),
                'stream': True,
            },
            json_response=False,
            result_parser=resources.LocalArtifact,
            output_file=output_file,
            create=create,
        )

    def download_archive(self, u, output_file, create=False):
        """ This method is special, in that it is simply for downloading from S3 """
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': u,
                'stream': True,
                'headers': {'Authorization': None}
            },
            json_response=False,
            result_parser=resources.LocalArtifact,
            output_file=output_file,
            create=create,
        )

    def stream(self, since=const.MAX_SINCE_TIME_STREAM):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/consumer/download/stream'.format(self.uri),
                'params': {'since': since},
            },
            result_parser=resources.ArtifactArchive,
        )

    def search_hash(self, h):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/search'.format(self.uri),
                'params': {
                    'type': h.hash_type,
                    'hash': h.hash,
                },
            },
            result_parser=resources.ArtifactInstance,
        )

    def search_metadata(self, q):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/search'.format(self.uri),
                'params': {
                    'type': 'metadata',
                },
                'json': q.query,
            },
            result_parser=resources.ArtifactInstance,
        )

    def submit(self, artifact):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/consumer/submission/{}'.format(self.uri, self.community),
                'files': {
                    'file': (artifact.artifact_name, artifact.open()),
                },
                # very oddly, when included in files parameter this errors out
                'data': {'artifact-type': artifact.artifact_type.name}
            },
            result_parser=resources.ArtifactInstance,
        )

    def rescan(self, h):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/consumer/submission/{}/rescan/{}/{}'.format(self.uri, self.community, h.hash_type, h.hash),
            },
            result_parser=resources.ArtifactInstance,
        )

    def lookup_uuid(self, submission_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/consumer/submission/{}/{}'.format(self.uri, self.community, submission_id),
            },
            result_parser=resources.ArtifactInstance,
        )

    def _get_engine_names(self):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/microengines/list'.format(self.uri),
                'headers': {'Authorization': None},
            },
            result_parser=resources.Engine,
        )

    def create_live_hunt(self, rule):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/hunt/live'.format(self.uri),
                'json': {'yara': rule.ruleset},
            },
            result_parser=resources.Hunt,
        )

    def get_live_hunt(self, hunt_id=None):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/hunt/live'.format(self.uri),
                'params': {
                    'id': hunt_id,
                },
            },
            result_parser=resources.Hunt,
        )

    def update_live_hunt(self, hunt_id=None, active=False):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'PUT',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/hunt/live'.format(self.uri),
                'json': {
                    'id': hunt_id,
                    'active': active,
                },
            },
            result_parser=resources.Hunt,
        )

    def delete_live_hunt(self, hunt_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'DELETE',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/hunt/live'.format(self.uri),
                'params': {'id': hunt_id}
            },
            result_parser=resources.Hunt,
        )

    def live_list(self):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/hunt/live/list'.format(self.uri),
                'params': {'all': 'true'},
            },
            result_parser=resources.Hunt,
        )

    def live_hunt_results(self, hunt_id=None, since=None):
        req = {
            'method': 'GET',
            'timeout': const.DEFAULT_HTTP_TIMEOUT,
            'url': '{}/hunt/live/results'.format(self.uri),
            'params': {
                'since': since,
                'id': hunt_id,
            },
        }
        return PolyswarmRequest(
            self.api_instance,
            req,
            result_parser=resources.HuntResult,
        )

    def create_historical_hunt(self, rule):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/hunt/historical'.format(self.uri),
                'json': {'yara': rule.ruleset},
            },
            result_parser=resources.Hunt,
        )

    def get_historical_hunt(self, hunt_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/hunt/historical'.format(self.uri),
                'params': {'id': hunt_id}
            },
            result_parser=resources.Hunt,
        )

    def delete_historical_hunt(self, hunt_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'DELETE',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/hunt/historical'.format(self.uri),
                'params': {'id': hunt_id}
            },
            result_parser=resources.Hunt,
        )

    def historical_list(self):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/hunt/historical/list'.format(self.uri),
                'params': {'all': 'true'},
            },
            result_parser=resources.Hunt,
        )

    def historical_hunt_results(self, hunt_id=None):
        req = {
            'method': 'GET',
            'timeout': const.DEFAULT_HTTP_TIMEOUT,
            'url': '{}/hunt/historical/results'.format(self.uri),
            'params': {
                'id': hunt_id,
            },
        }
        return PolyswarmRequest(
            self.api_instance,
            req,
            result_parser=resources.HuntResult,
        )

    def score(self, submission_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/consumer/polyscore/{}'.format(
                    self.uri, submission_id
                )
            },
            result_parser=resources.PolyScore,
        )


class PolyswarmRequestExecutor(object):
    """ This class accepts requests from a PolyswarmRequestGenerator and executes it """
    def __init__(self):
        self.requests = []

    def push(self, request):
        raise NotImplementedError()

    def execute(self):
        raise NotImplementedError()


class PolyswarmFuturesExecutor(PolyswarmRequestExecutor):
    def __init__(self):
        self.executor = futures.ThreadPoolExecutor(const.DEFAULT_WORKER_COUNT)
        super(PolyswarmFuturesExecutor, self).__init__()

    def push(self, request):
        self.requests.append(self.executor.submit(request.execute))
        return self

    def execute(self, as_completed=False):
        requests = self.requests
        # flush before looping in case we have nested executions
        self.requests = []
        if as_completed:
            for future in futures.as_completed(requests):
                yield future.result()
        else:
            futures.wait(requests)
            for request in requests:
                yield request.result()


class PolyswarmSynchronousExecutor(PolyswarmRequestExecutor):
    def push(self, request):
        self.requests.append(request)

    def execute(self):
        responses = []
        for request in self.requests:
            responses.append(request.execute())
        self.requests = []
        return responses
