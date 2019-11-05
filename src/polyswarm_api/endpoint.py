from concurrent import futures
from copy import deepcopy

from . import const
from . import utils
from . import http
from .types import result


class PolyswarmRequest(object):
    """This class holds a requests-compatible dictionary and extra infor we need to parse the reponse."""
    def __init__(self, api_instance, request_parameters, result=None):
        self.api_instance = api_instance
        self.request_parameters = request_parameters
        self.result = result
        self.raw_result = None

    def next_page(self):
        new_parameters = deepcopy(self.request_parameters)
        new_parameters['params']['offset'] += new_parameters['params']['limit']
        return PolyswarmRequest(
            self.api_instance,
            new_parameters,
            result=self.result,
        )


class PolyswarmRequestGenerator(object):
    """ This class will return requests-compatible arguments for the API """
    def __init__(self, api_instance, uri, community):
        self.api_instance = api_instance
        self.uri = uri
        self.community = community

        self.consumer_base = '{uri}/consumer'.format(uri=self.uri)
        self.search_base = '{uri}/search'.format(uri=self.uri)
        self.download_base = '{uri}/download'.format(uri=self.uri)
        self.community_base = '{consumer_uri}/{community}'.format(consumer_uri=self.consumer_base, community=community)
        self.hunt_base = '{uri}/hunt'.format(uri=self.uri)
        self.stream_base = '{uri}/download/stream'.format(uri=self.uri)

        self.download_fmt = '{}/{}/{}'
        self.hash_search_fmt = '{}/{}/{}'

    def download(self, hash_value, hash_type, output_file, file_handle=None, create=False):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': self.download_fmt.format(self.download_base, hash_type, hash_value),
                'stream': True,
            },
            result=result.DownloadResult(output_file, polyswarm=self.api_instance,
                                         file_handle=file_handle, create=create),
        )

    def download_archive(self, u, output_file, file_handle=None, create=False):
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
            result=result.DownloadResult(output_file, polyswarm=self.api_instance,
                                         file_handle=file_handle, create=create),
        )

    def stream(self, since=const.MAX_SINCE_TIME_STREAM):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/download/stream'.format(self.consumer_base),
                'params': {'since': since},
            },
            result=result.StreamResult()
        )

    def search_hash(self, h, with_instances=True, with_metadata=True):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': self.search_base,
                'params': {
                    'type': h.hash_type,
                    'hash': h.hash,
                    'with_instances': utils.bool_to_int[with_instances],
                    'with_metadata': utils.bool_to_int[with_metadata]
                },
            },
            result=result.SearchResult(h),
        )

    def search_metadata(self, q, with_instances=True, with_metadata=True):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': self.search_base,
                'params': {
                    'type': 'metadata',
                    'with_instances': utils.bool_to_int[with_instances],
                    'with_metadata': utils.bool_to_int[with_metadata]
                },
                'json': q.query,
            },
            result=result.SearchResult(q),
        )

    def submit(self, artifact):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': self.community_base,
                'files': {
                    'file': (artifact.artifact_name, artifact.file_handle),
                },
                # very oddly, when included in files parameter this errors out
                'data': {'artifact-type': artifact.artifact_type.name}
            },
            result=result.SubmitResult(artifact, polyswarm=self.api_instance)
        )

    def rescan(self, h, **kwargs):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/rescan/{}/{}'.format(self.community_base, h.hash_type, h.hash)
            },
            result=result.SubmitResult(h, polyswarm=self.api_instance)
        )

    def lookup_uuid(self, uuid, **kwargs):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/uuid/{}'.format(self.community_base, uuid)
            },
            result=result.ScanResult(polyswarm=self.api_instance)
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
            result=result.EngineNamesResult(polyswarm=self.api_instance)
        )

    def submit_live_hunt(self, rule):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/live'.format(self.hunt_base),
                'json': {'yara': rule.ruleset},
            },
            result=result.HuntSubmissionResult(rule, polyswarm=self.api_instance),
        )

    def live_lookup(self, with_bounty_results=True, with_metadata=True,
                    limit=const.RESULT_CHUNK_SIZE, offset=0, id=None,
                    since=0):
        req = {
            'method': 'GET',
            'timeout': const.DEFAULT_HTTP_TIMEOUT,
            'url': '{}/live/results'.format(self.hunt_base),
            'params': {
                'with_bounty_results': utils.bool_to_int[with_bounty_results],
                'with_metadata': utils.bool_to_int[with_metadata],
                'limit': limit,
                'offset': offset,
                'since': since,
            },
        }

        if id:
            req['params']['id'] = id

        return PolyswarmRequest(
            self.api_instance,
            req,
            result=result.HuntResult(hunt_id=id, polyswarm=self.api_instance)
        )

    def submit_historical_hunt(self, rule):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/historical'.format(self.hunt_base),
                'json': {'yara': rule.ruleset},
            },
            result=result.HuntSubmissionResult(rule, polyswarm=self.api_instance),
        )

    def historical_lookup(self, with_bounty_results=True, with_metadata=True,
                          limit=const.RESULT_CHUNK_SIZE, offset=0, id=None,
                          since=0):
        req = {
            'method': 'GET',
            'timeout': const.DEFAULT_HTTP_TIMEOUT,
            'url': '{}/historical/results'.format(self.hunt_base),
            'params': {
                'with_bounty_results': utils.bool_to_int[with_bounty_results],
                'with_metadata': utils.bool_to_int[with_metadata],
                'limit': limit,
                'offset': offset,
                'since': since,
            },
        }

        if id:
            req['params']['id'] = id

        return PolyswarmRequest(
            self.api_instance,
            req,
            result=result.HuntResult(hunt_id=id, polyswarm=self.api_instance)
        )

    def historical_delete(self, hunt_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'DELETE',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/historical'.format(self.hunt_base),
                'params': {'hunt_id': hunt_id}
            },
            result=result.HuntDeletionResult(polyswarm=self.api_instance)
        )

    def live_delete(self, hunt_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'DELETE',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/live'.format(self.hunt_base),
                'params': {'hunt_id': hunt_id}
            },
            result=result.HuntDeletionResult(polyswarm=self.api_instance)
        )

    def historical_list(self):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/historical'.format(self.hunt_base),
                'params': {'all': 'true'},
            },
            result=result.HuntListResult(polyswarm=self.api_instance)
        )

    def live_list(self):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/live'.format(self.hunt_base),
                'params': {'all': 'true'},
            },
            result=result.HuntListResult(polyswarm=self.api_instance)
        )

    def score(self, uuid):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/submission/{}/polyscore'.format(self.consumer_base, uuid)
            },
            result=result.ScoreResult(polyswarm=self.api_instance)
        )


class PolyswarmRequestExecutor(object):
    """ This class accepts requests from a PolyswarmRequestGenerator and executes it """
    def __init__(self, key, session=None):
        self.session = session or http.PolyswarmHTTP(key, retries=const.DEFAULT_RETRIES)
        self.requests = []

    def _request(self, request):
        request.raw_result = self.session.request(**request.request_parameters)
        request.raw_result.raise_for_status()

        if request.result is not None:
            request.result.parse_result(request.raw_result)

        return request

    def push(self, request):
        raise NotImplementedError()

    def execute(self):
        raise NotImplementedError()


class PolyswarmFuturesExecutor(PolyswarmRequestExecutor):
    def __init__(self, key):
        self.executor = futures.ThreadPoolExecutor(const.DEFAULT_WORKER_COUNT)
        super(PolyswarmFuturesExecutor, self).__init__(key)

    def push(self, request):
        self.requests.append(self.executor.submit(self._request, request))
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
            responses.append(self._request(request))
        self.requests = []
        return responses
