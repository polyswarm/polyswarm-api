from concurrent import futures

from . import const
from . import utils
from . import http
from .types import result


class PolyswarmRequest(object):
    """This class holds a requests-compatible dictionary and extra infor we need to parse the reponse."""
    def __init__(self, api_instance, request_parameters, output_file=None, result=None):
        self.api_instance = api_instance
        self.request_parameters = request_parameters
        self.output_file = output_file
        self.result = result
        self.raw_result = None


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

    def download(self, h, fh):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': self.download_fmt.format(self.download_base, h.hash_type, h.hash),
                'stream': True,
            },
            output_file=fh,
            result=result.DownloadResult,
        )

    def download_archive(self, u, fh):
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
            output_file=fh,
            result=result.DownloadResult,
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

        return PolyswarmRequest(req)

    def submit_historical_hunt(self, rule):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/historical'.format(self.hunt_base),
                'json': {'yara': rule.ruleset},
            },
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

        return PolyswarmRequest(req)

    def historical_delete(self, hunt_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'DELETE',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/historical'.format(self.hunt_base),
                'params': {'hunt_id': hunt_id}
            },
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
        )

    def score(self, uuid):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'timeout': const.DEFAULT_HTTP_TIMEOUT,
                'url': '{}/submission/{}/polyscore'.format(self.consumer_base, uuid)
            },
        )


class PolyswarmRequestExecutor(object):
    """ This class accepts requests from a PolyswarmRequestGenerator and executes it """
    def __init__(self, key, session=None):
        self.session = session or http.PolyswarmHTTP(key, retries=const.DEFAULT_RETRIES)
        self.requests = []

    def _request(self, request):
        request.raw_result = self.session.request(**request.request_parameters)
        request.raw_result.raise_for_status()

        if request.output_file:
            for chunk in request.raw_result.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
                request.output_file.write(chunk)

        if request.result:
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

    def execute(self):
        requests = self.requests
        # flush before looping in case we have nested executions
        self.requests = []
        for future in futures.as_completed(requests):
            yield future.result()


class PolyswarmSynchronousExecutor(PolyswarmRequestExecutor):
    def push(self, request):
        self.requests.append(request)

    def execute(self):
        responses = []
        for request in self.requests:
            responses.append(self._request(request))
        self.requests = []
        return responses
