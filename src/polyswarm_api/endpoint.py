from . import const, utils
from requests.exceptions import HTTPError


class PolyswarmRequestGenerator(object):
    """ This class will return requests-compatible arguments for the API """
    def __init__(self, uri, community):
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
        return {
            'method': 'GET',
            'url': self.download_fmt.format(self.download_base, h.hash_type, h.hash),
            'stream': True,
            'output_file': fh,
        }

    def download_archive(self, u, fh):
        """ This method is special, in that it is simply for downloading from S3 """
        return {
            'method': 'GET',
            'url': u,
            'stream': True,
            'output_file': fh,
            'headers': {'Authorization': None}
        }

    def stream(self, since=const.MAX_SINCE_TIME_STREAM):
        return {
            'method': 'GET',
            'url': '{}/download/stream'.format(self.consumer_base),
            'params': {'since': since},
        }

    def search_hash(self, h, with_instances=True, with_metadata=True):
        return {
            'method': 'GET',
            'url': self.search_base,
            'params': {
                'type': h.hash_type,
                'hash': h.hash,
                'with_instances': utils.bool_to_int[with_instances],
                'with_metadata': utils.bool_to_int[with_metadata]
            },
        }

    def search_metadata(self, q, with_instances=True, with_metadata=True):
        return {
            'method': 'GET',
            'url': self.search_base,
            'params': {
                'type': 'metadata',
                'with_instances': utils.bool_to_int[with_instances],
                'with_metadata': utils.bool_to_int[with_metadata]
            },
            'json': q.query,
        }

    def submit(self, artifact):
        return {
            'method': 'POST',
            'url': self.community_base,
            'files': {
                'file': (artifact.artifact_name, artifact.file_handle),
            },
            # very oddly, when included in files parameter this errors out
            'data': {'artifact-type': artifact.artifact_type.name}
        }

    def rescan(self, h, **kwargs):
        return {
            'method': 'POST',
            'url': '{}/rescan/{}/{}'.format(self.community_base, h.hash_type, h.hash)
        }

    def lookup_uuid(self, uuid, **kwargs):
        return {
            'method': 'GET',
            'url': '{}/uuid/{}'.format(self.community_base, uuid)
        }

    def _get_engine_names(self):
        return {
            'method': 'GET',
            'url': '{}/microengines/list'.format(self.uri),
            'headers': {'Authorization': None},
        }

    def submit_live_hunt(self, rule):
        return {
            'method': 'POST',
            'url': '{}/live'.format(self.hunt_base),
            'json': {'yara': rule.ruleset},
        }

    def live_lookup(self, with_bounty_results=True, with_metadata=True,
                    limit=const.RESULT_CHUNK_SIZE, offset=0, id=None,
                    since=0):
        req = {
            'method': 'GET',
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

        return req

    def submit_historical_hunt(self, rule):
        return {
            'method': 'POST',
            'url': '{}/historical'.format(self.hunt_base),
            'json': {'yara': rule.ruleset},
        }

    def historical_lookup(self, with_bounty_results=True, with_metadata=True,
                          limit=const.RESULT_CHUNK_SIZE, offset=0, id=None,
                          since=0):
        req = {
            'method': 'GET',
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

        return req

    def historical_delete(self, hunt_id):
        return {
            'method': 'DELETE',
            'url': '{}/historical'.format(self.hunt_base),
            'params': {'hunt_id': hunt_id}
        }

    def live_delete(self, hunt_id):
        return {
            'method': 'DELETE',
            'url': '{}/live'.format(self.hunt_base),
            'params': {'hunt_id': hunt_id}
        }

    def historical_list(self):
        return {
            'method': 'GET',
            'url': '{}/historical'.format(self.hunt_base),
            'params': {'all': 'true'},
        }

    def live_list(self):
        return {
            'method': 'GET',
            'url': '{}/live'.format(self.hunt_base),
            'params': {'all': 'true'},
        }

    def score(self, uuid):
        return {
            'method': 'GET',
            'url': '{}/submission/{}/polyscore'.format(self.consumer_base, uuid)
        }


class PolyswarmRequestExecutor(object):
    """ This class accepts requests from a PolyswarmRequestGenerator and executes it """
    def __init__(self, session=None, timeout=const.DEFAULT_HTTP_TIMEOUT):
        self.session = session
        self.timeout = timeout

    def execute(self, request):
        if 'timeout' not in request:
            request['timeout'] = self.timeout

        # this is a special case for handling output to a file
        output = request.get('output_file', None)

        if 'output_file' in request:
            del request['output_file']

        req = self.session.request(**request)

        if output:
            try:
                return self._download_to_fh(req, output)
            except HTTPError:
                return req

        return req

    def _download_to_fh(self, req, fh):
        raise NotImplementedError


class PolyswarmFuturesExecutor(PolyswarmRequestExecutor):
    def _download_to_fh(self, req, fh):
        # this is unfortunately the cleanest way I think I can do this with requests-futures
        # derived partially from https://github.com/ross/requests-futures/issues/54
        def do_download(r, f):
            for chunk in r.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
                f.write(chunk)
            return r
        resp = req.result()
        resp.raise_for_status()
        return self.session.executor.submit(do_download, resp, fh)


class PolyswarmSynchronousExecutor(PolyswarmRequestExecutor):
    def _download_to_fh(self, req, fh):
        req.raise_for_status()
        for chunk in req.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
            fh.write(chunk)
        return req


class PolyswarmEndpoint(object):
    """ This is the PolyswarmEndpoint class, that handles talking with the PolySwarm API"""
    def __init__(self,  request_generator=None, request_executor=None):
        self.generator = request_generator
        self.executor = request_executor

    def __getattr__(self, name):
        """
        This function is the black magic behind PolyswarmEndpoint. The goal of the function is to
        return a callable that chains together a RequestGenerator and a RequestExecutor, but to do
        this dynamically so that we don't have to manually define a new method for every possible
        RequestGenerator method.

        As such, we return a closure here, and this closure simply calls the given function name
        in the RequestGenerator, and passes this into the RequestExecutor's execute function to
        be run. The end result is a simple calling convention for all methods supported by
        the provided RequestGenerator, e.g. endpoint.search() -> returns a result.


        :param name: unresolved attribute name
        :return: closure that calls the RequestGenerator then executes it with a RequestExecutor
        """
        def endpoint_wrapper(*args, **kwargs):
            return self.executor.execute(getattr(self.generator, name)(*args, **kwargs))
        return endpoint_wrapper
