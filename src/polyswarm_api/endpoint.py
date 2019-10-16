from .http import PolyswarmHTTP, PolyswarmHTTPFutures
from . import const, utils

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
        }, fh

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
            'url': '{}/microengines/list'.format(self.uri)
        }

    def submit_live_hunt(self, rule):
        return {
            'method': 'POST',
            'url': '{}/live'.format(self.hunt_base),
            'json': {'yara': rule.ruleset},
        }

    def live_lookup(self, with_bounty_results=True, with_metadata=True,
                    limit=const.RESULT_CHUNK_SIZE, offset=0, id=None):
        req = {
            'method': 'GET',
            'url': '{}/live/results'.format(self.hunt_base),
            'params': {
                'with_bounty_results': utils.bool_to_int[with_bounty_results],
                'with_metadata': utils.bool_to_int[with_metadata],
                'limit': limit,
                'offset': offset,
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
                    limit=const.RESULT_CHUNK_SIZE, offset=0, id=None):
        req = {
            'method': 'GET',
            'url': '{}/historical/results'.format(self.hunt_base),
            'params': {
                'with_bounty_results': utils.bool_to_int[with_bounty_results],
                'with_metadata': utils.bool_to_int[with_metadata],
                'limit': limit,
                'offset': offset,
            },
        }

        if id:
            req['params']['id'] = id

        return req

    def historical_delete(self, hunt_id):
        return {
            'method': 'DELETE',
            'url': '{}/historical'.format(self.hunt_base),
            'json': {'hunt_id': hunt_id}
        }

    def live_delete(self, hunt_id):
        return {
            'method': 'DELETE',
            'url': '{}/live'.format(self.hunt_base),
            'json': {'hunt_id': hunt_id}
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


class PolyswarmRequestExecutor(object):
    """ This class accepts requests from a PolyswarmRequestGenerator and executes it """
    def __init__(self, key, timeout=const.DEFAULT_HTTP_TIMEOUT, retries=const.DEFAULT_RETRIES, request_cls=None):
        self.session = request_cls(key, retries)
        self.unauth_session = request_cls(key=None, retries=retries)
        self.timeout = timeout

    def execute(self, request):
        if 'timeout' not in request:
            request['timeout'] = self.timeout
        return self.session.request(**request)

    def unauth_execute(self, request):
        return self.unauth_session.request(**request)

    def _get_engine_names(self, request):
        return self.unauth_session.request(**request)

    def __getattr__(self, name):
        if name in self.__dict__:
            return self.__dict__[name]
        return self.execute

    def _download_to_fh(self, req, fh):
        raise NotImplementedError

    def download(self, request):
        request, fh = request
        if isinstance(fh, str):
            fh = open(fh, 'wb')

        req = self.execute(request)
        return self._download_to_fh(req, fh)


class PolyswarmFuturesExecutor(PolyswarmRequestExecutor):
    def __init__(self, key, timeout=const.DEFAULT_HTTP_TIMEOUT, retries=const.DEFAULT_RETRIES):
        super(PolyswarmFuturesExecutor, self).__init__(key, timeout, retries, PolyswarmHTTPFutures)

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
    def __init__(self, key, timeout=const.DEFAULT_HTTP_TIMEOUT, retries=const.DEFAULT_RETRIES):
        super(PolyswarmSynchronousExecutor, self).__init__(key, timeout, retries, PolyswarmHTTP)

    def _download_to_fh(self, req, fh):
        for chunk in req.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
            fh.write(chunk)
        return req


class PolyswarmEndpoint(object):
    """ This is the base class for PolyswarmEndpoint classes. Do not use directly. """
    def __init__(self,  key, uri=const.DEFAULT_GLOBAL_API, community=const.DEFAULT_COMMUNITY,
                 timeout=const.DEFAULT_HTTP_TIMEOUT, retries=const.DEFAULT_RETRIES,
                 request_gen_cls=PolyswarmRequestGenerator, request_exec_cls=PolyswarmFuturesExecutor):
        self.executor = request_exec_cls(key, timeout, retries)
        self.generator = request_gen_cls(uri, community)

    def __getattr__(self, name):
        def endpoint_wrapper(*args, **kwargs):
            return getattr(self.executor, name)(getattr(self.generator, name)(*args, **kwargs))
        return endpoint_wrapper
