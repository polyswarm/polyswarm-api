import os

from .http import PolyswarmHTTP, PolyswarmHTTPFutures
from .types.artifact import Artifact

from . import const, exceptions, utils
from .log import logger


def update_with_kwargs(supported_arguments=[]):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            out_args = func(self, *args, **kwargs)
            for arg in kwargs:
                if arg not in supported_arguments:
                    logger.warning("Argument %s not supported", arg)
                    continue
                out_args['params'][arg] = kwargs[arg] if not isinstance(kwargs[arg], bool) \
                    else utils.bool_to_int[kwargs[arg]]
            return out_args
        return wrapper
    return decorator


class PolyswarmRequestGenerator(object):
    """ This class will return requests-compatible arguments for the API """
    def __init__(self, uri, community, timeout):
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

        self.timeout = timeout

    @update_with_kwargs([])
    def download(self, h, **kwargs):
        return {
            'method': 'GET',
            'url': self.download_fmt.format(self.download_base, h.hash_type, h.hash),
            'stream': True,
        }

    @update_with_kwargs(["with_instances", "with_metadata"])
    def search(self, h, **kwargs):
        return {
            'method': 'GET',
            'url': self.search_base,
            'params': {'type': h.hash_type, 'hash': h.hash},
            'timeout': self.timeout,
        }

    @update_with_kwargs(["with_instances", "with_metadata"])
    def search_metadata(self, q, **kwargs):
        return {
            'method': 'GET',
            'url': self.search_base,
            'params': {'type': 'metadata'},
            'json': q.query,
            'timeout': self.timeout,
        }

    @update_with_kwargs([])
    def submit(self, artifact, **kwargs):
        return {
            'method': 'POST',
            'url': self.community_base,
            'files': {
                'file': (artifact.artifact_name, artifact.file_handle),
            },
            # very oddly, when included in files parameter this errors out
            'data': {'artifact-type': artifact.artifact_type.name}
        }

    @update_with_kwargs([])
    def rescan(self, h, **kwargs):
        return {
            'method': 'POST',
            'url': '{}/rescan/{}/{}'.format(self.community_base, h.hash_type, h.hash)
        }

    @update_with_kwargs([])
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

    @update_with_kwargs([])
    def submit_live_hunt(self, rule):
        return {
            'method': 'POST',
            'url': '{}/live'.format(self.hunt_base),
            'json': {'yara': rule.ruleset},
        }

    @update_with_kwargs(['with_bounty_results', 'with_metadata', 'limit', 'offset', 'id'])
    def live_lookup(self, *args, **kwargs):
        return {
            'method': 'GET',
            'url': '{}/live/results'.format(self.hunt_base),
            'params': {},
        }

    @update_with_kwargs([])
    def submit_historical_hunt(self, rule):
        return {
            'method': 'POST',
            'url': '{}/historical'.format(self.hunt_base),
            'json': {'yara': rule.ruleset},
        }

    @update_with_kwargs(['with_bounty_results', 'with_metadata', 'limit', 'offset', 'id'])
    def historical_lookup(self, *args, **kwargs):
        return {
            'method': 'GET',
            'url': '{}/historical/results'.format(self.hunt_base),
            'params': {},
        }


class PolyswarmEndpointBase(object):
    """ This is the base class for PolyswarmEndpoint classes. Do not use directly. """
    def __init__(self,  key, uri=const.DEFAULT_GLOBAL_API, community=const.DEFAULT_COMMUNITY,
                 timeout=const.DEFAULT_HTTP_TIMEOUT, retries=const.DEFAULT_RETRIES):
        self.session = None
        # this will likely be removed once we can get rid of engine resolution
        self.unauth_session = None
        self.req_gen = None

        raise NotImplementedError

    def _download_to_fh(self, req, fh):
        raise NotImplementedError

    def download(self, h, out_path):
        """
        Download a series of PSHashes to files

        :return: A future
        """
        in_progress, done = [], []

        fh = open(out_path, 'wb')
        req = self.session.request(**self.req_gen.download(h))
        return self._download_to_fh(req, fh)

    def search_hash(self, h, **kwargs):
        """
        Download a series of
        :param h: A Hash object
        :return: A request Future
        """
        return self.session.request(**self.req_gen.search(h, **kwargs))

    def search_metadata(self, query, **kwargs):
        return self.session.request(**self.req_gen.search_metadata(query, **kwargs))

    def lookup_uuid(self, uuid, **kwargs):
        return self.session.request(**self.req_gen.lookup_uuid(uuid, **kwargs))

    def submit(self, artifact, **kwargs):
        return self.session.request(**self.req_gen.submit(artifact, **kwargs))

    def rescan(self, h, **kwargs):
        return self.session.request(**self.req_gen.rescan(h, **kwargs))

    def _get_engine_names(self):
        """ This will be deprecated soon """
        return self.unauth_session.request(**self.req_gen._get_engine_names())

    def submit_historical_hunt(self, rule, **kwargs):
        return self.session.request(**self.req_gen.submit_historical_hunt(rule, **kwargs))

    def historical_lookup(self, **kwargs):
        return self.session.request(**self.req_gen.historical_lookup(**kwargs))

    def historical_list(self, **kwargs):
        return self.session.request(**self.req_gen.submit(**kwargs))

    def submit_live_hunt(self, rule, **kwargs):
        return self.session.request(**self.req_gen.submit_live_hunt(rule, **kwargs))

    def live_lookup(self, **kwargs):
        return self.session.request(**self.req_gen.live_lookup(**kwargs))

    def live_list(self, **kwargs):
        return self.session.request(**self.req_gen.submit(**kwargs))


class PolyswarmEndpointFutures(PolyswarmEndpointBase):
    """
    This class is used to perform actions via the Polyswarm API endpoint. Each function encapsulates a particular
    action on the API (search, download, hunt creation/results, etc) and returns a future for the tasks' completion.
    """
    def __init__(self,  key, uri=const.DEFAULT_GLOBAL_API, community=const.DEFAULT_COMMUNITY,
                 timeout=const.DEFAULT_HTTP_TIMEOUT, retries=const.DEFAULT_RETRIES):
        self.req_gen = PolyswarmRequestGenerator(uri, community, timeout)
        self.session = PolyswarmHTTPFutures(key, retries)
        self.unauth_session = PolyswarmHTTPFutures(None, retries)
        self.timeout = timeout

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



class PolyswarmEndpoint(PolyswarmEndpointBase):
    """
    This class is used to perform actions via the Polyswarm API endpoint. Each function encapsulates a particular
    action on the API (search, download, hunt creation/results, etc) and returns a requests response object
    """
    def __init__(self,  key, uri=const.DEFAULT_GLOBAL_API, community=const.DEFAULT_COMMUNITY,
                 timeout=const.DEFAULT_HTTP_TIMEOUT, retries=const.DEFAULT_RETRIES):
        self.req_gen = PolyswarmRequestGenerator(uri, community, timeout)
        self.session = PolyswarmHTTP(key, retries)
        self.unauth_session = PolyswarmHTTP(None, retries)
        self.timeout = timeout

    def _download_to_fh(self, req, fh):
        for chunk in req.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
            fh.write(chunk)