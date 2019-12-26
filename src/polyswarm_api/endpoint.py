import logging
import json
from future.utils import raise_from
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
        logger.debug('Creating PolyswarmRequest instance.\nRequest parameters: %s\nResult parser: %s',
                     request_parameters, result_parser.__name__)
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
        self.has_more = None
        self.parser_kwargs = kwargs

    def execute(self):
        logger.debug('Executing request.')
        self.request_parameters.setdefault('timeout', const.DEFAULT_HTTP_TIMEOUT)
        self.raw_result = self.session.request(**self.request_parameters)
        logger.debug('Request returned code %s with content:\n%s',
                     self.raw_result.status_code, self.raw_result.content)
        if self.result_parser is not None:
            self.parse_result(self.raw_result)
        return self

    def _bad_status_message(self):
        request_parameters = json.dumps(self.request_parameters, indent=4, sort_keys=True, cls=RequestParamsEncoder)
        message = "Error when running the request:\n{}\n" \
                  "Return code: {}\n" \
                  "Message: {}".format(request_parameters,
                                       self.status_code,
                                       self.result)
        if self.errors:
            message = '{}\nErrors:\n{}'.format(message, '\n'.join(str(error) for error in self.errors))
        return message

    def _extract_json_body(self, result):
        self.json = result.json()
        self.result = self.json.get('result')
        self.status = self.json.get('status')
        self.errors = self.json.get('errors')

    def parse_result(self, result):
        logger.debug('Parsing request results.')
        self.status_code = result.status_code
        try:
            if self.status_code // 100 != 2:
                self._extract_json_body(result)
                if self.status_code == 429:
                    raise exceptions.UsageLimitsExceededException(self, const.USAGE_EXCEEDED_MESSAGE)
                if self.status_code == 404:
                    raise exceptions.NotFoundException(self, self.result)
                raise exceptions.RequestException(self, self._bad_status_message())
            elif self.status_code == 204:
                raise exceptions.NoResultsException(self, 'The request returned no results.')
            else:
                if self.json_response:
                    self._extract_json_body(result)
                    self.total = self.json.get('total')
                    self.limit = self.json.get('limit')
                    self.offset = self.json.get('offset')
                    self.order_by = self.json.get('order_by')
                    self.direction = self.json.get('direction')
                    self.has_more = self.json.get('has_more')
                    if 'result' in self.json:
                        result = self.json['result']
                    elif 'results' in self.json:
                        result = self.json['results']
                    else:
                        raise exceptions.RequestException(
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
                raise raise_from(exceptions.RequestException(self, 'Server returned non-JSON response.'), e)

    def __iter__(self):
        return self.consume_results()

    def consume_results(self):
        # StopIteration is deprecated
        # As per https://www.python.org/dev/peps/pep-0479/
        # We simply return upon termination condition
        request = self
        while True:
            # consume items items from list if iterable
            # of yield the single result if not
            try:
                for result in request.result:
                    yield result
            except TypeError:
                yield request.result
                # if the result is not a list, there is not next page
                return

            # if the server indicates that there are no more results, return
            if not request.has_more:
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
        logger.debug('Creating PolyswarmRequestGenerator instance')
        self.api_instance = api_instance
        self.uri = api_instance.uri
        self.community = api_instance.community

    def download(self, hash_value, hash_type, output_file, create=False):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
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
                'url': '{}/search/hash/{}'.format(self.uri, h.hash_type),
                'params': {
                    'hash': h.hash,
                },
            },
            result_parser=resources.ArtifactInstance,
        )

    def search_metadata(self, query):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'url': '{}/search/metadata/metadata'.format(self.uri),
                'params': {
                    'query': query,
                },
            },
            result_parser=resources.ArtifactInstance,
        )

    def submit(self, artifact):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
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
                'url': '{}/consumer/submission/{}/rescan/{}/{}'.format(self.uri, self.community, h.hash_type, h.hash),
            },
            result_parser=resources.ArtifactInstance,
        )

    def rescanid(self, submission_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'url': '{}/consumer/submission/{}/rescan/{}'.format(self.uri, self.community, submission_id),
            },
            result_parser=resources.ArtifactInstance,
        )

    def lookup_uuid(self, submission_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'url': '{}/consumer/submission/{}/{}'.format(self.uri, self.community, submission_id),
            },
            result_parser=resources.ArtifactInstance,
        )

    def _get_engine_names(self):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'url': '{}/microengines/list'.format(self.uri),
                'headers': {'Authorization': None},
            },
            result_parser=resources.Engine,
        )

    def create_live_hunt(self, rule, active=True):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'POST',
                'url': '{}/hunt/live'.format(self.uri),
                'json': {'yara': rule.yara,
                         'active': active},
            },
            result_parser=resources.Hunt,
        )

    def get_live_hunt(self, hunt_id=None):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'url': '{}/hunt/live'.format(self.uri),
                'params': {'id': str(hunt_id) if hunt_id else ''},
            },
            result_parser=resources.Hunt,
        )

    def update_live_hunt(self, hunt_id=None, active=False):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'PUT',
                'url': '{}/hunt/live'.format(self.uri),
                'params': {'id': str(hunt_id) if hunt_id else ''},
                'json': {'active': active},
            },
            result_parser=resources.Hunt,
        )

    def delete_live_hunt(self, hunt_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'DELETE',
                'url': '{}/hunt/live'.format(self.uri),
                'params': {'id': str(hunt_id) if hunt_id else ''},
            },
            result_parser=resources.Hunt,
        )

    def live_list(self, since=None, all_=None):
        parameters = {
            'method': 'GET',
            'url': '{}/hunt/live/list'.format(self.uri),
            'params': {},
        }
        if since is not None:
            parameters['params']['since'] = since
        if all_ is not None:
            parameters['params']['all'] = int(all_)
        return PolyswarmRequest(
            self.api_instance,
            parameters,
            result_parser=resources.Hunt,
        )

    def live_hunt_results(self, hunt_id=None, since=None, tag=None, rule_name=None):
        req = {
            'method': 'GET',
            'url': '{}/hunt/live/results'.format(self.uri),
            'params': {
                'since': since,
                'id': str(hunt_id) if hunt_id else '',
            },
        }
        if tag is not None:
            req['params']['tag'] = tag
        if rule_name is not None:
            req['params']['rule_name'] = rule_name
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
                'url': '{}/hunt/historical'.format(self.uri),
                'json': {'yara': rule.yara},
            },
            result_parser=resources.Hunt,
        )

    def get_historical_hunt(self, hunt_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'url': '{}/hunt/historical'.format(self.uri),
                'params': {'id': str(hunt_id) if hunt_id else ''},
            },
            result_parser=resources.Hunt,
        )

    def delete_historical_hunt(self, hunt_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'DELETE',
                'url': '{}/hunt/historical'.format(self.uri),
                'params': {'id': str(hunt_id) if hunt_id else ''},
            },
            result_parser=resources.Hunt,
        )

    def historical_list(self, since=None):
        parameters = {
            'method': 'GET',
            'url': '{}/hunt/historical/list'.format(self.uri),
            'params': {},
        }
        if since is not None:
            parameters['params']['since'] = since
        return PolyswarmRequest(
            self.api_instance,
            parameters,
            result_parser=resources.Hunt,
        )

    def historical_hunt_results(self, hunt_id=None, tag=None, rule_name=None):
        req = {
            'method': 'GET',
            'url': '{}/hunt/historical/results'.format(self.uri),
            'params': {'id': str(hunt_id) if hunt_id else ''},
        }
        if tag is not None:
            req['params']['tag'] = tag
        if rule_name is not None:
            req['params']['rule_name'] = rule_name
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
                'url': '{}/consumer/polyscore/{}'.format(
                    self.uri, submission_id
                )
            },
            result_parser=resources.PolyScore,
        )

    def create_rule_set(self, rule):
        parameters = {
            'method': 'POST',
            'url': '{}/hunt/rule'.format(self.uri),
            'json': {
                'yara': rule.yara,
                'name': rule.name,
            },
        }
        if rule.description:
            parameters['json']['description'] = rule.description
        return PolyswarmRequest(
            self.api_instance,
            parameters,
            result_parser=resources.YaraRuleset,
        )

    def get_rule_set(self, rule_set_id=None):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'url': '{}/hunt/rule'.format(self.uri),
                'params': {'id': str(rule_set_id)},
            },
            result_parser=resources.YaraRuleset,
        )

    def update_rule_set(self, rule_set_id, name=None, rules=None, description=None):
        parameters = {
            'method': 'PUT',
            'url': '{}/hunt/rule'.format(self.uri),
            'params': {'id': str(rule_set_id)},
            'json': {},
        }
        if name:
            parameters['json']['name'] = name
        if rules:
            parameters['json']['yara'] = rules
        if description:
            parameters['json']['description'] = description
        return PolyswarmRequest(
            self.api_instance,
            parameters,
            result_parser=resources.YaraRuleset,
        )

    def delete_rule_set(self, rule_set_id):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'DELETE',
                'url': '{}/hunt/rule'.format(self.uri),
                'params': {'id': str(rule_set_id)},
            },
            result_parser=resources.YaraRuleset,
        )

    def list_rule_set(self):
        return PolyswarmRequest(
            self.api_instance,
            {
                'method': 'GET',
                'url': '{}/hunt/rule/list'.format(self.uri),
            },
            result_parser=resources.YaraRuleset,
        )
