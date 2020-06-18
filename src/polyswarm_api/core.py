import json
import logging
from copy import deepcopy
from urllib3 import Retry
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

import requests
from dateutil import parser
from future.utils import raise_from
from requests.adapters import HTTPAdapter

from polyswarm_api import settings, exceptions

logger = logging.getLogger(__name__)


class BaseResource:
    def __init__(self, api=None):
        self.api = api

    @classmethod
    def parse_result(cls, api, content, **kwargs):
        logger.debug('Parsing resource %s', cls.__name__)
        return cls(content, api=api, **kwargs)


class BaseJsonResource(BaseResource):
    def __init__(self, json=None, api=None):
        super(BaseJsonResource, self).__init__(api=api)
        self.json = json

    @classmethod
    def parse_result_list(cls, api_instance, json_data, **kwargs):
        return [cls.parse_result(api_instance, entry, **kwargs) for entry in json_data]

    def __reduce__(self):
        return (type(self), (self.__dict__.get('json'), self.api))


# TODO better way to do this with ABC?
class Hashable:
    @property
    def hash(self):
        return self.sha256

    @property
    def hash_type(self):
        return 'sha256'

    def __eq__(self, other):
        return self.hash == other


class AsInteger:
    def __int__(self):
        return int(self.id)


def parse_isoformat(date_string):
    """ Parses the current date format version """
    if date_string:
        return parser.isoparse(date_string)
    else:
        return None


JSONDecodeError = ValueError


class PolyswarmSession(requests.Session):
    def __init__(self, key, retries, user_agent=settings.DEFAULT_USER_AGENT):
        super(PolyswarmSession, self).__init__()
        logger.debug('Creating PolyswarmHTTP instance')
        self.requests_retry_session(retries=retries)

        if key:
            self.set_auth(key)

        if user_agent:
            self.set_user_agent(user_agent)

    def requests_retry_session(self, retries=settings.DEFAULT_RETRIES, backoff_factor=settings.DEFAULT_BACKOFF,
                               status_forcelist=settings.DEFAULT_RETRY_CODES):
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.mount('http://', adapter)
        self.mount('https://', adapter)

    def set_auth(self, key):
        if key:
            self.headers.update({'Authorization': key})
        else:
            self.headers.pop('Authorization', None)

    def set_user_agent(self, ua):
        if ua:
            self.headers.update({'User-Agent': ua})
        else:
            self.headers.pop('User-Agent', None)


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
        self.session = self.api_instance.session or PolyswarmSession(key, retries=settings.DEFAULT_RETRIES)
        self.timeout = self.api_instance.timeout or settings.DEFAULT_HTTP_TIMEOUT
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
        self.request_parameters.setdefault('timeout', self.timeout)
        if not self.json_response:
            self.request_parameters.setdefault('stream', True)
        self.raw_result = self.session.request(**self.request_parameters)
        logger.debug('Request returned code %s', self.raw_result.status_code)
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
                    message = '{} This may mean you need to purchase a ' \
                              'larger package, or that you have exceeded ' \
                              'rate limits. If you continue to have issues, ' \
                              'please contact us at info@polyswarm.io.'.format(self.result)
                    raise exceptions.UsageLimitsExceededException(self, message)
                if self.status_code == 404:
                    raise exceptions.NotFoundException(self, self.result)
                raise exceptions.RequestException(self, self._bad_status_message())
            elif self.status_code == 204:
                raise exceptions.NoResultsException(self, 'The request returned no results.')
            elif self.json_response:
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
                self.result = self.result_parser.parse_result(self.api_instance,
                                                              result.iter_content(settings.DOWNLOAD_CHUNK_SIZE),
                                                              **self.parser_kwargs)
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
        params = new_parameters.setdefault('params', {})
        if isinstance(params, dict):
            params['offset'] = self.offset
            params['limit'] = self.limit
        else:
            params = [p for p in params if p[0] != 'offset' and p[0] != 'limit']
            params.extend([('offset', self.offset), ('limit', self.limit)])
            new_parameters['params'] = params
        return PolyswarmRequest(
            self.api_instance,
            new_parameters,
            result_parser=self.result_parser,
        )