import json
import logging
from copy import deepcopy
from urllib3 import Retry
from binascii import unhexlify
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
    def __init__(self, api_instance, request_parameters, key=None, result_parser=None, **kwargs):
        logger.debug('Creating PolyswarmRequest instance.\nRequest parameters: %s\nResult parser: %s',
                     request_parameters, result_parser.__name__ if result_parser else 'No result parser')
        self.api_instance = api_instance
        # we should not access the api_instance session directly, but provide as a
        # parameter in the constructor, but this will do for the moment
        self.session = self.api_instance.session or PolyswarmSession(key, retries=settings.DEFAULT_RETRIES)
        self.timeout = self.api_instance.timeout or settings.DEFAULT_HTTP_TIMEOUT
        self.request_parameters = request_parameters
        self.result_parser = result_parser
        self.raw_result = None
        self.status_code = None
        self.status = None
        self.errors = None
        self._result = None

        self._paginated = False
        self.total = None
        self.limit = None
        self.offset = None
        self.order_by = None
        self.direction = None
        self.has_more = None

        self.parser_kwargs = kwargs

    def result(self):
        if self._paginated:
            return self.consume_results()
        else:
            return self._result

    def execute(self):
        logger.debug('Executing request.')
        self.request_parameters.setdefault('timeout', self.timeout)
        if self.result_parser and not issubclass(self.result_parser, BaseJsonResource):
            self.request_parameters.setdefault('stream', True)
        self.raw_result = self.session.request(**self.request_parameters)
        logger.debug('Request returned code %s', self.raw_result.status_code)
        self.parse_result(self.raw_result)
        return self

    def _bad_status_message(self):
        request_parameters = json.dumps(self.request_parameters, indent=4, sort_keys=True, cls=RequestParamsEncoder)
        message = "Error when running the request:\n{}\n" \
                  "Return code: {}\n" \
                  "Message: {}".format(request_parameters,
                                       self.status_code,
                                       self._result)
        if self.errors:
            message = '{}\nErrors:\n{}'.format(message, '\n'.join(str(error) for error in self.errors))
        return message

    def _extract_json_body(self, result):
        self.json = result.json()
        self._result = self.json.get('result')
        self.status = self.json.get('status')
        self.errors = self.json.get('errors')

    def parse_result(self, result):
        self.status_code = result.status_code
        if self.request_parameters['method'] == 'HEAD':
            logger.debug('HEAD method does not return results, setting it to the status code.')
            self._result = self.status_code
        if not self.result_parser:
            logger.debug('Result parser is not defined, skipping parsing results.')
            return
        logger.debug('Parsing request results.')
        try:
            if self.status_code // 100 != 2:
                self._extract_json_body(result)
                if self.status_code == 429:
                    message = '{} This may mean you need to purchase a ' \
                              'larger package, or that you have exceeded ' \
                              'rate limits. If you continue to have issues, ' \
                              'please contact us at info@polyswarm.io.'.format(self._result)
                    raise exceptions.UsageLimitsExceededException(self, message)
                elif self.status_code == 404:
                    raise exceptions.NotFoundException(self, self._result)
                else:
                    raise exceptions.RequestException(self, self._bad_status_message())
            elif self.status_code == 204:
                raise exceptions.NoResultsException(self, 'The request returned no results.')
            elif issubclass(self.result_parser, BaseJsonResource):
                self._extract_json_body(result)
                if 'has_more' in self.json:
                    # has_more will always be present, being either False or True
                    self._paginated = True
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
                    self._result = self.result_parser.parse_result_list(self.api_instance, result, **self.parser_kwargs)
                else:
                    self._result = self.result_parser.parse_result(self.api_instance, result, **self.parser_kwargs)
            else:
                self._result = self.result_parser.parse_result(self.api_instance, result, **self.parser_kwargs)
        except JSONDecodeError as e:
            if self.status_code == 404:
                raise raise_from(exceptions.NotFoundException(self, 'The requested endpoint does not exist.'), e)
            else:
                err_msg = 'Server returned non-JSON response [{}]: {}'.format(self.status_code, result)
                raise raise_from(exceptions.RequestException(self, err_msg), e)

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
                for result in request._result:
                    yield result
            except TypeError:
                yield request._result
                # if the result is not a list, there is not next page
                return

            # if the server indicates that there are no more results, return
            if not request.has_more:
                return
            # try to get the next page and execute the request
            request = request.next_page()

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
        ).execute()


class BaseResource(object):
    def __init__(self, content, *args, **kwargs):
        # hack to behave as in python 3, signature should be
        # __init__(self, content, *args, api=None, **kwargs)
        api = kwargs.pop('api', None)
        super(BaseResource, self).__init__(*args, **kwargs)
        self.api = api
        self._content = content

    @classmethod
    def parse_result(cls, api, content, **kwargs):
        logger.debug('Parsing resource %s', cls.__name__)
        return cls(content, api=api, **kwargs)


class BaseJsonResource(BaseResource):
    RESOURCE_ENDPOINT = None
    RESOURCE_ID_KEY = 'id'

    def __init__(self, content, *args, **kwargs):
        super(BaseJsonResource, self).__init__(content, *args, **kwargs)
        self.json = content

    def __int__(self):
        id_ = getattr(self, 'id', None)
        if id_ is None:
            raise TypeError('Resource {} does not have an id and can not be cast to int'.format(type(self).__name__))
        return int(id_)

    def _get(self, path, default=None, content=None):
        """
        Helper for rendering attributes of child objects in the json that might be None.
        Returns the default value if some of the items in the path is not present.
        """
        previous_attribute = 'resource_json'
        obj = content or self.json
        try:
            for attribute in path.split('.'):
                if obj is None:
                    raise KeyError('{} is None, can not resolve full path'.format(previous_attribute))
                if attribute.endswith(']'):
                    # handling the list case, e.g.: "root.list_attr[2]"
                    attribute, _, index = attribute.rpartition('[')
                    index = int(index.rstrip(']'))
                    obj = obj[attribute]
                    if obj is None:
                        raise KeyError('{} is None, but is it supposed to be a list'.format(attribute))
                    elif not isinstance(obj, list):
                        raise ValueError('Can not access index for {}, it is not a list.'.format(attribute))
                    else:
                        obj = obj[index]
                else:
                    obj = obj[attribute]
                previous_attribute = attribute
            return obj
        except (KeyError, IndexError) as e:
            logger.debug('Returning default value: %s', e)
            return default

    @classmethod
    def parse_result_list(cls, api_instance, json_data, **kwargs):
        return [cls.parse_result(api_instance, entry, **kwargs) for entry in json_data]

    @classmethod
    def _endpoint(cls, api, **kwargs):
        if cls.RESOURCE_ENDPOINT is None:
            raise exceptions.InvalidValueException('RESOURCE_ENDPOINT is not configured for this resource.')
        return '{api.uri}{endpoint}'.format(api=api, endpoint=cls.RESOURCE_ENDPOINT, **kwargs)

    @classmethod
    def _list_endpoint(cls, api, **kwargs):
        return cls._endpoint(api, **kwargs) + '/list'

    @classmethod
    def _create_endpoint(cls, api, **kwargs):
        return cls._endpoint(api, **kwargs)

    @classmethod
    def _get_endpoint(cls, api, **kwargs):
        return cls._endpoint(api, **kwargs)

    @classmethod
    def _head_endpoint(cls, api, **kwargs):
        return cls._endpoint(api, **kwargs)

    @classmethod
    def _update_endpoint(cls, api, **kwargs):
        return cls._endpoint(api, **kwargs)

    @classmethod
    def _delete_endpoint(cls, api, **kwargs):
        return cls._endpoint(api, **kwargs)

    @classmethod
    def _params(cls, method, *param_keys, **kwargs):
        params = {}
        json_params = {}
        for k, v in kwargs.items():
            if v is not None:
                # try to parse "*_id" stuff as integer
                if k.endswith('_id'):
                    try:
                        parsed_value = str(int(v))
                    except Exception:
                        # fallback to string
                        parsed_value = str(v)
                elif isinstance(v, bool):
                    parsed_value = int(v)
                else:
                    parsed_value = v
                if method == 'POST':
                    json_params[k] = parsed_value
                elif method == 'GET' or k in param_keys:
                    params[k] = parsed_value
                else:
                    json_params[k] = parsed_value

        params = params if params else None
        json_params = json_params if json_params else None
        return params, json_params

    @classmethod
    def _list_params(cls, **kwargs):
        return cls._params('GET', cls.RESOURCE_ID_KEY, **kwargs)

    @classmethod
    def _create_params(cls, **kwargs):
        return cls._params('POST', cls.RESOURCE_ID_KEY, **kwargs)

    @classmethod
    def _get_params(cls, **kwargs):
        return cls._params('GET', cls.RESOURCE_ID_KEY, **kwargs)

    @classmethod
    def _head_params(cls, **kwargs):
        return cls._params('HEAD', cls.RESOURCE_ID_KEY, **kwargs)

    @classmethod
    def _update_params(cls, **kwargs):
        return cls._params('PUT', cls.RESOURCE_ID_KEY, **kwargs)

    @classmethod
    def _delete_params(cls, **kwargs):
        return cls._params('DELETE', cls.RESOURCE_ID_KEY, **kwargs)

    @classmethod
    def _list_headers(cls, api):
        return None

    @classmethod
    def _create_headers(cls, api):
        return None

    @classmethod
    def _get_headers(cls, api):
        return None

    @classmethod
    def _head_headers(cls, api):
        return None

    @classmethod
    def _update_headers(cls, api):
        return None

    @classmethod
    def _delete_headers(cls, api):
        return None

    @classmethod
    def _build_request(cls, api, method, url, headers, params, json_params):
        request_params = {'method': method, 'url': url}
        if params:
            request_params['params'] = params
        if json_params:
            request_params['json'] = json_params
        if headers:
            request_params['headers'] = headers
        return PolyswarmRequest(api, request_params, result_parser=cls)

    @classmethod
    def create(cls, api, **kwargs):
        return cls._build_request(api, 'POST', cls._create_endpoint(api, **kwargs),
                                  cls._create_headers(api), *cls._create_params(**kwargs)).execute()

    @classmethod
    def get(cls, api, **kwargs):
        return cls._build_request(api, 'GET', cls._get_endpoint(api, **kwargs),
                                  cls._get_headers(api), *cls._get_params(**kwargs)).execute()

    @classmethod
    def head(cls, api, **kwargs):
        return cls._build_request(api, 'HEAD', cls._head_endpoint(api, **kwargs),
                                  cls._head_headers(api), *cls._head_params(**kwargs)).execute()

    @classmethod
    def update(cls, api, **kwargs):
        return cls._build_request(api, 'PUT', cls._update_endpoint(api, **kwargs),
                                  cls._update_headers(api), *cls._update_params(**kwargs)).execute()

    @classmethod
    def delete(cls, api, **kwargs):
        return cls._build_request(api, 'DELETE', cls._delete_endpoint(api, **kwargs),
                                  cls._delete_headers(api), *cls._delete_params(**kwargs)).execute()

    @classmethod
    def list(cls, api, **kwargs):
        return cls._build_request(api, 'GET', cls._list_endpoint(api, **kwargs),
                                  cls._list_headers(api), *cls._list_params(**kwargs)).execute()


def is_hex(value):
    try:
        _ = int(value, 16)
        return True
    except ValueError:
        return False


def is_valid_sha1(value):
    if len(value) != 40:
        return False
    return is_hex(value)


def is_valid_md5(value):
    if len(value) != 32:
        return False
    return is_hex(value)


def is_valid_sha256(value):
    if len(value) != 64:
        return False
    return is_hex(value)


class Hashable(object):
    SUPPORTED_HASH_TYPES = {
        'sha1': is_valid_sha1,
        'sha256': is_valid_sha256,
        'md5': is_valid_md5,
    }

    def __init__(self, *args, **kwargs):
        # hack to behave as in python 3, signature should be
        # __init__(self, content, *args, hash_value=None, hash_type=None, validate_hash=False, **kwargs)
        hash_value = kwargs.pop('hash_value', None)
        hash_type = kwargs.pop('hash_type', None)
        validate_hash = kwargs.pop('validate_hash', False)
        super(Hashable, self).__init__(*args, **kwargs)

        self._hash = hash_value.strip() if hash_value is not None else None

        if hash_type:
            if hash_type not in self.SUPPORTED_HASH_TYPES:
                raise exceptions.InvalidValueException('Hash type provided is not supported.')
            self._hash_type = hash_type
        else:
            self._hash_type = self.resolve_hash_type()

        if self._hash_type is None:
            raise exceptions.InvalidValueException('Invalid hash provided: {}'.format(self._hash))

        if validate_hash:
            self.validate()

    @property
    def hash(self):
        return self._hash

    @hash.setter
    def hash(self, value):
        self._hash = value.strip() if value is not None else None

    @property
    def hash_type(self):
        return self._hash_type

    def validate(self):
        hash_type = self.resolve_hash_type()
        if self.hash_type != hash_type:
            raise exceptions.InvalidValueException('Detected hash type {}, got type {} for hash {}'
                                                   .format(hash_type, self.hash_type, self.hash))

    def resolve_hash_type(self):
        for hash_type, validator in self.SUPPORTED_HASH_TYPES.items():
            if validator(self._hash):
                return hash_type
        return None

    @property
    def raw(self):
        return unhexlify(self.hash)

    def __eq__(self, other):
        return self.hash == other


def parse_isoformat(date_string):
    """ Parses the current date format version """
    if date_string:
        return parser.isoparse(date_string)
    else:
        return None
