import json
import logging
from copy import deepcopy
from binascii import unhexlify
from json.decoder import JSONDecodeError

import httpx
import datetime as dt
from dateutil import parser

from polyswarm_api import settings, exceptions

logger = logging.getLogger(__name__)


class PolyswarmSession:
    """Thin wrapper over ``httpx.Client`` exposing the request/verify/headers
    surface that ``PolyswarmRequest`` expects.

    Migrated from ``requests.Session`` to ``httpx.Client`` so that the sync
    and async clients share a single HTTP library.
    """

    def __init__(self, key, retries=settings.DEFAULT_RETRIES,
                 user_agent=settings.DEFAULT_USER_AGENT, verify=True,
                 timeout=settings.DEFAULT_HTTP_TIMEOUT, **httpx_kwargs):
        logger.debug('Creating PolyswarmSession (httpx-backed)')
        self.verify = verify
        hdrs = httpx_kwargs.pop('headers', None) or {}
        if key:
            hdrs['Authorization'] = key
        if user_agent:
            hdrs['User-Agent'] = user_agent
        transport = httpx_kwargs.pop('transport', None) or httpx.HTTPTransport(
            retries=retries, verify=verify,
        )
        self._client = httpx.Client(
            headers=hdrs,
            transport=transport,
            timeout=timeout,
            verify=verify,
            follow_redirects=True,
            **httpx_kwargs,
        )

    def request(self, method, url, **kwargs):
        # httpx doesn't accept ``stream=`` as a kwarg to ``.request()``
        # the way requests does. For now we drop it — large downloads
        # buffer fully into memory, matching the async client's behaviour
        # (see aio/core.py). Streamed download support is a future improvement.
        kwargs.pop('stream', None)
        # httpx rejects None header values; requests used them to remove
        # a header. Strip them out — session-level header stays.
        if 'headers' in kwargs:
            kwargs['headers'] = {k: v for k, v in kwargs['headers'].items() if v is not None}
            if not kwargs['headers']:
                del kwargs['headers']
        # httpx serialises bool params as lowercase ``true``/``false``;
        # requests used Python's ``str()`` which yields ``True``/``False``.
        # Existing cassettes were recorded against requests — normalise
        # to the requests format so they keep replaying.
        if 'params' in kwargs:
            kwargs['params'] = _normalise_bool_params(kwargs['params'])
        return self._client.request(method, url, **kwargs)

    @property
    def headers(self):
        return self._client.headers

    def close(self):
        self._client.close()


def _normalise_bool_params(params):
    """Convert bool values to capitalised strings (``'True'`` / ``'False'``)
    matching the ``str(bool)`` serialisation that ``requests`` produced.

    httpx writes booleans lowercase (``'true'`` / ``'false'``), so existing
    VCR cassettes recorded with requests would mismatch. Apply this on
    both the sync and async sessions to keep cassettes valid.
    """
    def _normalise_value(v):
        if isinstance(v, bool):
            return str(v)
        if isinstance(v, (list, tuple)):
            return [_normalise_value(item) for item in v]
        return v

    if isinstance(params, dict):
        return {k: _normalise_value(v) for k, v in params.items()}
    if isinstance(params, (list, tuple)):
        return [(k, _normalise_value(v)) for k, v in params]
    return params


class RequestParamsEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            return json.JSONEncoder.default(self, obj)
        except Exception:
            return str(obj)


class HttpxResponseAdapter:
    """Adapt ``httpx.Response`` to the ``requests.Response`` surface used by
    non-JSON resource parsers (e.g. ``LocalArtifact``, which calls
    ``response.iter_content(chunk_size)``).

    Shared between sync ``PolyswarmRequest`` and async
    ``AsyncPolyswarmRequest`` now that both transports use httpx.
    """

    def __init__(self, response):
        self.status_code = response.status_code
        self.headers = response.headers
        self.url = str(response.url)
        self._content = response.content

    def iter_content(self, chunk_size=None):
        content = self._content
        if not chunk_size or len(content) <= chunk_size:
            yield content
        else:
            for i in range(0, len(content), chunk_size):
                yield content[i:i + chunk_size]

    def json(self):
        return json.loads(self._content)


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
        self.raw_result = self.session.request(**self.request_parameters)
        logger.debug('Request returned code %s', self.raw_result.status_code)

        # Non-JSON parsers expect a ``requests.Response``-shaped object with
        # ``iter_content``. Wrap the ``httpx.Response`` so file downloads etc.
        # see the surface they expect.
        result_for_parsing = self.raw_result
        if (
            self.result_parser
            and not issubclass(self.result_parser, BaseJsonResource)
            and not hasattr(self.raw_result, 'iter_content')
        ):
            result_for_parsing = HttpxResponseAdapter(self.raw_result)

        self.parse_result(result_for_parsing)
        return self

    def _bad_status_message(self):
        request_parameters = json.dumps(self.request_parameters, indent=4, sort_keys=True, cls=RequestParamsEncoder)
        message = f"Error when running the request:\n{request_parameters}\n" \
                  f"Return code: {self.status_code}\n" \
                  f"Message: {self._result}"
        if self.errors:
            errors = '\n'.join(str(error) for error in self.errors)
            message = f'{message}\nErrors:\n{errors}'
        return message

    def _extract_json_body(self, result):
        self.json = result.json()
        self._result = self.json.get('result')
        self.status = self.json.get('status')
        self.errors = self.json.get('errors')

    def parse_result(self, result):
        self.status_code = result.status_code
        if self.request_parameters['method'] == 'HEAD':
            # HEAD: status code IS the result; suppress non-2xx mapping
            # so callers (e.g. ``exists_hash``) can read 404 as "absent"
            # without raising.
            logger.debug('HEAD method does not return results, setting it to the status code.')
            self._result = self.status_code
            return
        logger.debug('Parsing request results.')
        try:
            if self.status_code // 100 != 2:
                # Non-2xx: map to the appropriate exception regardless of
                # whether ``result_parser`` is set. Previously this branch
                # was gated on ``result_parser`` — endpoints whose
                # builders did not set one (e.g. ``Webhook.test``) would
                # silently swallow server errors.
                self._extract_json_body(result)
                if self.status_code == 429:
                    message = f'{self._result} This may mean you need to purchase a ' \
                              'larger package, or that you have exceeded ' \
                              'rate limits. If you continue to have issues, ' \
                              'please contact us at info@polyswarm.io.'
                    raise exceptions.UsageLimitsExceededException(self, message)
                elif self.status_code == 404:
                    raise exceptions.NotFoundException(self, self._result)
                elif self.status_code == 422:
                    raise exceptions.FailedInstanceException(self, self._result)
                else:
                    raise exceptions.RequestException(self, self._bad_status_message())
            if not self.result_parser:
                # 2xx without a parser: body is intentionally discarded
                # (e.g. fire-and-forget endpoints like ``Webhook.test``).
                logger.debug('Result parser is not defined, skipping parsing results.')
                return
            if self.status_code == 204:
                raise exceptions.NoResultsException(self, 'The request returned no results.')
            if issubclass(self.result_parser, BaseJsonResource):
                self._extract_json_body(result)
                if self.request_parameters['method'] == 'GET' and 'has_more' in self.json:
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
                raise exceptions.NotFoundException(self, 'The requested endpoint does not exist.') from e
            else:
                err_msg = f'Server returned non-JSON response [{self.status_code}]: {result}'
                raise exceptions.RequestException(self, err_msg) from e

    def __iter__(self):
        return self.consume_results()

    def consume_results(self):
        # StopIteration is deprecated
        # As per https://www.python.org/dev/peps/pep-0479/
        # We simply return upon termination condition
        request = self
        while True:
            # consume items from list if iterable
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


class BaseResource:
    def __init__(self, content, *args, **kwargs):
        # hack to behave as in python 3, signature should be
        # __init__(self, content, *args, api=None, **kwargs)
        api = kwargs.pop('api', None)
        super().__init__(*args, **kwargs)
        self.api = api
        self._content = content

    @classmethod
    def parse_result(cls, api, content, **kwargs):
        logger.debug('Parsing resource %s', cls.__name__)
        return cls(content, api=api, **kwargs)


class BaseJsonResource(BaseResource):
    RESOURCE_ENDPOINT = None
    RESOURCE_ID_KEYS = ['id']

    def __init__(self, content, *args, **kwargs):
        super().__init__(content, *args, **kwargs)
        self.json = content

    def __int__(self):
        id_ = getattr(self, 'id', None)
        if id_ is None:
            raise TypeError(f'Resource {type(self).__name__} does not have an id and can not be cast to int')
        return int(id_)

    def jmespath(self, expr):
        """Apply a JMESPath expression to this resource's underlying JSON.

        Lets callers pull fields out of any API response without manual dotted-path
        navigation or piping ``--fmt json`` CLI output through ``jq``. Uses JMESPath
        syntax — see https://jmespath.org for the full grammar (no leading dot,
        ``[*]`` projections, ``[?expr]`` filters, function calls, etc.).

        Returns ``None`` when the expression resolves nothing in the document.

        Example::

            instance = api.lookup(scan_id)
            polyscore = instance.jmespath("scan.latest_scan.polyscore")
            mal_engines = instance.jmespath(
                "scan.latest_scan.assertions[?verdict=='malicious'].engine.name"
            )
        """
        import jmespath as _jmespath
        return _jmespath.search(expr, self.json)

    def _get(self, path, default=None, content=None):
        """
        Helper for rendering attributes of child objects in the json that might be None.
        Returns the default value if any item in the path is not present.
        """
        previous_attribute = 'resource_json'
        obj = content or self.json
        try:
            for attribute in path.split('.'):
                if obj is None:
                    raise KeyError(f'{previous_attribute} is None, can not resolve full path')
                if attribute.endswith(']'):
                    # handling the list case, e.g.: "root.list_attr[2]"
                    attribute, _, index = attribute.rpartition('[')
                    index = int(index.rstrip(']'))
                    obj = obj[attribute]
                    if obj is None:
                        raise KeyError(f'{attribute} is None, but is it supposed to be a list')
                    elif not isinstance(obj, list):
                        raise ValueError(f'Can not access index for {attribute}, it is not a list.')
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
    def _endpoint(cls, api, endpoint_fmt=None, **kwargs):
        if cls.RESOURCE_ENDPOINT is None:
            raise exceptions.InvalidValueException('RESOURCE_ENDPOINT is not configured for this resource.')
        endpoint = cls.RESOURCE_ENDPOINT
        if endpoint_fmt is not None:
            endpoint = endpoint.format(**endpoint_fmt)
        return '{api.uri}{endpoint}'.format(api=api, endpoint=endpoint, **kwargs)

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
    def _params(cls, method, *param_keys, endpoint_fmt=None, **kwargs):
        params = {}
        json_params = {}
        for k, v in kwargs.items():
            if v is not None:
                # try to parse "*_id" stuff as integer
                if k == 'id' or k.endswith('_id'):
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
        return cls._params('GET', *cls.RESOURCE_ID_KEYS, **kwargs)

    @classmethod
    def _create_params(cls, **kwargs):
        return cls._params('POST', *cls.RESOURCE_ID_KEYS, **kwargs)

    @classmethod
    def _get_params(cls, **kwargs):
        return cls._params('GET', *cls.RESOURCE_ID_KEYS, **kwargs)

    @classmethod
    def _head_params(cls, **kwargs):
        return cls._params('HEAD', *cls.RESOURCE_ID_KEYS, **kwargs)

    @classmethod
    def _update_params(cls, **kwargs):
        return cls._params('PUT', *cls.RESOURCE_ID_KEYS, **kwargs)

    @classmethod
    def _delete_params(cls, **kwargs):
        return cls._params('DELETE', *cls.RESOURCE_ID_KEYS, **kwargs)

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

    # NOTE: these classmethods return an UNEXECUTED ``PolyswarmRequest``.
    # Phase 2 of the sync/async refactor (DN-8225) moved execution onto
    # the API client's ``_single`` / ``_paginate`` so the same request
    # builder works on both sync and async transports.

    @classmethod
    def create(cls, api, **kwargs):
        return cls._build_request(api, 'POST', cls._create_endpoint(api, **kwargs),
                                  cls._create_headers(api), *cls._create_params(**kwargs))

    @classmethod
    def get(cls, api, **kwargs):
        return cls._build_request(api, 'GET', cls._get_endpoint(api, **kwargs),
                                  cls._get_headers(api), *cls._get_params(**kwargs))

    @classmethod
    def head(cls, api, **kwargs):
        return cls._build_request(api, 'HEAD', cls._head_endpoint(api, **kwargs),
                                  cls._head_headers(api), *cls._head_params(**kwargs))

    @classmethod
    def update(cls, api, **kwargs):
        return cls._build_request(api, 'PUT', cls._update_endpoint(api, **kwargs),
                                  cls._update_headers(api), *cls._update_params(**kwargs))

    @classmethod
    def delete(cls, api, **kwargs):
        return cls._build_request(api, 'DELETE', cls._delete_endpoint(api, **kwargs),
                                  cls._delete_headers(api), *cls._delete_params(**kwargs))

    @classmethod
    def list(cls, api, **kwargs):
        return cls._build_request(api, 'GET', cls._list_endpoint(api, **kwargs),
                                  cls._list_headers(api), *cls._list_params(**kwargs))


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


class Hashable:
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
        super().__init__(*args, **kwargs)

        self._hash = hash_value.strip() if hash_value is not None else None

        if hash_type:
            if hash_type not in self.SUPPORTED_HASH_TYPES:
                raise exceptions.InvalidValueException('Hash type provided is not supported.')
            self._hash_type = hash_type
        else:
            self._hash_type = self.resolve_hash_type()

        if self._hash_type is None:
            raise exceptions.InvalidValueException(f'Invalid hash provided: {self._hash}')

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
            raise exceptions.InvalidValueException(
                f'Detected hash type {hash_type}, got type {self.hash_type} for hash {self.hash}')

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
    """Parses the current date format version """
    if isinstance(date_string, (dt.date, dt.datetime)):
        return date_string
    elif date_string:
        return parser.isoparse(date_string)
    else:
        return None
