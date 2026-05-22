"""Transport-agnostic bases and helpers shared by sync + async cores.

Lives outside the unasync codegen so that ``BaseJsonResource``,
``HttpxResponseAdapter``, the parameter helpers, and the Hashable mixin
have *single class identities* — otherwise the generated sync core and
the canonical async core would each get their own copy of
``BaseJsonResource``, and ``issubclass`` checks across modules would
mis-fire.

This module is hand-written. Edit it directly when changing the
resource-base surface.
"""

import json
import logging
import datetime as dt
from binascii import unhexlify

from dateutil import parser

from polyswarm_api import exceptions

logger = logging.getLogger(__name__)


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


class BaseResource:
    def __init__(self, content, *args, **kwargs):
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
        """Helper for rendering attributes of child objects in the json that might be None."""
        previous_attribute = 'resource_json'
        obj = content or self.json
        try:
            for attribute in path.split('.'):
                if obj is None:
                    raise KeyError(f'{previous_attribute} is None, can not resolve full path')
                if attribute.endswith(']'):
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
                if k == 'id' or k.endswith('_id'):
                    try:
                        parsed_value = str(int(v))
                    except Exception:
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
        # Lazy import to avoid circular dependency: ``polyswarm_api.core``
        # (the generated sync core) imports from this module, and we
        # need its ``PolyswarmRequest`` here to construct the result.
        # The async client's ``_coerce_request`` rebuilds this into an
        # ``AsyncPolyswarmRequest`` when running under the async path.
        from polyswarm_api.core import PolyswarmRequest
        request_params = {'method': method, 'url': url}
        if params:
            request_params['params'] = params
        if json_params:
            request_params['json'] = json_params
        if headers:
            request_params['headers'] = headers
        return PolyswarmRequest(api, request_params, result_parser=cls)

    # These classmethods return an UNEXECUTED request. The API client's
    # ``_single`` / ``_paginate`` owns execution; on the async side
    # ``_coerce_request`` rebuilds the sync request as an
    # ``AsyncPolyswarmRequest`` first.

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
