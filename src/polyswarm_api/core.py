"""Transport-agnostic foundations for the PolySwarm SDK.

This module is hand-written. No HTTP I/O happens here — that's the
session's job (see ``polyswarm_api.session`` /
``polyswarm_api.aio.session``). What lives here is shared by both
transports so ``issubclass`` checks, dataclass identities, and pure
parsing logic have a single source of truth:

- ``PolyswarmRequest``: a dataclass descriptor of one HTTP call plus
  the mutable response-state slots the session fills in after the call.
  No ``execute``; no ``await``; no httpx.
- ``parse_response``: a pure function that reads an httpx-shaped
  response and populates the request's response-state fields (or raises
  a typed exception). Testable with a fake response object.
- ``BaseResource`` / ``BaseJsonResource``: resource bases. Classmethod
  builders (``create``, ``get``, ``head``, ``update``, ``delete``,
  ``list``) construct ``PolyswarmRequest`` descriptors.
- ``Hashable`` + ``is_valid_*`` validators, ``parse_isoformat``,
  ``_normalise_bool_params``, ``RequestParamsEncoder``.

Both transports import from here.
"""

import dataclasses
import json
import logging
import datetime as dt
from binascii import unhexlify
from json.decoder import JSONDecodeError
from typing import Any, Mapping, Optional

from dateutil import parser

from polyswarm_api import exceptions

logger = logging.getLogger(__name__)


# ── Helpers ────────────────────────────────────────────────────────


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


# ── Request descriptor ─────────────────────────────────────────────


@dataclasses.dataclass
class PolyswarmRequest:
    """A pure description of one HTTP call plus the response slots the
    session fills in afterwards.

    Input fields (set at construction by resource builders):

    - ``api``: the api client the call belongs to. Carried so
      ``parse_response`` can attach ``.api`` to resulting resources;
      the descriptor itself never calls back into the api.
    - ``method``, ``url``: HTTP verb + URL.
    - ``params``, ``json``, ``headers``, ``content``, ``data``,
      ``files``, ``timeout``: pass-through to httpx's request kwargs.
      ``None`` means "don't send".
    - ``result_parser``: a class (typically ``BaseJsonResource``
      subclass) whose ``parse_result`` / ``parse_result_list``
      classmethod turns the response body into the user-facing object.
      ``None`` means fire-and-forget (used by e.g. ``Webhook.test``).
    - ``parser_kwargs``: extra kwargs forwarded to ``parse_result``
      (e.g. ``handle``, ``folder``, ``artifact_name`` for downloads).

    Response-state fields (mutated by the session after the call):

    - ``raw_result``: the httpx (or adapter) response.
    - ``status_code``: HTTP status.
    - ``status``, ``errors``: extracted from a JSON response envelope
      when present.
    - ``json``: after execution this holds the *parsed response body*
      (legacy semantics — overwrites the send-body kwarg of the same
      name; callers read ``request.json['result']`` etc.).
    - ``_result``: the parsed user-facing payload (single object, list,
      or status code for HEAD).
    - ``_paginated``: True iff the response envelope carried
      ``has_more``.
    - ``total``, ``limit``, ``offset``, ``order_by``, ``direction``,
      ``has_more``: pagination metadata.

    The descriptor has no ``execute`` method. The session executes it.
    """

    api: Any
    method: str
    url: str
    params: Any = None
    # Constructor send-body kwarg (kept for back-compat). ``__post_init__`` moves
    # it to ``input_json`` and resets this to ``None``; after execution
    # ``parse_response`` fills ``json`` with the RESPONSE body. So post-construction
    # ``request.json`` always means "the response", never the send body — the send
    # body lives in ``input_json``.
    json: Any = None
    headers: Optional[Mapping[str, Any]] = None
    content: Optional[bytes] = None
    data: Any = None
    files: Any = None
    timeout: Optional[float] = None
    result_parser: Optional[type] = None
    parser_kwargs: dict = dataclasses.field(default_factory=dict)

    # Response state (filled in by the session after execute).
    raw_result: Any = dataclasses.field(default=None, repr=False)
    status_code: Optional[int] = None
    status: Any = None
    errors: Any = None
    _result: Any = dataclasses.field(default=None, repr=False)
    _paginated: bool = False
    total: Optional[int] = None
    limit: Optional[int] = None
    offset: Optional[int] = None
    order_by: Optional[str] = None
    direction: Optional[str] = None
    has_more: Optional[bool] = None

    # The JSON body that actually goes on the wire. The constructor takes the send
    # body as ``json=`` (back-compat); ``__post_init__`` moves it here. This is the
    # canonical send body — ``to_httpx_kwargs`` and pagination cloning read it — and
    # it stays put for the descriptor's whole life, so it never collides with the
    # response that later lands in ``json``. Visible in ``repr`` as the honest
    # record of what was sent.
    input_json: Any = dataclasses.field(default=None, init=False)

    def __post_init__(self):
        # Relocate the constructor's send body to ``input_json`` and reserve
        # ``self.json`` for the response. Resolving the send/response overload here
        # — once, at construction — means no reader has to depend on running before
        # vs. after ``parse_response``.
        self.input_json = self.json
        self.json = None

    # ── Projections ────────────────────────────────────────────────

    def to_httpx_kwargs(self) -> dict:
        """Project the descriptor into a kwargs dict for httpx.

        ``None`` fields are omitted (httpx would treat them differently
        than "absent"). Headers with ``None`` values are stripped here;
        the session is responsible for honouring them as "drop the
        session-level header" — see ``suppressed_headers``.
        """
        kwargs: dict = {}
        if self.params is not None:
            kwargs['params'] = _normalise_bool_params(self.params)
        # The wire body is ``input_json`` (the send body); ``self.json`` carries the
        # response after execution and is never sent.
        if self.input_json is not None:
            kwargs['json'] = self.input_json
        if self.headers:
            clean = {k: v for k, v in self.headers.items() if v is not None}
            if clean:
                kwargs['headers'] = clean
        if self.content is not None:
            kwargs['content'] = self.content
        if self.data is not None:
            kwargs['data'] = self.data
        if self.files is not None:
            kwargs['files'] = self.files
        if self.timeout is not None:
            kwargs['timeout'] = self.timeout
        return kwargs

    def suppressed_headers(self) -> set:
        """Names of session-level headers the caller wants stripped.

        A header value of ``None`` on the request means "remove this
        header from the outgoing request even if the session sets it"
        (used to strip ``Authorization`` when hitting pre-signed S3
        URLs). The session honours these by building the request via
        ``client.build_request`` and popping the names from the merged
        headers before sending.
        """
        if not self.headers:
            return set()
        return {k for k, v in self.headers.items() if v is None}

    # The pre-4.0 ``request_parameters`` dict is still useful for
    # diagnostics (``RequestException`` formats it into the error
    # message). Expose it as a property for back-compat.

    @property
    def request_parameters(self) -> dict:
        # ``to_httpx_kwargs`` projects the send body from ``input_json``, so this
        # diagnostic faithfully reports what was sent — even in error messages
        # raised after ``parse_response`` has populated ``self.json``.
        params = {'method': self.method, 'url': self.url}
        params.update(self.to_httpx_kwargs())
        if self.headers and self.suppressed_headers():
            # Preserve the suppression sentinel for diagnostics.
            params.setdefault('headers', {})
            for k in self.suppressed_headers():
                params['headers'][k] = None
        return params

    # Convenience accessors kept for backward compatibility. The parsed JSON
    # body lives on ``.json``; there is no separate ``.json_body`` field (see
    # specs/02-resources.md).

    @property
    def api_instance(self):
        return self.api


# ── Pure response parser ───────────────────────────────────────────


def parse_response(response, request: 'PolyswarmRequest') -> 'PolyswarmRequest':
    """Read ``response`` (httpx-shaped) and populate ``request``'s
    response-state fields. Pure — no I/O, no httpx-specific behaviour
    beyond ``.status_code`` / ``.json()`` / ``.headers``.

    Returns the (now-populated) request for chaining. Raises a typed
    ``RequestException`` subclass on non-2xx; the exception carries
    ``.request = request`` (set by ``RequestException.__init__``), so
    callers can read ``exc.request.status_code`` / ``exc.request.json``
    / etc. The session does not catch and rewrap — attachment happens
    at construction time.
    """
    request.raw_result = response
    request.status_code = response.status_code

    if request.method == 'HEAD':
        # HEAD: status code IS the result; suppress non-2xx mapping so
        # callers (e.g. ``exists_hash``) can read 404 as "absent"
        # without raising.
        logger.debug(
            'HEAD method does not return results, setting it to the status code.',
        )
        request._result = request.status_code
        return request

    logger.debug('Parsing request results.')
    try:
        if request.status_code // 100 != 2:
            # Non-2xx: map to the appropriate exception regardless of
            # whether ``result_parser`` is set. Shared with the session's
            # streaming-download path via ``_raise_for_status`` (always raises).
            _raise_for_status(response, request)

        if not request.result_parser:
            # 2xx without a parser: body is intentionally discarded
            # (e.g. fire-and-forget endpoints like ``Webhook.test``).
            logger.debug('Result parser is not defined, skipping parsing results.')
            return request

        if request.status_code == 204:
            raise exceptions.NoResultsException(
                request, 'The request returned no results.',
            )

        if issubclass(request.result_parser, BaseJsonResource):
            _extract_json_body(response, request)
            body = request.json
            if request.method == 'GET' and 'has_more' in body:
                request._paginated = True
            request.total = body.get('total')
            request.limit = body.get('limit')
            request.offset = body.get('offset')
            request.order_by = body.get('order_by')
            request.direction = body.get('direction')
            request.has_more = body.get('has_more')
            if 'result' in body:
                payload = body['result']
            elif 'results' in body:
                payload = body['results']
            else:
                raise exceptions.RequestException(
                    request,
                    'The response standard must contain either the "result" or "results" key.',
                )
            if isinstance(payload, list):
                request._result = request.result_parser.parse_result_list(
                    request.api, payload, **request.parser_kwargs,
                )
            else:
                request._result = request.result_parser.parse_result(
                    request.api, payload, **request.parser_kwargs,
                )
        else:
            request._result = request.result_parser.parse_result(
                request.api, response, **request.parser_kwargs,
            )
    except JSONDecodeError as e:
        if request.status_code == 404:
            raise exceptions.NotFoundException(
                request, 'The requested endpoint does not exist.',
            ) from e
        else:
            err_msg = (
                f'Server returned non-JSON response [{request.status_code}]: {response}'
            )
            raise exceptions.RequestException(request, err_msg) from e

    return request


def _raise_for_status(response, request):
    """Map a non-2xx ``response`` to the appropriate typed exception.

    Shared by ``parse_response`` (buffered/JSON path) and the session's
    streaming-download path, so both raise identically (429/404/422/other,
    plus the non-JSON-body fallbacks). A 404 whose ``errors`` payload carries the
    ``KNOWN_GOOD`` code raises the ``NotFoundException`` subclass
    ``KnownGoodWithheldException``. The response body must already be
    readable — streaming callers ``read()`` / ``aread()`` it first. **Always
    raises; never returns.**
    """
    try:
        _extract_json_body(response, request)
    except JSONDecodeError as e:
        if request.status_code == 404:
            raise exceptions.NotFoundException(
                request, 'The requested endpoint does not exist.',
            ) from e
        raise exceptions.RequestException(
            request,
            f'Server returned non-JSON response [{request.status_code}]: {response}',
        ) from e
    if request.status_code == 429:
        message = (
            f'{request._result} This may mean you need to purchase a '
            'larger package, or that you have exceeded '
            'rate limits. If you continue to have issues, '
            'please contact us at info@polyswarm.io.'
        )
        raise exceptions.UsageLimitsExceededException(request, message)
    elif request.status_code == 404:
        # A download refused because the artifact is a known-good binary carries a
        # machine-readable code in the error envelope's ``errors`` slot. Raise the
        # ``NotFoundException`` subclass so callers can tell "withheld by design"
        # apart from a plain miss; every other 404 stays a plain NotFoundException.
        # The raw ``sources`` payload goes in as-is — the exception normalises it
        # into the documented list-of-feed-names shape.
        errors = request.errors
        if isinstance(errors, dict) and errors.get('code') == 'KNOWN_GOOD':
            raise exceptions.KnownGoodWithheldException(
                request, request._result, sources=errors.get('sources'),
            )
        raise exceptions.NotFoundException(request, request._result)
    elif request.status_code == 422:
        raise exceptions.FailedInstanceException(request, request._result)
    else:
        raise exceptions.RequestException(request, _bad_status_message(request))


def _extract_json_body(response, request):
    body = response.json()
    # ``request.json`` is the RESPONSE body after execution (the send body lives in
    # ``request.input_json``, untouched). Callers read ``request.json['result']`` /
    # ``exc.request.json[...]``; before this point ``json`` was ``None``.
    request.json = body
    request._result = body.get('result') if isinstance(body, dict) else None
    if isinstance(body, dict):
        request.status = body.get('status')
        request.errors = body.get('errors')


def _bad_status_message(request):
    request_parameters = json.dumps(
        request.request_parameters, indent=4, sort_keys=True, cls=RequestParamsEncoder,
    )
    message = (
        f'Error when running the request:\n{request_parameters}\n'
        f'Return code: {request.status_code}\n'
        f'Message: {request._result}'
    )
    if request.errors:
        # Two ``errors`` shapes are in play. The legacy shape is a **list** of
        # per-error entries — one rendered line each. The way-forward shape is a
        # **mapping** carrying the machine-readable code plus its context
        # (``{'code': 'KNOWN_GOOD', 'known_good': True, 'sources': [...]}``), and the
        # server forwards it on every status, not just the 404 the code was
        # introduced for. Iterating a mapping yields only its KEYS, so rendering it
        # like a list would drop every value from the message the caller sees —
        # render it as ``key=value`` lines instead.
        # The same reasoning applies to a bare string: iterating it yields characters, so
        # `"errors": "some prose"` would render one letter per line. Only genuinely
        # sequence-shaped payloads get the line-per-entry treatment.
        if isinstance(request.errors, dict):
            errors = '\n'.join(f'{k}={v}' for k, v in request.errors.items())
        elif isinstance(request.errors, (list, tuple)):
            errors = '\n'.join(str(error) for error in request.errors)
        else:
            errors = str(request.errors)
        message = f'{message}\nErrors:\n{errors}'
    return message


# ── Resource bases ─────────────────────────────────────────────────


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
            raise TypeError(
                f'Resource {type(self).__name__} does not have an id and can not be cast to int',
            )
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
            raise exceptions.InvalidValueException(
                'RESOURCE_ENDPOINT is not configured for this resource.',
            )
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
        return PolyswarmRequest(
            api=api,
            method=method,
            url=url,
            params=params,
            json=json_params,
            headers=headers,
            result_parser=cls,
        )

    # Classmethod builders return an unexecuted ``PolyswarmRequest``
    # descriptor. The api client's ``_single`` / ``_paginate`` hands it
    # to the session for execution.

    @classmethod
    def create(cls, api, **kwargs):
        return cls._build_request(
            api, 'POST', cls._create_endpoint(api, **kwargs),
            cls._create_headers(api), *cls._create_params(**kwargs),
        )

    @classmethod
    def get(cls, api, **kwargs):
        return cls._build_request(
            api, 'GET', cls._get_endpoint(api, **kwargs),
            cls._get_headers(api), *cls._get_params(**kwargs),
        )

    @classmethod
    def head(cls, api, **kwargs):
        return cls._build_request(
            api, 'HEAD', cls._head_endpoint(api, **kwargs),
            cls._head_headers(api), *cls._head_params(**kwargs),
        )

    @classmethod
    def update(cls, api, **kwargs):
        return cls._build_request(
            api, 'PUT', cls._update_endpoint(api, **kwargs),
            cls._update_headers(api), *cls._update_params(**kwargs),
        )

    @classmethod
    def delete(cls, api, **kwargs):
        return cls._build_request(
            api, 'DELETE', cls._delete_endpoint(api, **kwargs),
            cls._delete_headers(api), *cls._delete_params(**kwargs),
        )

    @classmethod
    def list(cls, api, **kwargs):
        return cls._build_request(
            api, 'GET', cls._list_endpoint(api, **kwargs),
            cls._list_headers(api), *cls._list_params(**kwargs),
        )


def as_result_bound(max_results):
    """The caller's result bound, or None when there isn't one.

    None, 0 and negatives all mean "no bound".
    """
    if not max_results or max_results < 0:
        return None
    return max_results


# ── Hash helpers ───────────────────────────────────────────────────


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
                f'Detected hash type {hash_type}, got type {self.hash_type} for hash {self.hash}',
            )

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
