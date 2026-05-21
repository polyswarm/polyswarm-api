"""Async HTTP transport for the PolySwarm API.

``AsyncPolyswarmRequest`` inherits ``parse_result`` and the rest of the
response-handling machinery from sync ``polyswarm_api.core.PolyswarmRequest``
— the sync code is the source of truth — and only overrides the bits
that actually need ``async``/``await``: ``execute`` and the pagination
helpers (``consume_results``, ``next_page``).
"""

from copy import deepcopy
from typing import AsyncGenerator

import httpx

from polyswarm_api import settings
from polyswarm_api.core import (
    BaseJsonResource,
    HttpxResponseAdapter,
    PolyswarmRequest,
    _normalise_bool_params,
)


class AsyncPolyswarmSession:
    """Async equivalent of ``polyswarm_api.core.PolyswarmSession``.

    Wraps ``httpx.AsyncClient`` with the same auth/retry/UA configuration
    as the sync ``PolyswarmSession(requests.Session)``.
    """

    def __init__(
        self,
        key: str,
        retries: int = settings.DEFAULT_RETRIES,
        user_agent: str = settings.DEFAULT_USER_AGENT,
        verify: bool = True,
        timeout: float = settings.DEFAULT_HTTP_TIMEOUT,
        **httpx_kwargs,
    ):
        headers = httpx_kwargs.pop("headers", None) or {}
        if key:
            headers["Authorization"] = key
        if user_agent:
            headers["User-Agent"] = user_agent

        transport = httpx_kwargs.pop("transport", None) or httpx.AsyncHTTPTransport(
            retries=retries, verify=verify
        )
        self._client = httpx.AsyncClient(
            headers=headers,
            transport=transport,
            timeout=timeout,
            verify=verify,
            follow_redirects=True,
            **httpx_kwargs,
        )

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        # Match the sync session's bool-param normalisation so existing
        # cassettes (recorded against requests) keep replaying.
        if 'params' in kwargs:
            kwargs['params'] = _normalise_bool_params(kwargs['params'])
        return await self._client.request(method, url, **kwargs)

    async def close(self):
        await self._client.aclose()


# ``_HttpxResponseAdapter`` is now ``HttpxResponseAdapter`` in
# ``polyswarm_api.core`` (shared with sync, which is also httpx-backed).
_HttpxResponseAdapter = HttpxResponseAdapter  # backward-compat alias


class AsyncPolyswarmRequest(PolyswarmRequest):
    """Async request execution.

    Inherits ``parse_result`` / ``_extract_json_body`` / ``_bad_status_message``
    and all the pagination metadata bookkeeping from the sync
    ``PolyswarmRequest``. Only the execute and pagination methods need
    sync/async-specific bodies.
    """

    async def execute(self):  # type: ignore[override]
        self.request_parameters.setdefault("timeout", self.timeout)

        if self.result_parser and not issubclass(self.result_parser, BaseJsonResource):
            self.request_parameters.setdefault("stream", True)

        params = dict(self.request_parameters)
        method = params.pop("method")
        url = params.pop("url")
        params.pop("stream", None)  # httpx doesn't accept stream= as a kwarg here.

        # httpx rejects None header values; requests uses None to remove
        # a header. Strip them out — the session-level header stays, but
        # no TypeError.
        if "headers" in params:
            params["headers"] = {
                k: v for k, v in params["headers"].items() if v is not None
            }
            if not params["headers"]:
                del params["headers"]

        self.raw_result = await self.session.request(method, url, **params)

        # Non-JSON parsers expect a requests-like ``iter_content`` surface.
        result_for_parsing = self.raw_result
        if (
            self.result_parser
            and not issubclass(self.result_parser, BaseJsonResource)
            and not hasattr(self.raw_result, 'iter_content')
        ):
            result_for_parsing = HttpxResponseAdapter(self.raw_result)

        self.parse_result(result_for_parsing)
        return self

    def __iter__(self):
        # Force callers to use ``async for`` over ``consume_results``.
        raise TypeError(
            "AsyncPolyswarmRequest does not support sync iteration; "
            "use 'async for item in request.consume_results()' instead."
        )

    async def consume_results(self) -> AsyncGenerator:  # type: ignore[override]
        request = self
        while True:
            try:
                for item in request._result:
                    yield item
            except TypeError:
                yield request._result
                return

            if not request.has_more:
                return
            request = await request.next_page()

    async def next_page(self) -> "AsyncPolyswarmRequest":  # type: ignore[override]
        new_parameters = deepcopy(self.request_parameters)
        params = new_parameters.setdefault("params", {})
        if isinstance(params, dict):
            params["offset"] = self.offset
            params["limit"] = self.limit
        else:
            params = [p for p in params if p[0] not in ("offset", "limit")]
            params.extend([("offset", self.offset), ("limit", self.limit)])
            new_parameters["params"] = params
        return await AsyncPolyswarmRequest(
            self.api_instance,
            new_parameters,
            result_parser=self.result_parser,
        ).execute()
