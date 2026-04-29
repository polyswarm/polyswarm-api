"""Async HTTP transport for PolySwarm API.

Replaces polyswarm_api.core.PolyswarmSession and PolyswarmRequest
with httpx.AsyncClient equivalents. Reuses all resource parsing,
exception handling, and pagination logic from the sync SDK.
"""

import json
import logging
from copy import deepcopy
from json.decoder import JSONDecodeError
from typing import AsyncGenerator

import httpx

from polyswarm_api import exceptions, settings
from polyswarm_api.core import BaseJsonResource, RequestParamsEncoder

logger = logging.getLogger(__name__)


class AsyncPolyswarmSession:
    """Async equivalent of polyswarm_api.core.PolyswarmSession.

    Wraps httpx.AsyncClient with the same auth/retry/UA configuration
    as the sync PolyswarmSession(requests.Session).
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
        """Execute an HTTP request."""
        return await self._client.request(method, url, **kwargs)

    async def close(self):
        """Close the underlying httpx client."""
        await self._client.aclose()


class _HttpxResponseAdapter:
    """Make httpx.Response compatible with code that expects a requests.Response.

    ``LocalArtifact`` (and a few other resource classes) call
    ``response.iter_content(chunk_size)`` which is a requests-ism.
    httpx exposes the same data via ``iter_bytes`` / ``.content``.
    """

    def __init__(self, response: httpx.Response):
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
                yield content[i : i + chunk_size]


class AsyncPolyswarmRequest:
    """Async equivalent of polyswarm_api.core.PolyswarmRequest.

    Same response parsing and pagination logic, but execute() is async
    and consume_results() is an async generator.
    """

    def __init__(self, api_instance, request_parameters, result_parser=None, **kwargs):
        self.api_instance = api_instance
        self.session = api_instance.session
        self.timeout = api_instance.timeout or settings.DEFAULT_HTTP_TIMEOUT
        self.request_parameters = request_parameters
        self.result_parser = result_parser
        self.raw_result = None
        self.status_code = None
        self.status = None
        self.errors = None
        self._result = None
        self.json = None

        self._paginated = False
        self.total = None
        self.limit = None
        self.offset = None
        self.order_by = None
        self.direction = None
        self.has_more = None

        self.parser_kwargs = kwargs

    def result(self):
        """Return parsed result — generator if paginated, single value otherwise."""
        if self._paginated:
            return self.consume_results()
        return self._result

    async def execute(self):
        """Execute the HTTP request asynchronously."""
        self.request_parameters.setdefault("timeout", self.timeout)

        # Determine if streaming is needed (non-JSON resources like file downloads)
        if self.result_parser and not issubclass(self.result_parser, BaseJsonResource):
            self.request_parameters.setdefault("stream", True)

        # Extract method and url from the request dict (requests-style → httpx-style)
        params = dict(self.request_parameters)
        method = params.pop("method")
        url = params.pop("url")
        params.pop("stream", None)  # httpx doesn't use stream= kwarg for non-streaming

        # httpx rejects None header values; requests uses None to *remove* a header.
        # Strip them out here — the session-level header stays, but no TypeError.
        if "headers" in params:
            params["headers"] = {
                k: v for k, v in params["headers"].items() if v is not None
            }
            if not params["headers"]:
                del params["headers"]

        self.raw_result = await self.session.request(method, url, **params)
        self.parse_result(self.raw_result)
        return self

    def parse_result(self, result):
        """Parse HTTP response — identical logic to sync PolyswarmRequest.parse_result()."""
        self.status_code = result.status_code

        if self.request_parameters["method"] == "HEAD":
            self._result = self.status_code

        if not self.result_parser:
            return

        try:
            if self.status_code // 100 != 2:
                self._extract_json_body(result)
                if self.status_code == 429:
                    message = (
                        f"{self._result} This may mean you need to purchase a "
                        "larger package, or that you have exceeded "
                        "rate limits. If you continue to have issues, "
                        "please contact us at info@polyswarm.io."
                    )
                    raise exceptions.UsageLimitsExceededException(self, message)
                elif self.status_code == 404:
                    raise exceptions.NotFoundException(self, self._result)
                elif self.status_code == 422:
                    raise exceptions.FailedInstanceException(self, self._result)
                else:
                    raise exceptions.RequestException(self, self._bad_status_message())
            elif self.status_code == 204:
                raise exceptions.NoResultsException(self, "The request returned no results.")
            elif issubclass(self.result_parser, BaseJsonResource):
                self._extract_json_body(result)
                if self.request_parameters["method"] == "GET" and "has_more" in self.json:
                    self._paginated = True
                self.total = self.json.get("total")
                self.limit = self.json.get("limit")
                self.offset = self.json.get("offset")
                self.order_by = self.json.get("order_by")
                self.direction = self.json.get("direction")
                self.has_more = self.json.get("has_more")
                if "result" in self.json:
                    result_data = self.json["result"]
                elif "results" in self.json:
                    result_data = self.json["results"]
                else:
                    raise exceptions.RequestException(
                        self,
                        'The response standard must contain either the "result" or "results" key.',
                    )
                if isinstance(result_data, list):
                    self._result = self.result_parser.parse_result_list(
                        self.api_instance, result_data, **self.parser_kwargs
                    )
                else:
                    self._result = self.result_parser.parse_result(
                        self.api_instance, result_data, **self.parser_kwargs
                    )
            else:
                # Non-JSON parsers (e.g. LocalArtifact) expect a requests.Response
                # interface (iter_content, etc.).  Wrap httpx.Response if needed.
                if isinstance(result, httpx.Response):
                    result = _HttpxResponseAdapter(result)
                self._result = self.result_parser.parse_result(
                    self.api_instance, result, **self.parser_kwargs
                )
        except JSONDecodeError as e:
            if self.status_code == 404:
                raise exceptions.NotFoundException(
                    self, "The requested endpoint does not exist."
                ) from e
            err_msg = f"Server returned non-JSON response [{self.status_code}]: {result}"
            raise exceptions.RequestException(self, err_msg) from e

    def _extract_json_body(self, result):
        self.json = result.json()
        self._result = self.json.get("result")
        self.status = self.json.get("status")
        self.errors = self.json.get("errors")

    def _bad_status_message(self):
        request_parameters = json.dumps(
            self.request_parameters, indent=4, sort_keys=True, cls=RequestParamsEncoder
        )
        message = (
            f"Error when running the request:\n{request_parameters}\n"
            f"Return code: {self.status_code}\n"
            f"Message: {self._result}"
        )
        if self.errors:
            errors = "\n".join(str(error) for error in self.errors)
            message = f"{message}\nErrors:\n{errors}"
        return message

    async def consume_results(self) -> AsyncGenerator:
        """Async equivalent of PolyswarmRequest.consume_results()."""
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

    async def next_page(self) -> "AsyncPolyswarmRequest":
        """Fetch the next page of paginated results."""
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
