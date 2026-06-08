"""HTTP transport — the session.

The canonical version of this file lives at
``polyswarm_api/aio/session.py``; the sync mirror at
``polyswarm_api/session.py`` is generated from it by
``scripts/regenerate_sync.py``. Edit only the canonical (async) file.

The session is the **only** place HTTP I/O happens in this SDK. It
owns an httpx client (``AsyncClient`` on the async transport;
``Client`` on the sync transport) and exposes two I/O methods:

- ``execute(request)`` — the authenticated round-trip. Sends the
  ``PolyswarmRequest`` descriptor, attaches the raw response,
  delegates to ``parse_response`` for body interpretation, and
  returns the now-populated request. Typed HTTP exceptions raised by
  ``parse_response`` already carry ``.request = request`` (set in the
  exception constructor) — the session re-raises them as-is.
- ``upload_file(url, artifact, …)`` — PUT a file to a pre-signed URL
  with the session-level ``Authorization`` header stripped (so the
  PolySwarm API key doesn't leak to S3). Retries on transient errors.

Customization is via subclass + inject: override any method on a
subclass and pass it as ``session=`` to the api client. See
``specs/05-downstream-contract.md`` for the contract.
"""

import io
import logging
import os

import httpx

from polyswarm_api import exceptions, settings  # noqa: F401  (exceptions re-exported by callers)
from polyswarm_api.core import (
    BaseJsonResource,
    parse_response,
    _raise_for_status,
)

logger = logging.getLogger(__name__)


class AsyncPolyswarmSession:
    """The transport — owns one httpx client (``AsyncClient`` on the
    async transport; ``Client`` on the sync transport) and exposes
    every HTTP-I/O operation the SDK performs.
    """

    def __init__(
        self,
        key,
        retries=settings.DEFAULT_RETRIES,
        user_agent=settings.DEFAULT_USER_AGENT,
        verify=True,
        timeout=settings.DEFAULT_HTTP_TIMEOUT,
        **httpx_kwargs,
    ):
        logger.debug('Creating %s (httpx-backed)', type(self).__name__)
        self.verify = verify
        # Copy: we inject Authorization / User-Agent below and must not mutate a
        # headers dict the caller passed in (it may be shared / reused).
        hdrs = dict(httpx_kwargs.pop('headers', None) or {})
        if key:
            hdrs['Authorization'] = key
        if user_agent:
            hdrs['User-Agent'] = user_agent
        transport = httpx_kwargs.pop('transport', None) or httpx.AsyncHTTPTransport(
            retries=retries, verify=verify,
        )
        self._client = httpx.AsyncClient(
            headers=hdrs,
            transport=transport,
            timeout=timeout,
            verify=verify,
            follow_redirects=True,
            **httpx_kwargs,
        )

    # ── Authenticated round-trip ──────────────────────────────────

    async def execute(self, request):
        """Send ``request`` and parse the response.

        JSON endpoints buffer the (small) body and delegate to the pure
        ``parse_response``. A non-``BaseJsonResource`` parser is a download:
        it takes the streaming branch (``_execute_download``) so the body is
        streamed to its destination instead of read into memory. The session
        is the single place ``await`` and the httpx client meet.
        """
        if (
            request.result_parser is not None
            and not issubclass(request.result_parser, BaseJsonResource)
        ):
            return await self._execute_download(request)

        kwargs = request.to_httpx_kwargs()
        suppress = request.suppressed_headers()

        if suppress:
            # Caller asked to drop session-level headers (e.g.
            # ``Authorization`` for a pre-signed S3 download). Build the
            # request via ``build_request`` so the client/request header
            # merge happens, then pop the suppressed names.
            req = self._client.build_request(request.method, request.url, **kwargs)
            for header_name in suppress:
                req.headers.pop(header_name, None)
            response = await self._client.send(req)
        else:
            response = await self._client.request(request.method, request.url, **kwargs)

        logger.debug('Request returned code %s', response.status_code)
        parse_response(response, request)
        return request

    # ── Streaming downloads ───────────────────────────────────────

    async def _execute_download(self, request):
        """Stream a non-JSON download to its destination without buffering the
        whole body in memory.

        The body is opened in streaming mode via ``send(..., stream=True)``,
        which also covers the auth-stripped off-domain S3 case (``download_archive``)
        because header suppression goes through ``build_request`` + pop here.
        Non-2xx responses are read and mapped through the shared
        ``_raise_for_status`` (identical typed exceptions to the JSON path). On
        2xx, the result-parser class resolves a destination handle
        (``open_destination``), the body is streamed into it chunk by chunk, and
        the parser wraps the written handle (``from_written``). A failed write to
        a file the SDK created is cleaned up.

        For a ``folder`` / file-handle destination this never holds the whole
        artifact in memory; a caller-supplied in-memory handle (e.g. ``BytesIO``)
        still lands in memory by the caller's own choice of sink.
        """
        kwargs = request.to_httpx_kwargs()
        suppress = request.suppressed_headers()
        req = self._client.build_request(request.method, request.url, **kwargs)
        for header_name in suppress:
            req.headers.pop(header_name, None)

        response = await self._client.send(req, stream=True)
        try:
            logger.debug('Download returned code %s', response.status_code)
            request.raw_result = response
            request.status_code = response.status_code
            if response.status_code // 100 != 2:
                # Read the (small) error body so the shared mapping can parse it.
                await response.aread()
                _raise_for_status(response, request)

            pk = request.parser_kwargs or {}
            handle, name, created = request.result_parser.open_destination(
                pk.get('folder'), pk.get('handle'), pk.get('artifact_name'), response,
            )
            try:
                async for chunk in response.aiter_bytes(settings.DOWNLOAD_CHUNK_SIZE):
                    handle.write(chunk)
                    if hasattr(handle, 'flush'):
                        handle.flush()
            except Exception:
                if created:
                    try:
                        handle.close()
                        os.remove(handle.name)
                    except Exception:
                        logger.exception('Failed to clean up the partially-written download.')
                raise
            request._result = request.result_parser.from_written(
                request.api, handle, name,
                artifact_type=pk.get('artifact_type'),
                analyze=pk.get('analyze', False),
            )
        finally:
            await response.aclose()
        return request

    # ── Pre-signed-URL uploads ────────────────────────────────────

    async def upload_file(self, upload_url, artifact, attempts=3, **kwargs):
        """PUT ``artifact`` to a pre-signed URL.

        The session-level ``Authorization`` header is stripped from the
        outgoing PUT — pre-signed URLs carry their own auth in the
        query parameters and the PolySwarm API key must not leak to
        the object store.

        Retries up to ``attempts`` times on transient HTTP / transport
        errors. Re-raises the last exception when retries are
        exhausted.
        """
        if not upload_url:
            raise exceptions.InvalidValueException(
                'upload_url must be set to upload a file',
            )
        if not artifact:
            raise exceptions.InvalidValueException(
                'A LocalArtifact must be provided in order to upload',
            )
        if attempts < 1:
            # Guard: otherwise the retry loop never runs and `raise last_exc`
            # below would be `raise None` (TypeError). attempts is part of the
            # public override surface, so reject the nonsensical value clearly.
            raise exceptions.InvalidValueException(
                'attempts must be >= 1',
            )

        last_exc = None
        for attempt_no in range(attempts):
            artifact.seek(0, io.SEEK_END)
            length = artifact.tell()
            artifact.seek(0)
            # Empty files use empty bytes to avoid chunked encoding.
            data = b'' if not length else artifact.read()
            try:
                r = await self._put_off_domain(upload_url, content=data, **kwargs)
                r.raise_for_status()
                return r
            except (httpx.HTTPStatusError, httpx.TransportError) as e:
                last_exc = e
                logger.debug(
                    'upload attempt %d/%d failed: %r', attempt_no + 1, attempts, e,
                )
        raise last_exc

    async def _put_off_domain(self, url, *, content, headers=None, **kwargs):
        """PUT ``content`` to ``url`` with the session-level
        ``Authorization`` header stripped.

        Used by ``upload_file`` to hit pre-signed S3 URLs without
        leaking the PolySwarm API key. ``client.put`` merges client +
        request headers and won't honour ``None`` as suppression; we
        go through ``client.build_request`` (which performs the
        merge) and pop the header off the resulting ``Headers`` before
        ``client.send``.

        Override on a subclass to change off-domain auth handling
        (e.g. inject S3 SigV4, swap the credential).
        """
        req_headers = dict(headers) if headers else {}
        req = self._client.build_request(
            'PUT', url, content=content, headers=req_headers, **kwargs,
        )
        req.headers.pop('Authorization', None)
        return await self._client.send(req)

    # ── Lifecycle ─────────────────────────────────────────────────

    @property
    def headers(self):
        return self._client.headers

    async def aclose(self):
        await self._client.aclose()
