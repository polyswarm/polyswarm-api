"""Async PolySwarm API client.

Mirrors polyswarm_api.api.PolyswarmAPI but uses httpx.AsyncClient for non-blocking
HTTP. All resource classes are reused from the sync SDK — only the transport layer
is replaced.

Usage::

    async with PolySwarmAsyncAPI(api_key) as client:
        # Search
        async for result in client.search_by_metadata("family:Emotet"):
            print(result.json)

        # Submit and wait
        instance = await client.submit("/path/to/sample.exe")
        scan = await client.wait_for(instance)

        # Sandbox
        task = await client.sandbox(instance.id, "triage", "win10-build-15063")
"""

import asyncio
import io
import logging
import time

from polyswarm_api import exceptions, resources, settings
from polyswarm_api._base import PolyswarmAPIBase

from .core import AsyncPolyswarmRequest, AsyncPolyswarmSession
from .upload import async_upload_file, async_upload_logo

logger = logging.getLogger(__name__)

__all__ = ["PolySwarmAsyncAPI"]


class PolySwarmAsyncAPI(PolyswarmAPIBase):
    """Async interface to the PolySwarm API.

    Same method signatures and return types as polyswarm_api.PolyswarmAPI,
    but all methods are async. Generator methods return async generators.
    Parallelism is left to the caller (asyncio.gather, semaphores, etc.).
    """


    def __init__(
        self,
        key: str,
        uri: str | None = None,
        community: str | None = None,
        timeout: float | None = None,
        verify: bool = True,
        **httpx_kwargs,
    ):
        super().__init__(key, uri=uri, community=community, timeout=timeout, verify=verify)
        self.session = AsyncPolyswarmSession(
            key,
            retries=settings.DEFAULT_RETRIES,
            verify=verify,
            timeout=self.timeout,
            **httpx_kwargs,
        )

    async def close(self):
        """Close the underlying HTTP client."""
        await self.session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    # ── PolyswarmAPIBase hooks ──────────────────────────────────────
    #
    # ``_single`` / ``_paginate`` accept either an unexecuted
    # ``PolyswarmRequest`` returned by a resource classmethod (Phase 2
    # endpoints) or a request-parameters dict (legacy / inline). The
    # async transport is plugged in via ``_request_cls``.

    _request_cls = AsyncPolyswarmRequest

    async def _single(self, request, result_parser=None, **kwargs):  # type: ignore[override]
        req = await self._coerce_request(request, result_parser, kwargs).execute()
        return req.result()

    async def _paginate(self, request, result_parser=None, **kwargs):  # type: ignore[override]
        req = await self._coerce_request(request, result_parser, kwargs).execute()
        if req._paginated:
            async for item in req.consume_results():
                yield item
        else:
            result = req._result
            if isinstance(result, list):
                for item in result:
                    yield item
            elif result is not None:
                yield result

    async def _sleep(self, seconds):
        await asyncio.sleep(seconds)

    # ── Internals ───────────────────────────────────────────────────

    async def _exec(self, request_parameters, result_parser=None, **kwargs):
        """Build and execute an ``AsyncPolyswarmRequest`` (legacy helper)."""
        return await AsyncPolyswarmRequest(
            self, request_parameters, result_parser=result_parser, **kwargs,
        ).execute()

    # Legacy alias retained for backward compatibility within this file.
    _generate = _paginate

    # ── Engines ──────────────────────────────────────────────────

    @property
    def engines(self):
        raise AttributeError(
            "Use 'await refresh_engine_cache()' then access '_engines' directly. "
            "Properties cannot be async."
        )

    async def refresh_engine_cache(self):
        """Refresh the cached engine listing."""
        engine_list = []
        async for engine in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.Engine.RESOURCE_ENDPOINT}/list",
                "headers": {"Authorization": None},
            },
            result_parser=resources.Engine,
        ):
            engine_list.append(engine)
        if not engine_list:
            raise exceptions.InvalidValueException("Received empty engines listing")
        self._engines = engine_list

    # ── Search & Lookup ──────────────────────────────────────────

    async def submit(
        self,
        artifact,
        artifact_type=resources.ArtifactType.FILE,
        artifact_name=None,
        scan_config=None,
        preprocessing=None,
        expiration_window=None,
    ):
        """Submit artifact for scanning. Returns ArtifactInstance.

        :param expiration_window: Expiration window in days (7, 30, or 180). Only valid for private communities.
        """
        artifact_type = resources.ArtifactType.parse(artifact_type)

        # Coerce artifact to LocalArtifact
        if isinstance(artifact, io.IOBase):
            artifact = resources.LocalArtifact.from_handle(
                self, artifact, artifact_name=artifact_name or "", artifact_type=artifact_type
            )
        elif isinstance(artifact, str):
            if artifact_type == resources.ArtifactType.FILE:
                artifact = resources.LocalArtifact.from_path(
                    self, artifact, artifact_type=artifact_type, artifact_name=artifact_name
                )
            elif artifact_type == resources.ArtifactType.URL:
                if preprocessing and preprocessing["type"] == "qrcode":
                    artifact = resources.LocalArtifact.from_path(
                        self, artifact, artifact_type=artifact_type, artifact_name=artifact_name
                    )
                else:
                    artifact = resources.LocalArtifact.from_content(
                        self, artifact, artifact_name=artifact_name or artifact,
                        artifact_type=artifact_type,
                    )

        if artifact_type == resources.ArtifactType.URL:
            scan_config = scan_config or "more-time"

        if isinstance(artifact, resources.LocalArtifact):
            # Create submission
            create_params = {
                "artifact_name": artifact.artifact_name,
                "artifact_type": artifact.artifact_type.name,
                "community": self.community,
            }
            if scan_config:
                create_params["scan_config"] = scan_config
            if preprocessing:
                create_params["preprocessing"] = preprocessing
            if expiration_window is not None:
                create_params["expiration_window"] = expiration_window

            instance = await self._single(
                {
                    "method": "POST",
                    "url": f"{self.uri}{resources.ArtifactInstance.RESOURCE_ENDPOINT}",
                    "json": create_params,
                },
                result_parser=resources.ArtifactInstance,
            )

            # Upload file to S3
            await async_upload_file(
                self.session._client, instance.upload_url, artifact
            )

            # Finalize — id goes in URL params, community in JSON body (mirrors sync update())
            return await self._single(
                {
                    "method": "PUT",
                    "url": f"{self.uri}{resources.ArtifactInstance.RESOURCE_ENDPOINT}",
                    "params": {"id": str(int(instance.id))},
                    "json": {"community": self.community},
                },
                result_parser=resources.ArtifactInstance,
            )

        raise exceptions.InvalidValueException(
            f"Unsupported artifact type: {type(artifact)}"
        )

    async def wait_for(self, scan, timeout=settings.DEFAULT_SCAN_TIMEOUT):
        """Async poll until scan completes or times out."""
        start = time.time()
        while True:
            scan_result = await self.lookup(scan)
            if scan_result.failed or scan_result.window_closed:
                return scan_result
            elif -1 < timeout < time.time() - start:
                raise exceptions.TimeoutException(
                    f"Timed out waiting for scan {scan} to finish. Please try again."
                )
            else:
                await asyncio.sleep(settings.POLL_FREQUENCY)

    # ── YARA Live Hunting ────────────────────────────────────────

    async def sandbox_file(
        self, artifact, provider_slug, vm_slug,
        artifact_type=resources.ArtifactType.FILE,
        artifact_name=None, network_enabled=True,
        preprocessing=None, arguments="",
    ):
        """Submit file directly to sandbox."""
        artifact_type = resources.ArtifactType.parse(artifact_type)

        # Coerce artifact to LocalArtifact
        if isinstance(artifact, io.IOBase):
            artifact = resources.LocalArtifact.from_handle(
                self, artifact, artifact_name=artifact_name or "", artifact_type=artifact_type
            )
        elif isinstance(artifact, str):
            if artifact_type == resources.ArtifactType.FILE:
                artifact = resources.LocalArtifact.from_path(
                    self, artifact, artifact_type=artifact_type, artifact_name=artifact_name
                )
            elif artifact_type == resources.ArtifactType.URL:
                artifact = resources.LocalArtifact.from_content(
                    self, artifact, artifact_name=artifact_name or artifact,
                    artifact_type=artifact_type,
                )

        json_params = {
            "artifact_name": artifact.artifact_name,
            "artifact_type": artifact.artifact_type.name,
            "community": self.community,
            "provider_slug": provider_slug,
            "vm_slug": vm_slug,
            "network_enabled": int(network_enabled),
        }
        if preprocessing:
            json_params["preprocessing"] = preprocessing
        if arguments:
            json_params["arguments"] = arguments

        # Create sandbox task
        task = await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.SandboxTask.RESOURCE_ENDPOINT}/instance",
                "json": json_params,
            },
            result_parser=resources.SandboxTask,
        )

        # Upload to S3
        await async_upload_file(self.session._client, task.upload_url, artifact)

        # Finalize
        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}{resources.SandboxTask.RESOURCE_ENDPOINT}/instance",
                "params": {"id": str(int(task))},
            },
            result_parser=resources.SandboxTask,
        )

    async def sandbox_url(
        self, url, provider_slug, vm_slug,
        browser=None, artifact=None, artifact_name=None, preprocessing=None,
    ):
        """Submit URL to sandbox."""
        if artifact and url:
            raise exceptions.InvalidValueException(
                "Cannot provide both artifact and url"
            )

        if artifact:
            if not preprocessing or preprocessing.get("type") != "qrcode":
                raise exceptions.InvalidValueException(
                    "artifact requires preprocessing type='qrcode'"
                )
            if isinstance(artifact, io.IOBase):
                local = resources.LocalArtifact.from_handle(
                    self, artifact, artifact_name=artifact_name or "",
                    artifact_type=resources.ArtifactType.URL,
                )
            elif isinstance(artifact, str):
                local = resources.LocalArtifact.from_path(
                    self, artifact, artifact_type=resources.ArtifactType.URL,
                    artifact_name=artifact_name,
                )
            else:
                local = artifact
        else:
            local = resources.LocalArtifact.from_content(
                self, url, artifact_name=artifact_name or url,
                artifact_type=resources.ArtifactType.URL,
            )

        json_params = {
            "artifact_name": local.artifact_name,
            "artifact_type": resources.ArtifactType.URL.name,
            "provider_slug": provider_slug,
            "vm_slug": vm_slug,
            "network_enabled": 1,
        }
        if browser:
            json_params["browser"] = browser
        if preprocessing:
            json_params["preprocessing"] = preprocessing

        task = await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.SandboxTask.RESOURCE_ENDPOINT}/instance",
                "json": json_params,
            },
            result_parser=resources.SandboxTask,
        )

        await async_upload_file(self.session._client, task.upload_url, local)

        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}{resources.SandboxTask.RESOURCE_ENDPOINT}/instance",
                "params": {"sandbox_task_id": str(int(task))},
            },
            result_parser=resources.SandboxTask,
        )

    async def sandbox_providers(self):
        """List sandbox providers. Async generator of SandboxProvider."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.SandboxProvider.RESOURCE_ENDPOINT}/list",
            },
            result_parser=resources.SandboxProvider,
        ):
            yield item

    async def report_wait_for(self, report_id, timeout=settings.DEFAULT_REPORT_TIMEOUT):
        """Async poll until report is ready."""
        start = time.time()
        while True:
            report = await self.report_get(report_id)
            if hasattr(report, "state") and report.state in ("SUCCEEDED", "FAILED"):
                return report
            elif -1 < timeout < time.time() - start:
                raise exceptions.TimeoutException(
                    f"Timed out waiting for report {report_id}."
                )
            else:
                await asyncio.sleep(settings.POLL_FREQUENCY)

    # ── Report Templates ─────────────────────────────────────────
