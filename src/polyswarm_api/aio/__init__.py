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

from .core import AsyncPolyswarmRequest, AsyncPolyswarmSession
from .upload import async_upload_file, async_upload_logo

logger = logging.getLogger(__name__)

__all__ = ["PolySwarmAsyncAPI"]


class PolySwarmAsyncAPI:
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
        self.uri = uri or settings.DEFAULT_GLOBAL_API
        self.community = community or settings.DEFAULT_COMMUNITY
        self.timeout = timeout or settings.DEFAULT_HTTP_TIMEOUT
        self.session = AsyncPolyswarmSession(
            key,
            retries=settings.DEFAULT_RETRIES,
            verify=verify,
            timeout=self.timeout,
            **httpx_kwargs,
        )
        self._engines = None

    async def close(self):
        """Close the underlying HTTP client."""
        await self.session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    # ── Internal helpers ─────────────────────────────────────────

    async def _exec(self, request_parameters, result_parser=None, **kwargs):
        """Build, execute, and return the AsyncPolyswarmRequest."""
        return await AsyncPolyswarmRequest(
            self, request_parameters, result_parser=result_parser, **kwargs
        ).execute()

    async def _single(self, request_parameters, result_parser=None, **kwargs):
        """Execute and return a single (non-paginated) result."""
        req = await self._exec(request_parameters, result_parser, **kwargs)
        return req.result()

    async def _generate(self, request_parameters, result_parser=None, **kwargs):
        """Execute and yield results from a (possibly paginated) response."""
        req = await self._exec(request_parameters, result_parser, **kwargs)
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

    async def exists(self, hash_, hash_type=None) -> bool:
        """Check if a hash exists in PolySwarm."""
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        req = await self._exec(
            {
                "method": "HEAD",
                "url": f"{self.uri}/search/hash/{hash_.hash_type}",
                "params": {"hash": hash_.hash, "community": self.community},
            },
        )
        return str(req.result()) == "200"

    async def search(self, hash_, hash_type=None):
        """Search by hash. Async generator of ArtifactInstance."""
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}/search/hash/{hash_.hash_type}",
                "params": {"hash": hash_.hash, "community": self.community},
            },
            result_parser=resources.ArtifactInstance,
        ):
            yield item

    async def search_url(self, url):
        """Search by URL. Async generator of ArtifactInstance."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}/search/url",
                "params": {"url": url, "community": self.community},
            },
            result_parser=resources.ArtifactInstance,
        ):
            yield item

    async def search_scans(self, hash_):
        """Search all historical scans for a SHA256. Async generator of ArtifactInstance."""
        hash_ = resources.Hash.from_hashable(hash_, hash_type="sha256")
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}/search/instances",
                "params": {"hash": hash_.hash, "community": self.community},
            },
            result_parser=resources.ArtifactInstance,
        ):
            yield item

    async def metadata_mapping(self):
        """Get available metadata field names and types."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.MetadataMapping.RESOURCE_ENDPOINT}",
            },
            result_parser=resources.MetadataMapping,
        )

    async def search_by_metadata(
        self, query, include=None, exclude=None, ips=None, urls=None, domains=None
    ):
        """Search by metadata. Async generator of Metadata."""
        params = {"query": query, "community": self.community}
        # Handle list parameters the same way as Metadata._get_params
        if include:
            params["include"] = include
        if exclude:
            params["exclude"] = exclude
        if ips:
            params["ips"] = ips
        if urls:
            params["urls"] = urls
        if domains:
            params["domains"] = domains

        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.Metadata.RESOURCE_ENDPOINT}",
                "params": params,
            },
            result_parser=resources.Metadata,
        ):
            yield item

    # ── IOCs ─────────────────────────────────────────────────────

    async def iocs_by_hash(self, hash_type, hash_value, hide_known_good=False, beta=False):
        """Get IOCs by hash. Async generator of IOC."""
        endpoint = "/ioc-beta" if beta else "/ioc"
        params = {}
        if hide_known_good:
            params["hide_known_good"] = int(hide_known_good)
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{endpoint}/{hash_type}/{hash_value}",
                "params": params or None,
            },
            result_parser=resources.IOC,
        ):
            yield item

    async def search_by_ioc(self, ip=None, domain=None, ttp=None, imphash=None):
        """Search by IOC. Async generator of IOC."""
        params = {}
        if ip:
            params["ip"] = ip
        if domain:
            params["domain"] = domain
        if ttp:
            params["ttp"] = ttp
        if imphash:
            params["imphash"] = imphash
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}/ioc/search",
                "params": params,
            },
            result_parser=resources.IOC,
        ):
            yield item

    async def check_known_hosts(self, ips=None, domains=None):
        """Check known good/bad hosts. Async generator of IOC."""
        params = []
        for ip in (ips or []):
            params.append(("ip", ip))
        for domain in (domains or []):
            params.append(("domain", domain))
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}/ioc/known",
                "params": params,
            },
            result_parser=resources.IOC,
        ):
            yield item

    async def add_known_good_host(self, type, source, host):
        """Add a known good IP or domain."""
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}/ioc/known",
                "json": {"type": type, "host": host, "source": source, "good": True},
            },
            result_parser=resources.IOC,
        )

    async def add_known_bad_host(self, type, source, host):
        """Add a known bad IP or domain."""
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}/ioc/known",
                "json": {"type": type, "host": host, "source": source, "good": False},
            },
            result_parser=resources.IOC,
        )

    async def update_known_good_host(self, id, type, source, host, good):
        """Update a known host entry."""
        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}/ioc/known",
                "json": {"id": str(int(id)), "type": type, "host": host, "source": source, "good": int(good)},
            },
            result_parser=resources.IOC,
        )

    async def delete_known_good_host(self, id):
        """Delete a known host entry."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}/ioc/known?id={id}",
            },
            result_parser=resources.IOC,
        )

    # ── Submission & Scanning ────────────────────────────────────

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

    async def lookup(self, scan):
        """Look up scan result by submission ID."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}/consumer/submission/{self.community}/{int(scan)}",
            },
            result_parser=resources.ArtifactInstance,
        )

    async def rescan(self, hash_, hash_type=None, scan_config=None):
        """Rescan a known hash."""
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        json_params = {}
        if scan_config:
            json_params["scan_config"] = scan_config
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}/consumer/submission/{self.community}/rescan/{hash_.hash_type}/{hash_.hash}",
                "json": json_params or None,
            },
            result_parser=resources.ArtifactInstance,
        )

    async def rescan_id(self, scan, scan_config=None):
        """Rescan by existing scan ID."""
        json_params = {}
        if scan_config:
            json_params["scan_config"] = scan_config
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}/consumer/submission/{self.community}/rescan/{int(scan)}",
                "json": json_params or None,
            },
            result_parser=resources.ArtifactInstance,
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

    async def live_start(self, rule_id):
        """Start a live YARA hunt."""
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.LiveYaraRuleset.RESOURCE_ENDPOINT}",
                "json": {"rule_id": str(int(rule_id))},
            },
            result_parser=resources.LiveYaraRuleset,
        )

    async def live_stop(self, rule_id):
        """Stop a live YARA hunt."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.LiveYaraRuleset.RESOURCE_ENDPOINT}",
                "json": {"rule_id": str(int(rule_id))},
            },
            result_parser=resources.LiveYaraRuleset,
        )

    async def live_feed(
        self, since=None, rule_name=None, family=None,
        polyscore_lower=None, polyscore_upper=None, community=None,
    ):
        """Get live hunt matches. Async generator of LiveHuntResult."""
        params = {"community": community or self.community}
        if since is not None:
            params["since"] = since
        if rule_name is not None:
            params["rule_name"] = rule_name
        if family is not None:
            params["family"] = family
        if polyscore_lower is not None:
            params["polyscore_lower"] = polyscore_lower
        if polyscore_upper is not None:
            params["polyscore_upper"] = polyscore_upper
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.LiveHuntResult.RESOURCE_ENDPOINT}/list",
                "params": params,
            },
            result_parser=resources.LiveHuntResult,
        ):
            yield item

    async def live_feed_delete(self, result_ids):
        """Delete live hunt results."""
        try:
            return await self._single(
                {
                    "method": "DELETE",
                    "url": f"{self.uri}{resources.LiveHuntResultList.RESOURCE_ENDPOINT}",
                    "json": {"result_ids": result_ids},
                },
                result_parser=resources.LiveHuntResultList,
            )
        except exceptions.NoResultsException:
            return None

    async def live_result(self, result_id):
        """Get a single live hunt result."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.LiveHuntResult.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(result_id))},
            },
            result_parser=resources.LiveHuntResult,
        )

    # ── YARA Historical Hunting ──────────────────────────────────

    async def historical_create(self, rule=None, ruleset_name=None):
        """Create a historical YARA hunt."""
        # Parse rule the same way as sync API._parse_rule()
        json_params = {}
        if isinstance(rule, resources.YaraRuleset):
            json_params["rule_id"] = str(int(rule))
        elif isinstance(rule, int):
            json_params["rule_id"] = str(rule)
        elif isinstance(rule, str):
            json_params["yara"] = rule
            if ruleset_name:
                json_params["name"] = ruleset_name
        elif rule is not None:
            json_params["rule_id"] = str(int(rule))

        json_params["community"] = self.community
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.HistoricalHunt.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.HistoricalHunt,
        )

    async def historical_get(self, hunt=None):
        """Get historical hunt details."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.HistoricalHunt.RESOURCE_ENDPOINT}/?id={hunt}",
                "params": {"id": str(int(hunt)), "community": self.community},
            },
            result_parser=resources.HistoricalHunt,
        )

    async def historical_update(self, hunt):
        """Cancel a historical hunt."""
        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}{resources.HistoricalHunt.RESOURCE_ENDPOINT}/?id={hunt}",
                "params": {"id": str(int(hunt)), "community": self.community},
            },
            result_parser=resources.HistoricalHunt,
        )

    async def historical_delete(self, hunt):
        """Delete a historical hunt."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.HistoricalHunt.RESOURCE_ENDPOINT}/?id={hunt}",
                "json": {"id": str(int(hunt)), "community": self.community},
            },
            result_parser=resources.HistoricalHunt,
        )

    async def historical_list(self, since=None):
        """List historical hunts. Async generator of HistoricalHunt."""
        params = {"community": self.community}
        if since is not None:
            params["since"] = since
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.HistoricalHunt.RESOURCE_ENDPOINT}/list",
                "params": params,
            },
            result_parser=resources.HistoricalHunt,
        ):
            yield item

    async def historical_result(self, result_id):
        """Get a single historical hunt result."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.HistoricalHuntResult.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(result_id)), "community": self.community},
            },
            result_parser=resources.HistoricalHuntResult,
        )

    async def historical_results(
        self, hunt=None, rule_name=None, family=None,
        polyscore_lower=None, polyscore_upper=None, community=None,
    ):
        """Get historical hunt results. Async generator of HistoricalHuntResult."""
        params = {"community": community or self.community}
        if hunt is not None:
            params["id"] = str(int(hunt))
        if rule_name is not None:
            params["rule_name"] = rule_name
        if family is not None:
            params["family"] = family
        if polyscore_lower is not None:
            params["polyscore_lower"] = polyscore_lower
        if polyscore_upper is not None:
            params["polyscore_upper"] = polyscore_upper
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.HistoricalHuntResultList.RESOURCE_ENDPOINT}",
                "params": params,
            },
            result_parser=resources.HistoricalHuntResultList,
        ):
            yield item

    async def historical_results_delete(self, result_ids):
        """Delete historical hunt results."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.HistoricalHuntResultList.RESOURCE_ENDPOINT}",
                "json": {"result_ids": result_ids, "community": self.community},
            },
            result_parser=resources.HistoricalHuntResultList,
        )

    async def historical_delete_list(self, historical_ids):
        """Delete multiple historical hunts."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.HistoricalHuntList.RESOURCE_ENDPOINT}",
                "json": {"historical_ids": historical_ids, "community": self.community},
            },
            result_parser=resources.HistoricalHuntList,
        )

    # ── YARA Rulesets ────────────────────────────────────────────

    async def ruleset_create(self, name, rules, description=None):
        """Create a YARA ruleset."""
        json_params = {"yara": rules, "name": name}
        if description:
            json_params["description"] = description
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.YaraRuleset.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.YaraRuleset,
        )

    async def ruleset_get(self, ruleset_id=None):
        """Get a YARA ruleset."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.YaraRuleset.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(ruleset_id)), "community": self.community},
            },
            result_parser=resources.YaraRuleset,
        )

    async def ruleset_update(self, ruleset_id, name=None, rules=None, description=None):
        """Update a YARA ruleset."""
        json_params = {"id": str(int(ruleset_id)), "community": self.community}
        if name is not None:
            json_params["name"] = name
        if rules is not None:
            json_params["yara"] = rules
        if description is not None:
            json_params["description"] = description
        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}{resources.YaraRuleset.RESOURCE_ENDPOINT}?id={ruleset_id}",
                "json": json_params,
            },
            result_parser=resources.YaraRuleset,
        )

    async def ruleset_delete(self, ruleset_id):
        """Delete a YARA ruleset."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.YaraRuleset.RESOURCE_ENDPOINT}?id={ruleset_id}",
                "json": {"id": str(int(ruleset_id)), "community": self.community},
            },
            result_parser=resources.YaraRuleset,
        )

    async def ruleset_list(self):
        """List YARA rulesets. Async generator of YaraRuleset."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.YaraRuleset.RESOURCE_ENDPOINT}/list",
                "params": {"community": self.community},
            },
            result_parser=resources.YaraRuleset,
        ):
            yield item

    # ── Tags ─────────────────────────────────────────────────────

    async def tag_create(self, name):
        """Create a tag."""
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.Tag.RESOURCE_ENDPOINT}",
                "json": {"name": name},
            },
            result_parser=resources.Tag,
        )

    async def tag_get(self, name):
        """Get a tag."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.Tag.RESOURCE_ENDPOINT}",
                "params": {"name": name},
            },
            result_parser=resources.Tag,
        )

    async def tag_delete(self, name):
        """Delete a tag."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.Tag.RESOURCE_ENDPOINT}",
                "json": {"name": name},
            },
            result_parser=resources.Tag,
        )

    async def tag_list(self):
        """List all tags. Async generator of Tag."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.Tag.RESOURCE_ENDPOINT}/list",
            },
            result_parser=resources.Tag,
        ):
            yield item

    # ── Tag Links ────────────────────────────────────────────────

    async def tag_link_get(self, sha256):
        """Get tags/families for a hash."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.TagLink.RESOURCE_ENDPOINT}",
                "params": {"hash": sha256},
            },
            result_parser=resources.TagLink,
        )

    async def tag_link_update(self, sha256, tags=None, families=None, emerging=None, remove=False):
        """Add/remove tags and families for a hash."""
        json_params = {"hash": sha256}
        if tags is not None:
            json_params["tags"] = tags
        if families is not None:
            json_params["families"] = families
        if emerging is not None:
            json_params["emerging"] = emerging
        if remove:
            json_params["remove"] = int(remove)
        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}{resources.TagLink.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.TagLink,
        )

    async def tag_link_list(self, tags=None, families=None, or_tags=None, or_families=None):
        """List artifacts by tag/family. Async generator of TagLink."""
        # Multi-value params need list format
        params = []
        for tag in (tags or []):
            params.append(("tags", tag))
        for family in (families or []):
            params.append(("families", family))
        for tag in (or_tags or []):
            params.append(("or_tags", tag))
        for family in (or_families or []):
            params.append(("or_families", family))
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.TagLink.RESOURCE_ENDPOINT}/list",
                "params": params or None,
            },
            result_parser=resources.TagLink,
        ):
            yield item

    # ── Malware Families ─────────────────────────────────────────

    async def family_create(self, name):
        """Create a malware family."""
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.MalwareFamily.RESOURCE_ENDPOINT}",
                "json": {"name": name},
            },
            result_parser=resources.MalwareFamily,
        )

    async def family_get(self, name):
        """Get a malware family."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.MalwareFamily.RESOURCE_ENDPOINT}",
                "params": {"name": name},
            },
            result_parser=resources.MalwareFamily,
        )

    async def family_delete(self, name):
        """Delete a malware family."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.MalwareFamily.RESOURCE_ENDPOINT}",
                "json": {"name": name},
            },
            result_parser=resources.MalwareFamily,
        )

    async def family_update(self, family_name, emerging=True):
        """Update a malware family's emerging status."""
        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}{resources.MalwareFamily.RESOURCE_ENDPOINT}",
                "json": {"name": family_name, "emerging": int(emerging)},
            },
            result_parser=resources.MalwareFamily,
        )

    async def family_list(self):
        """List malware families. Async generator of MalwareFamily."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.MalwareFamily.RESOURCE_ENDPOINT}/list",
            },
            result_parser=resources.MalwareFamily,
        ):
            yield item

    # ── Sandbox ──────────────────────────────────────────────────

    async def sandbox(self, instance_id, provider_slug, vm_slug, network_enabled=True):
        """Submit existing scan to sandbox."""
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.SandboxTask.RESOURCE_ENDPOINT}",
                "json": {
                    "artifact_id": str(int(instance_id)),
                    "provider_slug": provider_slug,
                    "vm_slug": vm_slug,
                    "network_enabled": int(network_enabled),
                },
            },
            result_parser=resources.SandboxTask,
        )

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

    async def sandbox_task_status(self, sandbox_task_id):
        """Get sandbox task status."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.SandboxTask.RESOURCE_ENDPOINT}",
                "params": {"sandbox_task_id": str(int(sandbox_task_id)), "community": self.community},
            },
            result_parser=resources.SandboxTask,
        )

    async def sandbox_task_latest(self, sha256, sandbox):
        """Get latest sandbox task for a hash."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.SandboxTask.RESOURCE_ENDPOINT}/latest",
                "params": {"sha256": sha256, "sandbox": sandbox},
            },
            result_parser=resources.SandboxTask,
        )

    async def sandbox_my_tasks_list(self, **kwargs):
        """List user's sandbox tasks. Async generator of SandboxTask."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.SandboxTask.RESOURCE_ENDPOINT}/my-tasks",
                "params": kwargs or None,
            },
            result_parser=resources.SandboxTask,
        ):
            yield item

    async def sandbox_task_list(self, sha256, **kwargs):
        """List sandbox tasks for a hash. Async generator of SandboxTask."""
        params = {"sha256": sha256}
        params.update(kwargs)
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.SandboxTask.RESOURCE_ENDPOINT}/list",
                "params": params,
            },
            result_parser=resources.SandboxTask,
        ):
            yield item

    # ── Downloads ────────────────────────────────────────────────

    async def download(self, out_dir, hash_, hash_type=None):
        """Download a sample by hash. Returns LocalArtifact."""
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        req = await self._exec(
            {
                "method": "GET",
                "url": f"{self.uri}/consumer/download/{hash_.hash_type}/{hash_.hash}",
                "params": {"community": self.community},
            },
            result_parser=resources.LocalArtifact,
            folder=out_dir,
        )
        result = req.result()
        if hasattr(result, "handle") and result.handle and not result.handle.closed:
            result.handle.close()
        return result

    async def download_id(self, out_dir, instance_id):
        """Download a sample by instance ID. Returns LocalArtifact."""
        req = await self._exec(
            {
                "method": "GET",
                "url": f"{self.uri}/consumer/download/id/{int(instance_id)}",
                "params": {"community": self.community},
            },
            result_parser=resources.LocalArtifact,
            folder=out_dir,
        )
        result = req.result()
        if hasattr(result, "handle") and result.handle and not result.handle.closed:
            result.handle.close()
        return result

    async def download_sandbox_artifact(self, out_dir, sandbox_task_id, instance_id):
        """Download a sandbox artifact. Returns LocalArtifact."""
        req = await self._exec(
            {
                "method": "GET",
                "url": f"{self.uri}/consumer/download/sandbox/{sandbox_task_id}/{instance_id}",
                "params": {"community": self.community},
            },
            result_parser=resources.LocalArtifact,
            folder=out_dir,
        )
        result = req.result()
        if hasattr(result, "handle") and result.handle and not result.handle.closed:
            result.handle.close()
        return result

    async def download_archive(self, out_dir, s3_path):
        """Download an archive from S3. Returns LocalArtifact."""
        req = await self._exec(
            {
                "method": "GET",
                "url": s3_path,
                "headers": {"Authorization": None},
            },
            result_parser=resources.LocalArtifact,
            folder=out_dir,
        )
        result = req.result()
        if hasattr(result, "handle") and result.handle and not result.handle.closed:
            result.handle.close()
        return result

    async def download_to_handle(self, hash_, fh, hash_type=None):
        """Download a sample to a file handle. Returns LocalArtifact."""
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        req = await self._exec(
            {
                "method": "GET",
                "url": f"{self.uri}/consumer/download/{hash_.hash_type}/{hash_.hash}",
                "params": {"community": self.community},
            },
            result_parser=resources.LocalArtifact,
            handle=fh,
        )
        return req.result()

    # ── Streaming ────────────────────────────────────────────────

    async def stream(self, since=settings.MAX_SINCE_TIME_STREAM):
        """Stream recent artifacts. Async generator of ArtifactArchive."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.ArtifactArchive.RESOURCE_ENDPOINT}",
                "params": {"since": since},
            },
            result_parser=resources.ArtifactArchive,
        ):
            yield item

    # ── Metadata Reprocessing ────────────────────────────────────

    async def rerun_metadata(self, hashes, analyses=None, skip_es=None):
        """Trigger metadata reanalysis."""
        json_params = {"hashes": hashes}
        if analyses is not None:
            json_params["analyses"] = analyses
        if skip_es is not None:
            json_params["skip_es"] = skip_es
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}/consumer/metadata",
                "json": json_params,
            },
            result_parser=resources.ArtifactInstance,
        )

    async def tool_metadata_create(self, instance_id, tool, tool_metadata):
        """Add custom tool metadata to a scan."""
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.ToolMetadata.RESOURCE_ENDPOINT}",
                "json": {
                    "instance_id": instance_id,
                    "tool": tool,
                    "tool_metadata": tool_metadata,
                },
            },
            result_parser=resources.ToolMetadata,
        )

    async def tool_metadata_list(self, instance_id):
        """List custom metadata for a scan. Async generator of ToolMetadata."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.ToolMetadata.RESOURCE_ENDPOINT}/list",
                "params": {"instance_id": str(int(instance_id))},
            },
            result_parser=resources.ToolMetadata,
        ):
            yield item

    # ── Engine Assertions & Votes ────────────────────────────────

    async def assertions_create(self, engine_id, date_start, date_end):
        """Create an assertions export job."""
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.AssertionsJob.RESOURCE_ENDPOINT}",
                "json": {"engine_id": str(int(engine_id)), "date_start": date_start, "date_end": date_end},
            },
            result_parser=resources.AssertionsJob,
        )

    async def assertions_get(self, assertions_id):
        """Get assertions job status."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.AssertionsJob.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(assertions_id))},
            },
            result_parser=resources.AssertionsJob,
        )

    async def assertions_delete(self, assertions_id):
        """Delete an assertions job."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.AssertionsJob.RESOURCE_ENDPOINT}",
                "json": {"id": str(int(assertions_id))},
            },
            result_parser=resources.AssertionsJob,
        )

    async def assertions_list(self, engine_id):
        """List assertions jobs. Async generator of AssertionsJob."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.AssertionsJob.RESOURCE_ENDPOINT}/list",
                "params": {"engine_id": str(int(engine_id))},
            },
            result_parser=resources.AssertionsJob,
        ):
            yield item

    async def votes_create(self, engine_id, date_start, date_end):
        """Create a votes export job."""
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.VotesJob.RESOURCE_ENDPOINT}",
                "json": {"engine_id": str(int(engine_id)), "date_start": date_start, "date_end": date_end},
            },
            result_parser=resources.VotesJob,
        )

    async def votes_get(self, votes_id):
        """Get votes job status."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.VotesJob.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(votes_id))},
            },
            result_parser=resources.VotesJob,
        )

    async def votes_delete(self, votes_id):
        """Delete a votes job."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.VotesJob.RESOURCE_ENDPOINT}",
                "json": {"id": str(int(votes_id))},
            },
            result_parser=resources.VotesJob,
        )

    async def votes_list(self, engine_id):
        """List votes jobs. Async generator of VotesJob."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.VotesJob.RESOURCE_ENDPOINT}/list",
                "params": {"engine_id": str(int(engine_id))},
            },
            result_parser=resources.VotesJob,
        ):
            yield item

    # ── Activity / Events ────────────────────────────────────────

    async def event_list(self, **kwargs):
        """List account activity. Async generator of Events."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.Events.RESOURCE_ENDPOINT}/list",
                "params": kwargs or None,
            },
            result_parser=resources.Events,
        ):
            yield item

    # ── Sample Bundles ───────────────────────────────────────────

    async def sample_bundle_task_create(
        self, instance_ids, preserve_filenames=False, filename=None, **kwargs,
    ):
        """Create a ZIP bundle of samples."""
        json_params = {
            "instance_ids": instance_ids,
            "preserve_filenames": int(preserve_filenames),
            "community": self.community,
        }
        if filename:
            json_params["filename"] = filename
        json_params.update(kwargs)
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.BundleTask.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.BundleTask,
        )

    async def sample_bundle_task_get(self, id, **kwargs):
        """Get bundle task status."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.BundleTask.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(id)), "community": self.community, **kwargs},
            },
            result_parser=resources.BundleTask,
        )

    async def sample_bundle_download(self, id, folder):
        """Download a completed bundle ZIP."""
        bundle = await self.sample_bundle_task_get(id)
        if hasattr(bundle, "state"):
            if bundle.state == "PENDING":
                raise exceptions.RequestException(None, "Bundle task is still pending")
            if bundle.state == "FAILED":
                raise exceptions.RequestException(None, "Bundle task failed")
        # Download from S3 URL
        req = await self._exec(
            {
                "method": "GET",
                "url": bundle.download_url,
                "headers": {"Authorization": None},
            },
            result_parser=resources.LocalArtifact,
            folder=folder,
        )
        result = req.result()
        if hasattr(result, "handle") and result.handle and not result.handle.closed:
            result.handle.close()
        return result

    # ── Reports ──────────────────────────────────────────────────

    async def report_create(
        self, type, format, instance_id=None, sandbox_task_id=None,
        template_id=None, template_metadata=None, **kwargs,
    ):
        """Create a PDF/HTML report."""
        json_params = {
            "type": type,
            "format": format,
            "community": self.community,
        }
        if instance_id is not None:
            json_params["instance_id"] = str(int(instance_id))
        if sandbox_task_id is not None:
            json_params["sandbox_task_id"] = str(int(sandbox_task_id))
        if template_id is not None:
            json_params["template_id"] = str(int(template_id))
        if template_metadata is not None:
            json_params["template_metadata"] = template_metadata
        json_params.update(kwargs)
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.ReportTask.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.ReportTask,
        )

    async def report_get(self, id, **kwargs):
        """Get report task status."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.ReportTask.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(id)), "community": self.community, **kwargs},
            },
            result_parser=resources.ReportTask,
        )

    async def report_download(self, report_id, folder):
        """Download a generated report."""
        report = await self.report_get(report_id)
        if hasattr(report, "state"):
            if report.state == "PENDING":
                raise exceptions.RequestException(None, "Report is still pending")
            if report.state == "FAILED":
                raise exceptions.RequestException(None, "Report generation failed")
        req = await self._exec(
            {
                "method": "GET",
                "url": report.download_url,
                "headers": {"Authorization": None},
            },
            result_parser=resources.LocalArtifact,
            folder=folder,
        )
        result = req.result()
        if hasattr(result, "handle") and result.handle and not result.handle.closed:
            result.handle.close()
        return result

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

    async def report_template_create(
        self, template_name, is_default=False, primary_color=None,
        footer_text=None, last_page_text=None, includes=None, **kwargs,
    ):
        """Create a report template."""
        json_params = {"template_name": template_name, "is_default": int(is_default)}
        if primary_color is not None:
            json_params["primary_color"] = primary_color
        if footer_text is not None:
            json_params["footer_text"] = footer_text
        if last_page_text is not None:
            json_params["last_page_text"] = last_page_text
        if includes is not None:
            json_params["includes"] = includes
        json_params.update(kwargs)
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.ReportTemplate.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.ReportTemplate,
        )

    async def report_template_update(
        self, template_id, template_name=None, is_default=None,
        primary_color=None, footer_text=None, last_page_text=None,
        includes=None, **kwargs,
    ):
        """Update a report template."""
        json_params = {"id": str(int(template_id))}
        if template_name is not None:
            json_params["template_name"] = template_name
        if is_default is not None:
            json_params["is_default"] = int(is_default)
        if primary_color is not None:
            json_params["primary_color"] = primary_color
        if footer_text is not None:
            json_params["footer_text"] = footer_text
        if last_page_text is not None:
            json_params["last_page_text"] = last_page_text
        if includes is not None:
            json_params["includes"] = includes
        json_params.update(kwargs)
        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}{resources.ReportTemplate.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.ReportTemplate,
        )

    async def report_template_get(self, template_id):
        """Get a report template."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.ReportTemplate.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(template_id))},
            },
            result_parser=resources.ReportTemplate,
        )

    async def report_template_delete(self, template_id):
        """Delete a report template."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.ReportTemplate.RESOURCE_ENDPOINT}",
                "json": {"id": str(int(template_id))},
            },
            result_parser=resources.ReportTemplate,
        )

    async def report_template_list(self, is_default=None, **kwargs):
        """List report templates. Async generator of ReportTemplate."""
        params = dict(kwargs)
        if is_default is not None:
            params["is_default"] = int(is_default)
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.ReportTemplate.RESOURCE_ENDPOINT}/list",
                "params": params or None,
            },
            result_parser=resources.ReportTemplate,
        ):
            yield item

    async def report_template_logo_download(self, template_id, folder):
        """Download a template logo."""
        template = await self.report_template_get(template_id)
        req = await self._exec(
            {
                "method": "GET",
                "url": template.logo_url,
            },
            result_parser=resources.LocalArtifact,
            folder=folder,
        )
        result = req.result()
        if hasattr(result, "handle") and result.handle and not result.handle.closed:
            result.handle.close()
        return result

    async def report_template_logo_delete(self, template_id):
        """Delete a template logo."""
        template = await self.report_template_get(template_id)
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.ReportTemplate.RESOURCE_ENDPOINT}/logo",
                "params": {"id": str(int(template_id))},
            },
            result_parser=resources.ReportTemplate,
        )

    async def report_template_logo_upload(self, template_id, logo_file, content_type):
        """Upload a logo for a report template."""
        template = await self.report_template_get(template_id)
        await async_upload_logo(
            self.session._client, template.upload_url, logo_file, content_type
        )
        return await self.report_template_get(template_id)

    # ── Account ──────────────────────────────────────────────────

    async def account_whois(self, **kwargs):
        """Get account WHOIS info."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.WhoIs.RESOURCE_ENDPOINT}",
                "params": kwargs or None,
            },
            result_parser=resources.WhoIs,
        )

    async def account_features(self, **kwargs):
        """Get account feature flags."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.AccountFeatures.RESOURCE_ENDPOINT}",
                "params": kwargs or None,
            },
            result_parser=resources.AccountFeatures,
        )

    # ── Sample (aggregated view) ─────────────────────────────────

    async def sample(
        self,
        sha256,
        artifact_instance_id=None,
        sandbox_task_id_cape=None,
        sandbox_task_id_triage=None,
        artifact_metadata_id=None,
    ):
        """Get aggregated sample info (artifact instance + sandbox + metadata).

        Returns a Sample resource with .artifact_instance, .sandbox, .metadata, .pending.
        """
        params = {}
        if artifact_instance_id is not None:
            params["artifact_instance_id"] = str(int(artifact_instance_id))
        if sandbox_task_id_cape is not None:
            params["sandbox_task_id_cape"] = str(int(sandbox_task_id_cape))
        if sandbox_task_id_triage is not None:
            params["sandbox_task_id_triage"] = str(int(sandbox_task_id_triage))
        if artifact_metadata_id is not None:
            params["artifact_metadata_id"] = str(int(artifact_metadata_id))
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.Sample.RESOURCE_ENDPOINT}/{sha256}",
                "params": params or None,
            },
            result_parser=resources.Sample,
        )

    # ── LLM Reports ──────────────────────────────────────────────

    async def llm_report_create(
        self, instance_id=None, cape_sandbox_task_id=None, triage_sandbox_task_id=None,
    ):
        """Create an LLM-generated analysis report from scan/sandbox results.

        :param instance_id: Artifact instance ID for scan-based report.
        :param cape_sandbox_task_id: Cape sandbox task ID.
        :param triage_sandbox_task_id: Triage sandbox task ID.
        """
        if not instance_id and not cape_sandbox_task_id and not triage_sandbox_task_id:
            raise exceptions.InvalidValueException(
                "Either instance_id or sandbox_task_id must be provided"
            )
        json_params = {}
        if instance_id is not None:
            json_params["instance_id"] = str(int(instance_id))
        if cape_sandbox_task_id is not None:
            json_params["cape_sandbox_task_id"] = str(int(cape_sandbox_task_id))
        if triage_sandbox_task_id is not None:
            json_params["triage_sandbox_task_id"] = str(int(triage_sandbox_task_id))
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.ReportLLMPostProcessing.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.ReportLLMPostProcessing,
        )

    async def llm_report_get(self, report_task_id):
        """Get LLM report generation status."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.ReportLLMPostProcessing.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(report_task_id)), "community": self.community},
            },
            result_parser=resources.ReportLLMPostProcessing,
        )

    async def llm_report_download(self, report_task_id, folder):
        """Download a completed LLM report."""
        report = await self.llm_report_get(report_task_id)
        req = await self._exec(
            {
                "method": "GET",
                "url": report.download_url,
                "headers": {"Authorization": None},
            },
            result_parser=resources.LocalArtifact,
            folder=folder,
        )
        result = req.result()
        if hasattr(result, "handle") and result.handle and not result.handle.closed:
            result.handle.close()
        return result

    # ── LLM Prompt Config ───────────────────────────────────────

    async def prompt_config_create(
        self, name, system_prompt, is_active=False,
        cape_only_prompt=None, triage_only_prompt=None, scan_only_prompt=None,
    ):
        """Create a new LLM prompt configuration."""
        json_params = {
            "name": name,
            "system_prompt": system_prompt,
            "is_active": int(is_active),
        }
        if cape_only_prompt is not None:
            json_params["cape_only_prompt"] = cape_only_prompt
        if triage_only_prompt is not None:
            json_params["triage_only_prompt"] = triage_only_prompt
        if scan_only_prompt is not None:
            json_params["scan_only_prompt"] = scan_only_prompt
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.LLMPromptConfig.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.LLMPromptConfig,
        )

    async def prompt_config_get(self, prompt_config_id):
        """Get an LLM prompt configuration by ID."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.LLMPromptConfig.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(prompt_config_id))},
            },
            result_parser=resources.LLMPromptConfig,
        )

    async def prompt_config_update(
        self, prompt_config_id, name=None, system_prompt=None, is_active=None,
        cape_only_prompt=None, triage_only_prompt=None, scan_only_prompt=None,
    ):
        """Update an existing LLM prompt configuration."""
        json_params = {"id": str(int(prompt_config_id))}
        if name is not None:
            json_params["name"] = name
        if system_prompt is not None:
            json_params["system_prompt"] = system_prompt
        if is_active is not None:
            json_params["is_active"] = int(is_active)
        if cape_only_prompt is not None:
            json_params["cape_only_prompt"] = cape_only_prompt
        if triage_only_prompt is not None:
            json_params["triage_only_prompt"] = triage_only_prompt
        if scan_only_prompt is not None:
            json_params["scan_only_prompt"] = scan_only_prompt
        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}{resources.LLMPromptConfig.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.LLMPromptConfig,
        )

    async def prompt_config_list(self, **kwargs):
        """List all LLM prompt configurations. Async generator of LLMPromptConfig."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.LLMPromptConfig.RESOURCE_ENDPOINT}/list",
                "params": kwargs or None,
            },
            result_parser=resources.LLMPromptConfig,
        ):
            yield item

    # ── Notification Webhooks ───────────────────────────────────

    async def notification_webhook_create(
        self, webhook_uri, secret, status="enabled", events=None,
    ):
        """Create a notification webhook."""
        json_params = {
            "webhook_uri": webhook_uri,
            "secret": secret,
            "status": status,
        }
        if events is not None:
            json_params["events"] = events
        return await self._single(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.Webhook.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.Webhook,
        )

    async def notification_webhook_get(self, webhook_id):
        """Get a notification webhook by ID."""
        return await self._single(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.Webhook.RESOURCE_ENDPOINT}",
                "params": {"id": str(int(webhook_id))},
            },
            result_parser=resources.Webhook,
        )

    async def notification_webhook_update(
        self, webhook_id, webhook_uri=None, secret=None, status=None,
        team_account_number=None, events=None,
    ):
        """Update an existing notification webhook."""
        json_params = {"id": str(int(webhook_id))}
        if webhook_uri is not None:
            json_params["webhook_uri"] = webhook_uri
        if secret is not None:
            json_params["secret"] = secret
        if status is not None:
            json_params["status"] = status
        if team_account_number is not None:
            json_params["team_account_number"] = team_account_number
        if events is not None:
            json_params["events"] = events
        return await self._single(
            {
                "method": "PUT",
                "url": f"{self.uri}{resources.Webhook.RESOURCE_ENDPOINT}",
                "json": json_params,
            },
            result_parser=resources.Webhook,
        )

    async def notification_webhook_delete(self, webhook_id):
        """Delete a notification webhook."""
        return await self._single(
            {
                "method": "DELETE",
                "url": f"{self.uri}{resources.Webhook.RESOURCE_ENDPOINT}",
                "json": {"id": str(int(webhook_id))},
            },
            result_parser=resources.Webhook,
        )

    async def notification_webhook_list(self):
        """List all notification webhooks. Async generator of Webhook."""
        async for item in self._generate(
            {
                "method": "GET",
                "url": f"{self.uri}{resources.Webhook.RESOURCE_ENDPOINT}/list",
            },
            result_parser=resources.Webhook,
        ):
            yield item

    async def notification_webhook_test(self, webhook_id):
        """Test a notification webhook by sending a test payload."""
        req = await self._exec(
            {
                "method": "POST",
                "url": f"{self.uri}{resources.Webhook.RESOURCE_ENDPOINT}/test",
                "params": {"id": str(int(webhook_id))},
            },
        )
        if req.status_code != 200:
            raise exceptions.RequestException(
                req, f"Failed to test webhook {webhook_id}"
            )
        return req
