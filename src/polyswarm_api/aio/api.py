"""PolySwarm API client.

The async version lives here; the sync mirror at
``polyswarm_api.api`` is generated from this file by
``scripts/regenerate_sync.py``. Edit only the async source — the sync
side is mechanically derived.

Public surface::

    from polyswarm_api import PolyswarmAPI                 # sync
    from polyswarm_api.aio import PolySwarmAsyncAPI        # async
"""

import asyncio
import io
import logging
import time

from polyswarm_api import exceptions, resources, settings

from .core import AsyncPolyswarmRequest, AsyncPolyswarmSession
from .upload import async_upload_file

logger = logging.getLogger(__name__)

__all__ = ["PolySwarmAsyncAPI"]


class PolySwarmAsyncAPI:
    """Interface to the PolySwarm API.

    The hand-written async client lives at ``polyswarm_api.aio`` and
    uses ``httpx.AsyncClient``. The synchronous mirror at
    ``polyswarm_api`` is generated from it and uses ``httpx.Client``.
    Both expose the same method names and return shapes — sync callers
    receive values / iterators directly; async callers ``await`` /
    ``async for``.
    """

    _request_cls = AsyncPolyswarmRequest

    def __init__(
        self,
        key: str,
        uri: str | None = None,
        community: str | None = None,
        timeout: float | None = None,
        verify: bool = True,
        **httpx_kwargs,
    ):
        key_masked = '******' + (key[-4:] if key and len(key) > 16 else '')
        logger.info(
            'Creating %s instance | api-key: %s, api-uri: %s, community: %s',
            type(self).__name__, key_masked, uri, community,
        )
        self.uri = uri or settings.DEFAULT_GLOBAL_API
        self.community = community or settings.DEFAULT_COMMUNITY
        self.timeout = timeout or settings.DEFAULT_HTTP_TIMEOUT
        self.verify = verify
        self._engines = None
        self.session = AsyncPolyswarmSession(
            key,
            retries=settings.DEFAULT_RETRIES,
            verify=verify,
            timeout=self.timeout,
            **httpx_kwargs,
        )

    def __repr__(self):
        clsname = f'{type(self).__module__}.{type(self).__name__}'
        attrs = f'uri={self.uri!r}, community={self.community!r}, timeout={self.timeout!r}'
        return f'<{clsname}({attrs}) at 0x{id(self):x}>'

    async def aclose(self):
        """Close the underlying HTTP client."""
        await self.session.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()

    # ── Transport hooks ─────────────────────────────────────────────
    #
    # ``_single`` / ``_paginate`` accept either an unexecuted
    # ``AsyncPolyswarmRequest`` returned by a resource classmethod or
    # a request-parameters dict (legacy / inline endpoint bodies).

    def _coerce_request(self, request, result_parser=None, parser_kwargs=None):
        """Normalise the ``_single`` / ``_paginate`` input into an
        ``AsyncPolyswarmRequest`` (sync mirror: ``PolyswarmRequest``).

        ``request`` is one of:

        * a request-parameters ``dict`` (legacy / inline endpoint bodies);
        * a request object exposing ``request_parameters`` /
          ``result_parser`` / ``parser_kwargs`` — typically returned by
          resource classmethods. We rebuild it on the subclass's
          ``_request_cls`` so the right transport is used.
        """
        parser_kwargs = parser_kwargs or {}
        if isinstance(request, dict):
            return self._request_cls(
                self, request, result_parser=result_parser, **parser_kwargs,
            )
        return self._request_cls(
            self,
            request.request_parameters,
            result_parser=request.result_parser,
            **request.parser_kwargs,
        )

    async def _single(self, request, result_parser=None, **kwargs):
        req = await self._coerce_request(request, result_parser, kwargs).execute()
        return req.result()

    async def _paginate(self, request, result_parser=None, **kwargs):
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

    async def _exec(self, request_parameters, result_parser=None, **kwargs):
        """Build and execute an ``AsyncPolyswarmRequest`` (legacy helper)."""
        return await AsyncPolyswarmRequest(
            self, request_parameters, result_parser=result_parser, **kwargs,
        ).execute()

    # ── Engines ──────────────────────────────────────────────────

    @property
    def engines(self):
        # Async clients can't expose a property that awaits — call
        # ``refresh_engine_cache()`` first and read ``self._engines``.
        # The sync mirror gets a working property via post-processing in
        # scripts/regenerate_sync.py (see ENGINES_SYNC there).
        raise AttributeError(
            "Use 'await refresh_engine_cache()' then access '_engines' directly. "
            "Properties cannot be async."
        )

    async def refresh_engine_cache(self):
        """Refresh the cached engine listing."""
        engine_list = []
        async for engine in self._paginate(
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

    def _parse_rule(self, rule):
        """Pure helper: normalise a rule argument into (ruleset, rule_id)."""
        if isinstance(rule, str):
            rule, rule_id = resources.YaraRuleset(dict(yara=rule), api=self), None
        elif isinstance(rule, (resources.YaraRuleset, int)):
            rule, rule_id = None, rule
        else:
            raise exceptions.InvalidValueException('Either yara or rule_id must be provided.')
        return rule, rule_id

    # ── Endpoint methods (canonical) ────────────────────────────

    async def metadata_mapping(self):
        """Return the ``MetadataMapping`` describing available metadata
        field names and types."""
        logger.info('Retrieving the metadata mapping')
        return await self._single(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataMapping.RESOURCE_ENDPOINT}'},
            result_parser=resources.MetadataMapping,
        )

    async def metadata_field_properties_write(self, field_path, description,
                                        example=None, category=None, aliases=None):
        """Upsert a metadata field properties entry (the single write path).

        :param field_path: Dotted ES leaf path (e.g. 'polyunite.malware_family').
        :param description: Human-readable description of the field.
        :param example: Optional example search string.
        :param category: Optional category grouping the field belongs to.
        :param aliases: Optional list of friendly-name shortcuts.
        :return: A ``MetadataFieldProperties`` resource.
        """
        logger.info('Writing metadata field properties %s', field_path)
        return await self._single(
            {'method': 'POST',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'json': {'field_path': field_path,
                      'description': description,
                      'example': example,
                      'category': category,
                      'aliases': aliases}},
            result_parser=resources.MetadataFieldProperties,
        )

    async def metadata_field_properties_get(self, field_path):
        """Get a metadata field properties entry by ``field_path``."""
        logger.info('Getting metadata field properties %s', field_path)
        return await self._single(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'params': {'field_path': field_path}},
            result_parser=resources.MetadataFieldProperties,
        )

    async def metadata_field_properties_delete(self, field_path):
        """Delete a metadata field properties entry."""
        logger.info('Deleting metadata field properties %s', field_path)
        return await self._single(
            {'method': 'DELETE',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'params': {'field_path': field_path}},
            result_parser=resources.MetadataFieldProperties,
        )

    async def metadata_field_properties_list(self):
        """Iterate all metadata field properties entries."""
        logger.info('Listing metadata field properties')
        async for item in self._paginate(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}/list'},
            result_parser=resources.MetadataFieldProperties,
        ):
            yield item

    async def search(self, hash_, hash_type=None):
        """
        Search for the latest scans matching the given hash and hash_type.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for hash %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        async for item in self._paginate(resources.ArtifactInstance.search_hash(self, hash_.hash, hash_.hash_type)):
            yield item

    async def search_url(self, url):
        """
        Search for the latest scan matching the given url.

        :param url: A url to be searched by exact match
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for url %s', url)
        async for item in self._paginate(resources.ArtifactInstance.search_url(self, url)):
            yield item

    async def search_scans(self, hash_):
        """
        Search for all scans ever made matching the given sha256.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for scans %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type='sha256')
        async for item in self._paginate(resources.ArtifactInstance.list_scans(self, hash_.hash)):
            yield item

    async def search_by_metadata(self, query, include=None, exclude=None, ips=None, urls=None, domains=None):
        """
        Search artifacts by metadata

        :param query: A query string
        :param include: A list of fields to be included in the result (.* wildcards are accepted)
        :param exclude: A list of fields to be excluded from the result (.* wildcards are accepted)
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for metadata %s', query)
        async for item in self._paginate(resources.Metadata.get(self, query=query, community=self.community, include=include, exclude=exclude, ips=ips, urls=urls, domains=domains)):
            yield item

    async def iocs_by_hash(self, hash_type, hash_value, hide_known_good=False, beta=False):
        """
        Retrieve IOCs by artifact hash

        :param hash_type: Hash type of the provided hash_
        :param hash_value: A list of fields to be included in the result (.* wildcards are accepted)
        :return: Generator of IOC resources
        """
        logger.info('Getting IOCs by hash %s:%s', hash_type, hash_value)
        async for item in self._paginate(resources.IOC.iocs_by_hash(self, hash_value, hash_type, hide_known_good=hide_known_good, beta=beta)):
            yield item

    async def search_by_ioc(self, ip=None, domain=None, ttp=None, imphash=None):
        """
        Search artifacts by IOC (ip, domain, ttp, or imphash)
        
        :param ip: ip address to search by
        :param domain: domain address to search by
        :param ttp: ttp to search by
        :param imphash: ImpHash to search by
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching by ioc %s', dict(ip=ip, domain=domain, ttp=ttp, imphash=imphash))
        async for item in self._paginate(resources.IOC.ioc_search(self, ip=ip, domain=domain, ttp=ttp, imphash=imphash)):
            yield item

    async def check_known_hosts(self, ips=[], domains=[]):
        """
        Check if ip addresses or domains are known.

        :param ips
        :param domains
        :return: Generator of IOC resources
        """
        logger.info('Checking known hosts ips: %s, domains: %s', ips, domains)
        async for item in self._paginate(resources.IOC.check_known_hosts(self, ips, domains)):
            yield item

    async def add_known_good_host(self, type, source, host):
        """
        Add a known good ip or domain.

        :param type
        :param source
        :param host
        :return: IOC resource
        """
        logger.info('Creating known good ioc %s %s %s', type, host, source)
        return await self._single(resources.IOC.create_known_good(self, type, host, source))

    async def add_known_bad_host(self, type, source, host):
        """
        Add a known bad ip or domain.

        :param type
        :param source
        :param host
        :return: IOC resource
        """
        logger.info('Creating known bad ioc %s %s %s', type, host, source)
        return await self._single(resources.IOC.create_known_bad(self, type, host, source))

    async def update_known_good_host(self, id, type, source, host, good):
        """
        Update a known ip or domain.

        :param type
        :param source
        :param host
        :return: IOC resource
        """
        logger.info('Updating known good ioc %s %s %s %s', id, type, host, source)
        return await self._single(resources.IOC.update_known_good(self, id, type, host, source, good))

    async def delete_known_good_host(self, id):
        logger.info('Deleting known good ioc %s', id)
        return await self._single(resources.IOC.delete_known_good(self, id))

    async def lookup(self, scan):
        """
        Lookup a scan by Scan id.

        :param scan: The Scan UUID to lookup
        :return: An ArtifactInstance resource
        """
        logger.info('Lookup scan %s', int(scan))
        return await self._single(resources.ArtifactInstance.lookup_uuid(self, scan))

    async def rescan(self, hash_, hash_type=None, scan_config=None):
        """
        Rescan a file based on and existing hash in the Polyswarm platform

        :param hash_: Hashable object (Artifact, local.LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :param scan_config: The scan configuration to be used, e.g.: "default", "more-time", "most-time"
        :return: A ArtifactInstance resources
        """
        logger.info('Rescan hash %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return await self._single(resources.ArtifactInstance.rescan(self, hash_.hash, hash_.hash_type, scan_config=scan_config))

    async def rescan_id(self, scan, scan_config=None):
        """
        Re-execute a new scan based on an existing scan.

        :param scan: Id of the existing scan
        :param scan_config: The scan configuration to be used, e.g.: "default", "more-time", "most-time"
        :return: A ArtifactInstance resource
        """
        logger.info('Rescan id %s', int(scan))
        return await self._single(resources.ArtifactInstance.rescan_id(self, scan, scan_config=scan_config))

    async def live_start(self, rule_id):
        """
        Create a new live hunt_id, and replace the currently running YARA rules.

        :param rule_id: Yara ruleset id
        :return: The ruleset with the associated live hunt
        """
        logger.info('Create live hunt for rule id %s', rule_id)
        return await self._single(resources.LiveYaraRuleset.create(self, rule_id=rule_id))

    async def live_stop(self, rule_id):
        """
        Stop a live hunt.

        :param rule_id: Yara ruleset id
        :return: The ruleset without an associate live hunt
        """
        logger.info('Delete live hunt for rule id %s', rule_id)
        return await self._single(resources.LiveYaraRuleset.delete(self, rule_id=rule_id))

    async def live_feed(self, since=None, rule_name=None, family=None,
                           polyscore_lower=None, polyscore_upper=None, community=None):
        """
        Get live hunts feed

        :param since: Fetch results from the last "since" minutes
        :param rule_name: Filter hunt results on the provided rule name (exact match).
        :param family: Filter hunt results based on the family name (exact match).
        :param polyscore_lower: Polyscore lower bound for the hunt results.
        :param polyscore_upper: Polyscore upper bound for the hunt results.
        :param community: Community to retrieve live results from, or public/private.
        :return: Generator of HuntResult resources
        """
        async for item in self._paginate(resources.LiveHuntResult.list(
            self, since=since, rule_name=rule_name, family=family,
            polyscore_lower=polyscore_lower, polyscore_upper=polyscore_upper,
            community=community or self.community)):
            yield item

    async def live_feed_delete(self, result_ids):
        """
        Delete live feed results

        :param result_ids: Live Feed Result IDs
        :return: The deleted LiveHuntResult resources
        """
        logger.info('Delete live results: %s', result_ids)
        try:
            return await self._single(resources.LiveHuntResultList.delete(self, result_ids=result_ids))
        except exceptions.NoResultsException:
            return None

    async def live_result(self, result_id):
        """
        Get yara ruleset for the live hunt result

        :param result_id: Live result id
        :return: A LiveHuntResult resource
        """
        return await self._single(resources.LiveHuntResult.get(self, id=result_id))

    async def historical_create(self, rule=None, ruleset_name=None):
        """
        Run a new historical hunt.

        :param rule: YaraRuleset object or string containing YARA rules to install
        :param ruleset_name: Name of the ruleset.
        :return: The created Hunt resource
        """
        logger.info('Create historical hunt %s', rule)
        rule, rule_id = self._parse_rule(rule)
        return await self._single(resources.HistoricalHunt.create(self, yara=rule.yara if rule else None, rule_id=rule_id,
                                               ruleset_name=ruleset_name, community=self.community))

    async def historical_get(self, hunt=None):
        """
        Get a historical hunt.

        :param hunt: Hunt ID
        :return: The Hunt resource
        """
        logger.info('Get historical hunt %s', hunt)
        return await self._single(resources.HistoricalHunt.get(self, id=hunt, community=self.community))

    async def historical_update(self, hunt):
        """
        Cancel a historical hunt
        :param hunt: The historical hunt id
        :return: The deleted HistoricalHunt resource
        """
        logger.info('Deleting historical hunt %s', hunt)
        return await self._single(resources.HistoricalHunt.update(self, id=hunt, community=self.community))

    async def historical_delete(self, hunt):
        """
        Delete a historical hunts.

        :param hunt: Hunt ID
        :return: The deleted Hunt resource
        """
        logger.info('Delete historical hunt %s', hunt)
        return await self._single(resources.HistoricalHunt.delete(self, id=hunt, community=self.community))

    async def historical_list(self, since=None):
        """
        List all historical hunts

        :return: Generator of Hunt resources
        """
        logger.info('List historical hunts since: %s', since)
        async for item in self._paginate(resources.HistoricalHunt.list(self, since=since, community=self.community)):
            yield item

    async def historical_result(self, result_id):
        """
        Get historical hunt result

        :param result_id: Historical result id
        :return: HistoricalHuntResult resource
        """
        return await self._single(resources.HistoricalHuntResult.get(self, id=result_id, community=self.community))

    async def historical_results(self, hunt=None, rule_name=None, family=None,
                           polyscore_lower=None, polyscore_upper=None, community=None):
        """
        Get results from a historical hunt

        :param hunt: ID of the hunt (None if latest hunt results are desired)
        :param rule_name: Filter hunt results on the provided rule name (exact match).
        :param family: Filter hunt results based on the family name (exact match).
        :param polyscore_lower: Polyscore lower bound for the hunt results.
        :param polyscore_upper: Polyscore upper bound for the hunt results.
        :param community: Community to retrieve live results from, or public/private.
        :return: Generator of HuntResult resources
        """
        logger.info('List historical results for hunt: %s', hunt)
        async for item in self._paginate(resources.HistoricalHuntResultList.get(
            self, id=hunt, rule_name=rule_name, family=family, community=community or self.community,
            polyscore_lower=polyscore_lower, polyscore_upper=polyscore_upper)):
            yield item

    async def historical_results_delete(self, result_ids):
        """
        Delete historical scan results

        :param result_ids: Historical Hunt Result IDs
        :return: The deleted HuntResult resources
        """
        logger.info('Delete historical results: %s', result_ids)
        return await self._single(resources.HistoricalHuntResultList.delete(self, result_ids=result_ids, community=self.community))

    async def historical_delete_list(self, historical_ids):
        """
        Delete historical hunts.

        :param historical_ids: Historical Hunt IDs
        :return: The deleted Hunt resource
        """
        logger.info('Delete historical hunts %s', historical_ids)
        return await self._single(resources.HistoricalHuntList.delete(self, historical_ids=historical_ids, community=self.community))

    async def ruleset_create(self, name, rules, description=None):
        """
        Create a Yara Ruleset from the provided rules with the given name in the polyswarm platform.
        :param name: Name of the ruleset
        :param rules: Yara rules as a string
        :param description: Description of the ruleset
        :return: A YaraRuleset resource
        """
        logger.info('Create ruleset %s: %s', name, rules)
        rules = resources.YaraRuleset(dict(name=name, description=description, yara=rules, community=self.community), api=self)
        return await self._single(resources.YaraRuleset.create(self, yara=rules.yara, name=rules.name, description=rules.description))

    async def ruleset_get(self, ruleset_id=None):
        """
        Retrieve a YaraRuleset from the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        logger.info('Get ruleset %s', ruleset_id)
        return await self._single(resources.YaraRuleset.get(self, id=ruleset_id, community=self.community))

    async def ruleset_update(self, ruleset_id, name=None, rules=None, description=None):
        """
        Update an existing YaraRuleset in the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :param name: New name of the ruleset
        :param rules: New yara rules as a string
        :param description: New description of the ruleset
        :return: The updated YaraRuleset resource
        """
        logger.info('Update ruleset %s', ruleset_id)
        return await self._single(resources.YaraRuleset.update(self, id=ruleset_id, name=name, yara=rules, description=description, community=self.community))

    async def ruleset_delete(self, ruleset_id):
        """
        Delete a YaraRuleset from the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        logger.info('Delete ruleset %s', ruleset_id)
        return await self._single(resources.YaraRuleset.delete(self, id=ruleset_id, community=self.community))

    async def ruleset_list(self):
        """
        List all YaraRulesets for the current account.
        :return: A generator of YaraRuleset resources
        """
        logger.info('List rulesets')
        async for item in self._paginate(resources.YaraRuleset.list(self, community=self.community)):
            yield item

    async def tag_link_get(self, sha256):
        """
        Fetch the Tags and Families associated with the given sha256.

        :param sha256: The sha256 of the artifact.
        :return: A TagLink resource
        """
        logger.info('Get tag link %s', sha256)
        return await self._single(resources.TagLink.get(self, hash=sha256))

    async def tag_link_update(self, sha256, tags=None, families=None, emerging=None, remove=False):
        """
        Update a TagLink with the given type or value by its id.
        :param sha256: The sha256 of the artifact.
        :param tags: A list of tags to be added or removed.
        :param families: A list of families to be added or removed.
        :param remove: A flag indicating if we should remove the provided tags/families.
        :return: A TagLink resource
        """
        logger.info('Update tag link %s', sha256)
        return await self._single(resources.TagLink.update(self, hash=sha256, tags=tags, families=families,
                                        emerging=emerging, remove=remove))

    async def tag_link_list(self, tags=None, families=None, or_tags=None, or_families=None):
        """
        Fetch all existing TagLinks for the provided tags.
        :param tags: A list of tags that must be associated with the TagLinks listed.
        :param families: A list of families that must be associated with the TagLinks listed.
        :param or_tags: A list of tags where the TagLinks must be associated with at least one.
        :param or_families: A list of families where the TagLinks must be associated with at least one.
        :return: A TagLink resource
        """
        logger.info('List tag links')
        return await self._single(resources.TagLink.list(self, tags=tags, families=families,
                                      or_tags=or_tags, or_families=or_families))

    async def tag_create(self, name):
        """
        Create a Tag.
        :param name: The tag we want to create.
        :return: A Tag resource
        """
        logger.info('Create tag %s', name)
        return await self._single(resources.Tag.create(self, name=name))

    async def tag_get(self, name):
        """
        Fetch a Tag.
        :param name: The tag we want to fetch.
        :return: A Tag resource
        """
        logger.info('Get tag %s', name)
        return await self._single(resources.Tag.get(self, name=name))

    async def tag_delete(self, name):
        """
        Delete a Tag.
        :param name: The tag we want to delete.
        :return: A Tag resource
        """
        logger.info('Delete tag %s', name)
        return await self._single(resources.Tag.delete(self, name=name))

    async def tag_list(self):
        """
        Fetch all existing Tags.
        :return: A generator of Tag resources
        """
        logger.info('List tags')
        async for item in self._paginate(resources.Tag.list(self)):
            yield item

    async def family_create(self, name):
        """
        Create a Family.
        :param name: The family name.
        :return: A MalwareFamily resource
        """
        logger.info('Creating family %s', name)
        return await self._single(resources.MalwareFamily.create(self, name=name))

    async def family_get(self, name):
        """
        Fetch a Family.
        :param name: The family name.
        :return: A MalwareFamily resource
        """
        logger.info('Getting family %s', name)
        return await self._single(resources.MalwareFamily.get(self, name=name))

    async def family_delete(self, name):
        """
        Delete a Family.
        :param name: The family name.
        :return: A MalwareFamily resource
        """
        logger.info('Deleting family %s', name)
        return await self._single(resources.MalwareFamily.delete(self, name=name))

    async def family_update(self, family_name, emerging=True):
        """
        Update the Family emerging status.
        :param family_name: The family name.
        :param emerging: A flag indicating if the family should be marked as emerging at this point in time.
        :return: A MalwareFamily resource
        """
        logger.info('Updating family %s', family_name)
        return await self._single(resources.MalwareFamily.update(self, name=family_name, emerging=emerging))

    async def family_list(self):
        """
        Fetch all existing Families
        :return: A generator of MalwareFamily resources
        """
        logger.info('Listing families')
        async for item in self._paginate(resources.MalwareFamily.list(self)):
            yield item

    async def assertions_create(self, engine_id, date_start, date_end):
        logger.info('Create assertions %s %s %s', engine_id, date_start, date_end)
        return await self._single(resources.AssertionsJob.create(self,
                                              engine_id=engine_id,
                                              date_start=date_start,
                                              date_end=date_end))

    async def assertions_get(self, assertions_id):
        logger.info('Get assertions %s', assertions_id)
        return await self._single(resources.AssertionsJob.get(self, id=assertions_id))

    async def assertions_delete(self, assertions_id):
        logger.info('Delete assertions %s', assertions_id)
        return await self._single(resources.AssertionsJob.delete(self, id=assertions_id))

    async def assertions_list(self, engine_id):
        logger.info('Get all assertions bundles for the engine %s', engine_id)
        async for item in self._paginate(resources.AssertionsJob.list(self, engine_id=engine_id)):
            yield item

    async def votes_create(self, engine_id, date_start, date_end):
        logger.info('Create votes %s %s %s', engine_id, date_start, date_end)
        return await self._single(resources.VotesJob.create(self,
                                         engine_id=engine_id,
                                         date_start=date_start,
                                         date_end=date_end))

    async def votes_get(self, votes_id):
        logger.info('Get votes %s', votes_id)
        return await self._single(resources.VotesJob.get(self, id=votes_id))

    async def votes_delete(self, votes_id):
        logger.info('Delete votes %s', votes_id)
        return await self._single(resources.VotesJob.delete(self, id=votes_id))

    async def votes_list(self, engine_id):
        logger.info('Get all votes bundles for the engine %s', engine_id)
        async for item in self._paginate(resources.VotesJob.list(self, engine_id=engine_id)):
            yield item

    async def sandbox(self, instance_id, provider_slug, vm_slug, network_enabled):
        logger.info(
            'Sandboxing %s in provider %s vm %s internet %s', instance_id, provider_slug, vm_slug, network_enabled)
        return await self._single(resources.SandboxTask.create(self, artifact_id=instance_id, provider_slug=provider_slug, vm_slug=vm_slug,
                                            network_enabled=network_enabled))

    async def sandbox_task_status(self, sandbox_task_id):
        """
        Check the status of a sandbox task.
        """
        logger.info('Checking the status of sandbox task %s', sandbox_task_id)
        return await self._single(resources.SandboxTask.get(self, sandbox_task_id=sandbox_task_id))

    async def sandbox_task_latest(self, sha256, sandbox):
        """
        Check the latest status of a sandbox task.
        """
        logger.info('Checking the sandbox task for %s', sha256)
        return await self._single(resources.SandboxTask.latest(self, sha256=sha256, sandbox=sandbox))

    async def sandbox_my_tasks_list(self, **kwargs):
        """
        Check the latest status of a sandbox task.
        """
        logger.info('Checking the latest tasks created by my account')
        async for item in self._paginate(resources.SandboxTask.my_tasks(self, **kwargs)):
            yield item

    async def sandbox_task_list(self, sha256, **kwargs):
        """
        Check the list of a sandbox tasks.
        """
        logger.info('Checking the sandbox tasks for %s', sha256)
        async for item in self._paginate(resources.SandboxTask.list(self, sha256=sha256, **kwargs)):
            yield item

    async def download_to_handle(self, hash_, fh, hash_type=None):
        """
        Grab the data of artifact identified by hash, and write the data to a file handle
        :param hash_: The hash we should use to lookup the artifact to download.
        :param fh: A file-like object which we are going to write the contents of the artifact to.
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A LocalHandle resource
        """
        logger.info('Downloading %s into handle', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return await self._single(resources.LocalArtifact.download(self, hash_.hash, hash_.hash_type, handle=fh))

    async def stream(self, since=settings.MAX_SINCE_TIME_STREAM):
        """
        Access the stream of artifacts (ask info@polyswarm.io about access)

        :param since: Fetch results from the last "since" minutes (up to 2 days)
        :return: Generator of ArtifactArchive resources
        """
        logger.info('Streaming since %s', since)
        async for item in self._paginate(resources.ArtifactArchive.get(self, since=since)):
            yield item

    async def rerun_metadata(self, hashes, analyses=None, skip_es=None):
        logger.info('Rerunning metadata for hashes %s', hashes)
        return await self._single(resources.ArtifactInstance.metadata_rerun(self, hashes, analyses=analyses, skip_es=skip_es))

    async def tool_metadata_create(self, instance_id, tool, tool_metadata):
        logger.info('Create tool metadata %s %s %s', instance_id, tool, tool_metadata)
        return await self._single(resources.ToolMetadata.create(
            self, instance_id=instance_id, tool=tool, tool_metadata=tool_metadata))

    async def tool_metadata_list(self, instance_id):
        logger.info('List tool metadata')
        async for item in self._paginate(resources.ToolMetadata.list(self, instance_id=instance_id)):
            yield item

    async def event_list(self, **kwargs):
        logger.info('List events')
        async for item in self._paginate(resources.Events.list(self, **kwargs)):
            yield item

    async def sample(self, sha256, artifact_instance_id=None, sandbox_task_id_cape=None,
               sandbox_task_id_triage=None, artifact_metadata_id=None, llm_report_id=None):
        """
        Get aggregated sample information including artifact instance, sandbox tasks, metadata,
        and LLM report.

        :param sha256: SHA256 hash of the artifact
        :param artifact_instance_id: Optional specific artifact instance ID
        :param sandbox_task_id_cape: Optional specific Cape sandbox task ID
        :param sandbox_task_id_triage: Optional specific Triage sandbox task ID
        :param artifact_metadata_id: Optional specific artifact metadata ID
        :param llm_report_id: Optional specific LLM report task ID
        :return: A Sample resource with aggregated data
        """
        logger.info('Getting sample %s', sha256)
        return await self._single(resources.Sample.create(
            self,
            endpoint_fmt={'sha256': sha256},
            community=self.community,
            artifact_instance_id=artifact_instance_id,
            sandbox_task_id_cape=sandbox_task_id_cape,
            sandbox_task_id_triage=sandbox_task_id_triage,
            artifact_metadata_id=artifact_metadata_id,
            llm_report_id=llm_report_id,
        ))

    async def sample_bundle_task_create(self, instance_ids, preserve_filenames=False, filename=None, **kwargs):
        """
        Create a task that creates a zip of sample/s
        """
        logger.info('Create zip archive task')
        task = await self._single(resources.BundleTask.create(self,
                                              instance_ids=instance_ids,
                                              filename=filename,
                                              preserve_filenames=preserve_filenames,
                                              community=self.community,
                                              **kwargs))
        return task

    async def sample_bundle_task_get(self, id, **kwargs):
        return await self._single(resources.BundleTask.get(self, id=id, community=self.community, **kwargs))

    async def llm_report_create(self, instance_id=None, cape_sandbox_task_id=None, triage_sandbox_task_id=None):
        """
        Create a llm generated report, from the scan and/or sandbox results.
        """
        if not instance_id and not cape_sandbox_task_id and not triage_sandbox_task_id:
            raise exceptions.InvalidValueException('Either instance_id or sandbox_task_id must be provided')
        report_task = await self._single(resources.ReportLLMPostProcessing.create(self,
                                                               instance_id=instance_id,
                                                               cape_sandbox_task_id=cape_sandbox_task_id,
                                                               triage_sandbox_task_id=triage_sandbox_task_id))
        return report_task

    async def llm_report_get(self, report_task_id):
        task = await self._single(resources.ReportLLMPostProcessing.get(self, id=report_task_id, community=self.community))
        return task

    async def report_create(self,
                      type,
                      format,
                      instance_id=None,
                      sandbox_task_id=None,
                      template_id=None,
                      template_metadata=None,
                      **kwargs):
        """
        Create a report, either 'pdf' or 'html' (format argument).
        Regarding the type argument, either instance_id (type='scan')
        or sandbox_task_id (type='sandbox') has to be provided.
        """
        report = await self._single(resources.ReportTask.create(self,
                                             type=type,
                                             format=format,
                                             instance_id=instance_id,
                                             sandbox_task_id=sandbox_task_id,
                                             template_id=template_id,
                                             template_metadata=template_metadata,
                                             community=self.community,
                                             **kwargs))
        return report

    async def report_get(self, id, **kwargs):
        return await self._single(resources.ReportTask.get(self, id=id, community=self.community, **kwargs))

    async def report_template_create(self,
                               template_name,
                               is_default=False,
                               primary_color=None,
                               footer_text=None,
                               last_page_text=None,
                               includes=None,
                               **kwargs):
        """
        Create a template for reports.
        A team account can have multiple templates, and the setting is_default=True
        makes it the default when a report is created without specifying template_id
        (see report_create method).
        The includes argument can be a list with sections to be included
        in the reports. The list can include any of the following section names:
        summary, detections, fileMetadata, network, droppedFiles, extractedConfig, analysis.
        """
        return await self._single(resources.ReportTemplate.create(self,
                                               template_name=template_name,
                                               is_default=is_default,
                                               primary_color=primary_color,
                                               footer_text=footer_text,
                                               last_page_text=last_page_text,
                                               includes=includes,
                                               **kwargs))

    async def report_template_update(self,
                               template_id,
                               template_name=None,
                               is_default=None,
                               primary_color=None,
                               footer_text=None,
                               last_page_text=None,
                               includes=None,
                               **kwargs):
        return await self._single(resources.ReportTemplate.update(self,
                                               id=template_id,
                                               template_name=template_name,
                                               is_default=is_default,
                                               primary_color=primary_color,
                                               footer_text=footer_text,
                                               last_page_text=last_page_text,
                                               includes=includes,
                                               **kwargs))

    async def report_template_get(self, template_id):
        return await self._single(resources.ReportTemplate.get(self, id=template_id))

    async def report_template_delete(self, template_id):
        return await self._single(resources.ReportTemplate.delete(self, id=template_id))

    async def report_template_list(self, is_default=None, **kwargs):
        async for item in self._paginate(resources.ReportTemplate.list(self, is_default=is_default, **kwargs)):
            yield item

    async def account_whois(self, **kwargs):
        return await self._single(resources.WhoIs.get(self, **kwargs))

    async def account_features(self, **kwargs):
        return await self._single(resources.AccountFeatures.get(self, **kwargs))

    async def prompt_config_create(self, name, system_prompt, is_active=False, cape_only_prompt=None, 
                            triage_only_prompt=None, scan_only_prompt=None):
        """
        Create a new LLM prompt configuration.
        :param name: The name of the prompt configuration
        :param system_prompt: The system prompt text
        :param is_active: Whether this should be the active prompt configuration (default False)
        :param cape_only_prompt: Optional Cape-specific prompt text
        :param triage_only_prompt: Optional Triage-specific prompt text
        :param scan_only_prompt: Optional Scan-specific prompt text
        :return: An LLMPromptConfig resource
        """
        logger.info('Creating prompt config %s', name)
        return await self._single(resources.LLMPromptConfig.create(self,
                                                name=name,
                                                system_prompt=system_prompt,
                                                is_active=is_active,
                                                cape_only_prompt=cape_only_prompt,
                                                triage_only_prompt=triage_only_prompt,
                                                scan_only_prompt=scan_only_prompt))

    async def prompt_config_get(self, prompt_config_id):
        """
        Get an LLM prompt configuration by ID.
        :param prompt_config_id: The ID of the prompt configuration
        :return: An LLMPromptConfig resource
        """
        logger.info('Getting prompt config %s', prompt_config_id)
        return await self._single(resources.LLMPromptConfig.get(self, id=prompt_config_id))

    async def prompt_config_update(self, prompt_config_id, name=None, system_prompt=None, is_active=None,
                            cape_only_prompt=None, triage_only_prompt=None, scan_only_prompt=None):
        """
        Update an existing LLM prompt configuration.
        :param prompt_config_id: The ID of the prompt configuration to update
        :param name: The new name (optional)
        :param system_prompt: The new system prompt text (optional)
        :param is_active: Whether this should be the active prompt configuration (optional)
        :param cape_only_prompt: Optional Cape-specific prompt text (optional)
        :param triage_only_prompt: Optional Triage-specific prompt text (optional)
        :param scan_only_prompt: Optional Scan-specific prompt text (optional)
        :return: An LLMPromptConfig resource
        """
        logger.info('Updating prompt config %s', prompt_config_id)
        return await self._single(resources.LLMPromptConfig.update(self,
                                                id=prompt_config_id,
                                                name=name,
                                                system_prompt=system_prompt,
                                                is_active=is_active,
                                                cape_only_prompt=cape_only_prompt,
                                                triage_only_prompt=triage_only_prompt,
                                                scan_only_prompt=scan_only_prompt))

    async def prompt_config_list(self, **kwargs):
        """
        List all LLM prompt configurations.
        :return: A generator of LLMPromptConfig resources
        """
        logger.info('Listing prompt configs')
        async for item in self._paginate(resources.LLMPromptConfig.list(self, **kwargs)):
            yield item

    async def notification_webhook_create(self, webhook_uri, secret, status='enabled', events=None):
        """
        Create a new webhook for notifications from Polyswarm events.
        
        :param webhook_uri: The URI where webhook events should be sent
        :param secret: The secret key used for HMAC signature verification
        :param status: Webhook status ('enabled' or 'disabled')
        :param events: Optional set specifying which events to subscribe to. Available options: sandbox_done
        :return: A Webhook resource
        """
        logger.info('Creating webhook %s', webhook_uri)
        return await self._single(resources.Webhook.create(self,
                                       webhook_uri=webhook_uri,
                                       secret=secret,
                                       status=status,
                                       events=events))

    async def notification_webhook_get(self, webhook_id):
        """
        Get a notification webhook by ID.
        :param webhook_id: The ID of the webhook
        :return: A Webhook resource
        """
        logger.info('Getting webhook %s', webhook_id)
        return await self._single(resources.Webhook.get(self, id=webhook_id))

    async def notification_webhook_update(self, webhook_id, webhook_uri=None, secret=None, status=None,
                      team_account_number=None, events=None):
        """
        Update an existing notification webhook.
        :param webhook_id: The ID of the webhook to update
        :param webhook_uri: The new webhook URI (optional)
        :param secret: The new secret SHA256 for HMAC signing (optional)
        :param status: The new status ('enabled' or 'disabled') (optional)
        :param events: Event configuration (optional)
        :return: A Webhook resource
        """
        logger.info('Updating webhook %s', webhook_id)
        return await self._single(resources.Webhook.update(self,
                                        id=webhook_id,
                                        webhook_uri=webhook_uri,
                                        secret=secret,
                                        status=status,
                                        events=events))

    async def notification_webhook_delete(self, webhook_id):
        """
        Delete a notification webhook.
        :param webhook_id: The ID of the webhook to delete
        :return: A success message
        """
        logger.info('Deleting webhook %s', webhook_id)
        return await self._single(resources.Webhook.delete(self, id=webhook_id))

    async def notification_webhook_list(self):
        """
        List all notification webhooks for the current account.
        :return: A generator of Webhook resources
        """
        logger.info('Listing webhooks')
        async for item in self._paginate(resources.Webhook.list(self)):
            yield item

    async def notification_webhook_test(self, webhook_id):
        """
        Test a notification webhook by sending a test payload.
        :param webhook_id: The ID of the webhook to test
        :raises: ``RequestException`` (or a specific subclass) when the server
            returns a non-2xx response.
        """
        logger.info('Testing webhook %s', webhook_id)
        # ``_single`` executes the request and raises the appropriate
        # ``RequestException`` subclass on any non-2xx response; nothing
        # extra to check here.
        return await self._single(resources.Webhook.test(self, webhook_id=webhook_id))

    # ── Multi-step / file-upload methods ─────────────────────

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
        """List sandboxes available in polyswarm.

        Mirrors the sync shape: returns an executed request whose ``.json``
        carries the providers-by-slug envelope. Caller reads
        ``(await api.sandbox_providers()).json``.
        """
        logger.info('Listing sandbox names')
        return await self._coerce_request(resources.SandboxProvider.list(self)).execute()

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

    async def report_template_logo_download(self, template_id, folder):
        """Download the logo image for a report template into ``folder``."""
        report = await self._single(resources.ReportTemplate.get(self, id=template_id))
        result = await self._single(report.download_logo(folder))
        result.handle.close()
        return result

    async def report_template_logo_delete(self, template_id):
        """Delete the logo image attached to a report template."""
        report = await self._single(resources.ReportTemplate.get(self, id=template_id))
        return await self._single(report.delete_logo())

    async def report_template_logo_upload(self, template_id, logo_file,
                                          content_type=None, content_tpe=None):
        """Upload a logo image for a report template.

        ``content_tpe`` is a legacy spelling kept for backwards compatibility.
        """
        if content_tpe is not None and content_type is None:
            content_type = content_tpe
        if content_type is None:
            raise exceptions.InvalidValueException(
                "missing required argument: 'content_type'",
            )
        report = await self._single(resources.ReportTemplate.get(self, id=template_id))
        return await self._single(report.upload_logo(logo_file, content_type))

    async def report_download(self, report_id, folder):
        """Download a completed report into ``folder``.

        Raises ``InvalidValueException`` if the report is still pending or
        has failed — call ``report_wait_for`` first if you need to block.
        """
        report = await self.report_get(id=report_id)
        if report.state == 'PENDING':
            raise exceptions.InvalidValueException(
                'Report is in PENDING state, wait for completion first',
            )
        if report.state == 'FAILED':
            raise exceptions.InvalidValueException(
                "Report is in FAILED state, won't be generated",
            )
        result = await self._single(report.download_report(folder=folder))
        result.handle.close()
        return result

    async def sample_bundle_download(self, id, folder):
        """Download the zip produced by a bundle task into ``folder``.

        Raises ``InvalidValueException`` if the bundle is still pending or
        has failed.
        """
        task = await self._single(
            resources.BundleTask.get(self, id=id, community=self.community),
        )
        if task.state == 'PENDING':
            raise exceptions.InvalidValueException(
                'Bundle is in PENDING state, wait for completion first',
            )
        if task.state == 'FAILED':
            raise exceptions.InvalidValueException(
                "Bundle is in FAILED state, won't be generated",
            )
        result = await self._single(task.download_zip(folder=folder))
        result.handle.close()
        return result

    async def llm_report_download(self, report_task_id, folder):
        """Download the rendered LLM-post-processing report into ``folder``."""
        task = await self._single(
            resources.ReportLLMPostProcessing.get(
                self, id=report_task_id, community=self.community,
            ),
        )
        result = await self._single(task.download_report(folder=folder))
        result.handle.close()
        return result

    async def download(self, out_dir, hash_, hash_type=None):
        """Download an artifact by hash into ``out_dir``.

        :param out_dir: Destination directory for the downloaded file.
        :param hash_: Hashable (Artifact, LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5.
        :param hash_type: Hash type; auto-detected from the literal if not provided.
        :return: A ``LocalArtifact`` resource with its handle already closed.
        """
        logger.info('Downloading %s into %s', hash_, out_dir)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        artifact = await self._single(
            resources.LocalArtifact.download(self, hash_.hash, hash_.hash_type, folder=out_dir),
        )
        artifact.handle.close()
        return artifact

    async def download_id(self, out_dir, instance_id):
        """Download an artifact by its instance id into ``out_dir``."""
        logger.info('Downloading %s into %s', instance_id, out_dir)
        artifact = await self._single(
            resources.LocalArtifact.download_id(self, instance_id, folder=out_dir),
        )
        artifact.handle.close()
        return artifact

    async def download_sandbox_artifact(self, out_dir, sandbox_task_id, instance_id):
        """Download a sandbox-produced artifact (e.g. PCAP, dropped file) into ``out_dir``."""
        logger.info('Downloading sandbox artifact %s %s', sandbox_task_id, instance_id)
        sandbox_artifact = await self._single(
            resources.LocalArtifact.download_sandbox_artifact(
                self, sandbox_task_id, instance_id, folder=out_dir,
            ),
        )
        sandbox_artifact.handle.close()
        return sandbox_artifact

    async def download_archive(self, out_dir, s3_path):
        """Download an artifact-archive tarball from the ``stream()`` feed into ``out_dir``."""
        logger.info('Downloading %s into %s', s3_path, out_dir)
        artifact = await self._single(
            resources.LocalArtifact.download_archive(self, s3_path, folder=out_dir),
        )
        artifact.handle.close()
        return artifact

    async def exists(self, hash_, hash_type=None, require_scan=False):
        """Check whether an artifact with the given hash is known.

        :param hash_: Hashable (Artifact, LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5.
        :param hash_type: Hash type; auto-detected if not provided.
        :param require_scan: If True, only count artifacts that have been scanned.
        :return: ``True`` if the artifact exists in PolySwarm's index.
        """
        logger.info('Exists for hash %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        result = await self._single(
            resources.ArtifactInstance.exists_hash(
                self, hash_.hash, hash_.hash_type, require_scan=require_scan,
            ),
        )
        return str(result) == '200'

