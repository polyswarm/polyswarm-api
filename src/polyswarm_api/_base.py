"""Shared infrastructure for the sync and async PolySwarm API clients.

The sync ``PolyswarmAPI`` (``polyswarm_api.api``) and async
``PolySwarmAsyncAPI`` (``polyswarm_api.aio``) both subclass
``PolyswarmAPIBase``. The base holds the constructor, instance state,
and (over time) every endpoint method as a one-line wrapper around
``self._single(...)`` or ``self._paginate(...)``. Sync subclass
implements those via the sync HTTP transport; async via the async one.

The trick that lets a single method body work for both: base methods
are regular ``def`` (not ``async def``) and ``return
self._single(...)``. Sync ``_single`` returns the parsed value; async
``_single`` returns a coroutine; the base method just passes that
through. Sync callers use the value directly, async callers ``await``
it. For paginated endpoints, the same applies with generators vs
async generators (``for`` / ``async for``).

This first PR lands the shared base + the response-parsing inheritance
(``AsyncPolyswarmRequest`` now inherits from ``PolyswarmRequest``) +
the metadata mapping/properties endpoints as a representative slice.
Bulk endpoint-method consolidation follows in subsequent PRs tracked
by DN-8225.
"""
from __future__ import annotations

import logging

from polyswarm_api import exceptions, resources, settings

logger = logging.getLogger(__name__)


class PolyswarmAPIBase:
    """Shared base for ``PolyswarmAPI`` and ``PolySwarmAsyncAPI``.

    Holds the constructor signature, instance attributes (``uri``,
    ``community``, ``timeout``, ``session``), and the eventual single
    home for every endpoint method. Subclasses implement
    ``_single`` / ``_paginate`` / ``_sleep`` to plug the sync vs async
    HTTP transport in.

    Not instantiable directly — use ``polyswarm_api.PolyswarmAPI`` (sync)
    or ``polyswarm_api.aio.PolySwarmAsyncAPI`` (async).
    """

    def __init__(self, key, uri=None, community=None, timeout=None, verify=True, **kwargs):
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
        # Subclasses set self.session.
        self.session = None

    def __repr__(self):
        clsname = f'{type(self).__module__}.{type(self).__name__}'
        attrs = f'uri={self.uri!r}, community={self.community!r}, timeout={self.timeout!r}'
        return f'<{clsname}({attrs}) at 0x{id(self):x}>'

    # ── Subclasses override these ────────────────────────────────────

    def _single(self, request):
        """Execute the (unexecuted) ``PolyswarmRequest`` and return its result.

        * Sync subclass: returns the value directly.
        * Async subclass: returns a coroutine yielding the value.
        """
        raise NotImplementedError

    def _paginate(self, request):
        """Execute the request and return an iterator over its results.

        * Sync subclass: returns a generator.
        * Async subclass: returns an async generator.
        """
        raise NotImplementedError

    def _sleep(self, seconds):
        """Block for ``seconds``. Sync uses ``time.sleep``; async ``asyncio.sleep``."""
        raise NotImplementedError

    _request_cls = None  # subclass sets to PolyswarmRequest / AsyncPolyswarmRequest

    def _coerce_request(self, request, result_parser=None, parser_kwargs=None):
        """Normalise the various inputs to ``_single`` / ``_paginate`` into
        a request instance of the subclass's ``_request_cls``.

        ``request`` is one of:

        * an unexecuted ``PolyswarmRequest`` returned by a resource
          classmethod (``resources.Foo.create(self, …)``) — rebuilt as
          the subclass's ``_request_cls`` so the right transport is used;
        * a request-parameters dict (legacy / inline endpoint bodies).
        """
        from polyswarm_api.core import PolyswarmRequest
        parser_kwargs = parser_kwargs or {}
        if isinstance(request, PolyswarmRequest):
            return self._request_cls(
                self,
                request.request_parameters,
                result_parser=request.result_parser,
                **request.parser_kwargs,
            )
        if isinstance(request, dict):
            return self._request_cls(
                self, request, result_parser=result_parser, **parser_kwargs,
            )
        raise TypeError(
            f'_single / _paginate expect a PolyswarmRequest or request-parameters '
            f'dict, got {type(request).__name__}',
        )

    # ── Shared endpoint surface ─────────────────────────────────────
    #
    # Each method is defined ONCE here and works for both sync and async
    # subclasses. The trick: bodies are sync-shaped (``return
    # self._single(...)``), and ``_single`` / ``_paginate`` are
    # overridden per subclass to return either a value/generator (sync)
    # or a coroutine/async generator (async). The caller awaits or
    # iterates over the result as appropriate.

    # ── Metadata ────────────────────────────────────────────────────

    def metadata_mapping(self):
        """Get available metadata field names and types.

        Sync: returns a ``MetadataMapping`` resource.
        Async: returns a coroutine; ``await`` it for the same.
        """
        logger.info('Retrieving the metadata mapping')
        return self._single(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataMapping.RESOURCE_ENDPOINT}'},
            result_parser=resources.MetadataMapping,
        )

    def metadata_field_properties_write(self, field_path, description,
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
        return self._single(
            {'method': 'POST',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'json': {'field_path': field_path,
                      'description': description,
                      'example': example,
                      'category': category,
                      'aliases': aliases}},
            result_parser=resources.MetadataFieldProperties,
        )

    def metadata_field_properties_get(self, field_path):
        """Get a metadata field properties entry by ``field_path``."""
        logger.info('Getting metadata field properties %s', field_path)
        return self._single(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'params': {'field_path': field_path}},
            result_parser=resources.MetadataFieldProperties,
        )

    def metadata_field_properties_delete(self, field_path):
        """Delete a metadata field properties entry."""
        logger.info('Deleting metadata field properties %s', field_path)
        return self._single(
            {'method': 'DELETE',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'params': {'field_path': field_path}},
            result_parser=resources.MetadataFieldProperties,
        )

    def metadata_field_properties_list(self):
        """List all metadata field properties entries.

        Sync: returns a generator. Async: returns an async generator.
        Iterate with ``for`` or ``async for`` accordingly.
        """
        logger.info('Listing metadata field properties')
        return self._paginate(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}/list'},
            result_parser=resources.MetadataFieldProperties,
        )


    # ── Migrated endpoint methods (Phase 2) ──────────────────────────
    #
    # Every method below was lifted verbatim from PolyswarmAPI. They
    # delegate to self._single(...) / self._paginate(...) so the same
    # body works for both sync and async transports.

    # ``exists`` and the download / template / multi-step methods live on
    # the subclasses ([PolyswarmAPI](api.py) /
    # [PolySwarmAsyncAPI](aio/api.py)) as sync+async pairs. The
    # ``return self._single(...)`` pass-through trick only works for
    # single-statement bodies; methods that read a ``_single`` result and
    # act on it can't share a body between transports.

    def search(self, hash_, hash_type=None):
        """
        Search for the latest scans matching the given hash and hash_type.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for hash %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self._paginate(resources.ArtifactInstance.search_hash(self, hash_.hash, hash_.hash_type))

    def search_url(self, url):
        """
        Search for the latest scan matching the given url.

        :param url: A url to be searched by exact match
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for url %s', url)
        return self._paginate(resources.ArtifactInstance.search_url(self, url))

    def search_scans(self, hash_):
        """
        Search for all scans ever made matching the given sha256.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for scans %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type='sha256')
        return self._paginate(resources.ArtifactInstance.list_scans(self, hash_.hash))

    # ``metadata_mapping`` and ``metadata_field_properties_*`` live on
    # ``PolyswarmAPIBase``; the sync/async dispatch is handled there.

    def search_by_metadata(self, query, include=None, exclude=None, ips=None, urls=None, domains=None):
        """
        Search artifacts by metadata

        :param query: A query string
        :param include: A list of fields to be included in the result (.* wildcards are accepted)
        :param exclude: A list of fields to be excluded from the result (.* wildcards are accepted)
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for metadata %s', query)
        return self._paginate(resources.Metadata.get(self, query=query, community=self.community, include=include, exclude=exclude, ips=ips, urls=urls, domains=domains))

    def iocs_by_hash(self, hash_type, hash_value, hide_known_good=False, beta=False):
        """
        Retrieve IOCs by artifact hash

        :param hash_type: Hash type of the provided hash_
        :param hash_value: A list of fields to be included in the result (.* wildcards are accepted)
        :return: Generator of IOC resources
        """
        logger.info('Getting IOCs by hash %s:%s', hash_type, hash_value)
        return self._paginate(resources.IOC.iocs_by_hash(self, hash_value, hash_type, hide_known_good=hide_known_good, beta=beta))

    def search_by_ioc(self, ip=None, domain=None, ttp=None, imphash=None):
        """
        Search artifacts by IOC (ip, domain, ttp, or imphash)
        
        :param ip: ip address to search by
        :param domain: domain address to search by
        :param ttp: ttp to search by
        :param imphash: ImpHash to search by
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching by ioc %s', dict(ip=ip, domain=domain, ttp=ttp, imphash=imphash))
        return self._paginate(resources.IOC.ioc_search(self, ip=ip, domain=domain, ttp=ttp, imphash=imphash))

    def check_known_hosts(self, ips=[], domains=[]):
        """
        Check if ip addresses or domains are known.

        :param ips
        :param domains
        :return: Generator of IOC resources
        """
        logger.info('Checking known hosts ips: %s, domains: %s', ips, domains)
        return self._paginate(resources.IOC.check_known_hosts(self, ips, domains))

    def add_known_good_host(self, type, source, host):
        """
        Add a known good ip or domain.

        :param type
        :param source
        :param host
        :return: IOC resource
        """
        logger.info('Creating known good ioc %s %s %s', type, host, source)
        return self._single(resources.IOC.create_known_good(self, type, host, source))

    def add_known_bad_host(self, type, source, host):
        """
        Add a known bad ip or domain.

        :param type
        :param source
        :param host
        :return: IOC resource
        """
        logger.info('Creating known bad ioc %s %s %s', type, host, source)
        return self._single(resources.IOC.create_known_bad(self, type, host, source))

    def update_known_good_host(self, id, type, source, host, good):
        """
        Update a known ip or domain.

        :param type
        :param source
        :param host
        :return: IOC resource
        """
        logger.info('Updating known good ioc %s %s %s %s', id, type, host, source)
        return self._single(resources.IOC.update_known_good(self, id, type, host, source, good))

    def delete_known_good_host(self, id):
        logger.info('Deleting known good ioc %s', id)
        return self._single(resources.IOC.delete_known_good(self, id))

    def lookup(self, scan):
        """
        Lookup a scan by Scan id.

        :param scan: The Scan UUID to lookup
        :return: An ArtifactInstance resource
        """
        logger.info('Lookup scan %s', int(scan))
        return self._single(resources.ArtifactInstance.lookup_uuid(self, scan))

    def rescan(self, hash_, hash_type=None, scan_config=None):
        """
        Rescan a file based on and existing hash in the Polyswarm platform

        :param hash_: Hashable object (Artifact, local.LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :param scan_config: The scan configuration to be used, e.g.: "default", "more-time", "most-time"
        :return: A ArtifactInstance resources
        """
        logger.info('Rescan hash %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self._single(resources.ArtifactInstance.rescan(self, hash_.hash, hash_.hash_type, scan_config=scan_config))

    def rescan_id(self, scan, scan_config=None):
        """
        Re-execute a new scan based on an existing scan.

        :param scan: Id of the existing scan
        :param scan_config: The scan configuration to be used, e.g.: "default", "more-time", "most-time"
        :return: A ArtifactInstance resource
        """
        logger.info('Rescan id %s', int(scan))
        return self._single(resources.ArtifactInstance.rescan_id(self, scan, scan_config=scan_config))

    def _parse_rule(self, rule):
        if isinstance(rule, str):
            rule, rule_id = resources.YaraRuleset(dict(yara=rule), api=self), None
        elif isinstance(rule, (resources.YaraRuleset, int)):
            rule, rule_id = None, rule
        else:
            raise exceptions.InvalidValueException('Either yara or rule_id must be provided.')
        return rule, rule_id

    def live_start(self, rule_id):
        """
        Create a new live hunt_id, and replace the currently running YARA rules.

        :param rule_id: Yara ruleset id
        :return: The ruleset with the associated live hunt
        """
        logger.info('Create live hunt for rule id %s', rule_id)
        return self._single(resources.LiveYaraRuleset.create(self, rule_id=rule_id))

    def live_stop(self, rule_id):
        """
        Stop a live hunt.

        :param rule_id: Yara ruleset id
        :return: The ruleset without an associate live hunt
        """
        logger.info('Delete live hunt for rule id %s', rule_id)
        return self._single(resources.LiveYaraRuleset.delete(self, rule_id=rule_id))

    def live_feed(self, since=None, rule_name=None, family=None,
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
        return self._paginate(resources.LiveHuntResult.list(
            self, since=since, rule_name=rule_name, family=family,
            polyscore_lower=polyscore_lower, polyscore_upper=polyscore_upper,
            community=community or self.community))

    def live_feed_delete(self, result_ids):
        """
        Delete live feed results

        :param result_ids: Live Feed Result IDs
        :return: The deleted LiveHuntResult resources
        """
        logger.info('Delete live results: %s', result_ids)
        try:
            return self._single(resources.LiveHuntResultList.delete(self, result_ids=result_ids))
        except exceptions.NoResultsException:
            return None

    def live_result(self, result_id):
        """
        Get yara ruleset for the live hunt result

        :param result_id: Live result id
        :return: A LiveHuntResult resource
        """
        return self._single(resources.LiveHuntResult.get(self, id=result_id))

    def historical_create(self, rule=None, ruleset_name=None):
        """
        Run a new historical hunt.

        :param rule: YaraRuleset object or string containing YARA rules to install
        :param ruleset_name: Name of the ruleset.
        :return: The created Hunt resource
        """
        logger.info('Create historical hunt %s', rule)
        rule, rule_id = self._parse_rule(rule)
        return self._single(resources.HistoricalHunt.create(self, yara=rule.yara if rule else None, rule_id=rule_id,
                                               ruleset_name=ruleset_name, community=self.community))

    def historical_get(self, hunt=None):
        """
        Get a historical hunt.

        :param hunt: Hunt ID
        :return: The Hunt resource
        """
        logger.info('Get historical hunt %s', hunt)
        return self._single(resources.HistoricalHunt.get(self, id=hunt, community=self.community))

    def historical_update(self, hunt):
        """
        Cancel a historical hunt
        :param hunt: The historical hunt id
        :return: The deleted HistoricalHunt resource
        """
        logger.info('Deleting historical hunt %s', hunt)
        return self._single(resources.HistoricalHunt.update(self, id=hunt, community=self.community))

    def historical_delete(self, hunt):
        """
        Delete a historical hunts.

        :param hunt: Hunt ID
        :return: The deleted Hunt resource
        """
        logger.info('Delete historical hunt %s', hunt)
        return self._single(resources.HistoricalHunt.delete(self, id=hunt, community=self.community))

    def historical_list(self, since=None):
        """
        List all historical hunts

        :return: Generator of Hunt resources
        """
        logger.info('List historical hunts since: %s', since)
        return self._paginate(resources.HistoricalHunt.list(self, since=since, community=self.community))

    def historical_result(self, result_id):
        """
        Get historical hunt result

        :param result_id: Historical result id
        :return: HistoricalHuntResult resource
        """
        return self._single(resources.HistoricalHuntResult.get(self, id=result_id, community=self.community))

    def historical_results(self, hunt=None, rule_name=None, family=None,
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
        return self._paginate(resources.HistoricalHuntResultList.get(
            self, id=hunt, rule_name=rule_name, family=family, community=community or self.community,
            polyscore_lower=polyscore_lower, polyscore_upper=polyscore_upper))

    def historical_results_delete(self, result_ids):
        """
        Delete historical scan results

        :param result_ids: Historical Hunt Result IDs
        :return: The deleted HuntResult resources
        """
        logger.info('Delete historical results: %s', result_ids)
        return self._single(resources.HistoricalHuntResultList.delete(self, result_ids=result_ids, community=self.community))

    def historical_delete_list(self, historical_ids):
        """
        Delete historical hunts.

        :param historical_ids: Historical Hunt IDs
        :return: The deleted Hunt resource
        """
        logger.info('Delete historical hunts %s', historical_ids)
        return self._single(resources.HistoricalHuntList.delete(self, historical_ids=historical_ids, community=self.community))

    def ruleset_create(self, name, rules, description=None):
        """
        Create a Yara Ruleset from the provided rules with the given name in the polyswarm platform.
        :param name: Name of the ruleset
        :param rules: Yara rules as a string
        :param description: Description of the ruleset
        :return: A YaraRuleset resource
        """
        logger.info('Create ruleset %s: %s', name, rules)
        rules = resources.YaraRuleset(dict(name=name, description=description, yara=rules, community=self.community), api=self)
        return self._single(resources.YaraRuleset.create(self, yara=rules.yara, name=rules.name, description=rules.description))

    def ruleset_get(self, ruleset_id=None):
        """
        Retrieve a YaraRuleset from the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        logger.info('Get ruleset %s', ruleset_id)
        return self._single(resources.YaraRuleset.get(self, id=ruleset_id, community=self.community))

    def ruleset_update(self, ruleset_id, name=None, rules=None, description=None):
        """
        Update an existing YaraRuleset in the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :param name: New name of the ruleset
        :param rules: New yara rules as a string
        :param description: New description of the ruleset
        :return: The updated YaraRuleset resource
        """
        logger.info('Update ruleset %s', ruleset_id)
        return self._single(resources.YaraRuleset.update(self, id=ruleset_id, name=name, yara=rules, description=description, community=self.community))

    def ruleset_delete(self, ruleset_id):
        """
        Delete a YaraRuleset from the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        logger.info('Delete ruleset %s', ruleset_id)
        return self._single(resources.YaraRuleset.delete(self, id=ruleset_id, community=self.community))

    def ruleset_list(self):
        """
        List all YaraRulesets for the current account.
        :return: A generator of YaraRuleset resources
        """
        logger.info('List rulesets')
        return self._paginate(resources.YaraRuleset.list(self, community=self.community))

    def tag_link_get(self, sha256):
        """
        Fetch the Tags and Families associated with the given sha256.

        :param sha256: The sha256 of the artifact.
        :return: A TagLink resource
        """
        logger.info('Get tag link %s', sha256)
        return self._single(resources.TagLink.get(self, hash=sha256))

    def tag_link_update(self, sha256, tags=None, families=None, emerging=None, remove=False):
        """
        Update a TagLink with the given type or value by its id.
        :param sha256: The sha256 of the artifact.
        :param tags: A list of tags to be added or removed.
        :param families: A list of families to be added or removed.
        :param remove: A flag indicating if we should remove the provided tags/families.
        :return: A TagLink resource
        """
        logger.info('Update tag link %s', sha256)
        return self._single(resources.TagLink.update(self, hash=sha256, tags=tags, families=families,
                                        emerging=emerging, remove=remove))

    def tag_link_list(self, tags=None, families=None, or_tags=None, or_families=None):
        """
        Fetch all existing TagLinks for the provided tags.
        :param tags: A list of tags that must be associated with the TagLinks listed.
        :param families: A list of families that must be associated with the TagLinks listed.
        :param or_tags: A list of tags where the TagLinks must be associated with at least one.
        :param or_families: A list of families where the TagLinks must be associated with at least one.
        :return: A TagLink resource
        """
        logger.info('List tag links')
        return self._single(resources.TagLink.list(self, tags=tags, families=families,
                                      or_tags=or_tags, or_families=or_families))

    def tag_create(self, name):
        """
        Create a Tag.
        :param name: The tag we want to create.
        :return: A Tag resource
        """
        logger.info('Create tag %s', name)
        return self._single(resources.Tag.create(self, name=name))

    def tag_get(self, name):
        """
        Fetch a Tag.
        :param name: The tag we want to fetch.
        :return: A Tag resource
        """
        logger.info('Get tag %s', name)
        return self._single(resources.Tag.get(self, name=name))

    def tag_delete(self, name):
        """
        Delete a Tag.
        :param name: The tag we want to delete.
        :return: A Tag resource
        """
        logger.info('Delete tag %s', name)
        return self._single(resources.Tag.delete(self, name=name))

    def tag_list(self):
        """
        Fetch all existing Tags.
        :return: A generator of Tag resources
        """
        logger.info('List tags')
        return self._paginate(resources.Tag.list(self))

    def family_create(self, name):
        """
        Create a Family.
        :param name: The family name.
        :return: A MalwareFamily resource
        """
        logger.info('Creating family %s', name)
        return self._single(resources.MalwareFamily.create(self, name=name))

    def family_get(self, name):
        """
        Fetch a Family.
        :param name: The family name.
        :return: A MalwareFamily resource
        """
        logger.info('Getting family %s', name)
        return self._single(resources.MalwareFamily.get(self, name=name))

    def family_delete(self, name):
        """
        Delete a Family.
        :param name: The family name.
        :return: A MalwareFamily resource
        """
        logger.info('Deleting family %s', name)
        return self._single(resources.MalwareFamily.delete(self, name=name))

    def family_update(self, family_name, emerging=True):
        """
        Update the Family emerging status.
        :param family_name: The family name.
        :param emerging: A flag indicating if the family should be marked as emerging at this point in time.
        :return: A MalwareFamily resource
        """
        logger.info('Updating family %s', family_name)
        return self._single(resources.MalwareFamily.update(self, name=family_name, emerging=emerging))

    def family_list(self):
        """
        Fetch all existing Families
        :return: A generator of MalwareFamily resources
        """
        logger.info('Listing families')
        return self._paginate(resources.MalwareFamily.list(self))

    def assertions_create(self, engine_id, date_start, date_end):
        logger.info('Create assertions %s %s %s', engine_id, date_start, date_end)
        return self._single(resources.AssertionsJob.create(self,
                                              engine_id=engine_id,
                                              date_start=date_start,
                                              date_end=date_end))

    def assertions_get(self, assertions_id):
        logger.info('Get assertions %s', assertions_id)
        return self._single(resources.AssertionsJob.get(self, id=assertions_id))

    def assertions_delete(self, assertions_id):
        logger.info('Delete assertions %s', assertions_id)
        return self._single(resources.AssertionsJob.delete(self, id=assertions_id))

    def assertions_list(self, engine_id):
        logger.info('Get all assertions bundles for the engine %s', engine_id)
        return self._paginate(resources.AssertionsJob.list(self, engine_id=engine_id))

    def votes_create(self, engine_id, date_start, date_end):
        logger.info('Create votes %s %s %s', engine_id, date_start, date_end)
        return self._single(resources.VotesJob.create(self,
                                         engine_id=engine_id,
                                         date_start=date_start,
                                         date_end=date_end))

    def votes_get(self, votes_id):
        logger.info('Get votes %s', votes_id)
        return self._single(resources.VotesJob.get(self, id=votes_id))

    def votes_delete(self, votes_id):
        logger.info('Delete votes %s', votes_id)
        return self._single(resources.VotesJob.delete(self, id=votes_id))

    def votes_list(self, engine_id):
        logger.info('Get all votes bundles for the engine %s', engine_id)
        return self._paginate(resources.VotesJob.list(self, engine_id=engine_id))

    def download(self, out_dir, hash_, hash_type=None):
        """
        Grab the data of an artifact identified by hash and write the data to a file in the provided directory
        under a file named after the hash_.
        :param out_dir: Destination directory to download the file.
        :param hash_: The hash we should use to lookup the artifact to download.
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading %s into %s', hash_, out_dir)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        artifact = self._single(resources.LocalArtifact.download(self, hash_.hash, hash_.hash_type, folder=out_dir))
        artifact.handle.close()

        return artifact

    def download_id(self, out_dir, instance_id):
        """
        Grab the data of an artifact identified by hash and write the data to a file in the provided directory
        under a file named after the hash_.
        :param out_dir: Destination directory to download the file.
        :param instance_id: The instance id we should use to lookup the artifact to download.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading %s into %s', instance_id, out_dir)
        artifact = self._single(resources.LocalArtifact.download_id(self, instance_id, folder=out_dir))
        artifact.handle.close()

        return artifact

    def download_sandbox_artifact(self, out_dir, sandbox_task_id, instance_id):
        """
        Grab the data of a sandbox artifact identified by sandbox task id and instance id,
        and write the data to a file in the provided directory under a file named after the sandbox artifact.
        :param out_dir: Destination directory to download the file.
        :param sandbox_task_id: The sandbox task id we should use to lookup the artifact to download.
        :param instance_id: The instance id we should use to lookup the artifact to download.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading sandbox artifact %s %s', sandbox_task_id, instance_id)
        sandbox_artifact = self._single(resources.LocalArtifact.download_sandbox_artifact(
            self, sandbox_task_id, instance_id, folder=out_dir))
        sandbox_artifact.handle.close()

        return sandbox_artifact

    def sandbox(self, instance_id, provider_slug, vm_slug, network_enabled):
        logger.info(
            'Sandboxing %s in provider %s vm %s internet %s', instance_id, provider_slug, vm_slug, network_enabled)
        return self._single(resources.SandboxTask.create(self, artifact_id=instance_id, provider_slug=provider_slug, vm_slug=vm_slug,
                                            network_enabled=network_enabled))

    def sandbox_task_status(self, sandbox_task_id):
        """
        Check the status of a sandbox task.
        """
        logger.info('Checking the status of sandbox task %s', sandbox_task_id)
        return self._single(resources.SandboxTask.get(self, sandbox_task_id=sandbox_task_id))

    def sandbox_task_latest(self, sha256, sandbox):
        """
        Check the latest status of a sandbox task.
        """
        logger.info('Checking the sandbox task for %s', sha256)
        return self._single(resources.SandboxTask.latest(self, sha256=sha256, sandbox=sandbox))

    def sandbox_my_tasks_list(self, **kwargs):
        """
        Check the latest status of a sandbox task.
        """
        logger.info('Checking the latest tasks created by my account')
        return self._paginate(resources.SandboxTask.my_tasks(self, **kwargs))

    def sandbox_task_list(self, sha256, **kwargs):
        """
        Check the list of a sandbox tasks.
        """
        logger.info('Checking the sandbox tasks for %s', sha256)
        return self._paginate(resources.SandboxTask.list(self, sha256=sha256, **kwargs))

    def download_archive(self, out_dir, s3_path):
        """
        Grab the data in the s3 path provided in the stream() method, and write the contents
        in the provided directory.
        :param out_dir: Destination directory to download the file.
        :param s3_path: Target S3 object to download.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading %s into %s', s3_path, out_dir)
        artifact = self._single(resources.LocalArtifact.download_archive(self, s3_path, folder=out_dir))
        artifact.handle.close()

        return artifact

    def download_to_handle(self, hash_, fh, hash_type=None):
        """
        Grab the data of artifact identified by hash, and write the data to a file handle
        :param hash_: The hash we should use to lookup the artifact to download.
        :param fh: A file-like object which we are going to write the contents of the artifact to.
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A LocalHandle resource
        """
        logger.info('Downloading %s into handle', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self._single(resources.LocalArtifact.download(self, hash_.hash, hash_.hash_type, handle=fh))

    def stream(self, since=settings.MAX_SINCE_TIME_STREAM):
        """
        Access the stream of artifacts (ask info@polyswarm.io about access)

        :param since: Fetch results from the last "since" minutes (up to 2 days)
        :return: Generator of ArtifactArchive resources
        """
        logger.info('Streaming since %s', since)
        return self._paginate(resources.ArtifactArchive.get(self, since=since))

    def rerun_metadata(self, hashes, analyses=None, skip_es=None):
        logger.info('Rerunning metadata for hashes %s', hashes)
        return self._single(resources.ArtifactInstance.metadata_rerun(self, hashes, analyses=analyses, skip_es=skip_es))

    def tool_metadata_create(self, instance_id, tool, tool_metadata):
        logger.info('Create tool metadata %s %s %s', instance_id, tool, tool_metadata)
        return self._single(resources.ToolMetadata.create(
            self, instance_id=instance_id, tool=tool, tool_metadata=tool_metadata))

    def tool_metadata_list(self, instance_id):
        logger.info('List tool metadata')
        return self._paginate(resources.ToolMetadata.list(self, instance_id=instance_id))

    def event_list(self, **kwargs):
        logger.info('List events')
        return self._paginate(resources.Events.list(self, **kwargs))

    def sample(self, sha256, artifact_instance_id=None, sandbox_task_id_cape=None,
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
        return self._single(resources.Sample.create(
            self,
            endpoint_fmt={'sha256': sha256},
            community=self.community,
            artifact_instance_id=artifact_instance_id,
            sandbox_task_id_cape=sandbox_task_id_cape,
            sandbox_task_id_triage=sandbox_task_id_triage,
            artifact_metadata_id=artifact_metadata_id,
            llm_report_id=llm_report_id,
        ))

    def sample_bundle_task_create(self, instance_ids, preserve_filenames=False, filename=None, **kwargs):
        """
        Create a task that creates a zip of sample/s
        """
        logger.info('Create zip archive task')
        task = self._single(resources.BundleTask.create(self,
                                              instance_ids=instance_ids,
                                              filename=filename,
                                              preserve_filenames=preserve_filenames,
                                              community=self.community,
                                              **kwargs))
        return task

    def sample_bundle_task_get(self, id, **kwargs):
        return self._single(resources.BundleTask.get(self, id=id, community=self.community, **kwargs))

    def sample_bundle_download(self, id, folder):
        task = self._single(resources.BundleTask.get(self, id=id, community=self.community))
        if task.state == 'PENDING':
            raise exceptions.InvalidValueException('Bundle is in PENDING state, wait for completion first')
        if task.state == 'FAILED':
            raise exceptions.InvalidValueException("Bundle is in FAILED state, won't be generated")
        result = self._single(task.download_zip(folder=folder))
        result.handle.close()
        return result

    def llm_report_create(self, instance_id=None, cape_sandbox_task_id=None, triage_sandbox_task_id=None):
        """
        Create a llm generated report, from the scan and/or sandbox results.
        """
        if not instance_id and not cape_sandbox_task_id and not triage_sandbox_task_id:
            raise exceptions.InvalidValueException('Either instance_id or sandbox_task_id must be provided')
        report_task = self._single(resources.ReportLLMPostProcessing.create(self,
                                                               instance_id=instance_id,
                                                               cape_sandbox_task_id=cape_sandbox_task_id,
                                                               triage_sandbox_task_id=triage_sandbox_task_id))
        return report_task

    def llm_report_get(self, report_task_id):
        task = self._single(resources.ReportLLMPostProcessing.get(self, id=report_task_id, community=self.community))
        return task

    def llm_report_download(self, report_task_id, folder):
        task = self._single(resources.ReportLLMPostProcessing.get(self, id=report_task_id, community=self.community))
        result = self._single(task.download_report(folder=folder))
        result.handle.close()
        return result

    def report_create(self,
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
        report = self._single(resources.ReportTask.create(self,
                                             type=type,
                                             format=format,
                                             instance_id=instance_id,
                                             sandbox_task_id=sandbox_task_id,
                                             template_id=template_id,
                                             template_metadata=template_metadata,
                                             community=self.community,
                                             **kwargs))
        return report

    def report_get(self, id, **kwargs):
        return self._single(resources.ReportTask.get(self, id=id, community=self.community, **kwargs))

    def report_download(self, report_id, folder):
        report = self.report_get(id=report_id)
        if report.state == 'PENDING':
            raise exceptions.InvalidValueException('Report is in PENDING state, wait for completion first')
        if report.state == 'FAILED':
            raise exceptions.InvalidValueException("Report is in FAILED state, won't be generated")
        result = self._single(report.download_report(folder=folder))
        result.handle.close()
        return result

    def report_template_logo_download(self, template_id, folder):
        report = self._single(resources.ReportTemplate.get(self, id=template_id))
        result = self._single(report.download_logo(folder))
        result.handle.close()
        return result

    def report_template_logo_delete(self, template_id):
        report = self._single(resources.ReportTemplate.get(self, id=template_id))
        result = self._single(report.delete_logo())
        return result

    def report_template_logo_upload(self, template_id, logo_file, content_type=None, content_tpe=None):
        if content_tpe is not None and content_type is None:
            content_type = content_tpe
        if content_type is None:
            raise exceptions.InvalidValueException("missing required argument: 'content_type'")
        report = self._single(resources.ReportTemplate.get(self, id=template_id))
        result = self._single(report.upload_logo(logo_file, content_type))
        return result

    def report_template_create(self,
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
        return self._single(resources.ReportTemplate.create(self,
                                               template_name=template_name,
                                               is_default=is_default,
                                               primary_color=primary_color,
                                               footer_text=footer_text,
                                               last_page_text=last_page_text,
                                               includes=includes,
                                               **kwargs))

    def report_template_update(self,
                               template_id,
                               template_name=None,
                               is_default=None,
                               primary_color=None,
                               footer_text=None,
                               last_page_text=None,
                               includes=None,
                               **kwargs):
        return self._single(resources.ReportTemplate.update(self,
                                               id=template_id,
                                               template_name=template_name,
                                               is_default=is_default,
                                               primary_color=primary_color,
                                               footer_text=footer_text,
                                               last_page_text=last_page_text,
                                               includes=includes,
                                               **kwargs))

    def report_template_get(self, template_id):
        return self._single(resources.ReportTemplate.get(self, id=template_id))

    def report_template_delete(self, template_id):
        return self._single(resources.ReportTemplate.delete(self, id=template_id))

    def report_template_list(self, is_default=None, **kwargs):
        return self._paginate(resources.ReportTemplate.list(self, is_default=is_default, **kwargs))

    def account_whois(self, **kwargs):
        return self._single(resources.WhoIs.get(self, **kwargs))

    def account_features(self, **kwargs):
        return self._single(resources.AccountFeatures.get(self, **kwargs))

    def prompt_config_create(self, name, system_prompt, is_active=False, cape_only_prompt=None, 
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
        return self._single(resources.LLMPromptConfig.create(self,
                                                name=name,
                                                system_prompt=system_prompt,
                                                is_active=is_active,
                                                cape_only_prompt=cape_only_prompt,
                                                triage_only_prompt=triage_only_prompt,
                                                scan_only_prompt=scan_only_prompt))

    def prompt_config_get(self, prompt_config_id):
        """
        Get an LLM prompt configuration by ID.
        :param prompt_config_id: The ID of the prompt configuration
        :return: An LLMPromptConfig resource
        """
        logger.info('Getting prompt config %s', prompt_config_id)
        return self._single(resources.LLMPromptConfig.get(self, id=prompt_config_id))

    def prompt_config_update(self, prompt_config_id, name=None, system_prompt=None, is_active=None,
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
        return self._single(resources.LLMPromptConfig.update(self,
                                                id=prompt_config_id,
                                                name=name,
                                                system_prompt=system_prompt,
                                                is_active=is_active,
                                                cape_only_prompt=cape_only_prompt,
                                                triage_only_prompt=triage_only_prompt,
                                                scan_only_prompt=scan_only_prompt))

    def prompt_config_list(self, **kwargs):
        """
        List all LLM prompt configurations.
        :return: A generator of LLMPromptConfig resources
        """
        logger.info('Listing prompt configs')
        return self._paginate(resources.LLMPromptConfig.list(self, **kwargs))

    def notification_webhook_create(self, webhook_uri, secret, status='enabled', events=None):
        """
        Create a new webhook for notifications from Polyswarm events.
        
        :param webhook_uri: The URI where webhook events should be sent
        :param secret: The secret key used for HMAC signature verification
        :param status: Webhook status ('enabled' or 'disabled')
        :param events: Optional set specifying which events to subscribe to. Available options: sandbox_done
        :return: A Webhook resource
        """
        logger.info('Creating webhook %s', webhook_uri)
        return self._single(resources.Webhook.create(self,
                                       webhook_uri=webhook_uri,
                                       secret=secret,
                                       status=status,
                                       events=events))

    def notification_webhook_get(self, webhook_id):
        """
        Get a notification webhook by ID.
        :param webhook_id: The ID of the webhook
        :return: A Webhook resource
        """
        logger.info('Getting webhook %s', webhook_id)
        return self._single(resources.Webhook.get(self, id=webhook_id))

    def notification_webhook_update(self, webhook_id, webhook_uri=None, secret=None, status=None,
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
        return self._single(resources.Webhook.update(self,
                                        id=webhook_id,
                                        webhook_uri=webhook_uri,
                                        secret=secret,
                                        status=status,
                                        events=events))

    def notification_webhook_delete(self, webhook_id):
        """
        Delete a notification webhook.
        :param webhook_id: The ID of the webhook to delete
        :return: A success message
        """
        logger.info('Deleting webhook %s', webhook_id)
        return self._single(resources.Webhook.delete(self, id=webhook_id))

    def notification_webhook_list(self):
        """
        List all notification webhooks for the current account.
        :return: A generator of Webhook resources
        """
        logger.info('Listing webhooks')
        return self._paginate(resources.Webhook.list(self))

    def notification_webhook_test(self, webhook_id):
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
        return self._single(resources.Webhook.test(self, webhook_id=webhook_id))
