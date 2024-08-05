import io
import logging
import time

import polyswarm_api.core

from urllib.parse import urlparse

from polyswarm_api import exceptions, resources, settings

logger = logging.getLogger(__name__)


class PolyswarmAPI:
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri=None, community=None, timeout=None, verify=True, **kwargs):
        """
        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param community: Community to scan against.
        :param timeout: Maximum time to wait for an http response on every request.
        :param verify: Boolean, whether or not to verify TLS connections.
        :param **kwargs: Keyword args to pass to requests.Session
        """
        key_masked = (key[0:4] if key and len(key) > 16 else '') + '******'
        logger.info('Creating PolyswarmAPI instance: api_key: %s, api_uri: %s, community: %s', key_masked, uri, community)
        self.uri = uri or settings.DEFAULT_GLOBAL_API
        self.community = community or settings.DEFAULT_COMMUNITY
        self.timeout = timeout or settings.DEFAULT_HTTP_TIMEOUT
        self.session = polyswarm_api.core.PolyswarmSession(key, retries=settings.DEFAULT_RETRIES, verify=verify, **kwargs)
        self._engines = None

    def __repr__(self):
        clsname = f'{self.__class__.__module__}.{self.__class__.__name__}'
        attrs = f'uri={self.uri!r}, community={self.community!r}, timeout={self.timeout!r}'
        return f'<{clsname}({attrs}) at 0x{id(self):x}>'

    @property
    def engines(self):
        if not self._engines:
            self.refresh_engine_cache()

        return self._engines

    def refresh_engine_cache(self):
        """
        Refresh the cached engine listing
        """
        engines = list(resources.Engine.list(self).result())
        if not engines:
            raise exceptions.InvalidValueException("Received empty engines listing")
        self._engines = engines

    def wait_for(self, scan, timeout=settings.DEFAULT_SCAN_TIMEOUT):
        """
        Wait for a Scan to scan successfully

        :param scan: Scan id to wait for
        :param timeout: Maximum time in seconds to wait before raising a TimeoutException
        :return: The ArtifactInstance resource waited on
        """
        logger.info('Waiting for %s', int(scan))
        start = time.time()
        while True:
            scan_result = self.lookup(scan)
            if scan_result.failed or scan_result.window_closed:
                return scan_result
            elif -1 < timeout < time.time() - start:
                raise exceptions.TimeoutException(
                    f'Timed out waiting for scan {scan} to finish. Please try again.')
            else:
                time.sleep(settings.POLL_FREQUENCY)

    def exists(self, hash_, hash_type=None):
        """
        Search for the latest scans matching the given hash and hash_type.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A boolean if the instance exists for search.
        """
        logger.info('Exists for hash %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        result = resources.ArtifactInstance.exists_hash(self, hash_.hash, hash_.hash_type).result()
        if str(result) == '200':
            return True
        else:
            return False

    def search(self, hash_, hash_type=None):
        """
        Search for the latest scans matching the given hash and hash_type.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for hash %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return resources.ArtifactInstance.search_hash(self, hash_.hash, hash_.hash_type).result()

    def search_url(self, url):
        """
        Search for the latest scan matching the given url.

        :param url: A url to be searched by exact match
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for url %s', url)
        return resources.ArtifactInstance.search_url(self, url).result()

    def search_scans(self, hash_):
        """
        Search for all scans ever made matching the given sha256.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for scans %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type='sha256')
        return resources.ArtifactInstance.list_scans(self, hash_.hash).result()

    def metadata_mapping(self):
        logger.info('Retrieving the metadata mapping')
        return resources.MetadataMapping.get(self).result()

    def search_by_metadata(self, query, include=None, exclude=None, ips=None, urls=None, domains=None):
        """
        Search artifacts by metadata

        :param query: A query string
        :param include: A list of fields to be included in the result (.* wildcards are accepted)
        :param exclude: A list of fields to be excluded from the result (.* wildcards are accepted)
        :return: Generator of ArtifactInstance resources
        """
        logger.info('Searching for metadata %s', query)
        return resources.Metadata.get(self, query=query, community=self.community, include=include, exclude=exclude, ips=ips, urls=urls, domains=domains).result()

    def iocs_by_hash(self, hash_type, hash_value, hide_known_good=False, beta=False):
        """
        Retrieve IOCs by artifact hash

        :param hash_type: Hash type of the provided hash_
        :param hash_value: A list of fields to be included in the result (.* wildcards are accepted)
        :return: Generator of IOC resources
        """
        logger.info('Getting IOCs by hash %s:%s', hash_type, hash_value)
        return resources.IOC.iocs_by_hash(self, hash_value, hash_type, hide_known_good=hide_known_good, beta=beta).result()

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
        return resources.IOC.ioc_search(self, ip=ip, domain=domain, ttp=ttp, imphash=imphash).result()

    def check_known_hosts(self, ips=[], domains=[]):
        """
        Check if ip addresses or domains are known.

        :param ips
        :param domains
        :return: Generator of IOC resources
        """
        logger.info('Checking known hosts ips: %s, domains: %s', ips, domains)
        return resources.IOC.check_known_hosts(self, ips, domains).result()

    def add_known_good_host(self, type, source, host):
        """
        Add a known good ip or domain.

        :param type
        :param source
        :param host
        :return: IOC resource
        """
        logger.info('Creating known good ioc %s %s %s', type, host, source)
        return resources.IOC.create_known_good(self, type, host, source).result()

    def add_known_bad_host(self, type, source, host):
        """
        Add a known bad ip or domain.

        :param type
        :param source
        :param host
        :return: IOC resource
        """
        logger.info('Creating known bad ioc %s %s %s', type, host, source)
        return resources.IOC.create_known_bad(self, type, host, source).result()

    def update_known_good_host(self, id, type, source, host, good):
        """
        Update a known ip or domain.

        :param type
        :param source
        :param host
        :return: IOC resource
        """
        logger.info('Updating known good ioc %s %s %s %s', id, type, host, source)
        return resources.IOC.update_known_good(self, id, type, host, source, good).result()

    def delete_known_good_host(self, id):
        logger.info('Deleting known good ioc %s', id)
        return resources.IOC.delete_known_good(self, id).result()

    def submit(
            self,
            artifact,
            artifact_type=resources.ArtifactType.FILE,
            artifact_name=None,
            scan_config=None,
            preprocessing=None,
    ):
        """
        Submit artifacts to polyswarm

        :param artifact: A file-like, path to file, url or LocalArtifact instance
        :param artifact_type: The ArtifactType or strings containing "file" or "url"
        :param artifact_name: An appropriate filename for the Artifact
        :param scan_config: The scan configuration to be used, e.g.: "default", "more-time", "most-time"
        :param preprocessing: Preprocessing settings to be applied to the artifact, None means no preprocessing,
                              otherwise a dict with the following attributes can be passed:
                              - type (string): either "zip" or "qrcode", the first mean the file is a zip that
                                the server has to decompress to then scan the content (only one file inside allowed).
                                "qrcode" means the file is a QR Code image with a URL as payload, and you want
                                to scan the URL, not the actual file (artifact_type has to be "URL").
                              - password (string, optional): will use this password to decompress the zip file.
        :return: An ArtifactInstance resource
        """
        logger.info('Submitting artifact of type %s', artifact_type)
        artifact_type = resources.ArtifactType.parse(artifact_type)
        if isinstance(artifact, io.IOBase):
            artifact = resources.LocalArtifact.from_handle(self, artifact, artifact_name=artifact_name or '',
                                                           artifact_type=artifact_type)
        elif isinstance(artifact, str):
            if artifact_type == resources.ArtifactType.FILE:
                artifact = resources.LocalArtifact.from_path(self, artifact, artifact_type=artifact_type,
                                                             artifact_name=artifact_name)
            elif artifact_type == resources.ArtifactType.URL:
                if preprocessing and preprocessing['type'] == 'qrcode':
                    artifact = resources.LocalArtifact.from_path(self,
                                                                 artifact,
                                                                 artifact_type=artifact_type,
                                                                 artifact_name=artifact_name)
                else:
                    artifact = resources.LocalArtifact.from_content(self,
                                                                    artifact,
                                                                    artifact_name=artifact_name or artifact,
                                                                    artifact_type=artifact_type)
        if artifact_type == resources.ArtifactType.URL:
            scan_config = scan_config or 'more-time'
        if isinstance(artifact, resources.LocalArtifact):
            instance = resources.ArtifactInstance.create(
                self,
                artifact_name=artifact.artifact_name,
                artifact_type=artifact.artifact_type.name,
                scan_config=scan_config,
                community=self.community,
                preprocessing=preprocessing,
            ).result()
            instance.upload_file(artifact)
            return resources.ArtifactInstance.update(self, id=instance.id, community=self.community).result()
        else:
            raise exceptions.InvalidValueException('Artifacts should be a path to a file or a LocalArtifact instance')

    def lookup(self, scan):
        """
        Lookup a scan by Scan id.

        :param scan: The Scan UUID to lookup
        :return: An ArtifactInstance resource
        """
        logger.info('Lookup scan %s', int(scan))
        return resources.ArtifactInstance.lookup_uuid(self, scan).result()

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
        return resources.ArtifactInstance.rescan(self, hash_.hash, hash_.hash_type, scan_config=scan_config).result()

    def rescan_id(self, scan, scan_config=None):
        """
        Re-execute a new scan based on an existing scan.

        :param scan: Id of the existing scan
        :param scan_config: The scan configuration to be used, e.g.: "default", "more-time", "most-time"
        :return: A ArtifactInstance resource
        """
        logger.info('Rescan id %s', int(scan))
        return resources.ArtifactInstance.rescan_id(self, scan, scan_config=scan_config).result()

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
        return resources.LiveYaraRuleset.create(self, rule_id=rule_id).result()

    def live_stop(self, rule_id):
        """
        Stop a live hunt.

        :param rule_id: Yara ruleset id
        :return: The ruleset without an associate live hunt
        """
        logger.info('Delete live hunt for rule id %s', rule_id)
        return resources.LiveYaraRuleset.delete(self, rule_id=rule_id).result()

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
        return resources.LiveHuntResult.list(
            self, since=since, rule_name=rule_name, family=family,
            polyscore_lower=polyscore_lower, polyscore_upper=polyscore_upper,
            community=community or self.community).result()

    def live_feed_delete(self, result_ids):
        """
        Delete live feed results

        :param result_ids: Live Feed Result IDs
        :return: The deleted LiveHuntResult resources
        """
        logger.info('Delete live results: %s', result_ids)
        try:
            return resources.LiveHuntResultList.delete(self, result_ids=result_ids).result()
        except exceptions.NoResultsException:
            return None

    def live_result(self, result_id):
        """
        Get yara ruleset for the live hunt result

        :param result_id: Live result id
        :return: Generator of HuntResult resources
        """
        return resources.LiveHuntResult.get(self, id=result_id).result()

    def historical_create(self, rule=None, ruleset_name=None):
        """
        Run a new historical hunt.

        :param rule: YaraRuleset object or string containing YARA rules to install
        :param ruleset_name: Name of the ruleset.
        :return: The created Hunt resource
        """
        logger.info('Create historical hunt %s', rule)
        rule, rule_id = self._parse_rule(rule)
        return resources.HistoricalHunt.create(self, yara=rule.yara if rule else None, rule_id=rule_id,
                                               ruleset_name=ruleset_name, community=self.community).result()

    def historical_get(self, hunt=None):
        """
        Get a historical hunt.

        :param hunt: Hunt ID
        :return: The Hunt resource
        """
        logger.info('Get historical hunt %s', hunt)
        return resources.HistoricalHunt.get(self, id=hunt, community=self.community).result()

    def historical_update(self, hunt):
        """
        Cancel a historical hunt
        :param hunt: The historical hunt id
        :return: The deleted HistoricalHunt resource
        """
        logger.info('Deleting historical hunt %s', hunt)
        return resources.HistoricalHunt.update(self, id=hunt, community=self.community).result()

    def historical_delete(self, hunt):
        """
        Delete a historical hunts.

        :param hunt: Hunt ID
        :return: The deleted Hunt resource
        """
        logger.info('Delete historical hunt %s', hunt)
        return resources.HistoricalHunt.delete(self, id=hunt, community=self.community).result()

    def historical_list(self, since=None):
        """
        List all historical hunts

        :return: Generator of Hunt resources
        """
        logger.info('List historical hunts since: %s', since)
        return resources.HistoricalHunt.list(self, since=since, community=self.community).result()

    def historical_result(self, result_id):
        """
        Get historical hunt result

        :param result_id: Historical result id
        :return: HistoricalHuntResult resource
        """
        return resources.HistoricalHuntResult.get(self, id=result_id, community=self.community).result()

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
        return resources.HistoricalHuntResultList.get(
            self, id=hunt, rule_name=rule_name, family=family, community=community or self.community,
            polyscore_lower=polyscore_lower, polyscore_upper=polyscore_upper).result()

    def historical_results_delete(self, result_ids):
        """
        Delete historical scan results

        :param result_ids: Historical Hunt Result IDs
        :return: The deleted HuntResult resources
        """
        logger.info('Delete historical results: %s', result_ids)
        return resources.HistoricalHuntResultList.delete(self, result_ids=result_ids, community=self.community).result()

    def historical_delete_list(self, historical_ids):
        """
        Delete a historical hunts.

        :param historical_ids: Historical Hunt IDs
        :return: The deleted Hunt resource
        """
        logger.info('Delete historical hunts %s', historical_ids)
        return resources.HistoricalHuntList.delete(self, historical_ids=historical_ids, community=self.community).result()

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
        return resources.YaraRuleset.create(self, yara=rules.yara, name=rules.name, description=rules.description).result()

    def ruleset_get(self, ruleset_id=None):
        """
        Retrieve a YaraRuleset from the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        logger.info('Get ruleset %s', ruleset_id)
        return resources.YaraRuleset.get(self, id=ruleset_id, community=self.community).result()

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
        return resources.YaraRuleset.update(self, id=ruleset_id, name=name, yara=rules, description=description, community=self.community).result()

    def ruleset_delete(self, ruleset_id):
        """
        Delete a YaraRuleset from the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        logger.info('Delete ruleset %s', ruleset_id)
        return resources.YaraRuleset.delete(self, id=ruleset_id, community=self.community).result()

    def ruleset_list(self):
        """
        List all YaraRulesets for the current account.
        :return: A generator of YaraRuleset resources
        """
        logger.info('List rulesets')
        return resources.YaraRuleset.list(self, community=self.community).result()

    def tag_link_get(self, sha256):
        """
        Fetch the Tags and Families associated with the given sha256.

        :param sha256: The sha256 of the artifact.
        :return: A TagLink resource
        """
        logger.info('Get tag link %s', sha256)
        return resources.TagLink.get(self, hash=sha256).result()

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
        return resources.TagLink.update(self, hash=sha256, tags=tags, families=families,
                                        emerging=emerging, remove=remove).result()

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
        return resources.TagLink.list(self, tags=tags, families=families,
                                      or_tags=or_tags, or_families=or_families).result()

    def tag_create(self, name):
        """
        Create a Tag.
        :param name: The tag we want to create.
        :return: A Tag resource
        """
        logger.info('Create tag %s', name)
        return resources.Tag.create(self, name=name).result()

    def tag_get(self, name):
        """
        Fetch a Tag.
        :param name: The tag we want to fetch.
        :return: A Tag resource
        """
        logger.info('Get tag %s', name)
        return resources.Tag.get(self, name=name).result()

    def tag_delete(self, name):
        """
        Delete a Tag.
        :param name: The tag we want to delete.
        :return: A Tag resource
        """
        logger.info('Delete tag %s', name)
        return resources.Tag.delete(self, name=name).result()

    def tag_list(self):
        """
        Fetch all existing Tags.
        :return: A generator of Tag resources
        """
        logger.info('List tags')
        return resources.Tag.list(self).result()

    def family_create(self, name):
        """
        Create a Family.
        :param name: The family name.
        :return: A MalwareFamily resource
        """
        logger.info('Creating family %s', name)
        return resources.MalwareFamily.create(self, name=name).result()

    def family_get(self, name):
        """
        Fetch a Family.
        :param name: The family name.
        :return: A MalwareFamily resource
        """
        logger.info('Getting family %s', name)
        return resources.MalwareFamily.get(self, name=name).result()

    def family_delete(self, name):
        """
        Delete a Family.
        :param name: The family name.
        :return: A MalwareFamily resource
        """
        logger.info('Deleting family %s', name)
        return resources.MalwareFamily.delete(self, name=name).result()

    def family_update(self, family_name, emerging=True):
        """
        Update the Family emerging status.
        :param family_name: The family name.
        :param emerging: A flag indicating if the family should be marked as emerging at this point in time.
        :return: A MalwareFamily resource
        """
        logger.info('Updating family %s', family_name)
        return resources.MalwareFamily.update(self, name=family_name, emerging=emerging).result()

    def family_list(self):
        """
        Fetch all existing Families
        :return: A generator of MalwareFamily resources
        """
        logger.info('Listing families')
        return resources.MalwareFamily.list(self).result()

    def assertions_create(self, engine_id, date_start, date_end):
        logger.info('Create assertions %s %s %s', engine_id, date_start, date_end)
        return resources.AssertionsJob.create(self,
                                              engine_id=engine_id,
                                              date_start=date_start,
                                              date_end=date_end).result()

    def assertions_get(self, assertions_id):
        logger.info('Get assertions %s', assertions_id)
        return resources.AssertionsJob.get(self, id=assertions_id).result()

    def assertions_delete(self, assertions_id):
        logger.info('Delete assertions %s', assertions_id)
        return resources.AssertionsJob.delete(self, id=assertions_id).result()

    def assertions_list(self, engine_id):
        logger.info('Get all assertions bundles for the engine %s', engine_id)
        return resources.AssertionsJob.list(self, engine_id=engine_id).result()

    def votes_create(self, engine_id, date_start, date_end):
        logger.info('Create votes %s %s %s', engine_id, date_start, date_end)
        return resources.VotesJob.create(self,
                                         engine_id=engine_id,
                                         date_start=date_start,
                                         date_end=date_end).result()

    def votes_get(self, votes_id):
        logger.info('Get votes %s', votes_id)
        return resources.VotesJob.get(self, id=votes_id).result()

    def votes_delete(self, votes_id):
        logger.info('Delete votes %s', votes_id)
        return resources.VotesJob.delete(self, id=votes_id).result()

    def votes_list(self, engine_id):
        logger.info('Get all votes bundles for the engine %s', engine_id)
        return resources.VotesJob.list(self, engine_id=engine_id).result()

    def download(self, out_dir, hash_, hash_type=None):
        """
        Grab the data of artifact identified by hash, and write the data to a file in the provided directory
        under a file named after the hash_.
        :param out_dir: Destination directory to download the file.
        :param hash_: The hash we should use to lookup the artifact to download.
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading %s into %s', hash_, out_dir)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        artifact = resources.LocalArtifact.download(self, hash_.hash, hash_.hash_type, folder=out_dir).result()
        artifact.handle.close()

        return artifact

    def download_id(self, out_dir, instance_id):
        """
        Grab the data of artifact identified by hash, and write the data to a file in the provided directory
        under a file named after the hash_.
        :param out_dir: Destination directory to download the file.
        :param instance_id: The instance id we should use to lookup the artifact to download.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading %s into %s', instance_id, out_dir)
        artifact = resources.LocalArtifact.download_id(self, instance_id, folder=out_dir).result()
        artifact.handle.close()

        return artifact

    def sandbox(self, instance_id, provider_slug, vm_slug, network_enabled):
        logger.info(
            'Sandboxing %s in provider %s vm %s internet %s', instance_id, provider_slug, vm_slug, network_enabled)
        return resources.SandboxTask.create(self, artifact_id=instance_id, provider_slug=provider_slug, vm_slug=vm_slug,
                                            network_enabled=network_enabled).result()

    def sandbox_file(
            self,
            artifact,
            provider_slug,
            vm_slug,
            artifact_type=resources.ArtifactType.FILE,
            artifact_name=None,
            network_enabled=True,
            preprocessing=None,
    ):
        """
        Submit artifacts to Polyswarm Sandboxing system.

        :param artifact: A file-like, path to file, url or LocalArtifact instance
        :param artifact_name: An appropriate filename for the Artifact
        :artifact_type: the type of artifact to be submitted, default FILE. Use URL type
                        with the preprocessing field to scan URLs inside QR Code images
        :param network_enabled: Whether the VM has to have Internet connection enabled or not.
        :param provider_slug: the slug of the provider that is going to execute the sandboxing, e.g.
                              'cape' or 'triage'.
                              Use `sandbox_providers()` to get the list of providers.
        :param vm_slug: The slug of the virtual machine used for the sandboxing, depending on the
                        VM chosen is the OS and software that is going to host the sandboxing. Each
                        provider (provider_slug) support different VMs, so check with `sandbox_providers()`
                        the list of VMs available.
        :param preprocessing: Preprocessing settings to be applied to the artifact, None means no preprocessing,
                              otherwise a dict with the following attributes can be passed:
                              - type (string): either "zip" or "qrcode", the first mean the file is a zip that
                                the server has to decompress to then scan the content (only one file inside allowed).
                                "qrcode" means the file is a QR Code image with a URL as payload, and you want
                                to scan the URL, not the actual file (artifact_type has to be "URL").
                              - password (string, optional): will use this password to decompress the zip file.
        :return: An ArtifactInstance resource
        """
        logger.info('Sandboxing %s in provider %s vm %s', artifact_type.name.lower(), provider_slug, vm_slug)
        artifact_type = resources.ArtifactType.parse(artifact_type)
        if isinstance(artifact, io.IOBase):
            artifact = resources.LocalArtifact.from_handle(self, artifact, artifact_name=artifact_name or '',
                                                           artifact_type=artifact_type)
        elif isinstance(artifact, str):
            if artifact_type == resources.ArtifactType.FILE:
                artifact = resources.LocalArtifact.from_path(self, artifact, artifact_type=artifact_type,
                                                             artifact_name=artifact_name)
            elif artifact_type == resources.ArtifactType.URL:
                artifact = resources.LocalArtifact.from_content(self, artifact,
                                                                artifact_name=artifact_name or artifact,
                                                                artifact_type=artifact_type)
        if isinstance(artifact, resources.LocalArtifact):
            task = resources.SandboxTask.create_file(
                self,
                artifact_name=artifact.artifact_name,
                artifact_type=artifact.artifact_type.name,
                community=self.community,
                provider_slug=provider_slug,
                vm_slug=vm_slug,
                network_enabled=network_enabled,
                preprocessing=preprocessing,
            ).result()
            task.upload_file(artifact)
            return resources.SandboxTask.update_file(self, id=task.id, community=self.community).result()
        else:
            raise exceptions.InvalidValueException(
                'Artifacts should be a path to a file or a LocalArtifact instance')

    def sandbox_url(self,
                    url,
                    provider_slug,
                    vm_slug,
                    browser=None,
                    artifact=None,
                    artifact_name=None,
                    preprocessing=None):
        """
        Submit URL to Polyswarm Sandboxing system.
        :param url: A string with the URL to be submitted. Set to `None` if the URL is provided
                    through a QR Code image in the artifact param (see artifact and preprocessing params).
        :param provider_slug: the slug of the provider that is going to execute the sandboxing, e.g.
                              'cape' or 'triage'.
                              Use `sandbox_providers()` to get the list of providers.
        :param vm_slug: The slug of the virtual machine used for the sandboxing, depending on the
                        VM chosen is the OS and software that is going to host the sandboxing. Each
                        provider (provider_slug) support different VMs, so check with `sandbox_providers()`
                        the list of VMs available.
        :param browser: browser name, e.g. 'edge' or 'firefox'.
        :param artifact: A file-like, path to file, or LocalArtifact instance (default None). The url
                         param has to be None to use this param. For now QR Code image files
                         are supported
        :param artifact_name: name of the artifact, if None (default) the URL string is used as a name,
                              or the file name if artifact is provided (QR Code image file).
        :param preprocessing: Preprocessing settings to be applied to the artifact, None means no preprocessing,
                              otherwise a dict with the following attributes can be passed:
                              - type (string): only "qrcode" is supported for URL sandboxing:
                                the file is a QR Code image with a URL as payload, and you want
                                to scan the URL, not the actual file. This argument has to be used with the
                                `artifact` param, and `url` set to `None`.
        """
        logger.info('Sandboxing url in provider %s vm %s', provider_slug, vm_slug)
        if artifact and url:
            raise exceptions.InvalidValueException("Cannot use artifact with url param")
        if artifact:
            if not preprocessing or preprocessing.get('type') != 'qrcode':
                raise exceptions.InvalidValueException("Only artifact of type qrcode is supported")
            if isinstance(artifact, str):
                artifact = resources.LocalArtifact.from_path(self,
                                                             artifact,
                                                             artifact_type='URL',
                                                             artifact_name=artifact_name)
            else:
                artifact = resources.LocalArtifact.from_handle(self,
                                                               artifact,
                                                               artifact_name=artifact_name or '',
                                                               artifact_type='URL')
        else:
            artifact_name = url
            artifact = resources.LocalArtifact.from_content(self,
                                                            url,
                                                            artifact_name=artifact_name,
                                                            artifact_type='URL')
        task = resources.SandboxTask.create_file(self,
                                                 artifact_name=artifact_name,
                                                 artifact_type="URL",
                                                 community=self.community,
                                                 provider_slug=provider_slug,
                                                 vm_slug=vm_slug,
                                                 browser=browser,
                                                 preprocessing=preprocessing,
                                                 network_enabled=True).result()
        task.upload_file(artifact)
        return resources.SandboxTask.update_file(self, id=task.id, community=self.community).result()

    def sandbox_providers(self):
        """
        List sandboxes available in polyswarm.
        """
        logger.info('Listing sandbox names')
        return resources.SandboxProvider.list(self)

    def sandbox_task_status(self, sandbox_task_id):
        """
        Check the status of a sandbox task.
        """
        logger.info('Checking the status of sandbox task %s', sandbox_task_id)
        return resources.SandboxTask.get(self, sandbox_task_id=sandbox_task_id).result()

    def sandbox_task_latest(self, sha256, sandbox):
        """
        Check the latest status of a sandbox task.
        """
        logger.info('Checking the sandbox task for %s', sha256)
        return resources.SandboxTask.latest(self, sha256=sha256, sandbox=sandbox).result()

    def sandbox_my_tasks_list(self, **kwargs):
        """
        Check the latest status of a sandbox task.
        """
        logger.info('Checking the latest tasks created by my account')
        return resources.SandboxTask.my_tasks(self, **kwargs).result()

    def sandbox_task_list(self, sha256, **kwargs):
        """
        Check the list of a sandbox tasks.
        """
        logger.info('Checking the sandbox tasks for %s', sha256)
        return resources.SandboxTask.list(self, sha256=sha256, **kwargs).result()

    def download_archive(self, out_dir, s3_path):
        """
        Grab the data in the s3 path provided in the stream() method, and write the contents
        in the provided directory.
        :param out_dir: Destination directory to download the file.
        :param s3_path: Target S3 object to download.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading %s into %s', s3_path, out_dir)
        artifact = resources.LocalArtifact.download_archive(self, s3_path, folder=out_dir).result()
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
        return resources.LocalArtifact.download(self, hash_.hash, hash_.hash_type, handle=fh).result()

    def stream(self, since=settings.MAX_SINCE_TIME_STREAM):
        """
        Access the stream of artifacts (ask info@polyswarm.io about access)

        :param since: Fetch results from the last "since" minutes (up to 2 days)
        :return: Generator of ArtifactArchive resources
        """
        logger.info('Streaming since %s', since)
        return resources.ArtifactArchive.get(self, since=since).result()

    def rerun_metadata(self, hashes, analyses=None, skip_es=None):
        logger.info('Rerunning metadata for hashes %s', hashes)
        return resources.ArtifactInstance.metadata_rerun(self, hashes, analyses=analyses, skip_es=skip_es).result()

    def tool_metadata_create(self, instance_id, tool, tool_metadata):
        logger.info('Create tool metadata %s %s %s', instance_id, tool, tool_metadata)
        return resources.ToolMetadata.create(
            self, instance_id=instance_id, tool=tool, tool_metadata=tool_metadata).result()

    def tool_metadata_list(self, instance_id):
        logger.info('List tool metadata')
        return resources.ToolMetadata.list(self, instance_id=instance_id).result()

    def event_list(self, **kwargs):
        logger.info('List events')
        return resources.Events.list(self, **kwargs).result()

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
        report = resources.ReportTask.create(self,
                                             type=type,
                                             format=format,
                                             instance_id=instance_id,
                                             sandbox_task_id=sandbox_task_id,
                                             template_id=template_id,
                                             template_metadata=template_metadata,
                                             **kwargs).result()
        return report

    def report_get(self, id, **kwargs):
        return resources.ReportTask.get(self, id=id, **kwargs).result()

    def report_download(self, report_id, folder):
        report = resources.ReportTask.get(self, id=report_id).result()
        if report.state == 'PENDING':
            raise exceptions.InvalidValueException('Report is in PENDING state, wait for completion first')
        if report.state == 'FAILED':
            raise exceptions.InvalidValueException("Report is in FAILED state, won't be generated")
        result = report.download_report(folder=folder).result()
        result.handle.close()
        return result

    def report_wait_for(self, report_id, timeout=settings.DEFAULT_REPORT_TIMEOUT):
        """
        Wait for a Report to finish successfully.

        :param report_id: Report id to wait for
        :param timeout: Maximum time in seconds to wait before raising a TimeoutException
        :return: The ReportTask resource waited on, either in 'SUCCEEDED' or 'FAILED' state
        """
        logger.info('Waiting for report %s', report_id)
        start = time.time()
        while True:
            report_result = self.report_get(id=report_id)
            if report_result.state != 'PENDING':
                return report_result
            elif -1 < timeout < time.time() - start:
                raise exceptions.TimeoutException(
                    f'Timed out waiting for report {report_id} to finish. Please try again.')
            else:
                time.sleep(settings.POLL_FREQUENCY)

    def report_template_logo_download(self, template_id, folder):
        report = resources.ReportTemplate.get(self, id=template_id).result()
        result = report.download_logo(folder).result()
        result.handle.close()
        return result

    def report_template_logo_delete(self, template_id):
        report = resources.ReportTemplate.get(self, id=template_id).result()
        result = report.delete_logo().result()
        return result

    def report_template_logo_upload(self, template_id, logo_file, content_tpe):
        report = resources.ReportTemplate.get(self, id=template_id).result()
        result = report.upload_logo(logo_file, content_tpe).result()
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
        A team account can have multiple templates, and setting is_default=True
        makes it the default when a report is created without specifying template_id
        (see report_create method).
        The includes argument can be a list with sections to be included
        in the reports. The list can include any of the following section names:
        summary, detections, fileMetadata, network, droppedFiles, extractedConfig, analysis.
        """
        return resources.ReportTemplate.create(self,
                                               template_name=template_name,
                                               is_default=is_default,
                                               primary_color=primary_color,
                                               footer_text=footer_text,
                                               last_page_text=last_page_text,
                                               includes=includes,
                                               **kwargs).result()

    def report_template_update(self,
                               template_id,
                               template_name=None,
                               is_default=None,
                               primary_color=None,
                               footer_text=None,
                               last_page_text=None,
                               includes=None,
                               **kwargs):
        return resources.ReportTemplate.update(self,
                                               id=template_id,
                                               template_name=template_name,
                                               is_default=is_default,
                                               primary_color=primary_color,
                                               footer_text=footer_text,
                                               last_page_text=last_page_text,
                                               includes=includes,
                                               **kwargs).result()

    def report_template_get(self, template_id):
        return resources.ReportTemplate.get(self, id=template_id).result()

    def report_template_delete(self, template_id):
        return resources.ReportTemplate.delete(self, id=template_id).result()

    def report_template_list(self, is_default=None, **kwargs):
        return resources.ReportTemplate.list(self, is_default=is_default, **kwargs).result()

    def account_whois(self, **kwargs):
        return resources.WhoIs.get(self, **kwargs).result()

    def account_features(self, **kwargs):
        return resources.AccountFeatures.get(self, **kwargs).result()
