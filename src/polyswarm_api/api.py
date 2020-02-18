import io
import logging
import time
import os

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from future.utils import string_types

from . import exceptions
from . import const
from . import endpoint
from . import http
from .types import resources


logger = logging.getLogger(__name__)


class PolyswarmAPI(object):
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri=None, community=None, validate_schemas=False, timeout=None):
        """
        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param community: Community to scan against.
        :param validate_schemas: Validate JSON objects when creating response objects. Will impact performance.
        :param timeout: Maximum time to wait for an http response on every request.
        """
        logger.debug('Creating PolyswarmAPI instance: api_key: %s, api_uri: %s, community: %s', key, uri, community)
        self.uri = uri or const.DEFAULT_GLOBAL_API
        self.community = community or const.DEFAULT_COMMUNITY
        self.timeout = timeout or const.DEFAULT_HTTP_TIMEOUT
        self.session = http.PolyswarmHTTP(key, retries=const.DEFAULT_RETRIES)
        self.generator = endpoint.PolyswarmRequestGenerator(self)
        self.validate = validate_schemas
        self._engines = None

    @property
    def engines(self):
        if not self._engines:
            self._engines = self.generator.get_engines().execute().result
            self._engines = {e.address.lower(): e for e in self._engines}
        return self._engines

    def resolve_engine_name(self, eth_pub):
        engine = self.engines.get(eth_pub.lower())
        engine_name = engine.name if engine else eth_pub
        return engine_name.lower()

    def check_version(self):
        """
        Checks GitHub to see if you have the latest version installed.
        TODO this will be re-enabled when better version info is available in the API

        :return: True,latest_version tuple if latest, False,latest_version tuple if not
        """
        raise NotImplementedError()

    def wait_for(self, scan, timeout=const.DEFAULT_SCAN_TIMEOUT):
        """
        Wait for a Scan to scan successfully

        :param scan: Scan id to wait for
        :param timeout: Maximum time in seconds to wait before raising a TimeoutException
        :return: The Scan resource waited on
        """
        start = time.time()
        while True:
            scan_result = self.lookup(scan)
            if scan_result.failed or scan_result.window_closed:
                return scan_result
            elif -1 < timeout < time.time() - start:
                raise exceptions.TimeoutException('Timed out waiting for scan {} to finish. Please try again.'
                                                  .format(scan))
            else:
                time.sleep(const.POLL_FREQUENCY)

    def search(self, hash_, hash_type=None):
        """
        Search a list of hashes.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: Generator of ArtifactInstance resources
        """

        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self.generator.search_hash(hash_.hash, hash_.hash_type).execute().consume_results()

    def search_scans(self, hash_):
        """
        Search a list of hashes.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: Generator of ArtifactInstance resources
        """

        hash_ = resources.Hash.from_hashable(hash_, hash_type='sha256')
        return self.generator.list_scans(hash_.hash).execute().consume_results()

    def search_by_feature(self, feature, *artifacts):
        """
        Search artifacts by feature

        :param feature: Feature to use
        :param artifacts: List of local.LocalArtifact objects
        :return: Generator of ArtifactInstance resources
        """
        raise NotImplementedError()

    def search_by_metadata(self, query):
        """
        Search artifacts by metadata

        :param query: A query string
        :return: Generator of ArtifactInstance resources
        """
        return self.generator.search_metadata(query).execute().consume_results()

    def submit(self, artifact, artifact_type=resources.ArtifactType.FILE):
        """
        Submit artifacts to polyswarm and return UUIDs

        :param artifact: List of local.LocalArtifacts or paths to local files
        :param artifact_type: The ArtifactType or strings containing "file" or "url"
        :return: Generator of Scan resources
        """
        artifact_type = resources.ArtifactType.parse(artifact_type)
        # TODO This is a python 2.7 check if artifact is a file-like instance, consider changing
        #  to isinstance(artifact, io.IOBase) when deprecating 2.7 and implementing making LocalHandle
        #  inherit io.IOBase, although this will change the method delegation logic in the resource
        if hasattr(artifact, 'read') and hasattr(artifact.read, '__call__'):
            artifact = resources.LocalArtifact(artifact, artifact_type=artifact_type, polyswarm=self, analyze=False)
        elif isinstance(artifact, string_types):
            if artifact_type == resources.ArtifactType.FILE:
                artifact = resources.LocalArtifact.from_path(self, artifact, artifact_type=artifact_type)
            elif artifact_type == resources.ArtifactType.URL:
                artifact = resources.LocalArtifact.from_content(self, artifact, artifact_name=artifact,
                                                                artifact_type=artifact_type)
        if isinstance(artifact, resources.LocalArtifact):
            return self.generator.submit(artifact, artifact.artifact_name, artifact.artifact_type.name).execute().result
        else:
            raise exceptions.InvalidValueException('Artifacts should be a path to a file or a LocalArtifact instance')

    def lookup(self, scan):
        """
        Lookup a scan by Scan id.

        :param scan: The Scan UUID to lookup
        :return: Generator of Scan resources
        """
        return self.generator.lookup_uuid(scan).execute().result

    def rescan(self, hash_, hash_type=None):
        """
        Rescan a file based on and existing hash in the Polyswarm platform

        :param hash_: Hashable object (Artifact, local.LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A ArtifactInstance resources
        """
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self.generator.rescan(hash_.hash, hash_.hash_type).execute().result

    def rescan_id(self, scan):
        """
        Re-execute a new scan based on an existing scan.

        :param scan: Id of the existing scan
        :return: A ArtifactInstance resource
        """
        return self.generator.rescanid(scan).execute().result

    def _parse_rule(self, rule):
        if isinstance(rule, string_types):
            rule, rule_id = resources.YaraRuleset(dict(yara=rule), polyswarm=self), None
            try:
                rule.validate()
            except exceptions.NotImportedException as e:
                logger.debug('%s\nSkipping validation.', str(e))
        elif isinstance(rule, (resources.YaraRuleset, int)):
            rule, rule_id = None, rule
        else:
            raise exceptions.InvalidValueException('Either yara or rule_id must be provided.')
        return rule, rule_id

    def live_create(self, rule, active=True, ruleset_name=None):
        """
        Create a new live hunt_id, and replace the currently running YARA rules.

        :param rule: YaraRuleset object or string containing YARA rules to install
        :return: The created Hunt resource
        """
        rule, rule_id = self._parse_rule(rule)
        return self.generator.create_live_hunt(rule=rule.yara if rule else None, rule_id=rule_id,
                                               active=active, ruleset_name=ruleset_name).execute().result

    def live_get(self, hunt=None):
        """
        Delete a live hunt.

        :param hunt: Hunt ID
        :return: The Hunt resource
        """
        return self.generator.get_live_hunt(hunt).execute().result

    def live_update(self, active, hunt=None):
        """
        Update a live hunt.

        :param hunt: Hunt ID
        :param active: True to start the live hunt and False to stop it
        :return: The updated Hunt resource
        """
        return self.generator.update_live_hunt(hunt, active=active).execute().result

    def live_delete(self, hunt=None):
        """
        Delete a live hunt.

        :param hunt: Hunt ID
        :return: The deleted Hunt resource
        """
        return self.generator.delete_live_hunt(hunt).execute().result

    def live_list(self, since=None, all_=None):
        """
        List all the live hunts

        :return: Generator of Hunt resources
        """
        return self.generator.live_list(since=since, all_=all_).execute().consume_results()

    def live_results(self, hunt=None, since=None, tag=None, rule_name=None):
        """
        Get results from a live hunt

        :param hunt: ID of the hunt (None if latest rule results are desired)
        :param since: Fetch results from the last "since" minutes
        :return: Generator of HuntResult resources
        """
        return self.generator.live_hunt_results(hunt_id=hunt, since=since,
                                                tag=tag, rule_name=rule_name).execute().consume_results()

    def historical_create(self, rule=None, ruleset_name=None):
        """
        Run a new historical hunt.

        :param rule: YaraRuleset object or string containing YARA rules to install
        :return: The created Hunt resource
        """
        rule, rule_id = self._parse_rule(rule)
        return self.generator.create_historical_hunt(rule=rule.yara if rule else None, rule_id=rule_id,
                                                     ruleset_name=ruleset_name).execute().result

    def historical_get(self, hunt=None):
        """
        Delete a live hunt.

        :param hunt: Hunt ID
        :return: The Hunt resource
        """
        return self.generator.get_historical_hunt(hunt).execute().result

    def historical_delete(self, hunt):
        """
        Delete a historical hunts.

        :param hunt: Hunt ID
        :return: The deleted Hunt resource
        """
        return self.generator.delete_historical_hunt(hunt).execute().result

    def historical_list(self, since=None):
        """
        List all historical hunts

        :return: Generator of Hunt resources
        """
        return self.generator.historical_list(since=since).execute().consume_results()

    def historical_results(self, hunt=None, tag=None, rule_name=None):
        """
        Get results from a historical hunt

        :param hunt: ID of the hunt (None if latest hunt results are desired)
        :return: Generator of HuntResult resources
        """
        return self.generator.historical_hunt_results(hunt_id=hunt, tag=tag, rule_name=rule_name).execute().consume_results()

    def ruleset_create(self, name, rules, description=None):
        """
        Create a Yara Ruleset from the provided rules with the given name in the polyswarm platform.
        :param name: Name of the ruleset
        :param rules: Yara rules as a string
        :param description: Description of the ruleset
        :return: A YaraRuleset resource
        """
        rules = resources.YaraRuleset(dict(name=name, description=description, yara=rules), polyswarm=self)
        try:
            rules.validate()
        except exceptions.NotImportedException as e:
            logger.debug('%s\nSkipping validation.', str(e))
        return self.generator.create_ruleset(rules.yara, rules.name, description=rules.description).execute().result

    def ruleset_get(self, ruleset_id=None):
        """
        Retrieve a YaraRuleset from the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        return self.generator.get_ruleset(ruleset_id).execute().result

    def ruleset_update(self, ruleset_id, name=None, rules=None, description=None):
        """
        Update an existing YaraRuleset in the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :param name: New name of the ruleset
        :param rules: New yara rules as a string
        :param description: New description of the ruleset
        :return: The updated YaraRuleset resource
        """
        return self.generator.update_ruleset(ruleset_id, name=name, rules=rules, description=description).execute().result

    def ruleset_delete(self, ruleset_id):
        """
        Delete a YaraRuleset from the polyswarm platform by its Id.
        :param ruleset_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        return self.generator.delete_ruleset(ruleset_id).execute().result

    def ruleset_list(self):
        """
        List all YaraRulesets for the current account.
        :return: A generator of YaraRuleset resources
        """
        return self.generator.list_ruleset().execute().consume_results()

    def tag_link_get(self, sha256):
        """
        Fetch the Tag associated with the given id.
        :return: A Tag resource
        """
        return self.generator.get_tag_link(sha256).execute().result

    def tag_link_update(self, sha256, tags=None, families=None, remove=False):
        """
        Update a Tag with the given type or value by its id.
        :return: A Tag resource
        """
        return self.generator.update_tag_link(sha256, tags=tags, families=families, remove=remove).execute().result

    def tag_create(self, name):
        """
        Create a Tag of the given type for the file identified by the sha256.
        :param sha256: Hash of the file.
        :return: A Tag resource
        """
        return self.generator.create_tag(name).execute().result

    def tag_get(self, name):
        """
        Fetch the Tag associated with the given id.
        :return: A Tag resource
        """
        return self.generator.get_tag(name).execute().result

    def tag_delete(self, name):
        """
        Delete the Tag associated with the given id.
        :return: A Tag resource
        """
        return self.generator.delete_tag(name).execute().result

    def tag_list(self):
        """
        Fetch the Tag associated with the given id.
        :return: A Tag resource
        """
        return self.generator.list_tag().execute().consume_results()

    def family_create(self, name):
        """
        Create a Tag of the given type for the file identified by the sha256.
        :param sha256: Hash of the file.
        :return: A Tag resource
        """
        return self.generator.create_family(name).execute().result

    def family_get(self, name):
        """
        Fetch the Tag associated with the given id.
        :return: A Tag resource
        """
        return self.generator.get_family(name).execute().result

    def family_delete(self, name):
        """
        Delete the Tag associated with the given id.
        :return: A Tag resource
        """
        return self.generator.delete_family(name).execute().result

    def family_update(self, family_name, emerging=True):
        """
        Return all tags associated with the file identified by the sha256.
        :param sha256: Hash of the file.
        :return: A generator of Tag resources
        """
        return self.generator.update_family(family_name, emerging=emerging).execute().result

    def family_list(self):
        """
        Fetch the Tag associated with the given id.
        :return: A Tag resource
        """
        return self.generator.list_family().execute().consume_results()

    def download(self, out_dir, hash_, hash_type=None):
        """
        Grab the data of artifact identified by hash, and write the data to a file in the provided directory
        under a file named after the hash_.
        :param out_dir: Destination directory to download the file.
        :param hash_: hash
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A LocalArtifact resource
        """
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        path = os.path.join(out_dir, hash_.hash)
        artifact = resources.LocalArtifact.from_path(self, path, create=True)
        self.generator.download(hash_.hash, hash_.hash_type, handle=artifact).execute()
        return artifact

    def download_archive(self, out_dir, s3_path):
        """
        Grab the data in the s3 path provided in the stream() method, and write the contents
        in the provided directory.
        :param out_dir: Destination directory to download the file.
        :param s3_path: Target S3 object to download.
        :return: A LocalArtifact resource
        """
        path = os.path.join(out_dir, os.path.basename(urlparse(s3_path).path))
        artifact = resources.LocalArtifact.from_path(self, path, create=True)
        self.generator.download_archive(s3_path, handle=artifact).execute()
        return artifact

    def download_to_handle(self, hash_, fh, hash_type=None):
        """
        Grab the data of artifact identified by hash, and write the data to a file handle
        :param hash_: hash
        :param fh: file handle
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A LocalArtifact resource
        """
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self.generator.download(hash_.hash, hash_.hash_type, handle=fh).execute().result

    def stream(self, since=const.MAX_SINCE_TIME_STREAM):
        """
        Access the stream of artifacts (ask info@polyswarm.io about access)

        :param destination: Directory to save the files
        :param since: Fetch results from the last "since" minutes (up to 2 days)
        :return: Generator of LocalArtifact resources
        """
        return self.generator.stream(since=since).execute().execute().consume_results()
