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
        self._engine_map = None
        self.validate = validate_schemas

    def _load_engine_map(self):
        if not self._engine_map:
            self._engine_map = self.generator._get_engine_names().execute().result
            self._engine_map = {e.address: e.name for e in self._engine_map}
        return self._engine_map

    def resolve_engine_name(self, eth_pub):
        engines = self._load_engine_map()
        return engines.get(eth_pub.lower(), eth_pub) if engines is not None else eth_pub

    def check_version(self):
        """
        Checks GitHub to see if you have the latest version installed.
        TODO this will be re-enabled when better version info is available in the API

        :return: True,latest_version tuple if latest, False,latest_version tuple if not
        """
        raise NotImplementedError()

    def wait_for(self, submission_id, timeout=const.DEFAULT_SCAN_TIMEOUT):
        """
        Wait for a Submission to scan successfully

        :param submission_id: Submission id to wait for
        :param timeout: Maximum time in seconds to wait before raising a TimeoutException
        :return: The Submission resource waited on
        """
        start = time.time()
        while True:
            scan_result = self.lookup(submission_id)
            if scan_result.failed or scan_result.window_closed:
                return scan_result
            elif -1 < timeout < time.time() - start:
                raise exceptions.TimeoutException('Timed out waiting for submission {} to finish. Please try again.'
                                                  .format(submission_id))
            else:
                time.sleep(3)

    def search(self, hash_, hash_type=None):
        """
        Search a list of hashes.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: Generator of ArtifactInstance resources
        """

        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self.generator.search_hash(hash_).execute().consume_results()

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
        :return: Generator of Submission resources
        """
        if isinstance(artifact, string_types):
            artifact_type = resources.ArtifactType.parse(artifact_type)
            if artifact_type == resources.ArtifactType.FILE:
                path = artifact
                artifact_name = os.path.basename(artifact)
                content=None
            else:
                path = None
                artifact_name = artifact
                content = artifact
            artifact = resources.LocalArtifact(path=path, artifact_name=artifact_name, content=content,
                                               artifact_type=artifact_type, analyze=False, polyswarm=self)
        if isinstance(artifact, resources.LocalArtifact):
            return self.generator.submit(artifact).execute().result
        else:
            raise exceptions.InvalidValueException('Artifacts should be a path to a file or a LocalArtifact instance')

    def lookup(self, submission_id):
        """
        Lookup a submission by Submission id.

        :param submission_id: The Submission UUID to lookup
        :return: Generator of Submission resources
        """
        return self.generator.lookup_uuid(submission_id).execute().result

    def rescan(self, hash_, hash_type=None):
        """
        Rescan a file based on and existing hash in the Polyswarm platform

        :param hash_: Hashable object (Artifact, local.LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A Submission resources
        """
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self.generator.rescan(hash_).execute().result

    def rescanid(self, submission_id):
        """
        Re-execute a new submission based on an existing submission.

        :param submission_id: Id of the existing submission
        :return: A Submission resource
        """
        return self.generator.rescanid(submission_id).execute().result

    def score(self, uuid_):
        """
        Lookup a PolyScore(s) for a given submission, by UUID

        :param uuids: UUIDs to lookup
        :return: Generator of PolyScore resources
        """
        return self.generator.score(uuid_).execute().result

    def live_create(self, rule=None, rule_id=None, active=True, ruleset_name=None):
        """
        Create a new live hunt_id, and replace the currently running YARA rules.

        :param rule: YaraRuleset object or string containing YARA rules to install
        :return: The created Hunt resource
        """
        if rule:
            if not isinstance(rule, resources.YaraRuleset):
                rule = resources.YaraRuleset(dict(yara=rule), polyswarm=self)
            try:
                rule.validate()
            except exceptions.NotImportedException as e:
                logger.debug('%s\nSkipping validation.', str(e))
        elif rule_id:
            pass
        else:
            raise exceptions.InvalidValueException('Either yara or rule_id must be provided.')
        return self.generator.create_live_hunt(rule=rule, rule_id=rule_id,
                                               active=active, ruleset_name=ruleset_name).execute().result

    def live_get(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: The Hunt resource
        """
        return self.generator.get_live_hunt(hunt_id).execute().result

    def live_update(self, active, hunt_id=None):
        """
        Update a live hunt.

        :param hunt_id: Hunt ID
        :param active: True to start the live hunt and False to stop it
        :return: The updated Hunt resource
        """
        return self.generator.update_live_hunt(hunt_id, active=active).execute().result

    def live_delete(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: The deleted Hunt resource
        """
        return self.generator.delete_live_hunt(hunt_id).execute().result

    def live_list(self, since=None, all_=None):
        """
        List all the live hunts

        :return: Generator of Hunt resources
        """
        return self.generator.live_list(since=since, all_=all_).execute().consume_results()

    def live_results(self, hunt_id=None, since=None, tag=None, rule_name=None):
        """
        Get results from a live hunt

        :param hunt_id: ID of the hunt (None if latest rule results are desired)
        :param since: Fetch results from the last "since" minutes
        :return: Generator of HuntResult resources
        """
        return self.generator.live_hunt_results(hunt_id=hunt_id, since=since,
                                                tag=tag, rule_name=rule_name).execute().consume_results()

    def historical_create(self, rule=None, rule_id=None, ruleset_name=None):
        """
        Run a new historical hunt.

        :param rule: YaraRuleset object or string containing YARA rules to install
        :return: The created Hunt resource
        """
        if rule:
            if not isinstance(rule, resources.YaraRuleset):
                rule = resources.YaraRuleset(dict(yara=rule), polyswarm=self)
            try:
                rule.validate()
            except exceptions.NotImportedException as e:
                logger.warning('%s\nSkipping validation.', str(e))
        elif rule_id:
            pass
        else:
            raise exceptions.InvalidValueException('Either yara or rule_id must be provided.')
        return self.generator.create_historical_hunt(rule=rule, rule_id=rule_id,
                                                     ruleset_name=ruleset_name).execute().result

    def historical_get(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: The Hunt resource
        """
        return self.generator.get_historical_hunt(hunt_id).execute().result

    def historical_delete(self, hunt_id):
        """
        Delete a historical hunts.

        :param hunt_id: Hunt ID
        :return: The deleted Hunt resource
        """
        return self.generator.delete_historical_hunt(hunt_id).execute().result

    def historical_list(self, since=None):
        """
        List all historical hunts

        :return: Generator of Hunt resources
        """
        return self.generator.historical_list(since=since).execute().consume_results()

    def historical_results(self, hunt_id=None, tag=None, rule_name=None):
        """
        Get results from a historical hunt

        :param hunt_id: ID of the hunt (None if latest hunt results are desired)
        :return: Generator of HuntResult resources
        """
        return self.generator.historical_hunt_results(hunt_id=hunt_id, tag=tag, rule_name=rule_name).execute().consume_results()

    def rule_set_create(self, name, rules, description=None):
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
            logger.warning('%s\nSkipping validation.', str(e))
        return self.generator.create_rule_set(rules).execute().result

    def rule_set_get(self, rule_set_id=None):
        """
        Retrieve a YaraRuleset from the polyswarm platform by its Id.
        :param rule_set_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        return self.generator.get_rule_set(rule_set_id).execute().result

    def rule_set_update(self, rule_set_id, name=None, rules=None, description=None):
        """
        Update an existing YaraRuleset in the polyswarm platform by its Id.
        :param rule_set_id: Id of the ruleset
        :param name: New name of the ruleset
        :param rules: New yara rules as a string
        :param description: New description of the ruleset
        :return: The updated YaraRuleset resource
        """
        return self.generator.update_rule_set(rule_set_id, name=name, rules=rules, description=description).execute().result

    def rule_set_delete(self, rule_set_id):
        """
        Delete a YaraRuleset from the polyswarm platform by its Id.
        :param rule_set_id: Id of the ruleset
        :return: A YaraRuleset resource
        """
        return self.generator.delete_rule_set(rule_set_id).execute().result

    def rule_set_list(self):
        """
        List all YaraRulesets for the current account.
        :return: A generator of YaraRuleset resources
        """
        return self.generator.list_rule_set().execute().consume_results()

    def tag_create(self, sha2566, tags=None, families=None):
        """
        Create a Tag of the given type for the file identified by the sha256.
        :param sha256: Hash of the file.
        :return: A Tag resource
        """
        return self.generator.create_tag(sha2566, tags=tags, families=families).execute().result

    def tag_get(self, sha256):
        """
        Fetch the Tag associated with the given id.
        :return: A Tag resource
        """
        return self.generator.get_tag(sha256).execute().result

    def tag_update(self, sha256, tags=None, families=None, remove=False):
        """
        Update a Tag with the given type or value by its id.
        :return: A Tag resource
        """
        return self.generator.update_tag(sha256, tags=tags, families=families, remove=remove).execute().result

    def tag_delete(self, sha256):
        """
        Delete the Tag associated with the given id.
        :return: A Tag resource
        """
        return self.generator.delete_tag(sha256).execute().result

    def tag_list(self, sha256):
        """
        Return all tags associated with the file identified by the sha256.
        :param sha256: Hash of the file.
        :return: A generator of Tag resources
        """
        return self.generator.list_tags(sha256).execute().consume_results()

    def family_emerging(self, family_name, emerging=True):
        """
        Return all tags associated with the file identified by the sha256.
        :param sha256: Hash of the file.
        :return: A generator of Tag resources
        """
        return self.generator.emerging_family(family_name, emerging=emerging).execute().result

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
        return self.generator.download(hash_.hash, hash_.hash_type, path, create=True).execute().result

    def download_archive(self, out_dir, s3_path):
        """
        Grab the data in the s3 path provided in the stream() method, and write the contents
        in the provided directory.
        :param out_dir: Destination directory to download the file.
        :param s3_path: Target S3 object to download.
        :return: A LocalArtifact resource
        """
        path = os.path.join(out_dir, os.path.basename(urlparse(s3_path).path))
        return self.generator.download_archive(s3_path, path, create=True).execute().result

    def download_to_filehandle(self, hash_, fh, hash_type=None):
        """
        Grab the data of artifact identified by hash, and write the data to a file handle
        :param hash_: hash
        :param fh: file handle
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A LocalArtifact resource
        """
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self.generator.download(hash_.hash, hash_.hash_type, fh).execute().result

    def stream(self, since=const.MAX_SINCE_TIME_STREAM):
        """
        Access the stream of artifacts (ask info@polyswarm.io about access)

        :param destination: Directory to save the files
        :param since: Fetch results from the last "since" minutes (up to 2 days)
        :return: Generator of LocalArtifact resources
        """
        return self.generator.stream(since=since).execute().execute().consume_results()
