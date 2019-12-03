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


class PolyswarmAPI(object):
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri=None, community=None, validate_schemas=False):
        """
        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param community: Community to scan against.
        :param validate_schemas: Validate JSON objects when creating response objects. Will impact performance.
        """
        self.uri = uri or const.DEFAULT_GLOBAL_API
        self.community = community or const.DEFAULT_COMMUNITY
        self.session = http.PolyswarmHTTP(key, retries=const.DEFAULT_RETRIES)
        self.generator = endpoint.PolyswarmRequestGenerator(self)
        self._engine_map = None
        self.validate = validate_schemas

    def _resolve_engine_name(self, eth_pub):
        if not self._engine_map:
            self._engine_map = self.generator._get_engine_names().execute().result
            self._engine_map = {e.address: e.name for e in self._engine_map}
        return self._engine_map.get(eth_pub.lower(), eth_pub) if self._engine_map is not None else eth_pub

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
                raise exceptions.TimeoutException()
            else:
                time.sleep(3)

    def search(self, hash_):
        """
        Search a list of hashes.

        :param hashes: A list of Hashable objects (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :return: Generator of ArtifactInstance resources
        """

        hash_ = resources.Hash.from_hashable(hash_)
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

        :param queries: List of MetadataQuery objects (or query_strings)
        :return: Generator of ArtifactInstance resources
        """
        query = query if isinstance(query, resources.MetadataQuery) else resources.MetadataQuery(query, polyswarm=self)
        return self.generator.search_metadata(query).execute().consume_results()

    def submit(self, artifact, artifact_type=resources.ArtifactType.FILE):
        """
        Submit artifacts to polyswarm and return UUIDs

        :param artifacts: List of local.LocalArtifacts or paths to local files
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

        :param uuids: UUIDs to lookup
        :return: Generator of Submission resources
        """
        return self.generator.lookup_uuid(submission_id).execute().result

    def rescan(self, hash_):
        """
        Submit rescans to polyswarm and return UUIDs

        :param hashes: Hashable objects (Artifact, local.LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :return: Generator of Submission resources
        """
        hash_ = resources.Hash.from_hashable(hash_)
        return self.generator.rescan(hash_).execute().result

    def score(self, uuid_):
        """
        Lookup a PolyScore(s) for a given submission, by UUID

        :param uuids: UUIDs to lookup
        :return: Generator of PolyScore resources
        """
        return self.generator.score(uuid_).execute().result

    def live_create(self, rules):
        """
        Create a new live hunt_id, and replace the currently running YARA rules.

        :param rules: YaraRuleset object or string containing YARA rules to install
        :return: The created Hunt resource
        """
        if not isinstance(rules, resources.YaraRuleset):
            rules = resources.YaraRuleset(rules, polyswarm=self)
        try:
            rules.validate()
        except exceptions.NotImportedException:
            # for now, we do nothing to avoid nagging the user
            pass
        return self.generator.create_live_hunt(rules).execute().result

    def live_get(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: The Hunt resource
        """
        return self.generator.get_live_hunt(hunt_id).execute().result

    def live_update(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: The updated Hunt resource
        """
        return self.generator.update_live_hunt(hunt_id).execute().result

    def live_delete(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: The deleted Hunt resource
        """
        return self.generator.delete_live_hunt(hunt_id).execute().result

    def live_list(self):
        """
        List all the live hunts

        :return: Generator of Hunt resources
        """
        return self.generator.live_list().execute().consume_results()

    def live_results(self, hunt_id=None, since=None):
        """
        Get results from a live hunt

        :param hunt_id: ID of the hunt (None if latest rule results are desired)
        :param since: Fetch results from the last "since" minutes
        :return: Generator of HuntResult resources
        """
        return self.generator.live_hunt_results(hunt_id=hunt_id, since=since).execute().consume_results()

    def historical_create(self, rules):
        """
        Run a new historical hunt.

        :param rules: YaraRuleset object or string containing YARA rules to install
        :return: The created Hunt resource
        """
        if not isinstance(rules, resources.YaraRuleset):
            rules = resources.YaraRuleset(rules, polyswarm=self)
        try:
            rules.validate()
        except exceptions.NotImportedException:
            # for now, we do nothing to avoid nagging the user
            pass
        return self.generator.create_historical_hunt(rules).execute().result

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

    def historical_list(self):
        """
        List all historical hunts

        :return: Generator of Hunt resources
        """
        return self.generator.historical_list().execute().consume_results()

    def historical_results(self, hunt_id=None):
        """
        Get results from a historical hunt

        :param hunt_id: ID of the hunt (None if latest hunt results are desired)
        :return: Generator of HuntResult resources
        """
        return self.generator.historical_hunt_results(hunt_id=hunt_id).execute().consume_results()

    def download(self, out_dir, hash_):
        hash_ = resources.Hash.from_hashable(hash_)
        path = os.path.join(out_dir, hash_.hash)
        return self.generator.download(hash_.hash, hash_.hash_type, path, create=True).execute().result

    def download_archive(self, out_dir, s3_path):
        path = os.path.join(out_dir, os.path.basename(urlparse(s3_path).path))
        return self.generator.download_archive(s3_path, path, create=True).execute().result

    def download_to_filehandle(self, h, fh):
        """
        Grab the data of artifact identified by hash, and write the data to a file handle
        :param h: hash
        :param fh: file handle
        :return: A LocalArtifact resources
        """
        h = resources.Hash.from_hashable(h)
        return self.generator.download(h.hash, h.hash_type, fh).execute().result

    def stream(self, since=const.MAX_SINCE_TIME_STREAM):
        """
        Access the stream of artifacts (ask info@polyswarm.io about access)

        :param destination: Directory to save the files
        :param since: Fetch results from the last "since" minutes (up to 2 days)
        :return: Generator of LocalArtifact resources
        """
        return self.generator.stream(since=since).execute().execute().consume_results()
