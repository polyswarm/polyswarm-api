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

    def __init__(self, key, uri='https://api.polyswarm.network/v2', community='lima',
                 validate_schemas=False, session=None, executor=None, generator=None):
        """
        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param timeout: How long to wait for operations to complete.
        :param community: Community to scan against.
        :param validate_schemas: Validate JSON objects when creating response objects. Will impact performance.
        """
        self.session = session or http.PolyswarmHTTP(key, retries=const.DEFAULT_RETRIES)
        self.executor = executor or endpoint.PolyswarmFuturesExecutor()
        self.generator = generator or endpoint.PolyswarmRequestGenerator(self, uri, community)
        self._engine_map = None
        self.validate = validate_schemas

    def _consume_results(self, request):
        while True:
            # consume items from the list
            for result in request.result:
                yield result
            # if the list is empty, stop
            # this could be a check for len(items) < page_size to avoid an extra request
            if not request.result:
                break
            # if not, get the next page as there might be more items
            else:
                self.executor.push(request.next_page())
                request = next(self.executor.execute())

    def _resolve_engine_name(self, eth_pub):
        if not self._engine_map:
            self._engine_map = next(self.executor.push(self.generator._get_engine_names()).execute()).result
            self._engine_map = {e.address: e.name for e in self._engine_map}
        return self._engine_map.get(eth_pub.lower(), eth_pub) if self._engine_map is not None else eth_pub

    def check_version(self):
        """
        Checks GitHub to see if you have the latest version installed.
        TODO this will be re-enabled when better version info is available in the API

        :return: True,latest_version tuple if latest, False,latest_version tuple if not
        """
        raise NotImplementedError()

    def wait_for(self, uuid, timeout=const.DEFAULT_SCAN_TIMEOUT):
        """
        Wait for submissions to scan successfully

        :param uuids: List of UUIDs to wait for
        :return: ScanResult generator
        """
        start = time.time()
        while True:
            scan_result = next(self.lookup(uuid))
            if scan_result.failed or scan_result.ready:
                return scan_result
            elif -1 < timeout < time.time() - start:
                raise exceptions.TimeoutException()
            else:
                time.sleep(3)

    def search(self, *hashes, **kwargs):
        """
        Search a list of hashes.

        :param hashes: A list of Hashable objects (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param kwargs: Arguments to pass to search. Supported: with_instances, with_metadata (booleans)
        :return: Generator of SearchResult objects
        """

        hashes = [resources.Hash.from_hashable(h) for h in hashes]

        for h in hashes:
            self.executor.push(self.generator.search_hash(h, **kwargs))

        for request in self.executor.execute():
            for result in self._consume_results(request):
                yield result

    def search_by_feature(self, feature, *artifacts):
        """
        Search artifacts by feature

        :param artifacts: List of local.LocalArtifact objects
        :param feature: Feature to use
        :return: SearchResult generator
        """
        raise NotImplementedError()

    def search_by_metadata(self, *queries, **kwargs):
        """
        Search artifacts by metadata

        :param queries: List of MetadataQuery objects (or query_strings)
        :return: SearchResult generator
        """
        for query in queries:
            if not isinstance(query, resources.MetadataQuery):
                query = resources.MetadataQuery(query, polyswarm=self)
            self.executor.push(self.generator.search_metadata(query, **kwargs))

        for request in self.executor.execute():
            for result in self._consume_results(request):
                yield result

    # TODO: replace with def submit(self, *artifacts, artifact_type=resources.ArtifactType.FILE):
    #  once we drop support for python 2.7
    def submit(self, *artifacts, **kwargs):
        """
        Submit artifacts to polyswarm and return UUIDs

        :param artifacts: List of local.LocalArtifacts or paths to local files
        :return: SubmitResult generator
        """
        artifact_type = kwargs.pop('artifact_type', resources.ArtifactType.FILE)
        for artifact in artifacts:
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
                self.executor.push(self.generator.submit(artifact))
            else:
                raise exceptions.InvalidValueException('Artifacts should be a path to a file or a LocalArtifact instance')
        # TODO: this should be replaced by yield from self.executor.execute() once we drop support for python 2.7
        for request in self.executor.execute():
            yield request.result

    def lookup(self, *uuids):
        """
        Lookup a submission by UUID.

        :param uuids: UUIDs to lookup
        :return: ScanResult object generator
        """
        for uuid in uuids:
            self.executor.push(self.generator.lookup_uuid(uuid))

        # TODO: this should be replaced by yield from self.executor.execute() once we drop support for python 2.7
        for request in self.executor.execute():
            yield request.result

    def rescan(self, *hashes, **kwargs):
        """
        Submit rescans to polyswarm and return UUIDs

        :param hashes: Hashable objects (Artifact, local.LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :return: SubmitResult generator
        """
        hashes = [resources.Hash.from_hashable(h) for h in hashes]

        for h in hashes:
            self.executor.push(self.generator.rescan(h, **kwargs))

        # TODO: this should be replaced by yield from self.executor.execute() once we drop support for python 2.7
        for request in self.executor.execute():
            yield request.result

    def score(self, *uuids):
        """
        Lookup a PolyScore(s) for a given submission, by UUID

        :param uuids: UUIDs to lookup
        :return: ScoreResult object generator
        """
        for uuid in uuids:
            self.executor.push(self.generator.score(uuid))

        # TODO: this should be replaced by yield from self.executor.execute() once we drop support for python 2.7
        for request in self.executor.execute():
            yield request.result

    def live_create(self, rules):
        """
        Create a new live hunt_id, and replace the currently running YARA rules.

        :param rules: YaraRuleset object or string containing YARA rules to install
        :return: HuntSubmissionResult object
        """
        if not isinstance(rules, resources.YaraRuleset):
            rules = resources.YaraRuleset(rules, polyswarm=self)
        try:
            rules.validate()
        except exceptions.NotImportedException:
            # for now, we do nothing to avoid nagging the user
            pass
        return next(self.executor.push(self.generator.create_live_hunt(rules)).execute()).result

    def live_get(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: HuntDeletionResult object
        """
        return next(self.executor.push(self.generator.get_live_hunt(hunt_id)).execute()).result

    def live_update(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: HuntDeletionResult object
        """
        return next(self.executor.push(self.generator.update_live_hunt(hunt_id)).execute()).result

    def live_delete(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: HuntDeletionResult object
        """
        return next(self.executor.push(self.generator.delete_live_hunt(hunt_id)).execute()).result

    def live_list(self):
        """
        List all the live hunts

        :return: HuntListResult object
        """
        return self._consume_results(next(self.executor.push(self.generator.live_list()).execute()))

    def live_results(self, hunt_id=None, since=None):
        """
        Get results from a live hunt

        :param hunt_id: ID of the hunt (None if latest rule results are desired)
        :return: HuntResult object
        """
        request = next(self.executor.push(self.generator.live_hunt_results(hunt_id=hunt_id, since=since)).execute())
        for result in self._consume_results(request):
            yield result

    def historical_create(self, rules):
        """
        Run a new historical hunt.

        :param rules: YaraRuleset object or string containing YARA rules to install
        :return: HuntSubmissionResult object
        """
        if not isinstance(rules, resources.YaraRuleset):
            rules = resources.YaraRuleset(rules, polyswarm=self)
        try:
            rules.validate()
        except exceptions.NotImportedException:
            # for now, we do nothing to avoid nagging the user
            pass
        return next(self.executor.push(self.generator.create_historical_hunt(rules)).execute()).result

    def historical_get(self, hunt_id=None):
        """
        Delete a live hunt.

        :param hunt_id: Hunt ID
        :return: HuntDeletionResult object
        """
        return next(self.executor.push(self.generator.get_historical_hunt(hunt_id)).execute()).result

    def historical_delete(self, hunt_id):
        """
        Delete a historical hunts.

        :param hunt_id: Hunt ID
        :return: HuntDeletionResult object
        """
        return next(self.executor.push(self.generator.delete_historical_hunt(hunt_id)).execute()).result

    def historical_list(self):
        """
        List all historical hunts

        :return: HuntListResult object
        """
        return self._consume_results(next(self.executor.push(self.generator.historical_list()).execute()))

    def historical_results(self, hunt_id=None):
        """
        Get results from a historical hunt

        :param hunt_id: ID of the hunt (None if latest hunt results are desired)
        :return: HuntResult object
        """
        request = next(self.executor.push(self.generator.historical_hunt_results(hunt_id=hunt_id)).execute())
        for result in self._consume_results(request):
            yield result

    def download(self, out_dir, *hashes):
        hashes = [resources.Hash.from_hashable(h) for h in hashes]

        for h in hashes:
            path = os.path.join(out_dir, h.hash)
            self.executor.push(self.generator.download(h.hash, h.hash_type, path, create=True))

        # TODO: this should be replaced by yield from self.executor.execute() once we drop support for python 2.7
        for request in self.executor.execute():
            yield request.result

    def download_to_filehandle(self, h, fh):
        """
        Grab the data of artifact indentified by hash, and write the data to a file handle
        :param h: hash
        :param fh: file handle
        :return: DownloadResult object
        """
        h = resources.Hash.from_hashable(h)
        return next(self.executor.push(self.generator.download(h.hash, h.hash_type, fh)).execute()).result

    def stream(self, destination=None, since=const.MAX_SINCE_TIME_STREAM):
        """
        Access the stream of artifacts (ask info@polyswarm.io about access)

        :param destination: Directory to save the files
        :param since: How far back to grab artifacts in minutes (up to 2 days)
        :return: DownloadResult generator
        """
        request = next(self.executor.push(self.generator.stream(since=since)).execute())
        for local_archive in self._consume_results(request):
            path = os.path.join(destination, os.path.basename(urlparse(local_archive.s3_path).path))

            self.executor.push(self.generator.download_archive(local_archive.s3_path, path, create=True))
            local_artifact = next(self.executor.execute()).result
            yield local_artifact
