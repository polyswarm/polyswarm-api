import time
import os
from io import BytesIO

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from . import exceptions
from . import const
from . import endpoint
from . import http
from .types import local
from .types import base


class PolyswarmAPI(object):
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri='https://api.polyswarm.network/v1', timeout=const.DEFAULT_SCAN_TIMEOUT,
                 community='lima', validate_schemas=False, session=None, executor=None, generator=None):
        """
        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param timeout: How long to wait for operations to complete.
        :param community: Community to scan against.
        :param validate_schemas: Validate JSON objects when creating response objects. Will impact performance.
        """
        self.session = session or http.PolyswarmHTTP(key, retries=const.DEFAULT_RETRIES)
        self.executor = executor or endpoint.PolyswarmFuturesExecutor()
        self.generator = generator or endpoint.PolyswarmRequestGenerator(self, key, uri, community)

        self.timeout = timeout
        self._engine_map = None
        self.validate = validate_schemas

    def _consume_results(self, request):
        while True:
            yield from request.result
            if not request.result:
                break
            else:
                self.executor.push(request.next_page())
                request = next(self.executor.execute())

    def search(self, *hashes, **kwargs):
        """
        Search a list of hashes.

        :param hashes: A list of Hashable objects (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param kwargs: Arguments to pass to search. Supported: with_instances, with_metadata (booleans)
        :return: Generator of SearchResult objects
        """

        hashes = [base.to_hash(h) for h in hashes]

        for h in hashes:
            self.executor.push(self.generator.search_hash(h, **kwargs))

        for request in self.executor.execute():
            yield from self._consume_results(request)

    def search_by_feature(self, feature, *artifacts):
        """
        Search artifacts by feature

        :param artifacts: List of local.LocalArtifact objects
        :param feature: Feature to use
        :return: SearchResult generator
        """
        raise NotImplementedError

    def search_by_metadata(self, *queries, **kwargs):
        """
        Search artifacts by metadata

        :param queries: List of MetadataQuery objects (or query_strings)
        :return: SearchResult generator
        """
        for query in queries:
            if not isinstance(query, local.MetadataQuery):
                query = local.MetadataQuery(query, polyswarm=self)
            self.executor.push(self.generator.search_metadata(query, **kwargs))

        for request in self.executor.execute():
            yield from self._consume_results(request)

    def download(self, out_dir, *hashes):
        hashes = [base.to_hash(h) for h in hashes]

        for h in hashes:
            path = os.path.join(out_dir, h.hash)
            self.executor.push(self.generator.download(h.hash, h.hash_type, path, create=True))

        for request in self.executor.execute():
            yield request.result

    def download_to_filehandle(self, h, fh):
        """
        Grab the data of artifact indentified by hash, and write the data to a file handle
        :param h: hash
        :param fh: file handle
        :return: DownloadResult object
        """
        h = base.to_hash(h)
        return next(self.executor.push(self.generator.download(h.hash, h.hash_type, fh)).execute()).result

    def submit(self, *artifacts):
        """
        Submit artifacts to polyswarm and return UUIDs

        :param artifacts: List of local.LocalArtifacts or paths to local files
        :return: SubmitResult generator
        """
        for artifact in artifacts:
            if not isinstance(artifact, local.LocalArtifact):
                artifact = local.LocalArtifact(path=artifact, artifact_name=os.path.basename(artifact),
                                               analyze=False, polyswarm=self)
            self.executor.push(self.generator.submit(artifact))
        for request in self.executor.execute():
            yield request.result

    def rescan_submit(self, *hashes, **kwargs):
        """
        Submit rescans to polyswarm and return UUIDs

        :param artifact_type: What type to use when rescanning artifact
        :param hashes: Hashable objects (Artifact, local.LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :return: SubmitResult generator
        """
        hashes = [base.to_hash(h) for h in hashes]

        for h in hashes:
            self.executor.push(self.generator.rescan(h, **kwargs))

        for request in self.executor.execute():
            yield request.result

    def scan(self, *artifacts):
        """
        Submit artifacts to polyswarm and wait for scan results

        :param artifacts: List of local.LocalArtifacts or paths to local files
        :return: ScanResult generator
        """
        for submission in self.submit(*artifacts):
            yield from self.wait_for(submission.uuid)

    def rescan(self, *hashes, **kwargs):
        """
        Rescan artifacts via polyswarm

        :param hashes: Hashable objects (Artifact, local.LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :param kwargs: Keyword arguments for the scan (none currently supported)
        :return: ScanResult generator
        """
        for submission in self.rescan_submit(*hashes, **kwargs):
            yield from self.wait_for(submission.uuid)

    def wait_for(self, *uuids):
        """
        Wait for submissions to scan successfully

        :param uuids: List of UUIDs to wait for
        :return: ScanResult generator
        """
        start = time.time()
        for uuid in uuids:
            while True:
                scan_result = next(self.lookup(uuid))

                if scan_result.ready:
                    yield scan_result
                    break
                elif -1 < self.timeout < time.time() - start:
                    scan_result.timeout = True
                    yield scan_result
                    break
                else:
                    time.sleep(3)

    def lookup(self, *uuids):
        """
        Lookup a submission by UUID.

        :param uuids: UUIDs to lookup
        :return: ScanResult object generator
        """
        for uuid in uuids:
            self.executor.push(self.generator.lookup_uuid(uuid))

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

        for request in self.executor.execute():
            yield request.result

    def scan_directory(self, directory, recursive=False):
        """
        Scan a directory of files via PolySwarm

        :param directory: Directory to scan
        :param recursive: Whether to look for files recursively
        :return: ScanResult generator
        """
        if recursive:
            file_list = [os.path.join(path, file)
                         for (path, dirs, files) in os.walk(directory)
                         for file in files if os.path.isfile(os.path.join(path, file))]
        else:
            file_list = [os.path.join(directory, file) for file in os.listdir(directory)
                         if os.path.isfile(os.path.join(directory, file))]

        return self.scan(*file_list)

    def scan_urls(self, *urls):
        """
        Scan URLs via PolySwarm

        :param urls: URLs to scan
        :return: ScanResult generator
        """
        _urls = []

        for url in urls:
            if not isinstance(url, local.LocalArtifact):
                url = local.LocalArtifact(content=BytesIO(url.encode("utf8")), artifact_name=url,
                                          artifact_type=base.ArtifactType.URL, analyze=False,
                                          polyswarm=self)
            _urls.append(url)

        return self.scan(*_urls)

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
        raise NotImplementedError

    def live_create(self, rules):
        """
        Create a new live hunt_id, and replace the currently running YARA rules.

        :param rules: YaraRuleset object or string containing YARA rules to install
        :return: HuntSubmissionResult object
        """
        if not isinstance(rules, local.YaraRuleset):
            rules = local.YaraRuleset(rules, polyswarm=self)
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
        yield from self._consume_results(request)

    def historical_create(self, rules):
        """
        Run a new historical hunt.

        :param rules: YaraRuleset object or string containing YARA rules to install
        :return: HuntSubmissionResult object
        """
        if not isinstance(rules, local.YaraRuleset):
            rules = local.YaraRuleset(rules, polyswarm=self)
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

    def historical_results(self, hunt_id=None, since=None):
        """
        Get results from a historical hunt

        :param hunt_id: ID of the hunt (None if latest hunt results are desired)
        :return: HuntResult object
        """
        request = next(self.executor.push(self.generator.historical_hunt_results(hunt_id=hunt_id, since=since)).execute())
        yield from self._consume_results(request)

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
