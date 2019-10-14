import time
import os

from . import const
from .endpoint import PolyswarmEndpointFutures
from .types.artifact import ArtifactType, LocalArtifact
from .types.hash import to_hash
from .types.query import MetadataQuery
from .types import result
from .types.hunt import YaraRuleset, Hunt


class PolyswarmAPI(object):
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri='https://api.polyswarm.network/v1', timeout=600, community='lima',
                 validate_schemas=False):
        """

        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param timeout: How long to wait for operations to complete.
        :param community: Community to scan against.
        :param validate_schemas: Validate JSON objects when creating response objects. Will impact performance.
        """
        self.endpoint = PolyswarmEndpointFutures(key, uri, community)
        self.timeout = timeout
        self._engine_map = None
        self.validate = validate_schemas

    def search(self, *hashes, **kwargs):
        """
        Search a list of hashes.

        :param hashes: A list of Hashable objects (Artifact, LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param kwargs: Arguments to pass to search. Supported: with_instances, with_metadata (booleans)
        :return: List of ApiResponse objects
        """

        hashes = [to_hash(h) for h in hashes]

        requests = [(h, self.endpoint.search_hash(h, **kwargs)) for h in hashes]

        # This allows us to do streaming results
        # We could use as_completed here but it would be out-of-order.
        # TODO should we consider making that an option?
        for h, response in requests:
            yield result.SearchResult(h, response.result(), polyswarm=self)

    def search_by_feature(self, feature, *artifacts):
        """
        Search artifacts by feature

        :param artifacts: List of LocalArtifact objects
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
        futures = []
        for query in queries:
            if not isinstance(query, MetadataQuery):
                query = MetadataQuery(query, polyswarm=self)
            futures.append((query, self.endpoint.search_metadata(query, **kwargs)))

        for query, future in futures:
            yield result.SearchResult(query, future.result(), polyswarm=self)

    def download(self, out_dir, *hashes):
        hashes = [to_hash(h) for h in hashes]

        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        futures = [(h, os.path.join(out_dir, h.hash),
                    self.endpoint.download(h, os.path.join(out_dir, h.hash))) for h in hashes]

        for h, path, f in futures:
            artifact = LocalArtifact(path=path, artifact_name=h.hash, analyze=False, polyswarm=self)
            yield result.DownloadResult(artifact, f.result())

    def submit(self, *artifacts):
        """
        Submit artifacts to polyswarm and return UUIDs

        :param artifacts: List of LocalArtifacts or paths to local files
        :return: SubmitResult generator
        """
        futures = []

        for artifact in artifacts:
            if not isinstance(artifact, LocalArtifact):
                artifact = LocalArtifact(path=artifact, artifact_name=os.path.basename(artifact),
                                         analyze=False, polyswarm=self)
            futures.append((artifact, self.endpoint.submit(artifact)))

        for a, f in futures:
            yield result.SubmitResult(a, f.result(), self)

    def rescan_submit(self, *hashes, **kwargs):
        """
        Submit rescans to polyswarm and return UUIDs

        :param artifact_type: What type to use when rescanning artifact
        :param hashes: Hashable objects (Artifact, LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :return: SubmitResult generator
        """
        hashes = [to_hash(h) for h in hashes]

        futures = [(h, self.endpoint.rescan(h, **kwargs)) for h in hashes]

        for h, f in futures:
            # artifact_type is not currently supported in rescan
            yield result.SubmitResult(h, f.result(), self)

    def scan(self, *artifacts):
        """
        Submit artifacts to polyswarm and wait for scan results

        :param artifacts: List of LocalArtifacts or paths to local files
        :return: ScanResult generator
        """
        for submission in self.submit(*artifacts):
            s = submission.wait_for_scan()
            s.artifact = submission.artifact
            yield s

    def rescan(self, *hashes, **kwargs):
        """
        Rescan artifacts via polyswarm

        :param hashes: Hashable objects (Artifact, LocalArtifact, or Hash) or hex-encoded SHA256/SHA1/MD5
        :param kwargs: Keyword arguments for the scan (none currently supported)
        :return: ScanResult generator
        """
        for submission in self.rescan_submit(*hashes, **kwargs):
            s = submission.wait_for_scan()
            s.artifact = submission.artifact
            yield s

    def wait_for(self, *uuids):
        """
        Wait for submissions to scan successfully

        :param uuids: List of UUIDs to wait for
        :return: ScanResult generator
        """

        for uuid in uuids:
            while True:
                scan_result = next(self.lookup(uuid))

                if scan_result.ready:
                    yield scan_result
                    break
                else:
                    time.sleep(0.25)

    def lookup(self, *uuids):
        """
        Lookup a submission by UUID.

        :param uuids: UUIDs to lookup
        :return: ScanResult object
        """
        futures = [(uuid, self.endpoint.lookup_uuid(uuid)) for uuid in uuids]

        for uuid, f in futures:
            yield result.ScanResult(f.result(), polyswarm=self)

    def scan_directory(self, directory, recursive=False):
        if recursive:
            file_list = [os.path.join(path, file)
                         for (path, dirs, files) in os.walk(directory)
                         for file in files if os.path.isfile(os.path.join(path, file))]
        else:
            file_list = [os.path.join(directory, file) for file in os.listdir(directory)
                         if os.path.isfile(os.path.join(directory, file))]

        return self.scan(*file_list)

    def scan_urls(self, *urls):
        _urls = []

        for url in urls:
            if not isinstance(url, LocalArtifact):
                # TODO artifact_name will be the actual url once we address blocking issue
                url = LocalArtifact(content=url.encode("utf8"), artifact_name='url', artifact_type=ArtifactType.URL,
                                    analyze=False, polyswarm=self)
            _urls.append(url)

        return self.scan(*_urls)

    def _resolve_engine_name(self, eth_pub):
        if not self._engine_map:
            resp = self.endpoint._get_engine_names().result()
            result = resp.json()
            engines_results = result.get('results', [])
            self._engine_map = dict([(engine.get('address'), engine.get('name')) for engine in engines_results])
        return self._engine_map.get(eth_pub.lower(), eth_pub) if self._engine_map is not None else ''

    def check_version(self):
        """
        Checks GitHub to see if you have the latest version installed.

        :return: True,latest_version tuple if latest, False,latest_version tuple if not
        """
        raise NotImplementedError

    def live(self, rules):
        """
        Create a new live hunt, and replace the currently running YARA rules.

        :param rules: YaraRuleset object or string containing YARA rules to install
        :return: HuntSubmissionResult object
        """
        if not isinstance(rules, YaraRuleset):
            rules = YaraRuleset(rules, polyswarm=self)

        future = self.endpoint.submit_live_hunt(rules)

        return result.HuntSubmissionResult(rules, future.result(), self)

    def historical(self, rules):
        """
        Run a new historical hunt.

        :param rules: YaraRuleset object or string containing YARA rules to install
        :return: HuntSubmissionResult object
        """
        if not isinstance(rules, YaraRuleset):
            rules = YaraRuleset(rules, polyswarm=self)

        future = self.endpoint.submit_historical_hunt(rules)

        return result.HuntSubmissionResult(rules, future.result(), self)

    def live_delete(self, hunt_id):
        """
        Delete a live scan.

        :param hunt_id: String containing hunt id
        """
        raise NotImplementedError

    def historical_delete(self, hunt_id):
        """
        Delete a historical scan.

        :param hunt_id: String containing hunt id
        """
        raise NotImplementedError

    def _get_hunt_results(self, hunt, endpoint_func, **kwargs):
        if hunt and not isinstance(hunt, Hunt):
            hunt = Hunt.from_id(hunt, self)

        if hunt:
            kwargs['id'] = hunt.hunt_id

        # at least make this consistent in the API
        # should change this
        if 'with_instances' in kwargs:
            kwargs['with_bounty_results'] = kwargs['with_instances']
            del kwargs['with_instances']

        # to provide streaming of results in large result sets, we chunk the
        # requests into pieces. this makes the UI significantly more responsive
        # and reduces the risk of timeouts under load. This does however mean that,
        # unlike other functions in this API, requests are not fully resolved when the
        # object is returned.
        kwargs['offset'] = 0
        kwargs['limit'] = const.RESULT_CHUNK_SIZE

        # need to get count before we get all chunks
        reqs = [endpoint_func(**kwargs)]
        first = result.HuntResultPart(hunt, reqs[0].result(), self)
        total = first.result.total

        for offset in range(const.RESULT_CHUNK_SIZE, total, const.RESULT_CHUNK_SIZE):
            kwargs['offset'] = offset
            reqs.append(endpoint_func(**kwargs))

        return result.HuntResult(hunt, reqs, self)

    def live_results(self, hunt=None, **kwargs):
        """
        Get results from a live hunt

        :param hunt_id: ID of the hunt (None if latest rule results are desired)
        :return: HuntResult object
        """
        return self._get_hunt_results(hunt, self.endpoint.live_lookup, **kwargs)

    def historical_results(self, hunt=None, **kwargs):
        """
        Get results from a historical hunt

        :param hunt_id: ID of the hunt (None if latest hunt results are desired)
        :return: Matches to the rules
        """
        return self._get_hunt_results(hunt, self.endpoint.historical_lookup, **kwargs)

    def stream(self, destination_dir=None, since=1440):
        """
        Get stream of tarballs from communities you have the stream privilege on.
        Contact us at info@polyswarm.io for more info on enabling this feature.

        :param destination_dir: Directory to down files to. None if you just want the list of URLs.
        :param since: Fetch all archives that are `since` minutes old or newer

        :return: List of signed S3 URLs for tarballs over the last two days
        """
        raise NotImplementedError
