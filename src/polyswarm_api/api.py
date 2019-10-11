import time
import os

from . import const
from .endpoint import PolyswarmEndpointFutures
from .types.artifact import Artifact, ArtifactType, LocalArtifact
from .types.hash import Hash, to_hash
from .types import result


class PolyswarmAPI(object):
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri='https://api.polyswarm.network/v1', timeout=600, community='lima'):
        """

        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param timeout: How long to wait for operations to complete.
        :param community: Community to scan against.
        """
        self.endpoint = PolyswarmEndpointFutures(key, uri, community)
        self.timeout = timeout
        self._engine_map = None

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
        :return: List of SearchResult objects
        """
        raise NotImplemented

    def search_by_metadata(self, query):
        """
        Search artifacts by metadata

        :param query: MetadataQuery object
        :return: SearchResult object
        """
        pass

    def download(self, out_dir, *hashes):
        pass

    def download_by_feature(self, *artifacts):
        pass

    def download_by_metadata(self, query):
        pass

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
                url = LocalArtifact(content=url.encode("utf8"), artifact_name=url, artifact_type=ArtifactType.URL,
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
        return self.loop.run_until_complete(self.ps_api.check_version())

    def get_file_data(self, sha256):
        """
        Get file data of a file from the PS API

        :param sha256: SHA256 of the file
        :return: Response dict containing file_data if successful, and status message about success/failure
        """
        return self.loop.run_until_complete(self.ps_api.get_file_data(sha256))


    def download_file(self, h, destination_dir, with_metadata=False, hash_type=None):
        """
        Download a file via the PS API

        :param h: Hash of the file you wish to download
        :param destination_dir: Directory you wish to save the file in
        :param with_metadata: Whether to save related file metadata into an associated JSON file
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: Dictionary containing path to the downloaded file if successful, error message if not
        """
        return self.loop.run_until_complete(self.ps_api.download_file(h, destination_dir,
                                                                      with_metadata, hash_type))

    def download_files(self, hashes, destination_dir, with_metadata=False, hash_type=None):
        """
        Download files  via the PS API

        :param hashes: Hashes of the files you wish to download
        :param destination_dir: Directory you wish to save the files in
        :param with_metadata: Whether to save related file metadata into an associated JSON files
        :param hash_type: Hash type [sha256|sha1|md5]

        :return: Dictionary containing path to the downloaded file if successful, error message if not
        """
        return self.loop.run_until_complete(self.ps_api.download_files(hashes, destination_dir,
                                                                       with_metadata, hash_type))

    def rescan_file(self, h, hash_type=None):
        """
        Rescan a file by its hash

        :param h: Hash of the file to rescan
        :param hash_type: Hash type [default:autodetect, sha256|sha1|md5]
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.rescan_file(h, hash_type))

    def rescan_files(self, hashes, hash_type=None):
        """
        Rescan a file by its hash

        :param hashes: Hashes of the files to rescan
        :param hash_type: Hash type [default:autodetect, sha256|sha1|md5]
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.rescan_files(hashes, hash_type))

    def new_live_hunt(self, rules):
        """
        Create a new live hunt, and replace the currently running YARA rules.

        :param rules: String containing YARA rules to install
        :return: ID of the new hunt.
        """
        return self.loop.run_until_complete(self.ps_api.new_live_hunt(rules))

    def new_historical_hunt(self, rules):
        """
        Run a new historical hunt.

        :param rules: String containing YARA rules to install
        :return: ID of the new hunt.
        """
        return self.loop.run_until_complete(self.ps_api.new_historical_hunt(rules))

    def delete_live_hunt(self, hunt_id):
        """
        Delete a live scan.

        :param hunt_id: String containing hunt id
        """
        return self.loop.run_until_complete(self.ps_api.delete_live_hunt(hunt_id))

    def delete_historical_hunt(self, hunt_id):
        """
        Delete a historical scan.

        :param hunt_id: String containing hunt id
        """
        return self.loop.run_until_complete(self.ps_api.delete_historical_hunt(hunt_id))

    def get_live_results(self, hunt_id=None, limit=const.MAX_HUNT_RESULTS, offset=0,
                                all_results=False, with_metadata=False, with_bounties=False):
        """
        Get results from a live hunt

        :param hunt_id: ID of the hunt (None if latest rule results are desired)
        :param limit: Limit the number of scan results, returns the most recent hits
        :param offset: Offset into the result set to return
        :param all_results: Boolean on whether to fetch all results. Note: this ignores limit/offset and can take awhile.
        :param with_metadata: Whether to include metadata in the results
        :param with_bounties: Whether to include bounty results in the results
        :return: Matches to the rules
        """
        return self.loop.run_until_complete(self.ps_api.get_live_results(hunt_id, limit, offset, all_results,
                                                                         with_metadata, with_bounties))

    def get_historical_results(self, hunt_id=None, limit=const.MAX_HUNT_RESULTS, offset=0,
                                all_results=False, with_metadata=False, with_bounties=False):
        """
        Get results from a historical hunt

        :param hunt_id: ID of the hunt (None if latest hunt results are desired)
        :param limit: Limit the number of scan results, returns the most recent hits
        :param offset: Offset into the result set to return
        :param all_results: Boolean on whether to fetch all results. Note: this ignores limit/offset and can take awhile.
        :param with_metadata: Whether to include metadata in the results
        :param with_bounties: Whether to include bounty results in the results
        :return: Matches to the rules
        """
        return self.loop.run_until_complete(self.ps_api.get_historical_results(hunt_id, limit, offset, all_results,
                                                                               with_metadata, with_bounties))

    def get_stream(self, destination_dir=None, since=1440):
        """
        Get stream of tarballs from communities you have the stream privilege on.
        Contact us at info@polyswarm.io for more info on enabling this feature.

        :param destination_dir: Directory to down files to. None if you just want the list of URLs.
        :param since: Fetch all archives that are `since` minutes old or newer

        :return: List of signed S3 URLs for tarballs over the last two days
        """
        return self.loop.run_until_complete(self.ps_api.get_stream(destination_dir, since))
