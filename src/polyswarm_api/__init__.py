import aiohttp
import asyncio
import io
import os
import logging
import hashlib
import time
import aiofiles
import json

from polyswarm_api.engine_resolver import EngineResolver

logger = logging.getLogger(__name__)


class PolyswarmAsyncAPI(object):
    """
    An asynchronous interface to the PolySwarm API.
    """

    # TODO this should point to api.polyswarm.network
    def __init__(self, key, uri="https://consumer.prod.polyswarm.network", get_limit=10,
                 post_limit=10, timeout=600, force=False, community="epoch"):
        """

        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param get_limit: How many simultaneous GET requests to make. Increase at your own risk.
        :param post_limit: How many simultaneous POST requests / second to make. Change at your own risk.
        :param timeout: How long to wait for scans to complete. This timeout will have 45 seconds added to it, the minimum bounty time.
        :param force: Force re-scans if file was already submitted.
        :param community: Community to scan against.
        """
        self.api_key = key

        self.uri = uri

        self.community_uri = "{}/{}".format(self.uri, community)

        self.force = force

        self.get_semaphore = asyncio.Semaphore(get_limit)

        self.network = "prod" if uri.find("lb.kb") == -1 else "lb.kb"

        # TODO does this need commmunity?
        self.portal_uri = "https://polyswarm.network/scan/results/" if self.network == "prod" else "https://portal.stage.polyswarm.network/"

        self.api_uri = "https://api.k.polyswarm.network" if self.network == "prod" else "https://api.lb.kb.polyswarm.network"

        self.engine_resolver = EngineResolver(self.api_uri)

        self.post_semaphore = asyncio.Semaphore(post_limit)

        self.timeout = timeout

    def set_force(self, force):
        """
        Enable forced re-submissions of bounties.

        :param force: Boolean force/don't force bounty re-submission
        :return: None
        """
        self.force = force

    def set_timeout(self, timeout):
        """
        Set timeout for file scans. This timeout will have 45 seconds added to it, the minimum bounty time.

        :param timeout: How long to wait for scan to complete
        :return: None
        """
        self.timeout = timeout

    def _fix_result(self, result):
        """
        For now, since the name-ETH address mappings are not added by consumer, we add them using
        a hardcoded dict. This function does that for us. It also adds in a permalink to the scan.
        These changes will be moved into consumer soon.

        :param result: The JSON we got from consumer API
        :return: JSON updated with name-ETH address mappings for microengines and arbiters
        """
        if 'uuid' in result:
            result['permalink'] = self.portal_uri+result['uuid']
        try:
            for file in result['files']:
                if 'assertions' in file:
                    for assertion in file['assertions']:
                        assertion['engine'] = self.engine_resolver.get_engine_name(assertion['author'])
                if 'votes' in file:
                    for vote in file['votes']:
                        vote['engine'] = self.engine_resolver.get_engine_name(vote['arbiter'])
        except KeyError:
            # ignore if not complete
            return result

        return result

    async def get_file_data(self, h, hash_type="sha256"):
        """
        Download file data via the PS API

        :param h: Hash of the file you wish to download
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: Dictionary containing the file data if found, error dictionary if not
        """
        async with self.get_semaphore:
            logger.debug("Downloading file hash %s with api key %s" % (h, self.api_key))
            async with aiohttp.ClientSession() as session:
                async with session.get("{}/download/{}/{}".format(self.uri, hash_type, h),
                                       headers={"Authorization": self.api_key}) as raw_response:
                    try:
                        response = await raw_response.read()
                    except Exception:
                        response = await raw_response.read() if raw_response else 'None'
                        logger.error('Received non-json response from PolySwarm API: %s', response)
                        response = {"status": "error", "reason": "unknown_error"}
                    if raw_response.status // 100 != 2:
                        if raw_response.status == 404:
                            return {"status": "error", "reason": "file_not_found"}
                        else:
                            return {"status": "error", "reason": "unknown_error"}
                    return {"file_data": response, "status": "OK",
                            "encoding": raw_response.headers.get('Content-Encoding', 'none')}

    async def post_file(self, file_obj, filename):
        """
        POST file to the PS API to be scanned asynchronously.

        :param file_obj: File-like object to POST to the API
        :param filename: Name of file to be given to the API
        :return: Dictionary of the result code and the UUID of the upload (if successful)
        """
        # TODO check file-size. For now, we need to handle error.
        data = aiohttp.FormData()
        data.add_field('file', file_obj, filename=filename)

        params = {"force": "true"} if self.force else {}
        async with self.post_semaphore:
            logger.debug("Posting file %s with api-key %s" % (filename, self.api_key))
            async with aiohttp.ClientSession() as session:
                async with session.post(self.community_uri, data=data, params=params,
                                               headers={"Authorization": self.api_key}) as raw_response:
                    try:
                        response = await raw_response.json()
                    except Exception:
                        response = await raw_response.read() if raw_response else 'None'
                        logger.error('Received non-json response from PolySwarm API: %s', response)
                        response = {"filename": filename, "result": "error"}
                    if raw_response.status // 100 != 2:
                        errors = response.get('errors')
                        logger.error("Error posting to PolySwarm API: {}".format(errors))
                        response = {"filename": filename, "status": "error"}
                    return response

    async def lookup_uuid(self, uuid):
        """
        Lookup a UUID using the PS API asynchronously.

        :param uuid: UUID to lookup.
        :return: JSON report file
        """
        async with self.get_semaphore:
            logger.debug("Looking up UUID %s", uuid)
            async with aiohttp.ClientSession() as session:
                async with session.get("%s/uuid/%s" % (self.community_uri, uuid),
                                       headers={"Authorization": self.api_key}) as raw_response:
                    try:
                        response = await raw_response.json()
                    except Exception:
                        response = await raw_response.read() if raw_response else 'None'
                        logger.error('Received non-json response from PolySwarm API: %s', response)
                        response = {'files': [], 'uuid': uuid}
                    if raw_response.status // 100 != 2:
                        errors = response.get('errors')
                        if raw_response.status == 400 and errors.find("has not been created") != -1:
                            return {'files': [], 'uuid': uuid}
                        logger.error("Error reading from PolySwarm API: {}".format(errors))
                        return {'files': [], 'uuid': uuid}
        return self._fix_result(response['result'])

    async def _wait_for_uuid(self, uuid):
        # check UUID status immediately, in case the file already exists
        result = await self.lookup_uuid(uuid)

        if self._reveal_closed(result):
            return result

        # wait for bounty to complete (20 blocks for assert, 25 for reveal)
        # TODO why are we using those numbers above, longer for reveal than assert is silly.
        await asyncio.sleep(45)

        started = time.time()

        while True:
            result = await self.lookup_uuid(uuid)

            if self._reveal_closed(result):
                return result

            await asyncio.sleep(1)

            if time.time()-started > self.timeout >= 0:
                break

        logger.warning("Failed to get results for uuid %s in time.", uuid)
        return {'files': result['files'], 'uuid': uuid}

    async def scan_fileobj(self, to_scan, filename="data"):
        """
        Scan a single file-like object using the PS API asynchronously.

        :param to_scan: File-like object to scan.
        :param filename: Filename to use
        :return: JSON report
        """

        result = await self.post_file(to_scan, filename)
        if result['status'] == "OK":
            uuid = result['result']
        else:
            logger.error("Failed to get UUID for scan of file %s", filename)
            return {"filename": filename, "files": []}

        logger.info("Successfully submitted file %s, UUID %s" % (filename, uuid))

        return await self._wait_for_uuid(uuid)

    async def scan_data(self, data, filename=None):
        """
        Scan bytes using the PS API asynchronously.

        :param data: Data (in bytes) to submit to be scanned
        :param filename: Filename to use in submission
        :return: JSON report
        """
        if filename is None:
            filename = hashlib.sha256(data).hexdigest()
        return await self.scan_fileobj(io.BytesIO(data), filename)

    async def scan_file(self, to_scan):
        """
        Scan a single file using the PS API asynchronously.

        :param to_scan: Path of file to scan.
        :return: JSON report file
        """

        with open(to_scan, "rb") as fobj:
            return await self.scan_fileobj(fobj, os.path.basename(to_scan))

    async def search_hash(self, to_scan, hash_type="sha256", rescan=False):
        """
        Search for a single hash using the PS API asynchronously.

        :param to_scan: Hash to search for
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        # TODO check file-size. For now, we need to handle error.
        # if the hash is not sha256, we need to do a lookup first to get the sha256
        if not rescan or hash_type != "sha256":
            async with self.get_semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get("{}/search/{}/{}".format(self.uri, hash_type, to_scan),
                                           headers={"Authorization": self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            raise Exception('Received non-json response from PolySwarm API: %s', response)
                        if raw_response.status // 100 != 2:
                            if raw_response.status == 404 and response.get("errors").find("has not been in any") != -1:
                                return {'hash': to_scan}

                            errors = response.get('errors')
                            raise Exception("Error reading from PolySwarm API: {}".format(errors))

        if rescan:
            try:
                sha256 = response['result']['files'][0]['hash'] if hash_type != "sha256" else to_scan
                await self.rescan_file(sha256)
                # get the new results, using sha256 so we know we get the same file even if collision happened
                return await self.search_hash(sha256, "sha256", rescan=False)
            except (KeyError, IndexError):
                logger.warning("Failed to parse response, not rescanning.")
                return response

        return self._fix_result(response['result'])

    async def rescan_hash(self, to_rescan, hash_type="sha256"):
        """
        Start a rescan for single hash using the PS API asynchronously.

        :param to_rescan: sha256 hash of the file to rescan
        :return: JSON report file
        """
        # TODO check file-size. For now, we need to handle error.
        async with self.get_semaphore:
            async with aiohttp.ClientSession() as session:
                async with session.get("{}/rescan/{}/{}".format(self.community_uri, hash_type, to_rescan),
                                       headers={"Authorization": self.api_key}) as raw_response:
                    try:
                        response = await raw_response.json()
                    except Exception:
                        response = await raw_response.read() if raw_response else 'None'
                        raise Exception('Received non-json response from PolySwarm API: %s', response)
                    if raw_response.status // 100 != 2:
                        # TODO this behavior in the API needs to change
                        if raw_response.status == 400 and response.get("errors").find("has not been in any") != -1:
                            return {'hash': to_rescan}

                        if raw_response.status == 404:
                            return {"hash": to_rescan, "reason": "file_not_found", "status": "error"}

                        errors = response.get('errors')
                        logger.error("Error posting to PolySwarm API: {}".format(errors))
                        response = {"hash": to_rescan, "status": "error"}

        return response

    async def scan_files(self, files):
        """
        Scan a collection of files using the PS API asynchronously.

        :param files: List of paths of files to scan.
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.scan_file(f) for f in files])

        return results

    async def lookup_uuids(self, uuids):
        """
        Scan a collection of uuids using the PS API asynchronously.

        :param uuids: List of uuids to scan.
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.lookup_uuid(u) for u in uuids])

        return results

    async def scan_directory(self, directory, recursive=False):
        """
        Scan a directory using the PS API asynchronously.

        :param directory: Directory to scan.
        :param recursive: Whether or not to scan the directory recursively.
        :return: JSON report file
        """
        if recursive:
            file_list = [os.path.join(path, file)
                            for (path, dirs, files) in os.walk(directory)
                            for file in files if os.path.isfile(os.path.join(path, file))]
        else:
            file_list = [os.path.join(directory, file) for file in os.listdir(directory)
                         if os.path.isfile(os.path.join(directory, file))]

        return await self.scan_files(file_list)

    async def search_hashes(self, hashes, hash_type="sha256", rescan=False):
        """
        Scan a collection of hashes using the PS API asynchronously.

        :param hashes: Hashes to scan.
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.search_hash(h, hash_type, rescan) for h in hashes])

        return results

    async def download_file(self, h, destination_dir, with_metadata=False, hash_type="sha256"):
        """
        Download a file via the PS API

        :param h: Hash of the file you wish to download
        :param destination_dir: Directory you wish to save the file in
        :param with_metadata: Whether to save related file metadata into an associated JSON file
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: Dictionary containing path to the downloaded file if successful, error message if not
        """
        results = await self.get_file_data(h, hash_type)

        out_path = os.path.join(destination_dir, h)

        if results['status'] == "OK":
            async with aiofiles.open(out_path, mode='wb') as f:
                await f.write(results['file_data'])
        else:
            results['file_hash'] = h
            return results

        if with_metadata:
            meta_results = await self.search_hash(h, hash_type=hash_type)
            if "files" in meta_results and "file_info" in meta_results["files"][0]:
                async with aiofiles.open(out_path+".json", mode="w") as f:
                    await f.write(json.dumps(meta_results["files"][0]))

        return {"file_path": out_path, "status": "OK", "file_hash": h}

    async def download_files(self, hashes, destination_dir, with_metadata=True, hash_type="sha256"):
        """
        Download files  via the PS API

        :param hashes: Hashes of the files you wish to download
        :param destination_dir: Directory you wish to save the files in
        :param with_metadata: Whether to save related file metadata into an associated JSON files
        :param hash_type: Hash type [sha256|sha1|md5]

        :return: Dictionary containing path to the downloaded file if successful, error message if not
        """
        results = await asyncio.gather(*[self.download_file(h, destination_dir,
                                                            with_metadata, hash_type) for h in hashes])

        return results

    async def rescan_file(self, h, hash_type="sha256"):
        """
        Rescan a file by its sha256/sha1/md5 hash

        :param h: Hash of the file to rescan
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: JSON report file
        """
        result = await self.rescan_hash(h, hash_type)

        if result['status'] != "OK":
            return result

        return await self._wait_for_uuid(result['result'])

    async def rescan_files(self, hashes, hash_type="sha256"):
        """
        Rescan files by sha256/sha1/md5 hash

        :param hashes: Hashes of the files to rescan
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: JSON report file
        """
        return await asyncio.gather(*[self.rescan_file(h, hash_type) for h in hashes])

    def _reveal_closed(self, result):
        """
        Check result dict if reveal window is closed or error occurred

        :param result: Result dict from UUID check
        :return: If the assertion reveal window is closed
        """

        # TODO this really should be better named in the JSON, as there are multiple windows
        return all(('window_closed' in file and file['window_closed']) or ('failed' in file and file['failed'])
                   for file in result['files'])


class PolyswarmAPI(object):
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri="https://consumer.prod.polyswarm.network", get_limit=10,
                 post_limit=4, timeout=600, force=False, community="epoch"):
        """

        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param get_limit: How many simultaneous GET requests to make. Increase at your own risk.
        :param post_limit: How many simultaneous POST requests / second to make. Change at your own risk.
        :param timeout: How long to wait for scans to complete. This should be at least 45 seconds for round to complete
        :param force: Force re-scans if file was already submitted.
        :param community: Community to scan against.
        """
        self.ps_api = PolyswarmAsyncAPI(key, uri, get_limit, post_limit, timeout, force, community)
        self.loop = asyncio.get_event_loop()

    def set_force(self, force):
        """
        Enable forced re-submissions of bounties.

        :param force: Boolean force/don't force bounty re-submission
        :return: None
        """
        self.ps_api.set_force(force)

    def set_timeout(self, timeout):
        """
        Set timeout for file scans. This timeout will have 45 seconds added to it, the minimum bounty time.

        :param timeout: How long to wait for scan to complete
        :return: None
        """
        self.ps_api.set_timeout(timeout)

    def get_file_data(self, sha256):
        """
        Get file data of a file from the PS API

        :param sha256: SHA256 of the file
        :return: Response dict containing file_data if successful, and status message about success/failure
        """
        return self.loop.run_until_complete(self.ps_api.get_file_data(sha256))

    def scan_fileobj(self, to_scan, filename="data"):
        """
        Scan a single file-like object using the PS API asynchronously.

        :param to_scan: File-like object to scan.
        :param filename: Filename to use
        :return: JSON report
        """
        return self.loop.run_until_complete(self.ps_api.scan_fileobj(to_scan, filename))

    def scan_data(self, data):
        """
        Scan bytes using the PS API asynchronously.

        :param data: Data (in bytes) to submit to be scanned
        :return: JSON report
        """
        return self.loop.run_until_complete(self.ps_api.scan_data(data))

    def scan_file(self, to_scan):
        """
        Scan a single file using the PS API synchronously.

        :param to_scan: Path of file to scan.
        :return: JSON report file
        """

        return self.loop.run_until_complete(self.ps_api.scan_file(to_scan))

    def scan_files(self, files):
        """
        Scan files using the PS API synchronously.

        :param files: List of paths of files to scan.
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.scan_files(files))

    def scan_directory(self, directory, recursive=False):
        """
        Scan files using the PS API synchronously

        :param directory: Directory to scan.
        :param recursive: Whether or not to scan the directory recursively.
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.scan_directory(directory, recursive))

    def search_hashes(self, hashes, hash_type="sha256", rescan=False):
        """
        Scan a collection of hashes using the PS API synchronously.

        :param hashes: Hashes to scan.
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.search_hashes(hashes, hash_type, rescan))

    def search_hash(self, to_scan, hash_type="sha256", rescan=False):
        """
        Scan a single hash using the PS API asynchronously.

        :param to_scan:
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.search_hash(to_scan, hash_type, rescan))

    def lookup_uuid(self, uuid):
        """
        Lookup a scan result by UUID.

        :param uuid: UUID to lookup
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.lookup_uuid(uuid))

    def lookup_uuids(self, uuids):
        """
        Lookup scans result for a list of UUIDs.

        :param uuids: List of UUIDs to lookup
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.lookup_uuids(uuids))

    def post_file(self, file_obj, filename):
        """
        POST file to the PS API to be scanned synchronously.

        :param file_obj: File-like object to POST to the API
        :param filename: Name of file to be given to the API
        :return: Dictionary of the result code and the UUID of the upload (if successful)
        """
        return self.loop.run_until_complete(self.ps_api.post_file(file_obj, filename))

    def download_file(self, h, destination_dir, with_metadata=False, hash_type="sha256"):
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

    def download_files(self, hashes, destination_dir, with_metadata=False, hash_type="sha256"):
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

    def rescan_file(self, h, hash_type="sha256"):
        """
        Rescan a file by its sha256/sha1/md5 hash

        :param h: Hash of the file to rescan
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.rescan_file(h, hash_type))

    def rescan_files(self, hashes, hash_type="sha256"):
        """
        Rescan a file by its sha256/sha1/md5 hash

        :param hashes: Hashes of the files to rescan
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.rescan_files(hashes, hash_type))
