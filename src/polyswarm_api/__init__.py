import aiohttp
import asyncio
import io
import os
import logging
import hashlib
import time
import aiofiles
import json
import urllib
from urllib import parse

logger = logging.getLogger(__name__)


# This will be removed after https://github.com/polyswarm/development-private/issues/191
class EngineResolver(object):

    def _lower_dict(self, d):
        return dict([(k, v.lower()) for k, v in d.items()])

    def __init__(self, network):
        self.engine_map = self._lower_dict({
            "0x89a2d261fecc717fea00f3f449c4ec6c4277cfd8": "ClamAV-Engine",
            "0x04c9aa5ecfd2eb126e93ef6d890c7d669acd1028": "ClamAV-Arbiter",
            "0x0d14c9f70301ceb14cadd847e87aa3b55c72bafd": "Ikarus",
            "0xbea35ed815c40e5a0fe470ec653776350ba49e14": "K7-Engine",
            "0x2a1eeee60a652961a4b6981b6103cdcb63efbd6b": "K7-Arbiter",
            "0x69d568837a75cd385ce6cafa176d878a1d3dc18f": "HatchingArb",
            "0x29f9c138f445dde9330361b4dcf3db635fab2672": "PSArbiter",
            "0x71175ca0caa19144b571a4a8483f7c29e2e15acb": "PSAmbassador",
            "0xb397baa27044a122875cdeb69cae7dd0c62a25db": "DrWeb",
            "0x1ef33589ed52b988a12e8ccc3d367283138b656a": "Lionic",
            "0x026dcc346c7bd89ff7747e8c8efb591d68dc1247": "XVirus",
            "0x15c588a0ff53f6c462fbdaf4285f7935f5d06e7c": "NanoAV",
            "0x17476473b96f8127d3d463ea783fa938cdf1b46b": "Tachyon",
            "0x89b1e316033b72b56bcbbf0e10610446fac26bac": "Zillya",
            "0xfec7050bf25efe1510a854ae63d00a952f0a104f": "PSConsumer",
            "0x06f2929f521cb9ef1ab769177c928784baf5af39": "Alibaba",
            "0x31174c90d709c952948a94b1ab5bc20c10cf364d": "Trustlook",
            "0x7624398543657e3330d6645e4b70a1358697d313": "Rising",
            "0xdae86a74f9996b66557cda627b1e0c5960f9142d": "Jiangmin",
            "0x4adfd72125b44dfc39bcd4eeb5fe1d59c6a75ad9": "IRIS-H",
            "0xb3f58a017e186942166c93107e5d17b1882f6734": "SecureAge",
            "0x4078de09c3cf6301c28b250984e76c437703c71d": "Qihoo",
        }) if network == "stage" else self._lower_dict({
            "0x3750266f07e0590aa16e55c32e08e48878010f8f": "ClamAV-Engine",
            "0xdc6a0f9c3af726ba05aac14605ac9b3b958512d7": "ClamAV-Arbiter",
            "0xa4815d9b8f710e610e8957f4ad13f725a4331cbb": "Ikarus",
            "0xbe0b3ec289aaf9206659f8214c49d083dc1a9e17": "K7-Engine",
            "0xd8b48da78188312c5fc079e532afd48de973767e": "K7-Arbiter",
            "0x1f50cf288b5d19a55ac4c6514e5ba6a704bd03ec": "HatchingArb",
            "0x2e03565b735e2343f7f0501a7772a42b1c0e8893": "PSArbiter",
            "0xbd981a0a28236158196b1291a0ee3df1e9fcc11d": "PSAmbassador",
            "0x7c6a9f9f9f1a67774999ff0e26ffdba2c9347eeb": "DrWeb",
            "0x0457c40dba29166c1d2485f93946688c1fc6cc58": "Lionic",
            "0x59af39803354bd08971ac8e7c6db7410a25ab8da": "XVirus",
            "0x2b4c240b376e5406c5e2559c27789d776ae97efd": "NanoAV",
            "0x1edf29c0977af06215032383f93deb9899d90118": "Tachyon",
            "0xf6019c1f057d26ffb2b41c221e0db4ef88931c86": "Zillya",
            "0x0409ba7c59127f81d8b09b3ec551204ebb3d034e": "PSConsumer",
            "0x10a9ee8552f2c6b2787b240cebefc4a4bcb96f27": "Alibaba",
            "0xf598f7da0d00d9ad21fb00663a7d62a19d43ea61": "Trustlook",
            "0xe2911b3c44a0c50b4d0cfe537a0c1a8b992f6ad0": "Rising",
            "0xa605715c448f4a2319de2ad01f174ca9c440c4eb": "Jiangmin",
            "0xa369322461e6b05ce0b3520765e032a3729ce4c7": "Tylabs",
            "0x47f0c884bb67b3959c166a87f2385f3977769e42": "IRIS-H",
            "0x0480ba80010adeafb67855343b711ae2e15d1b9c": "SecureAge",
        })
        self.reverse_engine_map = {v: k for k, v in self.engine_map.items()}

    def get_engine_name(self, eth_pub):
        return self.engine_map.get(eth_pub.lower(), eth_pub)


class PolyswarmAsyncAPI(object):
    """
    An asynchronous interface to the PolySwarm API.
    """

    def __init__(self, key, uri="https://api.polyswarm.network/v1", get_limit=100,
                 post_limit=1000, timeout=600, force=False, community="lima"):
        """

        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param get_limit: How many simultaneous GET requests to make. Increase at your own risk.
        :param post_limit: How many simultaneous POST requests / second to make. Change at your own risk.
        :param timeout: How long to wait for scans to complete. This timeout will have 45 seconds added to it, the minimum bounty time.
        :param force: Force re-scans if file was already submitted.
        :param community: Community to scan against.
        """
        self._stage_base_domain = "lb.kb.polyswarm.network"
        self.api_key = key

        self.uri = uri

        self.uri_parse = urllib.parse.urlparse(self.uri)

        self.network = "prod"
        self.portal_uri = "https://polyswarm.network/scan/results/"

        if self.uri_parse.hostname.endswith(self._stage_base_domain):
            self.network = "stage"
            # TODO change this to stage.lb.kb.polyswarm.network *after* portal chart in kube
            self.portal_uri = "https://portal.stage.polyswarm.network/scan/results/"

        self.consumer_uri = f"{self.uri}/consumer"
        self.search_uri = f"{self.uri}/search"
        self.download_uri = f"{self.uri}/download"
        self.community_uri = f"{self.consumer_uri}/{community}"
        self.hunt_uri = f"{self.uri}/hunt"
        self.stream_uri = f"{self.uri}/download/stream"

        self.force = force

        self.get_semaphore = asyncio.Semaphore(get_limit)

        # ...sigh
        self.engine_resolver = EngineResolver(self.network)

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

        result['status'] = 'OK'

        return result

    async def get_file_data(self, h, hash_type="sha256"):
        """
        Download file data via the PS API

        :param h: Hash of the file you wish to download
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: Dictionary containing the file data if found, error dictionary if not
        """
        async with self.get_semaphore:
            logger.debug(f"Downloading file hash {h} with api key {self.api_key}")
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f"{self.download_uri}/{hash_type}/{h}",
                                           headers={"Authorization": self.api_key}) as raw_response:
                        try:
                            response = await raw_response.read()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error(f'Received non-json response from PolySwarm API: {response}')
                            response = {"status": "error", "reason": "unknown_error"}
                        if raw_response.status // 100 != 2:
                            if raw_response.status == 404:
                                return {"status": "error", "reason": "file_not_found"}
                            else:
                                return {"status": "error", "reason": "unknown_error"}
                        return {"file_data": response, "status": "OK",
                                "encoding": raw_response.headers.get('Content-Encoding', 'none')}
                except Exception:
                    logger.error('Server request failed')
                    return {'reason': "unknown_error",  'status': "error"}

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
            logger.debug(f"Posting file {filename} with api-key {self.api_key}")
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post(self.community_uri, data=data, params=params,
                                            headers={"Authorization": self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error(f'Received non-json response from PolySwarm API: {response}')
                            response = {"filename": filename, "result": "error"}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            logger.error(f"Error posting to PolySwarm API: {errors}")
                            response = {"filename": filename, "status": "error"}
                        return response
                except Exception:
                    logger.error('Server request failed')
                    return {'filename': filename, 'status': "error"}

    async def lookup_uuid(self, uuid):
        """
        Lookup a UUID using the PS API asynchronously.

        :param uuid: UUID to lookup.
        :return: JSON report file
        """
        async with self.get_semaphore:
            logger.debug(f"Looking up UUID {uuid}")
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f"{self.community_uri}/uuid/{uuid}",
                                           headers={"Authorization": self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error(f'Received non-json response from PolySwarm API: {response}')
                            response = {'files': [], 'uuid': uuid}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            if raw_response.status == 400 and errors.find("has not been created") != -1:
                                return {'files': [], 'uuid': uuid}
                            logger.error(f"Error reading from PolySwarm API: {errors}")
                            return {'files': [], 'uuid': uuid}
                        return self._fix_result(response['result'])
                except Exception:
                    logger.error('Server request failed')
                    return {'reason': "unknown_error", 'status': "error", 'uuid': uuid}

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

            if result.get('status', 'error') == "error":
                return result

            if self._reveal_closed(result):
                return result

            await asyncio.sleep(1)

            if time.time()-started > self.timeout >= 0:
                break

        logger.warning(f"Failed to get results for uuid {uuid} in time.")
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
            logger.error(f"Failed to get UUID for scan of file {filename}")
            return {"filename": filename, "files": []}

        logger.info(f"Successfully submitted file {filename}, UUID {uuid}")

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

    async def search_hash(self, to_scan, hash_type="sha256"):
        """
        Search for a single hash using the PS API asynchronously.

        :param to_scan: Hash to search for
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: JSON report file
        """
        async with self.get_semaphore:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get("{}/{}/{}".format(self.search_uri, hash_type, to_scan),
                                           headers={"Authorization": self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            raise Exception('Received non-json response from PolySwarm API: %s', response)
                        if raw_response.status // 100 != 2:
                            if raw_response.status == 404 and response.get("errors").find("has not been in any") != -1:
                                return {'hash': to_scan, "search": f"{hash_type}={to_scan}", "result": []}

                            errors = response.get('errors')
                            raise Exception("Error reading from PolySwarm API: {}".format(errors))
                except Exception:
                    logger.error('Server request failed')
                    return {'reason': "unknown_error", 'result': [], 'hash': to_scan,
                            "search": f"{hash_type}={to_scan}", "status": "error"}

        response['search'] = f"{hash_type}={to_scan}"
        return response

    async def rescan_hash(self, to_rescan, hash_type="sha256"):
        """
        Start a rescan for single hash using the PS API asynchronously.

        :param to_rescan: hash of the file to rescan
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: JSON report file
        """
        # TODO check file-size. For now, we need to handle error.
        async with self.get_semaphore:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f"{self.community_uri}/rescan/{hash_type}/{to_rescan}",
                                           headers={"Authorization": self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            raise Exception(f'Received non-json response from PolySwarm API: {response}')
                        if raw_response.status // 100 != 2:
                            # TODO this behavior in the API needs to change
                            if raw_response.status == 400 and response.get("errors").find("has not been in any") != -1:
                                return {'hash': to_rescan}

                        if raw_response.status == 404:
                            return {"hash": to_rescan, "reason": "file_not_found", "status": "error"}

                        errors = response.get('errors')
                        logger.error(f"Error posting to PolySwarm API: {errors}")
                        response = {"hash": to_rescan, "status": "error"}
                except Exception:
                    logger.error('Server request failed')
                    return {'reason': "unknown_error", 'result': "error", "hash": to_rescan}

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

    async def search_hashes(self, hashes, hash_type="sha256"):
        """
        Scan a collection of hashes using the PS API asynchronously.

        :param hashes: Hashes to scan.
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.search_hash(h, hash_type) for h in hashes])

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
            if 'result' in meta_results and len(meta_results['result']) > 0:
                async with aiofiles.open(out_path+".json", mode="w") as f:
                    # this is a hash search, only return one result
                    await f.write(json.dumps(meta_results["result"][0]))

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

    async def _new_hunt(self, rules, scan_type):
        """
        Create a new scan, either live or historical.

        :param rules: String containing YARA rules to user
        :param scan_type: Type of scan, "live" or "historical"
        :return: ID of the new scan
        """
        data = {"yara": rules}

        async with self.post_semaphore:
            logger.debug(f"Posting rules with api-key {self.api_key}")
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post(f"{self.hunt_uri}/{scan_type}", json=data,
                                            headers={"Authorization": self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error(f'Received non-json response from PolySwarm API: {response}')
                            response = {"status": "error", 'result': []}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            logger.error(f"Error posting to PolySwarm API: {errors}")
                            response = {"status": "error", 'result': []}
                        return response
                except Exception:
                    logger.error('Server request failed')
                    return {'status': "error", 'result': []}

    async def new_live_hunt(self, rules):
        """
        Create a new live scan, and replace the currently running YARA rules.

        :param rules: String containing YARA rules to install
        :return: ID of the new scan.
        """
        return await self._new_hunt(rules, "live")

    async def new_historical_hunt(self, rules):
        """
        Run a new historical scan.

        :param rules: String containing YARA rules to install
        :return: ID of the new scan.
        """
        return await self._new_hunt(rules, "historical")

    async def _get_hunt_results(self, rule_id=None, scan_type="live"):
        """

        :param rule_id: Rule ID (None if latest rule results are desired)
        :param scan_type: Type of scan, "live" or "historical"
        :return: Matches to the rules
        """

        params = {}
        if rule_id is not None:
            params['id'] = rule_id

        async with self.get_semaphore:
            logger.debug(f"Reading results with api-key {self.api_key}")
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f"{self.hunt_uri}/{scan_type}/results", params=params,
                                            headers={"Authorization": self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error(f'Received non-json response from PolySwarm API: {response}')
                            response = {"status": "error", 'result': []}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            logger.error(f"Error reading from PolySwarm API: {errors}")
                            response = {"status": "error", 'result': []}
                        return response
                except Exception:
                    logger.error('Server request failed')
                    return {'status': "error", 'result': []}

    async def get_live_results(self, rule_id=None):
        """
        Get results from a live scan

        :param rule_id: Rule ID (None if latest rule results are desired)
        :return: Matches to the rules
        """
        return await self._get_hunt_results(rule_id, "live")

    async def get_historical_results(self, rule_id=None):
        """
        Get results from a historical scan

        :param rule_id: Rule ID (None if latest rule results are desired)
        :return: Matches to the rules
        """
        return await self._get_hunt_results(rule_id, "historical")

    async def get_stream(self, destination_dir=None):
        async with aiohttp.ClientSession() as session:
            async with self.get_semaphore:
                logger.debug(f"Reading results with api-key {self.api_key}")
                try:
                    async with session.get(f"{self.stream_uri}",
                                           headers={"Authorization": self.api_key},
                                           params={"since": 1440}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error(f'Received non-json response from PolySwarm API: {response}')
                            response = {"result": "error"}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            logger.error(f"Error posting to PolySwarm API: {errors}")
                            response = {"status": "error"}
                except Exception:
                    logger.error('Server request failed')
                    return {'status': "error"}

                if destination_dir is None:
                    return response

            for community in response['result'].values():
                for archive in community:
                    async with self.get_semaphore:
                        try:
                            async with session.get(archive) as raw_response:
                                try:
                                    file_name = parse.urlparse(archive).path.split("/")[-1]
                                    out_path = os.path.join(destination_dir, file_name)
                                    async with aiofiles.open(out_path, mode="wb") as out:
                                        while True:
                                            chunk = await raw_response.content.read(2*1024*1024)
                                            if not chunk:
                                                break
                                            await out.write(chunk)
                                except Exception:
                                    response = await raw_response.read() if raw_response else 'None'
                                    logger.error(f'Received non-json response from PolySwarm API: {response}')
                                if raw_response.status // 100 != 2:
                                    errors = response.get('errors')
                                    logger.error(f"Error reading from PolySwarm API: {errors}")
                        except Exception:
                            logger.error('Server request failed')
                            return {'status': "error"}
            return response


class PolyswarmAPI(object):
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri="https://api.polyswarm.network/v1", get_limit=100,
                 post_limit=1000, timeout=600, force=False, community="lima"):
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

    def search_hashes(self, hashes, hash_type="sha256"):
        """
        Scan a collection of hashes using the PS API synchronously.

        :param hashes: Hashes to scan.
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.search_hashes(hashes, hash_type))

    def search_hash(self, to_scan, hash_type="sha256"):
        """
        Scan a single hash using the PS API asynchronously.

        :param to_scan:
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.search_hash(to_scan, hash_type))

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

    def get_live_results(self, rule_id=None):
        """
        Get results from a live hunt

        :param rule_id: Rule ID (None if latest rule results are desired)
        :return: Matches to the rules
        """
        return self.loop.run_until_complete(self.ps_api.get_live_results(rule_id))

    def get_historical_results(self, rule_id=None):
        """
        Get results from a historical hunt

        :param rule_id: Rule ID (None if latest rule results are desired)
        :return: Matches to the rules
        """
        return self.loop.run_until_complete(self.ps_api.get_historical_results(rule_id))

    def get_stream(self, destination_dir=None):
        """
        Get stream of tarballs from communities you have the stream privilege on.
        Contact us at info@polyswarm.io for more info on enabling this feature.

        :param destination_dir: Directory to down files to. None if you just want the list of URLs.

        :return: List of signed S3 URLs for tarballs over the last two days
        """
        return self.loop.run_until_complete(self.ps_api.get_stream(destination_dir))
