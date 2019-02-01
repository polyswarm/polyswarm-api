import aiohttp
import asyncio
import io
import os
import json
import logging

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
            "0x31174c90d709c952948a94b1ab5bc20c10cf364d": "Trustlook",
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
            "0xf598f7da0d00d9ad21fb00663a7d62a19d43ea61": "Trustlook",
        })
        self.reverse_engine_map = {v: k for k, v in self.engine_map.items()}

    def get_engine_name(self, eth_pub):
        return self.engine_map.get(eth_pub.lower(), eth_pub)


def is_async(func):
    """
    Wrapper that ensures an aiohttp session exists in PolyswarmAPI
    on entry into an async method in the library.

    :param func: PolyswarmAPI method
    :return: wrapped PolyswarmAPI method
    """
    async def wrap_with_session(self, *args, **kwargs):
        # only let the entry function manage the session
        # session for now only lives for the life of the call,
        # acceptable for now
        manage_session = self.session is None
        if manage_session:
            self.session = aiohttp.ClientSession()

        res = await func(self, *args, **kwargs)

        if manage_session and not self.is_async:
            self.session.close()
            self.session = None

        return res
    return wrap_with_session


class PolyswarmAPI(object):
    """An interface to the public and private PolySwarm APIs."""

    # TODO this should point to api.polyswarm.network
    def __init__(self, key, uri="https://consumer.epoch.polyswarm.network", is_async=False, get_limit=10,
                 post_limit=4, timeout=120, force=False):
        """

        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param is_async: Enable if using async. Controls whether sessions are destroyed each call.
        :param get_limit: How many simultaneous GET requests to make. Increase at your own risk.
        :param post_limit: How many simultaneous POST requests / second to make. Change at your own risk.
        :param timeout: How long to wait for scans to complete. This should be at least 45 seconds for round to complete
        :param force: Force re-scans if file was already submitted.
        """
        self.api_key = key
        self.loop = asyncio.get_event_loop()
        self.uri = uri
        self.session = None

        # separate async API might be better here, TODO
        self.is_async = is_async

        self.force = force
        self.get_semaphore = asyncio.Semaphore(get_limit)

        self.network = "prod" if uri.find("stage") == -1 else "stage"

        self.portal_uri = "https://polyswarm.network/scan/results/" if self.network == "prod" else "https://portal.stage.polyswarm.network/"

        # ...sigh
        self.engine_resolver = EngineResolver(self.network)

        self.post_semaphore = asyncio.Semaphore(post_limit)

        self.timeout = timeout

    def _fix_result(self, result):
        """
        For now, since the name-ETH address mappings are not added by consume, we add them using
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

    def _reveal_closed(self, result):
        """
        Check result dict if reveal window is closed

        :param result: Result dict from UUID check
        :return: If the assertion reveal window is closed
        """

        # TODO this really should be better named in the JSON, as there are multiple windows
        return all('window_closed' in file and file['window_closed']
                   for file in result['files'])

    @is_async
    async def post_file_async(self, file_obj, filename):
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
            async with self.session.post(self.uri, data=data, params=params,
                                           headers={"Authorization": self.api_key}) as raw_response:
                try:
                    response = await raw_response.json()
                except:
                    response = await raw_response.read() if raw_response else 'None'
                    logger.error('Received non-json response from PolySwarm API: %s', response)
                    response = {"filename": filename, "result": "error"}
                if raw_response.status // 100 != 2:
                    errors = response.get('errors')
                    logger.error("Error posting to PolySwarm API: {}".format(errors))
                    response = {"filename": filename, "status": "error"}
                return response

    @is_async
    async def lookup_uuid_async(self, uuid):
        """
        Lookup a UUID using the PS API asynchronously.

        :param uuid: UUID to lookup.
        :return: JSON report file
        """
        async with self.get_semaphore:
            logger.debug("Looking up UUID %s", uuid)
            async with self.session.get("%s/uuid/%s" % (self.uri, uuid)) as raw_response:
                try:
                    response = await raw_response.json()
                except:
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

    @is_async
    async def scan_fileobj_async(self, to_scan, filename="data2"):
        """
        Scan a single file-like object using the PS API asynchronously.

        :param to_scan: File-like object to scan.
        :param filename: Filename to use
        :return: JSON report
        """

        result = await self.post_file_async(to_scan, filename)
        if result['status'] == "OK":
            uuid = result['result']
        else:
            logger.error("Failed to get UUID for scan of file %s", filename)
            return {"filename": filename, "files": []}

        logger.info("Successfully submitted file %s, UUID %s" % (filename, uuid))

        retries = self.timeout

        # check UUID status immediately, in case the file already exists
        result = await self.lookup_uuid_async(uuid)

        if self._reveal_closed(result):
            return result

        # wait for bounty to complete (20 blocks for assert, 25 for reveal)
        # TODO why are we using those numbers above, longer for reveal than assert is silly.
        await asyncio.sleep(45)

        while retries > 0:
            result = await self.lookup_uuid_async(uuid)

            if self._reveal_closed(result):
                return result

            await asyncio.sleep(1)

            retries -= 1

        logger.warn("Failed to get results for file %s (%s) in time.", filename, uuid)
        return {'files': [], 'uuid': uuid}

    @is_async
    async def scan_data_async(self, data):
        """
        Scan bytes using the PS API asynchronously.

        :param data: Data (in bytes) to submit to be scanned
        :return: JSON report
        """
        return await self.scan_fileobj_async(io.BytesIO(data))

    @is_async
    async def scan_file_async(self, to_scan):
        """
        Scan a single file using the PS API asynchronously.

        :param to_scan: Path of file to scan.
        :return: JSON report file
        """

        with open(to_scan, "rb") as fobj:
            return await self.scan_fileobj_async(fobj, os.path.basename(to_scan))

    @is_async
    async def scan_hash_async(self, to_scan):
        """
        Scan a single hash using the PS API asynchronously.

        :param to_scan:
        :return: JSON report file
        """
        # TODO check file-size. For now, we need to handle error.
        async with self.get_semaphore:
            async with self.session.get("%s/hash/%s" % (self.uri, to_scan)) as raw_response:
                try:
                    response = await raw_response.json()
                except:
                    response = await raw_response.read() if raw_response else 'None'
                    raise Exception('Received non-json response from PolySwarm API: %s', response)
                if raw_response.status // 100 != 2:
                    # TODO this behavior in the API needs to change
                    if raw_response.status == 400 and response.get("errors").find("has not been in any") != -1:
                        return {'hash': to_scan}

                    errors = response.get('errors')
                    raise Exception("Error reading from PolySwarm API: {}".format(errors))

        return await self.lookup_uuid_async(response['result'])

    @is_async
    async def scan_files_async(self, files):
        """
        Scan a collection of files using the PS API asynchronously.

        :param files: List of paths of files to scan.
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.scan_file_async(f) for f in files])

        return results

    @is_async
    async def lookup_uuids_async(self, uuids):
        """
        Scan a collection of uuids using the PS API asynchronously.

        :param uuids: List of uuids to scan.
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.lookup_uuid_async(u) for u in uuids])

        return results

    @is_async
    async def scan_directory_async(self, directory, recursive=False):
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

        return await self.scan_files_async(file_list)

    @is_async
    async def scan_hashes_async(self, hashes):
        """
        Scan a collection of hashes using the PS API asynchronously.

        :param hashes: Hashes to scan.
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.scan_hash_async(h) for h in hashes])

        return results

    def scan_fileobj(self, to_scan, filename="data"):
        """
        Scan a single file-like object using the PS API asynchronously.

        :param to_scan: File-like object to scan.
        :param filename: Filename to use
        :return: JSON report
        """
        return self.loop.run_until_complete(self.scan_fileobj_async(to_scan, filename))

    def scan_data(self, data):
        """
        Scan bytes using the PS API asynchronously.

        :param data: Data (in bytes) to submit to be scanned
        :return: JSON report
        """
        return self.loop.run_until_complete(self.scan_data_async(data))

    def scan_file(self, to_scan):
        """
        Scan a single file using the PS API synchronously.

        :param to_scan: Path of file to scan.
        :return: JSON report file
        """

        return self.loop.run_until_complete(self.scan_file_async(to_scan))

    def scan_files(self, files):
        """
        Scan files using the PS API synchronously.

        :param files: List of paths of files to scan.
        :return:
        """
        return self.loop.run_until_complete(self.scan_files_async(files))

    def scan_directory(self, directory, recursive=False):
        """
        Scan files using the PS API synchronously

        :param directory: Directory to scan.
        :param recursive: Whether or not to scan the directory recursively.
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.scan_directory_async(directory, recursive))

    def scan_hashes(self, hashes):
        """
        Scan a collection of hashes using the PS API synchronously.

        :param hashes: Hashes to scan.
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.scan_hashes_async(hashes))

    def scan_hash(self, to_scan):
        """
        Scan a single hash using the PS API asynchronously.

        :param to_scan:
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.scan_hash_async(to_scan))

    def lookup_uuid(self, uuid):
        """
        Lookup a scan result by UUID.

        :param uuid: UUID to lookup
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.lookup_uuid_async(uuid))

    def lookup_uuids(self, uuids):
        """
        Lookup scans result for a list of UUIDs.

        :param uuids: List of UUIDs to lookup
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.lookup_uuids_async(uuids))

    async def post_file(self, file_obj, filename):
        """
        POST file to the PS API to be scanned synchronously.

        :param file_obj: File-like object to POST to the API
        :param filename: Name of file to be given to the API
        :return: Dictionary of the result code and the UUID of the upload (if successful)
        """
        return self.loop.run_until_complete(self.post_file_async(file_obj, filename))

    def __del__(self):
        """
        Used to clean up sessions on death for async usage.

        :return: None
        """
        if self.is_async and self.session is not None:
            self.session.close()
