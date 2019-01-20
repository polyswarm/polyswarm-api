import aiohttp
import asyncio
import io
import os
import json

# This will be removed after https://github.com/polyswarm/development-private/issues/191
class EngineResolver(object):
    def _lower_dict(self, d):
        return dict([(k, v.lower()) for k, v in d.items()])

    def __init__(self, network):
        # TODO this is only for staging and should be dynamic
        # removed right now until cleared with engine authors
        self.engine_map = {}
        self.reverse_engine_map = {v: k for k, v in self.engine_map.items()}

    def get_engine_name(self, eth_pub):
        return self.engine_map.get(eth_pub.lower(), eth_pub)


def is_async(func):
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
                 post_limit=1, force=False, wait_for_arbitration=False):
        """

        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param is_async: Enable if using async. Controls whether sessions are destroyed each call.
        :param get_limit: How many simultaneous GET requests to make. Increase at your own risk.
        :param post_limit: How many simultaneous POST requests to make. Increase at your own risk.
        :param force: Force re-scans if file was already submitted.
        :param wait_for_arbitration: When scanning files, wait for arbiters to vote. This could take awhile.
        """
        self.api_key = key
        self.loop = asyncio.get_event_loop()
        self.uri = uri
        self.session = None

        # separate async API might be better here, TODO
        self.is_async = is_async

        self.force = force
        self.get_semaphore = asyncio.Semaphore(get_limit)
        self.post_semaphore = asyncio.Semaphore(post_limit)

        # ...sigh
        self.engine_resolver = EngineResolver("prod" if uri.find("stage") == -1 else "stage")

        self.wait_for_arbitration = wait_for_arbitration

    def _fix_engine_names(self, result):
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

    async def _post_file(self, file_obj, filename):
        """
        POST file to the PS API to be scanned.

        :param file_obj: File-like object to POST to the API
        :return: Dictionary of the result code and the UUID of the upload (if successful)
        """
        # TODO check file-size. For now, we need to handle error.
        data = aiohttp.FormData()
        data.add_field('file', file_obj, filename=filename)

        params = {"force": True} if self.force else {}
        async with self.post_semaphore:
            async with self.session.post(self.uri, data=data, params=params,
                                           headers={"Authorization": self.api_key}) as raw_response:
                try:
                    response = await raw_response.json()
                except:
                    response = await raw_response.read() if raw_response else 'None'
                    raise Exception('Received non-json response from PolySwarm API: %s', response)
                if raw_response.status // 100 != 2:
                    errors = response.get('errors')
                    raise Exception("Error posting to PolySwarm API: {}".format(errors))
                return response

    async def _get_results_from_uuid(self, uuid):
        async with self.get_semaphore:
            async with self.session.get("%s/uuid/%s" % (self.uri, uuid),
                                        headers={"Authorization": self.api_key}) as raw_response:
                try:
                    response = await raw_response.json()
                except:
                    response = await raw_response.read() if raw_response else 'None'
                    raise Exception('Received non-json response from PolySwarm API: %s', response)
                if raw_response.status // 100 != 2:
                    errors = response.get('errors')
                    raise Exception("Error reading from PolySwarm API: {}".format(errors))
        return self._fix_engine_names(response['result'])

    @is_async
    async def scan_fileobj_async(self, to_scan, filename="data2"):
        """
        Scan a single file-like object using the PS API asynchronously.

        :param to_scan: File-like object to scan.
        :param filename: Filename to use
        :return: JSON report
        """

        result = await self._post_file(to_scan, filename)
        if result['status'] == "OK":
            uuid = result['result']
        else:
            raise Exception("Failed to gather UUID for scan")

        # TODO hard code or not here?
        retries = 20

        # check UUID status immediately, in case the file already exists
        result = await self._get_results_from_uuid(uuid)

        if self._reveal_closed(result):
            return result

        # wait for bounty to complete (20 blocks for assert, 25 for reveal)
        # TODO why are we using those numbers above, longer for reveal than assert is silly.
        await asyncio.sleep(45)

        while retries > 0:
            result = await self._get_results_from_uuid(uuid)

            if self._reveal_closed(result):
                return result

            await asyncio.sleep(1)

            retries -= 1

        print("WARN: Failed to get results in time.")
        return {'files': []}

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
            async with self.session.get("%s/hash/%s" % (self.uri, to_scan),
                                           headers={"Authorization": self.api_key}) as raw_response:
                try:
                    response = await raw_response.json()
                except:
                    response = await raw_response.read() if raw_response else 'None'
                    raise Exception('Received non-json response from PolySwarm API: %s', response)
                if raw_response.status // 100 != 2:
                    errors = response.get('errors')
                    raise Exception("Error reading from PolySwarm API: {}".format(errors))

        return await self._get_results_from_uuid(response['result'])

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

    def __del__(self):
        """
        Used to clean up sessions on death for async usage.

        :return: None
        """
        if self.is_async and self.session is not None:
            self.session.close()
