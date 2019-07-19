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

from polyswarmartifact import ArtifactType

from .engine_resolver import EngineResolver
from ._version import __version__, __release_url__

logger = logging.getLogger(__name__)


class PolyswarmAsyncAPI(object):
    """
    An asynchronous interface to the PolySwarm API.
    """

    def __init__(self, key, uri='https://api.polyswarm.network/v1', get_limit=100,
                 post_limit=1000, timeout=600, force=False, community='lima', check_version=True):
        """

        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param get_limit: How many simultaneous GET requests to make. Increase at your own risk.
        :param post_limit: How many simultaneous POST requests / second to make. Change at your own risk.
        :param timeout: How long to wait for scans to complete. This timeout will have 45 seconds added to it, the minimum bounty time.
        :param force: Force re-scans if file was already submitted.
        :param community: Community to scan against.
        :param check_version: Whether or not to check Github for version information
        """
        self._stage_base_domain = 'lb.kb.polyswarm.network'
        self.api_key = key

        self.uri = uri

        self.uri_parse = urllib.parse.urlparse(self.uri)

        self.network = 'prod'
        self.portal_uri = 'https://polyswarm.network/scan/results/'

        if self.uri_parse.hostname.endswith(self._stage_base_domain):
            self.network = 'stage'
            # TODO change this to stage.lb.kb.polyswarm.network *after* portal chart in kube
            self.portal_uri = 'https://portal.stage.polyswarm.network/scan/results/'

        self.consumer_uri = '{uri}/consumer'.format(uri=self.uri)
        self.search_uri = '{uri}/search'.format(uri=self.uri)
        self.download_uri = '{uri}/download'.format(uri=self.uri)
        self.community_uri = '{consumer_uri}/{community}'.format(consumer_uri=self.consumer_uri, community=community)
        self.hunt_uri = '{uri}/hunt'.format(uri=self.uri)
        self.stream_uri = '{uri}/download/stream'.format(uri=self.uri)

        self.force = force

        self.get_semaphore = asyncio.Semaphore(get_limit)

        self.network = 'prod' if uri.find('lb.kb') == -1 else 'lb.kb'

        # TODO does this need commmunity?
        self.portal_uri = 'https://polyswarm.network/scan/results/' if self.network == 'prod' else 'https://portal.stage.polyswarm.network/'

        self.engine_resolver = EngineResolver(self.uri)

        self.post_semaphore = asyncio.Semaphore(post_limit)

        self.timeout = timeout

        if check_version:
            up_to_date, version = asyncio.get_event_loop().run_until_complete(self.check_version())
            if not up_to_date and version is not None:
                logger.warning('PolySwarmAPI out of date. Installed version: %s, Current version: %s', __version__,
                               version)
                logger.warning('To update, run: pip install -U polyswarm-api')
                logger.warning('Please upgrade or certain features may not work properly.')

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
            result['permalink'] = self.portal_uri + result['uuid']
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

    async def check_version(self):
        """
        Checks GitHub to see if you have the latest version installed.

        :return: True,latest_version tuple if latest, False,latest_version tuple if not
        """
        check_fail_msg = 'Could not check GitHub for latest release (installed version is {version}). ' \
                         'Please check version manually.'.format(version=__version__)
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(__release_url__) as raw_response:
                    try:
                        j = await raw_response.json()
                    except Exception:
                        logger.warning(check_fail_msg)
                        return False, None

                    release = j.get('tag_name', None)

                    if release is None:
                        logger.warning(check_fail_msg)
                        return False, None

                    if release != __version__:
                        return False, release
                    else:
                        return True, release

            except Exception:
                logger.warning(check_fail_msg)
                return False, None

    async def get_file_data(self, h, hash_type='sha256'):
        """
        Download file data via the PS API

        :param h: Hash of the file you wish to download
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: Dictionary containing the file data if found, error dictionary if not
        """
        async with self.get_semaphore:
            logger.debug('Downloading file hash %s with api key %s', h, self.api_key)
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get('{download_uri}/{hash_type}/{hash}'.format(download_uri=self.download_uri,
                                                                                      hash_type=hash_type,
                                                                                      hash=h),
                                           headers={'Authorization': self.api_key}) as raw_response:
                        try:
                            response = await raw_response.read()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error('Received non-json response from PolySwarm API: %s', response)
                            response = {'status': 'error', 'reason': 'unknown_error'}
                        if raw_response.status // 100 != 2:
                            if raw_response.status == 404:
                                return {'status': 'error', 'reason': 'file_not_found'}
                            else:
                                return {'status': 'error', 'reason': 'unknown_error'}
                        return {'file_data': response, 'status': 'OK',
                                'encoding': raw_response.headers.get('Content-Encoding', 'none')}
                except Exception:
                    logger.error('Server request failed')
                    return {'reason': 'unknown_error', 'status': 'error'}

    async def post_artifact(self, artifact_data_obj, artifact_data_name, artifact_type=ArtifactType.FILE):
        """
        POST artifact to the PS API to be scanned asynchronously.

        :param artifact_data_obj: File-like object to POST to the API
        :param artifact_data_name: Name of data to be given to the API
        :param artifact_type: Type of artifact being posted
        :return: Dictionary of the result code and the UUID of the upload (if successful)
        """
        # TODO check file-size. For now, we need to handle error.
        data = aiohttp.FormData()
        data.add_field('file', artifact_data_obj, filename=artifact_data_name)
        data.add_field('artifact-type', artifact_type.name)

        params = {'force': 'true'} if self.force else {}
        async with self.post_semaphore:
            logger.debug('Posting artifact %s with api-key %s', artifact_data_name, self.api_key)
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post(self.community_uri, data=data, params=params,
                                            headers={'Authorization': self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error('Received non-json response from PolySwarm API: %s', response)
                            response = {'filename': artifact_data_name, 'result': 'error'}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            logger.error('Error posting to PolySwarm API: %s', errors)
                            response = {'filename': artifact_data_name, 'status': 'error'}
                        return response
                except Exception:
                    logger.error('Server request failed')
                    return {'filename': artifact_data_name, 'status': 'error'}

    async def post_url(self, url, url_name='url'):
        """
        POST URL to the PS API to be scanned asynchronously

        :param url: URL to scan
        :param url_name: Name referring to URL
        :return: Dictionary of the result code and the UUID of the scan (if successful)
        """
        return await self.post_artifact(io.StringIO(url), url_name, ArtifactType.URL)

    async def post_file(self, file_obj, filename):
        """
        POST file to the PS API to be scanned asynchronously.

        :param file_obj: File-like object to POST to the API
        :param filename: Name of file to be given to the API
        :return: Dictionary of the result code and the UUID of the upload (if successful)
        """
        # TODO check file-size. For now, we need to handle error.
        return await self.post_artifact(file_obj, filename, ArtifactType.FILE)

    async def lookup_uuid(self, uuid):
        """
        Lookup a UUID using the PS API asynchronously.

        :param uuid: UUID to lookup.
        :return: JSON report file
        """
        async with self.get_semaphore:
            logger.debug('Looking up UUID %s', uuid)
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get('{community_uri}/uuid/{uuid}'.format(community_uri=self.community_uri,
                                                                                uuid=uuid),
                                           headers={'Authorization': self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error('Received non-json response from PolySwarm API: %s', response)
                            response = {'files': [], 'uuid': uuid}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            if raw_response.status == 400 and errors.find('has not been created') != -1:
                                return {'files': [], 'uuid': uuid}
                            logger.error('Error reading from PolySwarm API: %s', errors)
                            return {'files': [], 'uuid': uuid}
                        return self._fix_result(response['result'])
                except Exception:
                    logger.error('Server request failed')
                    return {'reason': 'unknown_error', 'status': 'error', 'uuid': uuid}

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

            if result.get('status', 'error') == 'error':
                return result

            if self._reveal_closed(result):
                return result

            await asyncio.sleep(1)

            if time.time() - started > self.timeout >= 0:
                break

        logger.warning('Failed to get results for uuid %s in time.', uuid)
        return {'files': result['files'], 'uuid': uuid}

    async def scan_url(self, to_scan, name='url'):
        """
        Scan a single URL using the PS API asynchronously

        :param to_scan: URL to scan
        :param name: name to associate with the artifact
        :return: JSON report
        """
        result = await self.post_url(to_scan, name)
        if result['status'] == 'OK':
            uuid = result['result']
        else:
            logger.error('Failed to get UUID for scan of file %s', name)
            return {'filename': name, 'files': []}

        logger.info('Successfully submitted file %s, UUID %s', name, uuid)

        return await self._wait_for_uuid(uuid)

    async def scan_fileobj(self, to_scan, filename='data'):
        """
        Scan a single file-like object using the PS API asynchronously.

        :param to_scan: File-like object to scan.
        :param filename: Filename to use
        :return: JSON report
        """

        result = await self.post_file(to_scan, filename)
        if result['status'] == 'OK':
            uuid = result['result']
        else:
            logger.error('Failed to get UUID for scan of file %s', filename)
            return {'filename': filename, 'files': []}

        logger.info('Successfully submitted file %s, UUID %s', filename, uuid)

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

        with open(to_scan, 'rb') as fobj:
            return await self.scan_fileobj(fobj, os.path.basename(to_scan))

    async def search_hash(self, to_scan, hash_type='sha256'):
        """
        Search for a single hash using the PS API asynchronously.

        :param to_scan: Hash to search for
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: JSON report file
        """
        async with self.get_semaphore:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(self.search_uri,
                                           params={'type': hash_type, 'hash': to_scan, 'with_instances': 'true'},
                                           headers={'Authorization': self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            raise Exception('Received non-json response from PolySwarm API: {}'.format(response))
                        if raw_response.status // 100 != 2:
                            if raw_response.status == 404:
                                return {'hash': to_scan,
                                        'search': '{hash_type}={hash}'.format(hash_type=hash_type, hash=to_scan),
                                        'result': [],
                                        'status': 'OK'}

                            errors = response.get('errors')
                            raise Exception('Error reading from PolySwarm API: {}'.format(errors))
                except Exception:
                    logger.error('Server request failed')
                    return {'reason': 'unknown_error', 'result': [], 'hash': to_scan,
                            'search': '{hash_type}={hash}'.format(hash_type=hash_type, hash=to_scan),
                            'status': 'error'}

        response['search'] = '{hash_type}={hash}'.format(hash_type=hash_type, hash=to_scan)
        return response

    async def search_query(self, query, raw=True):
        """
        Search by Elasticsearch query using the PS API asynchronously.

        :param query: Elasticsearch JSON query or search string
        :param raw: If true, treated as ES JSON query. If false, treated as an ES query_string
        :return: JSON report file
        """

        if not raw:
            query = {
                'query': {
                    'query_string': {
                        'query': query
                    }
                }
            }
        async with self.get_semaphore:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(self.search_uri,
                                           headers={'Authorization': self.api_key},
                                           params={'type': 'metadata', 'with_instances': 'true'},
                                           json=query) as raw_response:

                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            response = response.decode('utf-8')
                            raise Exception('Received non-json response from PolySwarm API: {}'.format(response))

                        if raw_response.status == 404:
                            return {'search': query, 'result': [], 'status': 'OK'}
                        elif raw_response.status // 100 != 2:
                            raise Exception('Error reading from PolySwarm API: {}'.format(response['errors']))

                except Exception as e:
                    logger.error('Server request failed: %s', e)
                    return {'reason': 'unknown_error', 'result': [], 'search': query, 'status': 'error'}

        response['search'] = query
        return response

    async def rescan_hash(self, to_rescan, hash_type='sha256'):
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
                    async with session.get(
                            '{community_uri}/rescan/{hash_type}/{hash}'.format(community_uri=self.community_uri,
                                                                               hash_type=hash_type,
                                                                               hash=to_rescan),
                            headers={'Authorization': self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            raise Exception('Received non-json response from PolySwarm API: %s', response)

                        if raw_response.status == 404:
                            return {'hash': to_rescan, 'reason': 'file_not_found', 'status': 'error',
                                    'result': 'not found'}

                        if raw_response.status // 100 != 2:
                            # TODO this behavior in the API needs to change
                            if raw_response.status == 400 and response.get('errors').find('has not been in any') != -1:
                                return {'hash': to_rescan, 'status': 'error', 'result': 'not found'}

                            errors = response.get('errors')
                            logger.error('Error posting to PolySwarm API: %s', errors)
                            return {'hash': to_rescan, 'status': 'error', 'result': errors}
                except Exception:
                    logger.error('Server request failed')
                    return {'reason': 'unknown_error', 'result': 'error', 'hash': to_rescan, 'status': 'error'}

        return response

    async def scan_files(self, files):
        """
        Scan a collection of files using the PS API asynchronously.

        :param files: List of paths of files to scan.
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.scan_file(f) for f in files])

        return results

    async def scan_urls(self, urls):
        """
        Scan a collection of URLs using the PS API asynchronously.

        :param urls: List of URLs to scan.
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.scan_url(f) for f in urls])

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

    async def search_hashes(self, hashes, hash_type='sha256'):
        """
        Scan a collection of hashes using the PS API asynchronously.

        :param hashes: Hashes to scan.
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        results = await asyncio.gather(*[self.search_hash(h, hash_type) for h in hashes])

        return results

    async def download_file(self, h, destination_dir, with_metadata=False, hash_type='sha256'):
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

        if results['status'] == 'OK':
            async with aiofiles.open(out_path, mode='wb') as f:
                await f.write(results['file_data'])
        else:
            results['file_hash'] = h
            return results

        if with_metadata:
            meta_results = await self.search_hash(h, hash_type=hash_type)
            if 'result' in meta_results and len(meta_results['result']) > 0:
                async with aiofiles.open(out_path + '.json', mode='w') as f:
                    # this is a hash search, only return one result
                    await f.write(json.dumps(meta_results['result'][0]))

        return {'file_path': out_path, 'status': 'OK', 'file_hash': h}

    async def download_files(self, hashes, destination_dir, with_metadata=True, hash_type='sha256'):
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

    async def rescan_file(self, h, hash_type='sha256'):
        """
        Rescan a file by its sha256/sha1/md5 hash

        :param h: Hash of the file to rescan
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: JSON report file
        """
        result = await self.rescan_hash(h, hash_type)

        if result['status'] != 'OK':
            return result

        return await self._wait_for_uuid(result['result'])

    async def rescan_files(self, hashes, hash_type='sha256'):
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
        data = {'yara': rules}

        async with self.post_semaphore:
            logger.debug('Posting rules with api-key %s', self.api_key)
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post('{hunt_uri}/{scan_type}'.format(hunt_uri=self.hunt_uri,
                                                                            scan_type=scan_type),
                                            json=data,
                                            headers={'Authorization': self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error('Received non-json response from PolySwarm API: %s', response)
                            response = {'status': 'error', 'result': []}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            logger.error('Error posting to PolySwarm API: %s', errors)
                            response = {'status': 'error', 'result': []}
                        return response
                except Exception:
                    logger.error('Server request failed')
                    return {'status': 'error', 'result': []}

    async def new_live_hunt(self, rules):
        """
        Create a new live scan, and replace the currently running YARA rules.

        :param rules: String containing YARA rules to install
        :return: ID of the new scan.
        """
        return await self._new_hunt(rules, 'live')

    async def new_historical_hunt(self, rules):
        """
        Run a new historical scan.

        :param rules: String containing YARA rules to install
        :return: ID of the new scan.
        """
        return await self._new_hunt(rules, 'historical')

    async def _get_hunt_results(self, hunt_id=None, scan_type='live'):
        """

        :param hunt_id: Rule ID (None if latest rule results are desired)
        :param scan_type: Type of scan, "live" or "historical"
        :return: Matches to the rules
        """

        params = {}
        if hunt_id is not None:
            params['id'] = hunt_id

        async with self.get_semaphore:
            logger.debug('Reading results with api-key %s', self.api_key)
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get('{hunt_uri}/{scan_type}/results'.format(hunt_uri=self.hunt_uri,
                                                                                   scan_type=scan_type),
                                           params=params,
                                           headers={'Authorization': self.api_key}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error('Received non-json response from PolySwarm API: %s', response)
                            response = {'status': 'error', 'result': []}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            logger.error('Error reading from PolySwarm API: %s', errors)
                            response = {'status': 'error', 'result': []}
                        return response
                except Exception:
                    logger.error('Server request failed')
                    return {'status': 'error', 'result': []}

    async def get_live_results(self, hunt_id=None):
        """
        Get results from a live scan

        :param hunt_id: ID of the hunt (None if latest rule results are desired)
        :return: Matches to the rules
        """
        return await self._get_hunt_results(hunt_id, 'live')

    async def get_historical_results(self, hunt_id=None):
        """
        Get results from a historical scan

        :param hunt_id: ID of the hunt (None if latest rule results are desired)
        :return: Matches to the rules
        """
        return await self._get_hunt_results(hunt_id, 'historical')

    async def get_stream(self, destination_dir=None):
        async with aiohttp.ClientSession() as session:
            async with self.get_semaphore:
                logger.debug('Reading results with api-key %s', self.api_key)
                try:
                    async with session.get('{stream_uri}'.format(stream_uri=self.stream_uri),
                                           headers={'Authorization': self.api_key},
                                           params={'since': 1440}) as raw_response:
                        try:
                            response = await raw_response.json()
                        except Exception:
                            response = await raw_response.read() if raw_response else 'None'
                            logger.error('Received non-json response from PolySwarm API: %s', response)
                            response = {'result': 'error'}
                        if raw_response.status // 100 != 2:
                            errors = response.get('errors')
                            logger.error('Error posting to PolySwarm API: %s', errors)
                            response = {'status': 'error'}
                except Exception:
                    logger.error('Server request failed')
                    return {'status': 'error'}

                if destination_dir is None:
                    return response

            for community in response['result'].values():
                for archive in community:
                    async with self.get_semaphore:
                        try:
                            async with session.get(archive) as raw_response:
                                try:
                                    file_name = parse.urlparse(archive).path.split('/')[-1]
                                    out_path = os.path.join(destination_dir, file_name)
                                    async with aiofiles.open(out_path, mode='wb') as out:
                                        while True:
                                            chunk = await raw_response.content.read(2 * 1024 * 1024)
                                            if not chunk:
                                                break
                                            await out.write(chunk)
                                except Exception:
                                    response = await raw_response.read() if raw_response else 'None'
                                    logger.error('Received non-json response from PolySwarm API: %s', response)
                                if raw_response.status // 100 != 2:
                                    errors = response.get('errors')
                                    logger.error('Error reading from PolySwarm API: %s', errors)
                        except Exception:
                            logger.error('Server request failed')
                            return {'status': 'error'}
            return response


class PolyswarmAPI(object):
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri='https://api.polyswarm.network/v1', get_limit=100,
                 post_limit=1000, timeout=600, force=False, community='lima', check_version=True):
        """

        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param get_limit: How many simultaneous GET requests to make. Increase at your own risk.
        :param post_limit: How many simultaneous POST requests / second to make. Change at your own risk.
        :param timeout: How long to wait for scans to complete. This should be at least 45 seconds for round to complete
        :param force: Force re-scans if file was already submitted.
        :param community: Community to scan against.
        :param check_version: Whether or not to check Github for version information
        """
        self.ps_api = PolyswarmAsyncAPI(key, uri, get_limit, post_limit, timeout, force, community, check_version)
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

    def scan_fileobj(self, to_scan, filename='data'):
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

    def scan_url(self, to_scan, name='url'):
        """
        Scan a single URL using the PS API synchronously

        :param to_scan: URL to scan
        :param name: name to associate with the artifact
        :return: JSON report
        """
        return self.loop.run_until_complete(self.ps_api.scan_url(to_scan, name))

    def scan_urls(self, to_scan):
        """
        Scan list of URLs using the PS API synchronously

        :param to_scan: List of URLs to scan
        :return: JSON report
        """
        return self.loop.run_until_complete(self.ps_api.scan_urls(to_scan))

    def scan_directory(self, directory, recursive=False):
        """
        Scan files using the PS API synchronously

        :param directory: Directory to scan.
        :param recursive: Whether or not to scan the directory recursively.
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.scan_directory(directory, recursive))

    def search_hashes(self, hashes, hash_type='sha256'):
        """
        Scan a collection of hashes using the PS API synchronously.

        :param hashes: Hashes to scan.
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.search_hashes(hashes, hash_type))

    def search_hash(self, to_scan, hash_type='sha256'):
        """
        Scan a single hash using the PS API asynchronously.

        :param to_scan:
        :param hash_type: Hash type [sha256|sha1|md5]
        :param rescan: Whether to initiate a rescan for fresh results
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.search_hash(to_scan, hash_type))

    def search_query(self, query, raw=True):
        """
        Search by Elasticsearch query using the PS API asynchronously.

        :param query: Elasticsearch JSON query or search string
        :param raw: If true, treated as ES JSON query. If false, treated as an ES query_string
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.search_query(query, raw))

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

    def post_url(self, url):
        """
        POST URL to the PS API to be scanned synchronously

        :param url: URL to scan
        :return: Dictionary of the result code and the UUID of the scan (if successful)
        """
        return self.loop.run_until_complete(self.ps_api.post_url(url))

    def download_file(self, h, destination_dir, with_metadata=False, hash_type='sha256'):
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

    def download_files(self, hashes, destination_dir, with_metadata=False, hash_type='sha256'):
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

    def rescan_file(self, h, hash_type='sha256'):
        """
        Rescan a file by its sha256/sha1/md5 hash

        :param h: Hash of the file to rescan
        :param hash_type: Hash type [sha256|sha1|md5]
        :return: JSON report file
        """
        return self.loop.run_until_complete(self.ps_api.rescan_file(h, hash_type))

    def rescan_files(self, hashes, hash_type='sha256'):
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

    def get_live_results(self, hunt_id=None):
        """
        Get results from a live hunt

        :param hunt_id: ID of the hunt (None if latest rule results are desired)
        :return: Matches to the rules
        """
        return self.loop.run_until_complete(self.ps_api.get_live_results(hunt_id))

    def get_historical_results(self, hunt_id=None):
        """
        Get results from a historical hunt

        :param hunt_id: ID of the hunt (None if latest hunt results are desired)
        :return: Matches to the rules
        """
        return self.loop.run_until_complete(self.ps_api.get_historical_results(hunt_id))

    def get_stream(self, destination_dir=None):
        """
        Get stream of tarballs from communities you have the stream privilege on.
        Contact us at info@polyswarm.io for more info on enabling this feature.

        :param destination_dir: Directory to down files to. None if you just want the list of URLs.

        :return: List of signed S3 URLs for tarballs over the last two days
        """
        return self.loop.run_until_complete(self.ps_api.get_stream(destination_dir))
