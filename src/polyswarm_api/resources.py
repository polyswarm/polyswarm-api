import logging
import os
import io
import functools
import requests
from enum import Enum
from hashlib import sha256 as _sha256, sha1 as _sha1, md5 as _md5
from urllib.parse import urlparse

# Windows might raise an OSError instead of an ImportError like this
# OSError: [WinError 193] %1 is not a valid Win32 application
try:
    import yara
except (ImportError, OSError):
    yara = None

from polyswarm_api import exceptions, core, settings

logger = logging.getLogger(__name__)

#####################################################################
# Resources returned by the API
#####################################################################


class Engine(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/microengines'

    def __init__(self, content, api=None):
        super().__init__(content=content, api=api)
        self.id = str(content['id'])
        self.name = content['name']

        try:
            self.address = content['address'].lower()
        except:
            self.address = None

        account_number = content.get('accountNumber')
        self.account_number = str(account_number) if account_number else None

        self.engine_type = content.get('engineType', 'microengine')
        self.is_microengine = self.engine_type == 'microengine'
        self.is_arbiter = self.engine_type == 'arbiter'

        self.status = content.get('status', 'disabled')
        self.verified = self.status == 'verified'

        # These fields can be `null`; don't replace w/ default value in `get()`
        self.artifact_types = set(content.get('artifactTypes') or [])
        self.tags = set(content.get('tags') or [])
        self.communities = set(content.get('communities') or [])
        self.mimetypes = set(content.get('mimeTypes') or [])

        self.created_at = core.parse_isoformat(content.get('createdAt'))
        self.modified_at = core.parse_isoformat(content.get('modifiedAt'))
        self.archived_at = core.parse_isoformat(content.get('archivedAt'))

    @classmethod
    def _list_headers(cls, api):
        return {'Authorization': None}

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return self.id == other.id if isinstance(other, Engine) else False

    def __repr__(self):
        return '{}(name={}, address={}, status={}, engine_type={})'.format(
            self.__class__.__name__,
            self.name,
            self.address,
            self.status,
            self.engine_type,
        )


class ToolMetadata(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/artifact/metadata'


class MetadataMapping(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/search/metadata/mappings'


class Metadata(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/search/metadata/query'
    KNOWN_KEYS = {'artifact', 'exiftool', 'hash', 'lief', 'pefile', 'scan', 'strings'}

    def __init__(self, content, api=None):
        super().__init__(content=content, api=api)
        self.created = core.parse_isoformat(self.artifact.get('created'))

        self.id = self._get('artifact.id')
        self.sha1 = self._get('artifact.sha1')
        self.sha256 = self._get('artifact.sha256')
        self.md5 = self._get('artifact.md5')

        self.ssdeep = self._get('hash.ssdeep')
        self.tlsh = self._get('hash.tlsh')

        self.first_seen = core.parse_isoformat(self._get('scan.first_scan.created'))
        self.last_scanned = core.parse_isoformat(self._get('scan.latest_scan.created'))
        self.mimetype = self._get('scan.mimetype.mime')
        self.extended_mimetype = self._get('scan.mimetype.extended')
        self.malicious = self._get('scan.detections.malicious')
        self.benign = self._get('scan.detections.benign')
        self.total_detections = self._get('scan.detections.total')
        self.filenames = self._get('scan.filename')

        self.domains = self._get('strings.domains')
        self.ipv4 = self._get('strings.ipv4')
        self.ipv6 = self._get('strings.ipv6')
        self.urls = self._get('strings.urls')

    def __contains__(self, item):
        return item in self.json

    def __getattr__(self, name):
        try:
            return self.json[name]
        except KeyError:
            if name in Metadata.KNOWN_KEYS:
                return {}
            raise AttributeError()

    @classmethod
    def _get_params(cls, **kwargs):
        params = []
        include = kwargs.pop('include', ()) or ()
        exclude = kwargs.pop('exclude', ()) or ()
        ips = kwargs.pop('ips', ()) or ()
        urls = kwargs.pop('urls', ()) or ()
        domains = kwargs.pop('domains', ()) or ()
        params.extend(('include', v) for v in include)
        params.extend(('exclude', v) for v in exclude)
        params.extend(('ips', v) for v in ips)
        params.extend(('urls', v) for v in urls)
        params.extend(('domains', v) for v in domains)
        super_params, json_params = super()._get_params(**kwargs)
        params.extend(super_params.items())
        return params, json_params


class IOC(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/ioc'

    @classmethod
    def iocs_by_hash(cls, api, hash_value, hash_type, hide_known_good=False, beta=False):
        path = 'ioc-beta' if beta else 'ioc'
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/{path}/{hash_type}/{hash_value}',
                'params': {
                    'hide_known_good': hide_known_good,
                    'community': api.community,
                },
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def ioc_search(cls, api, ip=None, domain=None, ttp=None, imphash=None):
        params = dict(community=api.community)
        if ip is not None:
            params['ip'] = ip
        if domain is not None:
            params['domain'] = domain
        if ttp is not None:
            params['ttp'] = ttp
        if imphash is not None:
            params['imphash'] = imphash
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/ioc/search',
                'params': params
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def check_known_hosts(cls, api, ips, domains):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/ioc/known',
                'params': {
                    'ip': ips,
                    'domain': domains
                }
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def create_known_good(cls, api, type, host, source):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'POST',
                'url': f'{api.uri}/ioc/known',
                'json': {
                    'type': type,
                    'host': host,
                    'source': source,
                    'good': True
                }
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def create_known_bad(cls, api, type, host, source):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'POST',
                'url': f'{api.uri}/ioc/known',
                'json': {
                    'type': type,
                    'host': host,
                    'source': source,
                    'good': False
                }
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def update_known_good(cls, api, id, type, host, source, good):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'PUT',
                'url': f'{api.uri}/ioc/known',
                'json': {
                    'id': id,
                    'type': type,
                    'host': host,
                    'source': source,
                    'good': good
                }
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def delete_known_good(cls, api, id):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'DELETE',
                'url': f'{api.uri}/ioc/known',
                'params': {
                    'id': id
                }
            },
            result_parser=cls,
        ).execute()


class ArtifactInstance(core.BaseJsonResource, core.Hashable):
    RESOURCE_ENDPOINT = '/instance'

    def __init__(self, content, api=None):
        super().__init__(content=content, api=api,
                         hash_value=content['sha256'], hash_type='sha256')
        # Artifact fields
        self.sha256 = content['sha256']
        self.artifact_id = content.get('artifact_id')
        self.md5 = content['md5']
        self.sha1 = content['sha1']
        self.mimetype = content['mimetype']
        self.size = content['size']
        self.extended_type = content['extended_type']
        self.first_seen = core.parse_isoformat(content['first_seen'])
        self.upload_url = content['upload_url']
        # Deprecated
        self.last_seen = core.parse_isoformat(content.get('last_seen'))
        self.last_scanned = core.parse_isoformat(content.get('last_scanned'))
        metadata_json = content.get('metadata') or []
        metadata = {metadata['tool']: metadata['tool_metadata'] for metadata in metadata_json}
        self.metadata = Metadata(metadata, api)

        # ArtifactInstance fields
        self.id = content.get('id')
        self.assertions = [Assertion(a, api=api, scanfile=self) for a in content.get('assertions', [])]
        self.country = content.get('country')
        self.community = content.get('community')
        self.created = core.parse_isoformat(content.get('created'))
        self.failed = content.get('failed')
        self.failed_reason = content.get('failed_reason')
        self.filename = content.get('filename')
        self.result = content.get('result')
        self.type = content.get('type')
        self.votes = [Vote(v, api=api, scanfile=self) for v in content.get('votes', [])]
        self.window_closed = content.get('window_closed')
        self.polyscore = float(content['polyscore']) if content.get('polyscore') is not None else None
        if content.get('permalink'):
            self.permalink = content.get('permalink')
        else:
            self.permalink = settings.DEFAULT_PERMALINK_BASE + '/' + str(self.hash) + '/' + str(self.id)

        self._malicious_assertions = None
        self._benign_assertions = None
        self._valid_assertions = None

    def upload_file(self, artifact, attempts=3, **kwargs):
        if not self.upload_url:
            raise exceptions.InvalidValueException('upload_url must be set to upload a file')
        if not artifact:
            raise exceptions.InvalidValueException('A LocalArtifact must be provided in order to upload')
        r = None
        while attempts > 0 and not r:
            attempts -= 1
            artifact.seek(0, io.SEEK_END)
            length = artifact.tell()
            artifact.seek(0)
            # https://github.com/psf/requests/issues/4215#issuecomment-319521235
            # We have to manually handle the case when the file is empty
            # in a way that requests won't set Transfer-Encoding: chunked
            if not length:
                artifact = ''
            r = requests.put(self.upload_url, data=artifact, **kwargs)
            r.raise_for_status()
        return r

    @classmethod
    def exists_hash(cls, api, hash_value, hash_type):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'HEAD',
                'url': f'{api.uri}/search/hash/{hash_type}',
                'params': {
                    'hash': hash_value,
                    'community': api.community,
                },
            },
        ).execute()

    @classmethod
    def search_hash(cls, api, hash_value, hash_type):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/search/hash/{hash_type}',
                'params': {
                    'hash': hash_value,
                    'community': api.community,
                },
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def search_url(cls, api, url):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/search/url',
                'params': {
                    'url': url,
                    'community': api.community,
                },
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def list_scans(cls, api, hash_value):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/search/instances',
                'params': {
                    'hash': hash_value,
                    'community': api.community,
                },
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def submit(cls, api, artifact, artifact_name, artifact_type, scan_config=None):
        parameters = {
            'method': 'POST',
            'url': f'{api.uri}/consumer/submission/{api.community}',
            'files': {
                'file': (artifact_name, artifact),
            },
            # very oddly, when included in files parameter this errors out
            'data': {
                'artifact-type': artifact_type,
            }
        }
        if scan_config:
            parameters['data']['scan-config'] = scan_config
        return core.PolyswarmRequest(
            api,
            parameters,
            result_parser=cls,
        ).execute()

    @classmethod
    def rescan(cls, api, hash_value, hash_type, scan_config=None):
        parameters = {
            'method': 'POST',
            'url': f'{api.uri}/consumer/submission/{api.community}/rescan/{hash_type}/{hash_value}',
            'data': {'community': api.community}
        }
        if scan_config:
            parameters['data']['scan-config'] = scan_config
        return core.PolyswarmRequest(
            api,
            parameters,
            result_parser=cls,
        ).execute()

    @classmethod
    def rescan_id(cls, api, submission_id, scan_config=None):
        parameters = {
            'method': 'POST',
            'url': f'{api.uri}/consumer/submission/{api.community}/rescan/{int(submission_id)}',
        }
        if scan_config:
            parameters.setdefault('data', {})['scan-config'] = scan_config
        return core.PolyswarmRequest(
            api,
            parameters,
            result_parser=cls,
        ).execute()

    @classmethod
    def lookup_uuid(cls, api, submission_id):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/consumer/submission/{api.community}/{int(submission_id)}',
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def metadata_rerun(cls, api, hashes, analyses=None, skip_es=None):
        parameters = {
            'method': 'POST',
            'url': f'{api.uri}/consumer/metadata',
            'json': {'hashes': hashes},
        }
        if analyses:
            parameters['json']['analyses'] = analyses
        if skip_es:
            parameters['json']['skip_es'] = skip_es
        return core.PolyswarmRequest(
            api,
            parameters,
            result_parser=cls,
        ).execute()

    def __str__(self):
        return "ArtifactInstance-<%s>" % self.hash

    @property
    def malicious_assertions(self):
        if not self._malicious_assertions:
            self._malicious_assertions = [a for a in self.assertions if a.mask and a.verdict]
        return self._malicious_assertions

    @property
    def benign_assertions(self):
        if not self._benign_assertions:
            self._benign_assertions = [a for a in self.assertions if a.mask and not a.verdict]
        return self._benign_assertions

    @property
    def valid_assertions(self):
        if not self._valid_assertions:
            self._valid_assertions = [a for a in self.assertions if a.mask]
        return self._valid_assertions


class ArtifactArchive(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/consumer/download/stream'

    def __init__(self, content, api=None):
        super().__init__(content=content, api=api)
        self.id = content['id']
        self.community = content['community']
        self.created = core.parse_isoformat(content['created'])
        self.uri = content['uri']


class AssertionsJob(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/consumer/assertions-job'

    def __init__(self, content, api=None):
        super().__init__(content=content, api=api)
        self.id = content['id']
        self.engine_id = content['engine_id']
        self.created = core.parse_isoformat(content['created'])
        self.date_start = core.parse_isoformat(content['date_start'])
        self.date_end = core.parse_isoformat(content['date_end'])
        self.storage_path = content['storage_path']
        self.true_positive = content['true_positive']
        self.true_negative = content['true_negative']
        self.false_positive = content['false_positive']
        self.false_negative = content['false_negative']
        self.suspicious = content['suspicious']
        self.unknown = content['unknown']
        self.total = content['total']


class VotesJob(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/consumer/votes-job'

    def __init__(self, content, api=None):
        super().__init__(content=content, api=api)
        self.id = content['id']
        self.engine_id = content['engine_id']
        self.created = core.parse_isoformat(content['created'])
        self.date_start = core.parse_isoformat(content['date_start'])
        self.date_end = core.parse_isoformat(content['date_end'])
        self.storage_path = content['storage_path']
        self.true_positive = content['true_positive']
        self.true_negative = content['true_negative']
        self.false_positive = content['false_positive']
        self.false_negative = content['false_negative']
        self.suspicious = content['suspicious']
        self.unknown = content['unknown']
        self.total = content['total']


def _read_chunks(file_handle):
    while True:
        data = file_handle.read(settings.FILE_CHUNK_SIZE)
        if not data:
            break
        yield data


def all_hashes(file_handle, algorithms=(_sha256, _sha1, _md5)):
    hashers = [alg() for alg in algorithms]
    for data in _read_chunks(file_handle):
        [h.update(data) for h in hashers]
    return [Hash(h.hexdigest()) for h in hashers]


class LocalArtifact(core.BaseResource, core.Hashable):
    """ Artifact for which we have local content """
    def __init__(self, response, api=None, handle=None, folder=None,
                 artifact_name=None, artifact_type=None, analyze=False, **kwargs):
        """
        A representation of an artifact we have locally

        :param artifact_name: Name of the artifact
        :param artifact_type: Type of artifact
        :param api: PolyswarmAPI instance
        :param analyze: Boolean, if True will run analyses on artifact on startup (Note: this may still run later if False)
        """
        # check if we have a destination to store the file
        # raise an error if we don't have exacltly one
        if folder and handle:
            raise exceptions.InvalidValueException('Only one of path or handle should be defined.')
        if not (folder or handle):
            raise exceptions.InvalidValueException('At least one of path or handle must be defined.')

        # initialize super classes and default values
        super().__init__(response, api=api, hash_type='sha256')
        self.sha256 = None
        self.sha1 = None
        self.md5 = None
        self.analyzed = False
        self.artifact_type = artifact_type or ArtifactType.FILE

        # resolve the file name
        if artifact_name:
            # prioritize explicitly provided name
            self.artifact_name = artifact_name
        else:
            if response:
                # respect content-disposition if there is a response
                filename = response.headers.get('content-disposition', '').partition('filename=')[2]
                if filename:
                    self.artifact_name = filename
                elif os.path.basename(getattr(handle, 'name', '')):
                    self.artifact_name = os.path.basename(getattr(handle, 'name', ''))
                else:
                    self.artifact_name = os.path.basename(urlparse(response.url).path)
            elif os.path.basename(getattr(handle, 'name', '')):
                # if there is no response and no artifact_name, try to get from the handle
                self.artifact_name = os.path.basename(getattr(handle, 'name', ''))

        # resolve the handle to be used
        # only one of handle or folder can be provided (we checked for this above)
        # if one was explicitly provided, use it
        # if we have a folder, use a file named after file_name in that folder
        # otherwise use an in-memory handle
        remove_on_error = False
        try:
            if folder:
                if not os.path.exists(folder):
                    os.makedirs(folder, exist_ok=True)
                remove_on_error = True
                self.handle = open(os.path.join(folder, self.artifact_name), mode='wb+', **kwargs)
            else:
                self.handle = handle or io.BytesIO()

            if response:
                # process the content in the response if available, write to handle
                for chunk in response.iter_content(settings.DOWNLOAD_CHUNK_SIZE):
                    self.handle.write(chunk)
                    if hasattr(self.handle, 'flush'):
                        self.handle.flush()
            if analyze:
                # analyze the artifact in case it is needed
                self.analyze_artifact()
        except Exception:
            try:
                if remove_on_error and self.handle:
                    # make sure we cleanup the handle
                    # if an exception happened and this is a file we created
                    self.handle.close()
                    os.remove(self.handle.name)
            except Exception:
                logger.exception('Failed to cleanup the target file.')
            raise

    @classmethod
    def download(cls, api, hash_value, hash_type, handle=None, folder=None, artifact_name=None):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/consumer/download/{hash_type}/{hash_value}',
                'stream': True,
                'params': { 'community': api.community },
            },
            result_parser=cls,
            handle=handle,
            folder=folder,
            artifact_name=artifact_name,
        ).execute()

    @classmethod
    def download_id(cls, api, instance_id, handle=None, folder=None, artifact_name=None):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/instance/download',
                'stream': True,
                'params': {'instance_id': instance_id},
            },
            result_parser=cls,
            handle=handle,
            folder=folder,
            artifact_name=artifact_name,
        ).execute()

    @classmethod
    def download_archive(cls, api, u, handle=None, folder=None, artifact_name=None):
        """ This method is special, in that it is simply for downloading from S3 """
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': u,
                'stream': True,
                'headers': {'Authorization': None}
            },
            result_parser=cls,
            handle=handle,
            folder=folder,
            artifact_name=artifact_name,
        ).execute()

    # Inspired by
    # https://github.com/python/cpython/blob/29500737d45cbca9604d9ce845fb2acc3f531401/Lib/tempfile.py#L461
    def __getattr__(self, name):
        # Attribute lookups are delegated to the underlying file
        # and cached for non-numeric results
        # (i.e. methods are cached, closed and friends are not)
        a = getattr(self.handle, name)

        if hasattr(a, '__call__'):
            func = a

            @functools.wraps(func)
            def func_wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            a = func_wrapper
        if not isinstance(a, int):
            setattr(self, name, a)
        return a

    # https://github.com/python/cpython/blob/29500737d45cbca9604d9ce845fb2acc3f531401/Lib/tempfile.py#L499
    # iter() doesn't use __getattr__ to find the __iter__ method
    def __iter__(self):
        for line in self.handle:
            yield line

    @classmethod
    def from_handle(cls, api, handle, artifact_type=None, analyze=False, artifact_name=None, **kwargs):
        # create the LocalHandle with the given handle and don't write anything to it
        return cls(b'', handle=handle, artifact_name=artifact_name,
                   artifact_type=artifact_type, analyze=analyze, api=api)

    @classmethod
    def from_path(cls, api, path, artifact_type=None, analyze=False, artifact_name=None, **kwargs):
        if not isinstance(path, str):
            raise exceptions.InvalidValueException('Path should be a string')
        artifact_name = artifact_name or os.path.basename(path)
        handle = open(path, mode='rb', **kwargs)
        # create the LocalHandle with the given handle and don't write anything to it
        return cls(b'', handle=handle, artifact_name=artifact_name,
                   artifact_type=artifact_type, analyze=analyze, api=api)

    @classmethod
    def from_content(cls, api, content, artifact_name=None, artifact_type=None, analyze=False):
        if isinstance(content, str):
            content = content.encode("utf8")
        handle = io.BytesIO(content)
        # create the LocalHandle with the given handle and don't write anything to it
        return cls(b'', handle=handle, artifact_name=artifact_name,
                   artifact_type=artifact_type, analyze=analyze, api=api)

    @property
    def hash(self):
        self.analyze_artifact()
        return super().hash

    def analyze_artifact(self, force=False):
        if not self.analyzed or force:
            self.handle.seek(0)
            self._calc_hashes(self.handle)
            self.handle.seek(0)
            self._run_analyzers(self.handle)
            self.analyzed = True
            # define the hash value only when analyzed
            self._hash = self.sha256

    def _calc_hashes(self, fh):
        self.sha256, self.sha1, self.md5 = all_hashes(fh)

    def _run_analyzers(self, fh):
        # TODO implement custom analyzer support, so users can implement plugins here.
        return {}

    def __str__(self):
        return "Artifact <%s>" % self.hash


class YaraRuleset(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/hunt/rule'

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.id = content.get('id')
        self.livescan_id = content.get('livescan_id')
        self.livescan_created = content.get('livescan_created')
        self.name = content.get('name')
        self.description = content.get('description')
        self.created = core.parse_isoformat(content.get('created'))
        self.modified = core.parse_isoformat(content.get('modified'))
        self.deleted = content.get('deleted')
        self.yara = content.get('yara')


class LiveYaraRuleset(YaraRuleset):
    RESOURCE_ENDPOINT = '/hunt/rule/live'


class LiveHuntResult(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/hunt/live'

    def __init__(self, content, api=None):
        super().__init__(content=content, api=api)
        self.id = content['id']
        self.livescan_id = content['livescan_id']
        self.instance_id = content['instance_id']
        self.created = core.parse_isoformat(content['created'])
        self.sha256 = content['sha256']
        self.rule_name = content['rule_name']
        self.tags = content['tags']
        self.polyscore = content['polyscore']
        self.malware_family = content['malware_family']
        self.detections = content['detections']
        self.yara = content.get('yara')
        self.download_url = content.get('download_url')
        self.community = content.get('community')


class LiveHuntResultList(LiveHuntResult):
    RESOURCE_ENDPOINT = '/hunt/live/list'


class HistoricalHunt(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/hunt/historical'

    def __init__(self, content, api=None):
        super().__init__(content=content, api=api)
        # active only present for live   hunts
        self.id = content['id']
        self.created = core.parse_isoformat(content['created'])
        self.status = content['status']
        self.active = content.get('active')
        self.ruleset_name = content.get('ruleset_name')
        self.yara = content.get('yara')
        self.summary = content.get('summary')
        self.progress = content['progress']
        self.results_csv_uri = content['results_csv_uri']
        self.communities = content.get('communities')


class HistoricalHuntList(HistoricalHunt):
    RESOURCE_ENDPOINT = '/hunt/historical/list'


class HistoricalHuntResult(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/hunt/historical/results'

    def __init__(self, content, api=None):
        super().__init__(content=content, api=api)
        self.id = content['id']
        self.historicalscan_id = content['historicalscan_id']
        self.instance_id = content['instance_id']
        self.sha256 = content['sha256']
        self.created = core.parse_isoformat(content['created'])
        self.rule_name = content['rule_name']
        self.tags = content['tags']
        self.polyscore = content['polyscore']
        self.malware_family = content['malware_family']
        self.detections = content['detections']
        self.download_url = content.get('download_url')
        self.community = content.get('community')


class HistoricalHuntResultList(HistoricalHuntResult):
    RESOURCE_ENDPOINT = '/hunt/historical/results/list'


class TagLink(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/tags/link'
    RESOURCE_ID_KEYS = ['hash']

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.id = content.get('id')
        self.sha256 = content.get('sha256')
        self.created = core.parse_isoformat(content.get('created'))
        self.updated = core.parse_isoformat(content.get('updated'))
        self.first_seen = core.parse_isoformat(content.get('first_seen'))
        self.tags = content.get('tags')
        self.families = content.get('families')
        self.emerging = core.parse_isoformat(content.get('emerging'))

    @classmethod
    def _list_params(cls, **kwargs):
        params = []
        empty = tuple()
        params.extend(('tag', p) for p in kwargs.get('tags', empty))
        params.extend(('family', p) for p in kwargs.get('families', empty))
        params.extend(('or_tag', p) for p in kwargs.get('or_tags', empty))
        params.extend(('or_family', p) for p in kwargs.get('or_families', empty))
        params.append(('emerging', kwargs.get('emerging', empty)))
        return params, None


class MalwareFamily(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/tags/family'
    RESOURCE_ID_KEYS = ['name']

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.id = content.get('id')
        self.created = core.parse_isoformat(content.get('created'))
        self.updated = core.parse_isoformat(content.get('updated'))
        self.name = content.get('name')
        self.emerging = core.parse_isoformat(content.get('emerging'))


class Tag(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/tags/tag'
    RESOURCE_ID_KEYS = ['name']

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.id = content.get('id')
        self.created = core.parse_isoformat(content.get('created'))
        self.updated = core.parse_isoformat(content.get('updated'))
        self.name = content.get('name')


#####################################################################
# Nested Resources
#####################################################################


class Assertion(core.BaseJsonResource):
    def __init__(self, content, api=None, scanfile=None):
        super().__init__(content, api=api)
        self.scanfile = scanfile
        self.author = content['author']
        self.author_name = content['author_name']
        self.engine_name = content['engine'].get('name')
        self.bid = int(content['bid'])
        self.mask = content['mask']
        # deal with metadata being a string instead of null
        self.metadata = content['metadata'] if content['metadata'] else {}
        self.verdict = content['verdict']

    def __str__(self):
        return "Assertion-%s: %s" % (self.engine_name, self.verdict)


class Vote(core.BaseJsonResource):
    def __init__(self, content, api=None, scanfile=None):
        super().__init__(content, api=api)
        self.scanfile = scanfile
        self.arbiter = content['arbiter']
        self.vote = content['vote']

    def __str__(self):
        return "Vote-%s: %s" % (self.arbiter, self.vote)


#####################################################################
# Resources Used as input parameters in PolyswarmAPI
#####################################################################


class ArtifactType(Enum):
    FILE = 0
    URL = 1

    @staticmethod
    def parse(value):
        if isinstance(value, ArtifactType):
            return value
        try:
            return ArtifactType[value.upper()]
        except Exception as e:
            raise exceptions.InvalidValueException(
                    f'Unable to get the artifact type from the provided value {value}') from e

    @staticmethod
    def to_string(artifact_type):
        return artifact_type.name.lower()

    def decode_content(self, content):
        if content is None:
            return None

        if self == ArtifactType.URL:
            try:
                return content.decode('utf-8')
            except UnicodeDecodeError:
                raise exceptions.DecodeErrorException('Error decoding URL')
        else:
            return content


class Hash(core.Hashable):
    def __init__(self, hash_, hash_type=None, validate_hash=True):
        super().__init__(hash_value=hash_, hash_type=hash_type, validate_hash=validate_hash)

    @classmethod
    def from_hashable(cls, hash_, hash_type=None):
        """
        Coerce to Hashable object

        :param hash_: Hashable object
        :param hash_type: Hash type
        :param polyswarm: PolyswarmAPI instance
        :return: Hash
        """
        if issubclass(type(hash_), core.Hashable):
            if hash_type and hash_.hash_type != hash_type:
                raise exceptions.InvalidValueException(
                    f'Detected hash type {hash_.hash_type}, got {hash_type} for hashable {hash_.hash}')
            return Hash(hash_.hash, hash_type=hash_type)
        return Hash(hash_, hash_type=hash_type)

    def __hash__(self):
        return hash(self.hash)

    def __str__(self):
        return self.hash

    def __repr__(self):
        return f"{self.hash_type}={self.hash}"


class SandboxTask(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/sandbox/sandboxtask'

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.id = content['id']
        self.community = content['community']
        self.sandbox = content['sandbox']
        self.created = content['created']
        self.expiration = content['expiration']
        self.status = content['status']
        self.account_number = content['account_number']
        self.team_account_number = content['team_account_number']
        self.instance_id = content['instance_id']
        self.sha256 = content['sha256']
        self.report = content['report']
        self.upload_url = content['upload_url']
        self.config = content['config']
        self.artifact = content['artifact']
        self.sandbox_artifacts = [SandboxArtifact(a, api=api) for a in content.get('sandbox_artifacts', [])]

    def upload_file(self, artifact, attempts=3, **kwargs):
        if not self.upload_url:
            raise exceptions.InvalidValueException('upload_url must be set to upload a file')
        if not artifact:
            raise exceptions.InvalidValueException('A LocalArtifact must be provided in order to upload')
        r = None
        while attempts > 0 and not r:
            attempts -= 1
            artifact.seek(0, io.SEEK_END)
            length = artifact.tell()
            artifact.seek(0)
            # https://github.com/psf/requests/issues/4215#issuecomment-319521235
            # We have to manually handle the case when the file is empty
            # in a way that requests won't set Transfer-Encoding: chunked
            if not length:
                artifact = ''
            r = requests.put(self.upload_url, data=artifact, **kwargs)
            r.raise_for_status()
        return r

    @classmethod
    def get(cls, api, **kwargs):
        return super().get(api, community=api.community, **kwargs)

    @classmethod
    def latest(cls, api, **kwargs):
        params, _ = cls._get_params(community=api.community, **kwargs)
        url = cls._endpoint(api) + '/latest'
        parameters = {'method': 'GET', 'url': url, 'params': params}
        return core.PolyswarmRequest(api, parameters, result_parser=cls).execute()

    @classmethod
    def my_tasks(cls, api, **kwargs):
        params, _ = cls._get_params(community=api.community, **kwargs)
        url = cls._endpoint(api) + '/my-tasks'
        parameters = {'method': 'GET', 'url': url, 'params': params}
        return core.PolyswarmRequest(api, parameters, result_parser=cls).execute()

    @classmethod
    def create_file(cls, api, **kwargs):
        return cls._build_request(api, 'POST', cls._create_endpoint(api, **kwargs) + '/instance',
                                  cls._create_headers(api), *cls._create_params(**kwargs)).execute()

    @classmethod
    def update_file(cls, api, **kwargs):
        return cls._build_request(api, 'PUT', cls._update_endpoint(api, **kwargs) + '/instance',
                                  cls._update_headers(api), *cls._update_params(**kwargs)).execute()


class SandboxArtifact(core.BaseJsonResource):
    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.created = content['created']
        self.id = content['id']
        self.instance_id = content['instance_id']
        self.name = content['name']
        self.mimetype = content['mimetype']
        self.extended_type = content['extended_type']
        self.type = content['type']


class SandboxProvider(core.BaseJsonResource):
    RESOURCE_ENDPOINT = "/sandbox/provider"

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.slug = content['slug']
        self.name = content['name']
        self.tool = content['tool']
        self.vms = content['vms']

    @classmethod
    def parse_result(cls, api, content, **kwargs):
        logger.debug('Parsing resource %s', cls.__name__)
        return [super(SandboxProvider, cls).parse_result(api, content[slug], **kwargs) for slug in content.keys()]


class Events(core.BaseJsonResource):
    RESOURCE_ENDPOINT = "/activity"

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.event_timestamp = content['event_timestamp']
        self.event_type = content['event_type']
        self.source = content['source']
        self.team_account_id = content['team_account_id']
        self.user_account_id = content['user_account_id']


class ReportTask(core.BaseJsonResource):
    RESOURCE_ENDPOINT = "/reports"

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.id = content['id']
        self.type = content['type']
        self.format = content['format']
        self.state = content['state']
        self.community = content['community']
        self.created = content['created']
        self.template_id = content.get('template_id')
        self.template_metadata = content.get('template_metadata', {})
        self.sandbox_task_id = content.get('sandbox_task_id')
        self.instance_id = content.get('instance_id')
        self.url = content['url']

    def download_report(self, folder=None):
        """ This method is special, in that it is simply for downloading from S3 """
        if self.state == 'PENDING':
            raise exceptions.InvalidValueException('Report is in PENDING state, wait for completion first')
        if self.state == 'FAILED':
            raise exceptions.InvalidValueException("Report is in FAILED state, won't be generated")
        return core.PolyswarmRequest(
            self.api,
            {
                'method': 'GET',
                'url': self.url,
                'stream': True,
                'headers': {'Authorization': None}
            },
            result_parser=LocalArtifact,
            folder=folder,
        ).execute()


class ReportTemplate(core.BaseJsonResource):
    RESOURCE_ENDPOINT = "/reports/templates"

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        if content:
            self.id = content['id']
            self.created = content['created']
            self.template_name = content['template_name']
            self.includes = content.get('includes')
            self.primary_color = content.get('primary_color')
            self.footer_text = content.get('footer_text')
            self.last_page_text = content.get('last_page_text')
            self.is_default = content.get('is_default', False)
            self.logo_content_length = content.get('logo_content_length')
            self.logo_url = f"{self.api.uri}/reports/templates/logo?id={self.id}"
            self.logo_content_type = content.get('logo_content_type')
            self.logo_height = content.get('logo_height')
            self.logo_width = content.get('logo_width')

    def download_logo(self, folder):
        return core.PolyswarmRequest(
            self.api,
            {
                'method': 'GET',
                'url': self.logo_url,
            },
            result_parser=LocalArtifact,
            folder=folder,
        ).execute()

    def delete_logo(self):
        return core.PolyswarmRequest(
            self.api,
            {
                'method': 'DELETE',
                'url': self.logo_url,
            },
        ).execute()

    def upload_logo(self, logo_file, content_tpe):
        if not logo_file:
            raise exceptions.InvalidValueException('A local file must be provided in order to upload')
        logo_file.seek(0, io.SEEK_END)
        length = logo_file.tell()
        logo_file.seek(0)
        if not length:
            raise exceptions.InvalidValueException('Empty file')
        # r = requests.put(self.upload_url, data=logo_file, **kwargs)
        # r.raise_for_status()
        # return r
        return core.PolyswarmRequest(
            self.api,
            {
                'method': 'PUT',
                'url': f'{self.api.uri}/reports/templates/logo?id={self.id}',
                'data': logo_file,
                'headers': {'Content-Type': content_tpe}
            },
            result_parser=self.__class__
        ).execute()


class AccountFeatures(core.BaseJsonResource):
    RESOURCE_ENDPOINT = "/public/accounts"

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.account_number = content['account_number']
        self.user_account_number = content.get('user_account_number')
        self.account_plan_name = content['account_plan_name']
        self.plan_period_start = content['plan_period_start']
        self.plan_period_end = content['plan_period_end']
        self.window_start = content['window_start']
        self.window_end = content['window_end']
        self.tenant = content.get('tenant')
        self.daily_api_limit = content['daily_api_limit']
        self.daily_api_remaining = content['daily_api_remaining']
        self.has_stream_access = content['has_stream_access']
        self.is_trial = content['is_trial']
        self.is_trial_expired = content['is_trial_expired']
        self.trial_started_at = content['trial_started_at']
        self.trial_ended_at = content['trial_ended_at']
        self.features = []
        for feature in content['features']:
            self.features.append({
                'base_uses': feature['base_uses'],
                'name': feature['name'],
                'remaining_uses': feature['remaining_uses'],
                'tag': feature['tag'],
                'value': feature['value'],
                'overage': feature.get('overage'),
                'backing_feature': feature.get('backing_feature'),
            })


class WhoIs(core.BaseJsonResource):
    RESOURCE_ENDPOINT = "/public/accounts/whois"

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.account_number = content['account_number']
        self.user_account_number = content.get('user_account_number')
        self.account_name = content['account_name']
        self.account_type = content['account_type']
        self.communities = content['communities']
        self.tenant = content.get('tenant')
