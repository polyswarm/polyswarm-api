import logging
import os
import io
import functools
import warnings
import requests
from enum import Enum
from hashlib import sha256 as _sha256, sha1 as _sha1, md5 as _md5

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from future.utils import raise_from, string_types

# Windows might rase an OSError instead of an ImportError like this
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
        super(Engine, self).__init__(content=content, api=api)
        self.id = str(content['id'])
        self.name = content['name']

        try:
            self.address = content['address'].lower()
        except:
            self.address = None

        self.engine_type = content.get('engineType')
        self.verified = content.get('status') == 'verified'

        # These fields can be `null`; don't replace w/ default value in `get()`
        self.artifact_types = content.get('artifactTypes') or []
        self.tags = content.get('tags') or []
        self.communities = content.get('communities') or []

    @classmethod
    def _list_headers(cls, api):
        return {'Authorization': None}

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return self.id == other.id if isinstance(other, Engine) else False

    def is_arbiter(self):
        return self.engine_type == 'arbiter'

class ToolMetadata(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/artifact/metadata'


class MetadataMapping(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/search/metadata/mappings'


class Metadata(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/search/metadata/query'
    KNOWN_KEYS = {'artifact', 'exiftool', 'hash', 'lief', 'pefile', 'scan', 'strings'}

    def __init__(self, content, api=None):
        super(Metadata, self).__init__(content=content, api=api)
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
        params.extend(('include', v) for v in include)
        params.extend(('exclude', v) for v in exclude)
        super_params, json_params = super(Metadata, cls)._get_params(**kwargs)
        params.extend(super_params.items())
        return params, json_params


class ArtifactInstance(core.BaseJsonResource, core.Hashable):
    RESOURCE_ENDPOINT = '/instance'

    def __init__(self, content, api=None):
        super(ArtifactInstance, self).__init__(content=content, api=api,
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
        self.filename = content.get('filename')
        self.result = content.get('result')
        self.type = content.get('type')
        self.votes = [Vote(v, api=api, scanfile=self) for v in content.get('votes', [])]
        self.window_closed = content.get('window_closed')
        self.polyscore = float(content['polyscore']) if content.get('polyscore') is not None else None
        self.permalink = settings.DEFAULT_PERMALINK_BASE + '/' + str(self.hash)

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
            artifact.seek(0)
            r = requests.put(self.upload_url, data=artifact, **kwargs)
        return r

    @classmethod
    def exists_hash(cls, api, hash_value, hash_type):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'HEAD',
                'url': '{}/search/hash/{}'.format(api.uri, hash_type),
                'params': {
                    'hash': hash_value,
                },
            },
        ).execute()

    @classmethod
    def search_hash(cls, api, hash_value, hash_type):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': '{}/search/hash/{}'.format(api.uri, hash_type),
                'params': {
                    'hash': hash_value,
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
                'url': '{}/search/url'.format(api.uri),
                'params': {
                    'url': url,
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
                'url': '{}/search/instances'.format(api.uri),
                'params': {
                    'hash': hash_value,
                },
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def submit(cls, api, artifact, artifact_name, artifact_type, scan_config=None):
        parameters = {
            'method': 'POST',
            'url': '{}/consumer/submission/{}'.format(api.uri, api.community),
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
            'url': '{}/consumer/submission/{}/rescan/{}/{}'.format(api.uri, api.community, hash_type, hash_value),
        }
        if scan_config:
            parameters.setdefault('data', {})['scan-config'] = scan_config
        return core.PolyswarmRequest(
            api,
            parameters,
            result_parser=cls,
        ).execute()

    @classmethod
    def rescan_id(cls, api, submission_id, scan_config=None):
        parameters = {
            'method': 'POST',
            'url': '{}/consumer/submission/{}/rescan/{}'.format(api.uri, api.community, int(submission_id)),
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
                'url': '{}/consumer/submission/{}/{}'.format(api.uri, api.community, int(submission_id)),
            },
            result_parser=cls,
        ).execute()

    @classmethod
    def metadata_rerun(cls, api, hashes, analyses=None, skip_es=None):
        parameters = {
            'method': 'POST',
            'url': '{}/consumer/metadata'.format(api.uri),
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

    @property
    def filenames(self):
        warnings.warn('This property is deprecated and will be removed in the next major version. '
                      'Please use "Metadata().filenames" in the future.')
        return []


class ArtifactArchive(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/consumer/download/stream'

    def __init__(self, content, api=None):
        super(ArtifactArchive, self).__init__(content=content, api=api)
        self.id = content['id']
        self.community = content['community']
        self.created = core.parse_isoformat(content['created'])
        self.uri = content['uri']


class Hunt(core.BaseJsonResource):
    def __init__(self, content, api=None):
        super(Hunt, self).__init__(content=content, api=api)
        # active only present for live hunts
        self.id = content['id']
        self.created = core.parse_isoformat(content['created'])
        self.status = content['status']
        self.active = content.get('active')
        self.ruleset_name = content.get('ruleset_name')


class LiveHunt(Hunt):
    RESOURCE_ENDPOINT = '/hunt/live'


class HistoricalHunt(Hunt):
    RESOURCE_ENDPOINT = '/hunt/historical'


class HuntResult(core.BaseJsonResource):
    def __init__(self, content, api=None):
        super(HuntResult, self).__init__(content=content, api=api)
        self.id = content['id']
        self.rule_name = content['rule_name']
        self.tags = content['tags']
        self.created = core.parse_isoformat(content['created'])
        self.sha256 = content['sha256']
        self.historicalscan_id = content['historicalscan_id']
        self.livescan_id = content['livescan_id']
        self.artifact = ArtifactInstance(content['artifact'], api)


class LiveHuntResult(HuntResult):
    RESOURCE_ENDPOINT = '/hunt/live/results'


class HistoricalHuntResult(HuntResult):
    RESOURCE_ENDPOINT = '/hunt/historical/results'


class AssertionsJob(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/consumer/assertions-job'

    def __init__(self, content, api=None):
        super(AssertionsJob, self).__init__(content=content, api=api)
        self.id = content['id']
        self.engine_id = content['engine_id']
        self.created = core.parse_isoformat(content['created'])
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
        super(VotesJob, self).__init__(content=content, api=api)
        self.id = content['id']
        self.engine_id = content['engine_id']
        self.created = core.parse_isoformat(content['created'])
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
        super(LocalArtifact, self).__init__(response, api=api, hash_type='sha256')
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
                # TODO: this should be replaced with os.makedirs(path, exist_ok=True)
                #  once we drop support to python 2.7
                if not os.path.exists(folder):
                    try:
                        os.makedirs(folder)
                    except FileExistsError:
                        pass
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
                'url': '{}/download/{}/{}'.format(api.uri, hash_type, hash_value),
                'stream': True,
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

    @classmethod
    def from_handle(cls, api, handle, artifact_type=None, analyze=False, artifact_name=None, **kwargs):
        # create the LocalHandle with the given handle and don't write anything to it
        return cls(b'', handle=handle, artifact_name=artifact_name,
                   artifact_type=artifact_type, analyze=analyze, api=api)

    @classmethod
    def from_path(cls, api, path, artifact_type=None, analyze=False, artifact_name=None, **kwargs):
        if not isinstance(path, string_types):
            raise exceptions.InvalidValueException('Path should be a string')
        artifact_name = artifact_name or os.path.basename(path)
        handle = open(path, mode='rb', **kwargs)
        # create the LocalHandle with the given handle and don't write anything to it
        return cls(b'', handle=handle, artifact_name=artifact_name,
                   artifact_type=artifact_type, analyze=analyze, api=api)

    @classmethod
    def from_content(cls, api, content, artifact_name=None, artifact_type=None, analyze=False):
        if isinstance(content, string_types):
            content = content.encode("utf8")
        handle = io.BytesIO(content)
        # create the LocalHandle with the given handle and don't write anything to it
        return cls(b'', handle=handle, artifact_name=artifact_name,
                   artifact_type=artifact_type, analyze=analyze, api=api)

    @property
    def hash(self):
        self.analyze_artifact()
        return super(LocalArtifact, self).hash

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
        super(YaraRuleset, self).__init__(content, api=api)
        self.yara = content['yara']
        self.name = content.get('name')
        self.id = content.get('id')
        self.description = content.get('description')
        self.created = core.parse_isoformat(content.get('created'))
        self.modified = core.parse_isoformat(content.get('modified'))
        self.deleted = content.get('deleted')

        if not self.yara:
            raise exceptions.InvalidValueException("Must provide yara ruleset content")

    def validate(self):
        try:
            yara.compile(source=self.yara)
        except AttributeError:
            raise exceptions.NotImportedException("Cannot validate rules locally without yara-python")
        except yara.SyntaxError as e:
            raise exceptions.InvalidYaraRulesException('Malformed yara file: {}'.format(e.args[0]) + '\n')
        return True


class TagLink(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/tags/link'
    RESOURCE_ID_KEY = 'hash'

    def __init__(self, content, api=None):
        super(TagLink, self).__init__(content, api=api)
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
    RESOURCE_ID_KEY = 'name'

    def __init__(self, content, api=None):
        super(MalwareFamily, self).__init__(content, api=api)
        self.id = content.get('id')
        self.created = core.parse_isoformat(content.get('created'))
        self.updated = core.parse_isoformat(content.get('updated'))
        self.name = content.get('name')
        self.emerging = core.parse_isoformat(content.get('emerging'))


class Tag(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/tags/tag'
    RESOURCE_ID_KEY = 'name'

    def __init__(self, content, api=None):
        super(Tag, self).__init__(content, api=api)
        self.id = content.get('id')
        self.created = core.parse_isoformat(content.get('created'))
        self.updated = core.parse_isoformat(content.get('updated'))
        self.name = content.get('name')


#####################################################################
# Nested Resources
#####################################################################


class Assertion(core.BaseJsonResource):
    def __init__(self, content, api=None, scanfile=None):
        super(Assertion, self).__init__(content, api=api)
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
        super(Vote, self).__init__(content, api=api)
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
            raise raise_from(
                exceptions.InvalidValueException(
                    'Unable to get the artifact type from the provided value {}'.format(value)), e)

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
        super(Hash, self).__init__(hash_value=hash_, hash_type=hash_type, validate_hash=validate_hash)

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
                raise exceptions.InvalidValueException('Detected hash type {}, got {} for hashable {}'
                                                       .format(hash_.hash_type, hash_type, hash_.hash))
            return Hash(hash_.hash, hash_type=hash_type)
        return Hash(hash_, hash_type=hash_type)

    def __hash__(self):
        return hash(self.hash)

    def __str__(self):
        return self.hash

    def __repr__(self):
        return "{}={}".format(self.hash_type, self.hash)
