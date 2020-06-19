import logging
import os
import io
import functools
import warnings
from binascii import unhexlify
from enum import Enum
from hashlib import sha256 as _sha256, sha1 as _sha1, md5 as _md5

from future.utils import raise_from, string_types

try:
    import yara
except ImportError:
    yara = None

from polyswarm_api import exceptions, core, settings

logger = logging.getLogger(__name__)


#####################################################################
# Resources returned by the API
#####################################################################

class Engine(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/microengines'

    def __init__(self, json, api=None):
        super(Engine, self).__init__(json=json, api=api)
        self.address = json['address'].lower()
        self.name = json.get('name')

    @classmethod
    def _list_headers(cls, api):
        return {'Authorization': None}


class Metadata(core.BaseJsonResource, core.AsInteger):
    RESOURCE_ENDPOINT = '/search/metadata/query'
    KNOWN_KEYS = {'artifact', 'exiftool', 'hash', 'lief', 'pefile', 'scan', 'strings'}

    def __init__(self, json, api=None):
        super(Metadata, self).__init__(json=json, api=api)
        self.created = core.parse_isoformat(self.artifact.get('created'))

        self.id = self.artifact.get('id')

        self.sha1 = self.artifact.get('sha1')
        self.sha256 = self.artifact.get('sha256')
        self.md5 = self.artifact.get('md5')

        self.ssdeep = self.hash.get('ssdeep')
        self.tlsh = self.hash.get('tlsh')

        self.first_seen = core.parse_isoformat(self.scan.get('first_scan', {}).get('created'))
        self.last_scanned = core.parse_isoformat(self.scan.get('latest_scan', {}).get('created'))
        self.mimetype = self.scan.get('mimetype', {}).get('mime')
        self.extended_mimetype = self.scan.get('mimetype', {}).get('extended')
        self.malicious = self.scan.get('detections', {}).get('malicious')
        self.benign = self.scan.get('detections', {}).get('benign')
        self.total_detections = self.scan.get('detections', {}).get('total')
        self.filenames = self.scan.get('filename')

        self.domains = self.strings.get('domains')
        self.ipv4 = self.strings.get('ipv4')
        self.ipv6 = self.strings.get('ipv6')
        self.urls = self.strings.get('urls')

    @classmethod
    def _get_params(cls, **kwargs):
        return cls._params('query', **kwargs)

    def __contains__(self, item):
        return item in self.json

    def __getattr__(self, name):
        try:
            return self.json[name]
        except KeyError:
            if name in Metadata.KNOWN_KEYS:
                return {}
            raise AttributeError()


class ArtifactInstance(core.BaseJsonResource, core.Hashable, core.AsInteger):
    def __init__(self, json, api=None):
        super(ArtifactInstance, self).__init__(json=json, api=api)
        # Artifact fields
        self.artifact_id = json['artifact_id']
        self.sha256 = json['sha256']
        self.md5 = json['md5']
        self.sha1 = json['sha1']
        self.mimetype = json['mimetype']
        self.size = json['size']
        self.extended_type = json['extended_type']
        self.first_seen = core.parse_isoformat(json['first_seen'])
        # Deprecated
        self.last_seen = core.parse_isoformat(json['last_seen'])
        self.last_scanned = core.parse_isoformat(json['last_scanned'])
        metadata_json = json.get('metadata') or []
        metadata = {metadata['tool']: metadata['tool_metadata'] for metadata in metadata_json}
        self.metadata = Metadata(metadata, api)

        # ArtifactInstance fields
        self.id = json.get('id')
        self.assertions = [Assertion(self, a, api) for a in json.get('assertions', [])]
        self.country = json.get('country')
        self.community = json.get('community')
        self.created = core.parse_isoformat(json.get('created'))
        self.failed = json.get('failed')
        self.filename = json.get('filename')
        self.result = json.get('result')
        self.type = json.get('type')
        self.votes = [Vote(self, v, api) for v in json.get('votes', [])]
        self.window_closed = json.get('window_closed')
        self.polyscore = float(json['polyscore']) if json.get('polyscore') is not None else None
        self.permalink = settings.DEFAULT_PERMALINK_BASE + '/' + str(self.hash)

        self._malicious_assertions = None
        self._benign_assertions = None
        self._valid_assertions = None

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
        )

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
        )

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
        )

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
        )

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
        )

    @classmethod
    def rescanid(cls, api, submission_id, scan_config=None):
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
        )

    @classmethod
    def lookup_uuid(cls, api, submission_id):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': '{}/consumer/submission/{}/{}'.format(api.uri, api.community, int(submission_id)),
            },
            result_parser=cls,
        )

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
        )

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


class ArtifactArchive(core.BaseJsonResource, core.AsInteger):
    def __init__(self, json, api=None):
        super(ArtifactArchive, self).__init__(json=json, api=api)
        self.id = json['id']
        self.community = json['community']
        self.created = core.parse_isoformat(json['created'])
        self.uri = json['uri']

    @classmethod
    def stream(cls, api, since=settings.MAX_SINCE_TIME_STREAM):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': '{}/consumer/download/stream'.format(api.uri),
                'params': {'since': since},
            },
            result_parser=cls,
        )


class Hunt(core.BaseJsonResource, core.AsInteger):
    def __init__(self, json, api=None):
        super(Hunt, self).__init__(json=json, api=api)
        # active only present for live hunts
        self.id = json['id']
        self.created = core.parse_isoformat(json['created'])
        self.status = json['status']
        self.active = json.get('active')
        self.ruleset_name = json.get('ruleset_name')


class LiveHunt(Hunt):
    RESOURCE_ENDPOINT = '/hunt/live'

    @classmethod
    def _list_params(cls, **kwargs):
        return cls._params('since', 'all', **kwargs)


class HistoricalHunt(Hunt):
    RESOURCE_ENDPOINT = '/hunt/historical'

    @classmethod
    def _list_params(cls, **kwargs):
        return cls._params('since', **kwargs)


class HuntResult(core.BaseJsonResource, core.AsInteger):
    def __init__(self, json, api=None):
        super(HuntResult, self).__init__(json=json, api=api)
        self.id = json['id']
        self.rule_name = json['rule_name']
        self.tags = json['tags']
        self.created = core.parse_isoformat(json['created'])
        self.sha256 = json['sha256']
        self.historicalscan_id = json['historicalscan_id']
        self.livescan_id = json['livescan_id']
        self.artifact = ArtifactInstance(json['artifact'], api)

    @classmethod
    def live_hunt_results(cls, api, hunt_id=None, since=None, tag=None, rule_name=None):
        req = {
            'method': 'GET',
            'url': '{}/hunt/live/results'.format(api.uri),
            'params': {
                'since': since,
                'id': str(int(hunt_id)) if hunt_id else '',
            },
        }
        if tag is not None:
            req['params']['tag'] = tag
        if rule_name is not None:
            req['params']['rule_name'] = rule_name
        return core.PolyswarmRequest(
            api,
            req,
            result_parser=cls,
        )

    @classmethod
    def historical_hunt_results(cls, api, hunt_id=None, tag=None, rule_name=None):
        req = {
            'method': 'GET',
            'url': '{}/hunt/historical/results'.format(api.uri),
            'params': {'id': str(int(hunt_id)) if hunt_id else ''},
        }
        if tag is not None:
            req['params']['tag'] = tag
        if rule_name is not None:
            req['params']['rule_name'] = rule_name
        return core.PolyswarmRequest(
            api,
            req,
            result_parser=cls,
        )


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


class LocalHandle(core.BaseResource):
    def __init__(self, content, api=None, handle=None):
        super(LocalHandle, self).__init__(api=api)
        self.handle = handle or io.BytesIO()
        for chunk in content:
            self.handle.write(chunk)
            if hasattr(self.handle, 'flush'):
                self.handle.flush()

    @classmethod
    def download(cls, api, hash_value, hash_type, handle=None):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': '{}/download/{}/{}'.format(api.uri, hash_type, hash_value),
                'stream': True,
            },
            result_parser=cls,
            handle=handle,
        )

    @classmethod
    def download_archive(cls, api, u, handle=None):
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
        )

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


class LocalArtifact(LocalHandle, core.Hashable):
    """ Artifact for which we have local content """
    def __init__(self, handle, artifact_name=None, artifact_type=None, api=None, analyze=True):
        """
        A representation of an artifact we have locally

        :param artifact_name: Name of the artifact
        :param artifact_type: Type of artifact
        :param api: PolyswarmAPI instance
        :param analyze: Boolean, if True will run analyses on artifact on startup (Note: this may still run later if False)
        """
        # create the LocalHandle with the given handle and don't write anything to it
        super(LocalArtifact, self).__init__(b'', api=api, handle=handle)

        self.sha256 = None
        self.sha1 = None
        self.md5 = None
        self.analyzed = False

        self.artifact_type = artifact_type or ArtifactType.FILE

        self.artifact_name = artifact_name or os.path.basename(getattr(handle, 'name', '')) or str(self.hash)

        if analyze:
            self.analyze_artifact()

    @classmethod
    def from_path(cls, api, path, artifact_type=None, analyze=False, create=False, artifact_name=None, **kwargs):
        if not isinstance(path, string_types):
            raise exceptions.InvalidValueException('Path should be a string')
        folder, file_name = os.path.split(path)
        if create:
            # TODO: this should be replaced with os.makedirs(path, exist_ok=True)
            #  once we drop support to python 2.7
            if not os.path.exists(folder):
                try:
                    os.makedirs(folder)
                except FileExistsError:
                    pass
        elif not os.path.isfile(path):
            raise exceptions.ArtifactDeletedException("The file does not exist")

        mode = kwargs.pop('mode', 'wb+' if create else 'rb')
        handler = open(path, mode=mode, **kwargs)
        return cls(handler, artifact_name=artifact_name or file_name, artifact_type=artifact_type, analyze=analyze, api=api)

    @classmethod
    def from_content(cls, api, content, artifact_name=None, artifact_type=None, analyze=False):
        if isinstance(content, string_types):
            content = content.encode("utf8")
        handler = io.BytesIO(content)
        return cls(handler, artifact_name=artifact_name, artifact_type=artifact_type, analyze=analyze, api=api)

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

    def _calc_hashes(self, fh):
        self.sha256, self.sha1, self.md5 = all_hashes(fh)

    def _run_analyzers(self, fh):
        # TODO implement custom analyzer support, so users can implement plugins here.
        return {}

    def __str__(self):
        return "Artifact <%s>" % self.hash


class YaraRuleset(core.BaseJsonResource, core.AsInteger):
    RESOURCE_ENDPOINT = '/hunt/rule'

    def __init__(self, json, api=None):
        super(YaraRuleset, self).__init__(json, api)
        self.yara = json['yara']
        self.name = json.get('name')
        self.id = json.get('id')
        self.description = json.get('description')
        self.created = core.parse_isoformat(json.get('created'))
        self.modified = core.parse_isoformat(json.get('modified'))
        self.deleted = json.get('deleted')

        if not self.yara:
            raise exceptions.InvalidValueException("Must provide yara ruleset content")

    def validate(self):
        if not yara:
            raise exceptions.NotImportedException("Cannot validate rules locally without yara-python")

        try:
            yara.compile(source=self.yara)
        except yara.SyntaxError as e:
            raise exceptions.InvalidYaraRulesException('Malformed yara file: {}'.format(e.args[0]) + '\n')

        return True


class TagLink(core.BaseJsonResource, core.AsInteger):
    RESOURCE_ENDPOINT = '/tags/link'
    RESOURCE_ID_KEY = 'hash'

    def __init__(self, json, api=None):
        super(TagLink, self).__init__(json, api)
        self.id = json.get('id')
        self.sha256 = json.get('sha256')
        self.created = core.parse_isoformat(json.get('created'))
        self.updated = core.parse_isoformat(json.get('updated'))
        self.first_seen = core.parse_isoformat(json.get('first_seen'))
        self.tags = json.get('tags')
        self.families = json.get('families')

    @classmethod
    def _list_params(cls, **kwargs):
        params = []
        empty = tuple()
        params.extend(('tag', p) for p in kwargs.get('tags', empty))
        params.extend(('family', p) for p in kwargs.get('families', empty))
        params.extend(('or_tag', p) for p in kwargs.get('or_tags', empty))
        params.extend(('or_family', p) for p in kwargs.get('or_families', empty))
        return params, None


class MalwareFamily(core.BaseJsonResource, core.AsInteger):
    RESOURCE_ENDPOINT = '/tags/family'
    RESOURCE_ID_KEY = 'name'

    def __init__(self, json, api=None):
        super(MalwareFamily, self).__init__(json, api)
        self.id = json.get('id')
        self.created = core.parse_isoformat(json.get('created'))
        self.updated = core.parse_isoformat(json.get('updated'))
        self.name = json.get('name')
        self.emerging = core.parse_isoformat(json.get('emerging'))


class Tag(core.BaseJsonResource, core.AsInteger):
    RESOURCE_ENDPOINT = '/tags/family'
    RESOURCE_ID_KEY = 'name'

    def __init__(self, json, api=None):
        super(Tag, self).__init__(json, api)
        self.id = json.get('id')
        self.created = core.parse_isoformat(json.get('created'))
        self.updated = core.parse_isoformat(json.get('updated'))
        self.name = json.get('name')


#####################################################################
# Nested Resources
#####################################################################


class Assertion(core.BaseJsonResource):
    def __init__(self, scanfile, json, api=None):
        super(Assertion, self).__init__(json=json, api=api)
        self.scanfile = scanfile
        self.author = json['author']
        self.author_name = json['author_name']
        self.engine_name = json['engine'].get('name')
        self.bid = int(json['bid'])
        self.mask = json['mask']
        # deal with metadata being a string instead of null
        self.metadata = json['metadata'] if json['metadata'] else {}
        self.verdict = json['verdict']

    def __str__(self):
        return "Assertion-%s: %s" % (self.engine_name, self.verdict)


class Vote(core.BaseJsonResource):
    def __init__(self, scanfile, json, api=None):
        super(Vote, self).__init__(json=json, api=api)
        self.scanfile = scanfile
        self.arbiter = json['arbiter']
        self.vote = json['vote']

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


def is_hex(value):
    try:
        _ = int(value, 16)
        return True
    except ValueError:
        return False


def is_valid_sha1(value):
    if len(value) != 40:
        return False
    return is_hex(value)


def is_valid_md5(value):
    if len(value) != 32:
        return False
    return is_hex(value)


def is_valid_sha256(value):
    if len(value) != 64:
        return False
    return is_hex(value)


class Hash(core.Hashable):
    SUPPORTED_HASH_TYPES = {
        'sha1': is_valid_sha1,
        'sha256': is_valid_sha256,
        'md5': is_valid_md5,
    }

    def __init__(self, hash_, hash_type=None):
        super(Hash, self).__init__()
        hash_ = hash_.strip()

        if hash_type and hash_type not in Hash.SUPPORTED_HASH_TYPES:
            raise exceptions.InvalidValueException('Hash type provided is not supported.')

        self._hash_type = Hash.get_hash_type(hash_)

        if self._hash_type is None:
            raise exceptions.InvalidValueException('Invalid hash provided: {}'.format(hash_))

        if hash_type and self.hash_type != hash_type:
            raise exceptions.InvalidValueException('Detected hash type {}, got {} for hash {}'
                                                   .format(hash_type, self.hash_type, hash_))

        self._hash = hash_

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
            return hash_
        return Hash(hash_, hash_type=hash_type)

    @classmethod
    def get_hash_type(cls, value):
        for hash_type, check in cls.SUPPORTED_HASH_TYPES.items():
            if check(value):
                return hash_type
        return None

    @property
    def raw(self):
        return unhexlify(self.hash)

    @property
    def hash(self):
        return self._hash

    @property
    def hash_type(self):
        return self._hash_type

    def __hash__(self):
        return hash(self.hash)

    def __str__(self):
        return self.hash

    def __repr__(self):
        return "{}={}".format(self.hash_type, self.hash)
