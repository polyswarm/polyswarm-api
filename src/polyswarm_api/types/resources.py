import logging
import os
import io
import functools
from binascii import unhexlify
from enum import Enum
from hashlib import sha256 as _sha256, sha1 as _sha1, md5 as _md5

from future.utils import raise_from, string_types

from polyswarm_api.const import FILE_CHUNK_SIZE

try:
    import yara
except ImportError:
    yara = None

from polyswarm_api import exceptions
from polyswarm_api import const
from . import base
from . import schemas
from . import date

logger = logging.getLogger(__name__)


#####################################################################
# Resources returned by the API
#####################################################################

class Engine(base.BasePSJSONType):
    def __init__(self, json, polyswarm=None):
        super(Engine, self).__init__(json=json, polyswarm=polyswarm)
        self.address = json['address'].lower()
        self.name = json.get('name')


class Metadata(base.BasePSJSONType, base.AsInteger):
    KNOWN_KEYS = {'artifact', 'exiftool', 'hash', 'lief', 'pefile', 'scan', 'strings'}

    def __init__(self, json, polyswarm=None):
        super(Metadata, self).__init__(json=json, polyswarm=polyswarm)
        self.created = date.parse_isoformat(self.artifact.get('created'))

        self.id = self.artifact.get('id')

        self.sha1 = self.hash.get('sha1')
        self.sha256 = self.hash.get('sha256')
        self.md5 = self.hash.get('md5')
        self.ssdeep = self.hash.get('ssdeep')
        self.tlsh = self.hash.get('tlsh')

        self.first_seen = date.parse_isoformat(self.scan.get('first_seen'))
        self.last_seen = date.parse_isoformat(self.scan.get('last_seen'))
        self.mimetype = self.scan.get('mimetype', {}).get('mime')
        self.extended_mimetype = self.scan.get('mimetype', {}).get('extended')
        self.detections = self.scan.get('detections', {}).get('malicious')
        self.total_detections = self.scan.get('detections', {}).get('total')

        self.domains = self.strings.get('domains')
        self.ipv4 = self.strings.get('ipv4')
        self.ipv6 = self.strings.get('ipv6')
        self.urls = self.strings.get('urls')

    def __contains__(self, item):
        return item in self.json

    def __getattr__(self, name):
        try:
            return self.json[name]
        except KeyError:
            if name in Metadata.KNOWN_KEYS:
                return {}
            raise AttributeError()


class ArtifactInstance(base.BasePSJSONType, base.Hashable, base.AsInteger):
    SCHEMA = schemas.artifact_instance_schema

    def __init__(self, json, polyswarm=None):
        super(ArtifactInstance, self).__init__(json=json, polyswarm=polyswarm)
        self.id = json['id']
        self.artifact_id = json['artifact_id']
        self.assertions = [Assertion(self, a, polyswarm) for a in json['assertions']]
        self.country = json['country']
        self.community = json['community']
        self.created = date.parse_isoformat(json['created'])
        self.extended_type = json['extended_type']
        self.failed = json['failed']
        self.filename = json['filename']
        self.last_seen = date.parse_isoformat(json['last_seen'])
        self.first_seen = date.parse_isoformat(json['first_seen'])
        self.md5 = json['md5']
        self.mimetype = json['mimetype']
        self.result = json['result']
        self.sha1 = json['sha1']
        self.sha256 = json['sha256']
        self.size = json['size']
        self.type = json['type']
        self.votes = [Vote(self, v, polyswarm) for v in json['votes']]
        self.window_closed = json['window_closed']
        self.polyscore = float(json['polyscore']) if json.get('polyscore') is not None else None
        self.permalink = const.DEFAULT_PERMALINK_BASE + '/' + str(self.hash)

        metadata_json = json.get('metadata') or []
        metadata = {metadata['tool']: metadata['tool_metadata'] for metadata in metadata_json}
        self.metadata = Metadata(metadata, polyswarm)

        self._detections = None
        self._valid_assertions = None
        self._filenames = None

    def __str__(self):
        return "ArtifactInstance-<%s>" % self.hash

    @property
    def detections(self):
        if not self._detections:
            self._detections = [a for a in self.assertions if a.mask and a.verdict]
        return self._detections

    @property
    def valid_assertions(self):
        if not self._valid_assertions:
            self._valid_assertions = [a for a in self.assertions if a.mask]
        return self._valid_assertions

    @property
    def filenames(self):
        if self._filenames is None:
            for metadata in self.json.get('metadata', []):
                if metadata.get('tool') == 'scan':
                    self._filenames = metadata.get('tool_metadata', {}).get('filename', [])
                    break
            else:
                self._filenames = []
        return self._filenames


class ArtifactArchive(base.BasePSJSONType, base.AsInteger):
    SCHEMA = schemas.artifact_archive_schema

    def __init__(self, json, polyswarm=None):
        super(ArtifactArchive, self).__init__(json=json, polyswarm=polyswarm)
        self.id = json['id']
        self.community = json['community']
        self.created = date.parse_isoformat(json['created'])
        self.uri = json['uri']


class Hunt(base.BasePSJSONType, base.AsInteger):
    SCHEMA = schemas.hunt_status

    def __init__(self, json, polyswarm=None):
        super(Hunt, self).__init__(json=json, polyswarm=polyswarm)
        # active only present for live hunts
        self.id = json['id']
        self.created = date.parse_isoformat(json['created'])
        self.status = json['status']
        self.active = json.get('active')
        self.ruleset_name = json.get('ruleset_name')


class HuntResult(base.BasePSJSONType, base.AsInteger):
    SCHEMA = schemas.hunt_result

    def __init__(self, json, polyswarm=None):
        super(HuntResult, self).__init__(json=json, polyswarm=polyswarm)
        self.id = json['id']
        self.rule_name = json['rule_name']
        self.tags = json['tags']
        self.created = date.parse_isoformat(json['created'])
        self.sha256 = json['sha256']
        self.historicalscan_id = json['historicalscan_id']
        self.livescan_id = json['livescan_id']
        self.artifact = ArtifactInstance(json['artifact'], polyswarm)


def _read_chunks(file_handle):
    while True:
        data = file_handle.read(FILE_CHUNK_SIZE)
        if not data:
            break
        yield data


def all_hashes(file_handle, algorithms=(_sha256, _sha1, _md5)):
    hashers = [alg() for alg in algorithms]
    for data in _read_chunks(file_handle):
        [h.update(data) for h in hashers]
    return [Hash(h.hexdigest()) for h in hashers]


class LocalHandle(base.BasePSResourceType):
    def __init__(self, contents, polyswarm=None, handle=None):
        super(LocalHandle, self).__init__(polyswarm=polyswarm)
        self.handle = handle or io.BytesIO()
        for chunk in contents:
            self.handle.write(chunk)

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


class LocalArtifact(LocalHandle, base.Hashable):
    """ Artifact for which we have local content """
    def __init__(self, handle, artifact_name=None, artifact_type=None, polyswarm=None, analyze=True):
        """
        A representation of an artifact we have locally

        :param artifact_name: Name of the artifact
        :param artifact_type: Type of artifact
        :param polyswarm: PolyswarmAPI instance
        :param analyze: Boolean, if True will run analyses on artifact on startup (Note: this may still run later if False)
        """
        # create the LocalHandle with the given handle and don't write anything to it
        super(LocalArtifact, self).__init__(b'', polyswarm=polyswarm, handle=handle)
        self.artifact_type = artifact_type or ArtifactType.FILE
        self.artifact_name = artifact_name or self.hash

        self.sha256 = None
        self.sha1 = None
        self.md5 = None
        self.analyzed = False
        if analyze:
            self.analyze_artifact()

    @classmethod
    def from_path(cls, api, path, artifact_type=None, analyze=False, create=False, **kwargs):
        if not isinstance(path, string_types):
            raise exceptions.InvalidValueException('Path should be a string')
        folder, file_name = os.path.split(path)
        if create:
            # TODO: this should be replaced with os.makedirs(path, exist_ok=True)
            #  once we drop support to python 2.7
            if not os.path.exists(folder):
                os.makedirs(folder)
        elif not os.path.isfile(path):
            raise exceptions.ArtifactDeletedException("The file does not exist")

        mode = kwargs.pop('mode', 'wb+' if create else 'rb')
        handler = open(path, mode=mode, **kwargs)
        return cls(handler, artifact_name=file_name, artifact_type=artifact_type, analyze=analyze, polyswarm=api)

    @classmethod
    def from_content(cls, api, content, artifact_name=None, artifact_type=None, analyze=False):
        if isinstance(content, string_types):
            content = content.encode("utf8")
        handler = io.BytesIO(content)
        return cls(handler, artifact_name=artifact_name, artifact_type=artifact_type, analyze=analyze, polyswarm=api)

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


class YaraRuleset(base.BasePSJSONType, base.AsInteger):
    def __init__(self, json, polyswarm=None):
        super(YaraRuleset, self).__init__(json, polyswarm)
        self.yara = json['yara']
        self.name = json.get('name')
        self.id = json.get('id')
        self.description = json.get('description')
        self.created = date.parse_isoformat(json.get('created'))
        self.modified = date.parse_isoformat(json.get('modified'))
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


class TagLink(base.BasePSJSONType, base.AsInteger):
    def __init__(self, json, polyswarm=None):
        super(TagLink, self).__init__(json, polyswarm)
        self.id = json.get('id')
        self.sha256 = json.get('sha256')
        self.created = date.parse_isoformat(json.get('created'))
        self.updated = date.parse_isoformat(json.get('updated'))
        self.first_seen = date.parse_isoformat(json.get('first_seen'))
        self.tags = json.get('tags')
        self.families = json.get('families')


class MalwareFamily(base.BasePSJSONType, base.AsInteger):
    def __init__(self, json, polyswarm=None):
        super(MalwareFamily, self).__init__(json, polyswarm)
        self.id = json.get('id')
        self.created = date.parse_isoformat(json.get('created'))
        self.updated = date.parse_isoformat(json.get('updated'))
        self.name = json.get('name')
        self.emerging = date.parse_isoformat(json.get('emerging'))


class Tag(base.BasePSJSONType, base.AsInteger):
    def __init__(self, json, polyswarm=None):
        super(Tag, self).__init__(json, polyswarm)
        self.id = json.get('id')
        self.created = date.parse_isoformat(json.get('created'))
        self.updated = date.parse_isoformat(json.get('updated'))
        self.name = json.get('name')


#####################################################################
# Nested Resources
#####################################################################


class Assertion(base.BasePSJSONType):
    SCHEMA = schemas.assertion_schema

    def __init__(self, scanfile, json, polyswarm=None):
        super(Assertion, self).__init__(json=json, polyswarm=polyswarm)
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


class Vote(base.BasePSJSONType):
    SCHEMA = schemas.vote_schema

    def __init__(self, scanfile, json, polyswarm=None):
        super(Vote, self).__init__(json=json, polyswarm=polyswarm)
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


class Hash(base.Hashable, base.BasePSType):
    SCHEMA = {'type': ['string', 'null']}

    SUPPORTED_HASH_TYPES = {
        'sha1': is_valid_sha1,
        'sha256': is_valid_sha256,
        'md5': is_valid_md5,
    }

    def __init__(self, hash_, hash_type=None, polyswarm=None):
        super(Hash, self).__init__(polyswarm=polyswarm)
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
    def from_hashable(cls, hash_, polyswarm=None, hash_type=None):
        """
        Coerce to Hashable object

        :param hash_: Hashable object
        :param hash_type: Hash type
        :param polyswarm: PolyswarmAPI instance
        :return: Hash
        """
        if issubclass(type(hash_), base.Hashable):
            if hash_type and hash_.hash_type != hash_type:
                raise exceptions.InvalidValueException('Detected hash type {}, got {} for hashable {}'
                                                       .format(hash_.hash_type, hash_type, hash_.hash))
            return hash_
        return Hash(hash_, hash_type=hash_type, polyswarm=polyswarm)

    @classmethod
    def get_hash_type(cls, value):
        for hash_type, check in cls.SUPPORTED_HASH_TYPES.items():
            if check(value):
                return hash_type
        return None

    @property
    def raw(self):
        return unhexlify(self.hash)

    def search(self):
        if not self.polyswarm:
            raise exceptions.MissingAPIInstanceException("Missing API instance")
        return self.polyswarm.search_hashes([self])

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
