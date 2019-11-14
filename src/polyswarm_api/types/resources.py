import json
import logging
import os
import tempfile
from binascii import unhexlify
from enum import Enum
from hashlib import sha256 as _sha256, sha1 as _sha1, md5 as _md5

from future.utils import raise_from, string_types
from jsonschema import validate, ValidationError
from ordered_set import OrderedSet

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


class Submission(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = schemas.bounty_schema

    def __init__(self, json, polyswarm=None):
        super(Submission, self).__init__(json=json, polyswarm=polyswarm)
        self.status = json['status']
        self.uuid = json['uuid']
        self.community = json.get('community')
        self.country = json.get('country')
        self.instances = [ArtifactInstance(f, polyswarm) for f in json['instances']]

        self._permalink = None

    @property
    def failed(self):
        return self.status == 'Bounty Failed'

    @property
    def ready(self):
        return self.status == 'Bounty Awaiting Arbitration' or self.status == 'Bounty Settled'

    @property
    def permalink(self):
        if not self._permalink and self.uuid:
            self._permalink = const.DEFAULT_PERMALINK_BASE + '/' + self.uuid
        return self._permalink

    def __str__(self):
        return "Submission-%s" % self.uuid


class PolyScore(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = schemas.polyscore_schema

    def __init__(self, json, polyswarm=None):
        super(PolyScore, self).__init__(json=json, polyswarm=polyswarm)

        self.scores = json['scores']

    def get_score_by_id(self, instance_id):
        return self.scores.get(str(instance_id), None)


class Engine(base.BasePSJSONType, base.BasePSResourceType):
    def __init__(self, json, polyswarm=None):
        super(Engine, self).__init__(json=json, polyswarm=polyswarm)
        self.address = json['address'].lower()
        self.name = json.get('name')


class ArtifactInstance(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = schemas.artifact_instance_schema

    def __init__(self, json, polyswarm=None):
        super(ArtifactInstance, self).__init__(json=json, polyswarm=polyswarm)
        self.id = json['id']
        self.submission_id = json['submission_id']
        self.submission_uuid = json['submission_uuid']
        self.artifact_id = json['id']
        self.account_id = json['account_id']
        self.assertions = [Assertion(self, a, polyswarm) for a in json['assertions']]
        self.country = json['country']
        self.community = json['community']
        self.created = date.parse_isoformat(json['created'])
        self.extended_type = json['extended_type']
        self.failed = json['failed']
        self.filename = json['filename']
        self.first_seen = json['first_seen']
        self.last_seen = date.parse_isoformat(json['last_seen'])
        self.md5 = json['md5']
        self.metadata = ArtifactMetadata(self, json.get('artifact_metadata', {}), polyswarm)
        self.mimetype = json['mimetype']
        self.result = json['result']
        self.sha1 = json['sha1']
        self.sha256 = json['sha256']
        self.size = json['size']
        self.type = json['type']
        self.votes = [Vote(self, v, polyswarm) for v in json['votes']]
        self.window_closed = json['window_closed']

        self._submission = None
        self._polyscore = None
        self._permalink = None
        self._detections = None
        self._valid_assertions = None

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
    def polyscore(self):
        if self.polyswarm and not self._polyscore and self.submission_uuid:
            polyscore = next(self.polyswarm.score(self.submission_uuid))
            self._polyscore = polyscore.get_score_by_id(self.id)
        return self._polyscore

    @property
    def submission(self):
        if self.polyswarm and not self._submission and self.submission_uuid:
            self._submission = next(self.polyswarm.lookup(self.submission_uuid))
        return self._submission

    @property
    def permalink(self):
        if not self._permalink and self.submission_uuid:
            self._permalink = const.DEFAULT_PERMALINK_BASE + '/' + self.submission_uuid
        return self._permalink


class ArtifactArchive(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = schemas.artifact_archive_schema

    def __init__(self, json, polyswarm=None):
        super(ArtifactArchive, self).__init__(json=json, polyswarm=polyswarm)
        self.id = json['id']
        self.community = json['community']
        self.created = date.parse_isoformat(json['created'])
        self.s3_path = json['s3_path']


class Hunt(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = schemas.hunt_status

    def __init__(self, json, polyswarm=None):
        super(Hunt, self).__init__(json=json, polyswarm=polyswarm)
        # active only present for live hunts
        self.id = json['id']
        self.created = date.parse_isoformat(json['created'])
        self.status = json['status']
        self.active = json.get('active')


class HuntResult(base.BasePSJSONType, base.BasePSResourceType):
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
        self.artifact = Artifact(json['artifact'], polyswarm)


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


class LocalArtifact(base.Hashable, base.BasePSResourceType):
    """ Artifact for which we have local content """
    def __init__(self, path=None, content=None, artifact_name=None, artifact_type=None, polyswarm=None, analyze=True):
        """
        A representation of an artifact we have locally

        :param path: Path to the artifact
        :param content: Content of the artifact
        :param artifact_name: Name of the artifact
        :param artifact_type: Type of artifact
        :param remote: Associated Artifact object of polyswarm API data
        :param polyswarm: PolyswarmAPI instance
        :param lookup: Boolean, if True will look up associated Artifact data
        :param analyze: Boolean, if True will run analyses on artifact on startup (Note: this may still run later if False)
        """
        super(LocalArtifact, self).__init__(polyswarm=polyswarm)
        if not (path or content):
            raise exceptions.InvalidValueException("Must provide either a path to a file or the artifact content")

        if content is not None:
            if isinstance(content, string_types):
                content = content.encode("utf8")
            with tempfile.NamedTemporaryFile(delete=False) as file:
                self.path = file.name
                file.write(content)
        else:
            self.path = path

        self.artifact_type = artifact_type or ArtifactType.FILE
        self._artifact_name = artifact_name

        self.sha256 = None
        self.sha1 = None
        self.md5 = None

        self.analyzed = False
        if analyze:
            self.analyze_artifact()

        super(LocalArtifact, self).__init__()

    @classmethod
    def parse_result(cls, api_instance, result, output_file=None, create=False):
        if isinstance(output_file, string_types):
            path, file_name = os.path.split(output_file)
            parsed_result = cls(path=output_file, artifact_name=file_name, analyze=False, polyswarm=api_instance)
            if create:
                # TODO: this should be replaced with os.makedirs(path, exist_ok=True)
                #  once we drop support to python 2.7
                if not os.path.exists(path):
                    os.makedirs(path)
            with open(output_file, 'wb') as file_handle:
                for chunk in result.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
                    file_handle.write(chunk)
        else:
            parsed_result = cls(path=output_file, analyze=False, polyswarm=api_instance)
            for chunk in result.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
                output_file.write(chunk)
        return parsed_result

    @property
    def hash(self):
        self.analyze_artifact()
        return self.sha256

    @property
    def hash_type(self):
        return "sha256"

    @property
    def artifact_name(self):
        if self._artifact_name:
            return self._artifact_name
        return self.hash

    # TODO: replace with def open(self, *args, mode='rb', **kwargs):
    #  once we drop support for python 2.7
    def open(self, *args, **kwargs):
        mode = kwargs.pop('mode', 'rb')
        if isinstance(self.path, string_types):
            self._raise_if_deleted()
            return open(self.path, *args, mode=mode, **kwargs)
        else:
            return self.path

    def analyze_artifact(self, force=False):
        self._raise_if_deleted()
        if not self.analyzed or force:
            with self.open() as fh:
                self._calc_hashes(fh)
                fh.seek(0)
                self._run_analyzers(fh)
            self.analyzed = True

    def _raise_if_deleted(self):
        if not os.path.isfile(self.path):
            raise exceptions.ArtifactDeletedException("Tried to use deleted LocalArtifact")

    def _calc_hashes(self, fh):
        self.sha256, self.sha1, self.md5 = all_hashes(fh)

    def _calc_features(self, fh):
        # TODO implement feature extraction here. This will be used by search_features function.
        return {}

    def _run_analyzers(self, fh):
        # TODO implement custom analyzer support, so users can implement plugins here.
        return {}

    def delete(self):
        os.remove(self.path)

    def __str__(self):
        return "Artifact <%s>" % self.hash


#####################################################################
# Nested Resources
#####################################################################


class Artifact(base.Hashable, base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = schemas.artifact_schema

    def __init__(self, json, polyswarm=None):
        """
        A representation of artifact data retrieved from the polyswarm API


        :param path: Path to the artifact
        :param content: Content of the artifact
        :param artifact_name: Name of the artifact (filename, or otherwise)
        :param artifact_type: base.ArtifactType of the artifact
        :param polyswarm: Current PolyswarmAPI instance
        :param json: JSON used to
        :param analyze:
        """
        super(Artifact, self).__init__(json=json, polyswarm=polyswarm)

        self.mimetype = json['mimetype']
        self.extended_type = json['extended_type']
        self.first_seen = date.parse_isoformat(json['first_seen'])
        self.id = json['id']
        self.sha256 = Hash(json['sha256'], 'sha256', polyswarm)
        self.sha1 = Hash(json['sha1'], 'sha1', polyswarm)
        self.md5 = Hash(json['md5'], 'md5', polyswarm)

        self.instances = list(
            sorted(
                [ArtifactInstance(instance,polyswarm=polyswarm) for instance in json.get('artifact_instances', [])],
                key=lambda x: x.submitted, reverse=True
            ))

        # for now, we don't have a special Metadata object, but if something differentiates this
        # in the future from a simple dict, we can
        self.metadata = ArtifactMetadata(self, json.get('artifact_metadata', {}), polyswarm)

        self._polyscore = None

    @property
    def hash(self):
        return self.sha256

    @property
    def hash_type(self):
        return "sha256"

    def __str__(self):
        return "Artifact <%s>" % self.hash

    @classmethod
    def from_json(cls, json, polyswarm=None):
        pass

    def download(self, out_path=None):
        """
        Download an artifact

        :param out_path: output path for artifact
        :return: LocalArtifact instance
        """
        if not any([self.sha256, self.md5, self.sha1]):
            raise exceptions.InvalidValueException('At least one hash type must be defined.')
        result = self.polyswarm.download(self)
        result.artifact = self
        return result

    @property
    def similar(self):
        return []

    @property
    def last_scan(self):
        if len(self.scans) > 0:
            return self.scans[0]
        return None

    @property
    def first_scan(self):
        if len(self.scans) > 0:
            return self.scans[-1]
        return None

    @property
    def scans(self):
        # do not report scans as they are running, only once window has closed
        return list(filter(None, [instance for instance in self.instances
                                  if instance.window_closed and not instance.failed]))

    @property
    def scan_permalink(self):
        if len(self.bounties) == 0:
            return None
        return self.instances[0].submission_uuid

    @property
    def bounties(self):
        return [instance.bounty for instance in self.instances if instance.bounty]

    @property
    def filenames(self):
        """ Unique filenames in all observed instances"""
        return list(OrderedSet([instance.name for instance in self.instances if instance.name]))

    @property
    def countries(self):
        return list(OrderedSet([instance.country for instance in self.instances if instance.country]))

    @property
    def detections(self):
        latest = self.last_scan
        if latest:
            return [a for a in latest.assertions if a.mask and a.verdict]
        else:
            return []

    @property
    def polyscore(self):
        if self._polyscore:
            return self._polyscore

        # need polyswarm API to look this up
        if not self.polyswarm:
            return None

        latest = self.last_scan

        if not latest:
            return None

        return latest.polyscore


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


class ArtifactMetadata(base.BasePSJSONType):
    SCHEMA = schemas.artifact_metadata

    def __init__(self, artifact, json, polyswarm=None):
        super(ArtifactMetadata, self).__init__(json=json, polyswarm=polyswarm)

        self.artifact = artifact
        self.hash = json.get('hash', {})
        self.exiftool = json.get('exiftool', {})
        self.lief = json.get('lief', {})
        self.pefile = json.get('pefile', {})


#####################################################################
# Resources Used as input parameters in PolyswarmAPI
#####################################################################


class YaraRuleset(base.BasePSJSONType):
    def __init__(self, ruleset, path=None, polyswarm=None):
        super(YaraRuleset, self).__init__(polyswarm)

        if not (path or ruleset):
            raise exceptions.InvalidValueException("Must provide artifact content, either via path or content argument")

        if ruleset:
            self.ruleset = ruleset
        else:
            self.ruleset = open(path, "r").read()

    def validate(self):
        if not yara:
            raise exceptions.NotImportedException("Cannot validate rules locally without yara-python")

        try:
            yara.compile(source=self.ruleset)
        except yara.SyntaxError as e:
            raise exceptions.InvalidYaraRulesException(*e.args)

        return True


class Query(base.BasePSType):
    def __init__(self, polyswarm=None):
        super(Query, self).__init__(polyswarm)


class MetadataQuery(Query):
    """ Class representing a MetadataQuery """
    def __init__(self, query, raw=False, polyswarm=None):
        super(MetadataQuery, self).__init__(polyswarm)
        if not raw:
            query = {
                'query': {
                    'query_string': {
                        'query': query
                    }
                }
            }
        self.query = query
        self.validate()

    def validate(self):
        try:
            validate(self.query, schemas.search_schema)
        except ValidationError:
            raise exceptions.InvalidJSONResponseException("Failed to validate json against schema",
                                                          self.query, schemas.search_schema)

    def __repr__(self):
        return json.dumps(self.query)


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
                exceptions.InvalidValueException('Unable to get the artifact type from the provided value {}'
                                                 .format(value),
                                                 e))

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
            raise exceptions.InvalidValueException("Invalid hash provided: %s", hash_)

        if hash_type and self.hash_type != hash_type:
            raise exceptions.InvalidValueException("Expected hash type %s, got %s", hash_type, self.hash_type)

        self._hash = hash_

    @classmethod
    def from_hashable(cls, h, polyswarm=None):
        """
        Coerce to Hashable object

        :param h: Hashable object
        :param polyswarm: PolyswarmAPI instance
        :return: Hash
        """
        if issubclass(type(h), base.Hashable):
            return h
        return Hash(h, polyswarm)

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
