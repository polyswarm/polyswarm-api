import logging
from enum import Enum
from binascii import unhexlify
from hashlib import sha256 as _sha256, md5 as _md5, sha1 as _sha1

from jsonschema import validate, ValidationError

from polyswarm_api.exceptions import InvalidHashException
from polyswarm_api.utils import logger

from .. import exceptions
from ..const import FILE_CHUNK_SIZE


logger = logging.getLogger(__name__)


class BasePSType(object):
    def __init__(self, polyswarm=None):
        self.polyswarm = polyswarm


class BasePSJSONType(BasePSType):
    SCHEMA = {
        'type': ['object', 'array']
    }

    def __init__(self, json=None, polyswarm=None):
        super(BasePSJSONType, self).__init__(polyswarm=polyswarm)
        self._json = None
        if json is not None:
            self.json = json

    @property
    def json(self):
        return self._json

    @json.setter
    def json(self, value):
        # this is expensive on thousands of objects
        # avoid if disabled
        if self.polyswarm and self.polyswarm.validate:
             self.validate(value)
        self._json = value

    def validate(self, json, schema=None):
        if not schema:
            schema = self.SCHEMA

        try:
            validate(json, schema)
        except ValidationError:
            raise exceptions.InvalidJSONResponseException("Failed to validate json against schema", json, self.SCHEMA)


class BasePSResourceType:
    @classmethod
    def parse_result(cls, api_instance, json_result, **kwargs):
        return cls(json_result, polyswarm=api_instance, **kwargs)

    @classmethod
    def parse_result_list(cls, api_instance, json_data, **kwargs):
        return [cls.parse_result(api_instance, entry, **kwargs) for entry in json_data]


# TODO make polyswarmartifact support 2.7 so this is not necessary
class ArtifactType(Enum):
    FILE = 0
    URL = 1

    @staticmethod
    def from_string(value):
        if value is not None:
            try:
                return ArtifactType[value.upper()]
            except KeyError:
                logger.critical('%s is not a supported artifact type', value)

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


# TODO better way to do this with ABC?
class Hashable(BasePSType):
    @property
    def hash(self):
        raise NotImplementedError

    @property
    def hash_type(self):
        raise NotImplementedError

    def __eq__(self, other):
        return self.hash == other


class Hash(Hashable):
    SCHEMA = {'type': ['string', 'null']}

    def __init__(self, h, expected_type=None, polyswarm=None):
        super(Hash, self).__init__()
        self.polyswarm = polyswarm
        self._hash_type = get_hash_type(h)

        if self._hash_type is None:
            raise exceptions.InvalidHashException("Invalid hash provided: %s", h)

        if expected_type and self.hash_type != expected_type:
            raise exceptions.InvalidHashException("Expected sha256, got %s", self.hash_type)

        self._hash = h

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


def is_hex(value):
    try:
        a = int(value, 16)
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


def _read_chunks(file_handle):
    while True:
        data = file_handle.read(FILE_CHUNK_SIZE)
        if not data:
            break
        yield data


def _hash_wrap(file_handle, algs):
    hashers = [alg() for alg in algs]
    for data in _read_chunks(file_handle):
        [h.update(data) for h in hashers]
    return [Hash(h.hexdigest()) for h in hashers]


def sha256(file_handle):
    return _hash_wrap(file_handle, [_sha256])[0]


def sha1(file_handle):
    return _hash_wrap(file_handle, [_sha1])[0]


def md5(file_handle):
    return _hash_wrap(file_handle, [_md5])[0]


def all_hashes(file_handle):
    return _hash_wrap(file_handle, [_sha256, _sha1, _md5])


def get_hash_type(value):
    for hash_type, check in SUPPORTED_HASH_TYPES.items():
        if check(value):
            return hash_type
    return None


def to_hash(h, polyswarm=None):
    """
    Coerce to Hashable object

    :param h: Hashable object
    :param polyswarm: PolyswarmAPI instance
    :return: Hash
    """
    if issubclass(type(h), Hashable):
        return h
    return Hash(h, polyswarm)


SUPPORTED_HASH_TYPES = {
    'sha1': is_valid_sha1,
    'sha256': is_valid_sha256,
    'md5': is_valid_md5,
}


def is_supported_hash_type(hash_type):
    if hash_type in SUPPORTED_HASH_TYPES:
        return True

    return False


def get_hashes_from_file(file):
    return [h.strip() for h in file.readlines()]


def parse_hashes(hashes, hash_type=None, hash_file=None):

    hashes = list(hashes)

    # validate 'hash_type' if not None
    if hash_type and not is_supported_hash_type(hash_type):
        logger.error('Hash type not supported.')


    if hash_file:
        hashes += get_hashes_from_file(hash_file)

    out = []
    for h in hashes:
        try:
            out.append(Hash(h, hash_type))
        except InvalidHashException:
            logger.warning("Invalid hash %s provided, ignoring.", h)
    return out