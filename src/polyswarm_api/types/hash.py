from binascii import unhexlify
from hashlib import sha256 as _sha256, md5 as _md5, sha1 as _sha1

from .. import exceptions

from ..const import FILE_CHUNK_SIZE
from .base import BasePSType


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
            raise exceptions.MissingAPIInstance("Missing API instance")
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


SUPPORTED_HASH_TYPES = {
    'sha1': is_valid_sha1,
    'sha256': is_valid_sha256,
    'md5': is_valid_md5,
}


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
