from .types.hash import SUPPORTED_HASH_TYPES, Hash, is_hex, is_valid_md5, is_valid_sha1, is_valid_sha256, get_hash_type
from .exceptions import InvalidHashException

from .log import logger

# TODO this is a hack around bad behavior in API. Fix this in AI.
bool_to_int = {True: 1, False: ""}


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def is_supported_hash_type(hash_type):
    if hash_type in SUPPORTED_HASH_TYPES:
        return True

    return False


def get_hashes_from_file(file):
    return [h.strip() for h in file.readlines()]


def remove_invalid_hashes(hash_candidates):
    valid_hashes = []
    for candidate in hash_candidates:
        # check if are correct default hashes [sha1|sha256|md5]
        hash_type = get_hash_type(candidate)
        if hash_type:
            valid_hashes.append(candidate)
        else:
            logger.warning('Invalid hash %s, ignoring.', candidate)
    return valid_hashes


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
