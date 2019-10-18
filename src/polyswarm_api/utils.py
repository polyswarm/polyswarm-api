import click
import datetime

from uuid import UUID

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


def is_valid_uuid(value):
    try:
        val = UUID(value, version=4)
        return True
    except:
        return False


def validate_uuid(ctx, param, value):
    for uuid in value:
        if not is_valid_uuid(uuid):
            raise click.BadParameter('UUID {} not valid, please check and try again.'.format(uuid))
    return value


def validate_hash(ctx, param, h):
    if not (is_valid_sha256(h) or is_valid_md5(h) or is_valid_sha1(h)):
        raise click.BadParameter('Hash {} not valid, must be sha256|md5|sha1 in hexadecimal format'.format(h))
    return h


def validate_hashes(ctx, param, value):
    for h in value:
        validate_hash(ctx, param, h)
    return value


def validate_key(ctx, param, value):
    if not is_hex(value) or len(value) != 32:
        raise click.BadParameter('Invalid API key. Make sure you specified your key via -a or environment variable and try again.')
    return value


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


def parse_date(date_string):
    """ Parses the current date format version """
    return datetime.datetime.strptime(date_string, '%a, %d %b %Y %H:%M:%S %Z')


def parse_timestamp(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp)
