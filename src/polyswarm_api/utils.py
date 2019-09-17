import click
import logging

from .const import SUPPORTED_HASH_TYPES

logger = logging.getLogger(__name__)


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

def get_hash_type(value):
    if is_valid_sha1(value):
        return 'sha1'
    elif is_valid_sha256(value):
        return 'sha256'
    elif is_valid_md5(value):
        return 'md5'
    else:
        return None

def is_valid_hash(hash_candidate, candidates_hash_type):
    if candidates_hash_type == 'sha256':
        return is_valid_sha256(hash_candidate)
    elif candidates_hash_type == 'sha1':
        return is_valid_sha1(hash_candidate)
    elif candidates_hash_type == 'md5':
        return is_valid_md5(hash_candidate)
    else:
        return False

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

def validate_hash(ctx, param, value):
    for h in value:
        if not (is_valid_sha256(h) or is_valid_md5(h) or is_valid_sha1(h)):
            raise click.BadParameter('Hash {} not valid, must be sha256|md5|sha1 in hexadecimal format'.format(h))
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

def parse_hashes(hash, hash_type, hash_file=None):

    hashes = list(hash)

    # validate 'hash_type' if not None
    if hash_type and not is_supported_hash_type(hash_type):
        logger.error('Hash type not supported.')
        return (None, None)

    if hash_file:
        hashes += get_hashes_from_file(hash_file)

    # return only valid hashes
    hashes = remove_invalid_hashes(hashes)

    return (hashes, hash_type)
