#!/usr/bin/env python3
import click
import logging
import sys
import os
from uuid import UUID

from . import PolyswarmAPI
from .formatting import PSResultFormatter, PSDownloadResultFormatter

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

logger = logging.getLogger(__name__)


def is_hex(value):
    try:
        a = int(value, 16)
        return True
    except ValueError:
        return False


def _is_valid_sha1(value):
    if len(value) != 40:
        return False
    return is_hex(value)


def _is_valid_md5(value):
    if len(value) != 32:
        return False
    return is_hex(value)


def _is_valid_sha256(value):
    if len(value) != 64:
        return False
    return is_hex(value)


def _is_valid_uuid(value):
    try:
        val = UUID(value, version=4)
        return True
    except:
        return False


def validate_uuid(ctx, param, value):
    for uuid in value:
        if not _is_valid_uuid(uuid):
            raise click.BadParameter('UUID %s not valid, please check and try again.' % uuid)
    return value


def validate_hash(ctx, param, value):
    for h in value:
        if not (_is_valid_sha256(h) or _is_valid_md5(h) or _is_valid_sha1(h)):
            raise click.BadParameter('Hash %s not valid, must be sha256|md5|sha1 in hexadecimal format' % h)
    return value


def validate_key(ctx, param, value):
    if not is_hex(value) or len(value) != 32:
        raise click.BadParameter("Invalid API key. Make sure you specified your key via -a or environment variable and try again.")
    return value


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-a", "--api-key", help="Your API key for polyswarm.network (required)", default="", callback=validate_key, envvar="POLYSWARM_API_KEY")
@click.option("-u", "--api-uri", default="https://consumer.prod.polyswarm.network", envvar="POLYSWARM_API_URI", help="The API endpoint (ADVANCED)")
@click.option("-o", "--output-file", default=sys.stdout, type=click.File("w"), help="Path to output file.")
@click.option("--fmt", "--output-format", default="text", type=click.Choice(['text', 'json']), help="Output format. Human-readable text or JSON.")
@click.option("--color/--no-color", default=True, help="Use colored output in text mode.")
@click.option('-v', '--verbose', default=0, count=True)
@click.option('-c', "--community", default="epoch", envvar="POLYSWARM_COMMUNITY", help="Community to use.")
@click.pass_context
def polyswarm(ctx, api_key, api_uri, output_file, output_format, color, verbose, community):
    """
    This is a PolySwarm CLI client, which allows you to interact directly
    with the PolySwarm network to scan files, search hashes, and more.
    """
    # TODO shouldn't need to do this here
    ctx.obj = {}

    if ctx.invoked_subcommand is None:
        return

    if verbose > 2:
        log_level = logging.DEBUG
    elif verbose == 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARN

    logging.basicConfig(level=log_level)

    # only allow color for stdout
    if output_file != sys.stdout:
        color = False

    logging.debug("Creating API instance: api_key:%s, api_uri:%s" % (api_key, api_uri))
    ctx.obj['api'] = PolyswarmAPI(api_key, api_uri, community=community)
    ctx.obj['color'] = color
    ctx.obj['output_format'] = output_format
    ctx.obj['output'] = output_file


def _do_scan(api, paths, recursive=False):
    # separate into paths and directories
    # TODO do this async so we don't have dumb edge cases

    # TODO dedupe

    directories, files = [], []
    for path in paths:
        if os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            directories.append(path)
        else:
            logger.warning("Path %s is neither a file nor a directory, ignoring." % path)

    results = api.scan_files(files)

    for d in directories:
        results.extend(api.scan_directory(d, recursive=recursive))

    return results


@click.option("-f", "--force", is_flag=True, default=False,  help="Force re-scan even if file has already been analyzed.")
@click.option("-r", "--recursive", is_flag=True, default=False, help="Scan directories recursively")
@click.option("-t", "--timeout", type=click.INT, default=-1, help="How long to wait for results (default: forever, -1)")
@click.argument('path', nargs=-1, type=click.Path(exists=True))
@polyswarm.command("scan", short_help="scan files/directories")
@click.pass_context
def scan(ctx, path, force, recursive, timeout):
    """
    Scan files or directories via PolySwarm
    """
    api = ctx.obj['api']

    api.timeout = timeout

    api.set_force(force)

    results = _do_scan(api, path, recursive)

    rf = PSResultFormatter(results, color=ctx.obj['color'],
                                    output_format=ctx.obj['output_format'])
    ctx.obj['output'].write(str(rf))


@click.option('-r', '--hash-file', help="File of hashes, one per line.", type=click.File('r'))
@click.option("--hash-type", help="Hash type to search [sha256|sha1|md5], default=sha256", default="sha256")
@click.option("--rescan", is_flag=True, default=False, help="Rescan any files that exist for latest results.")
@click.argument('hash', nargs=-1, callback=validate_hash)
@polyswarm.command("search", short_help="search for hash")
@click.pass_context
def search(ctx, hash, hash_file, hash_type, rescan):
    """
    Search PolySwarm for files matching sha256 hashes
    """
    api = ctx.obj['api']

    hashes = list(hash)

    # TODO dedupe
    if hash_file:
        for h in hash_file.readlines():
            h = h.strip()
            if (hash_type == "sha256" and _is_valid_sha256(h)) or \
                    (hash_type == "sha1" and _is_valid_sha1(h)) or \
                    (hash_type == "md5" and _is_valid_md5(h)):
                hashes.append(h)
            else:
                logger.warning("Invalid hash %s in file, ignoring." % h)
        
    rf = PSResultFormatter(api.search_hashes(hashes, hash_type, rescan), color=ctx.obj['color'],
                           output_format=ctx.obj['output_format'])
    ctx.obj['output'].write(str(rf))


@click.option('-r', '--uuid-file', help="File of UUIDs, one per line.", type=click.File('r'))
@click.argument('uuid', 'uuid', nargs=-1, callback=validate_uuid)
@polyswarm.command("lookup", short_help="lookup UUID(s)")
@click.pass_context
def lookup(ctx, uuid, uuid_file):
    """
    Lookup a PolySwarm scan by UUID for current status.
    """
    api = ctx.obj['api']

    uuids = list(uuid)

    # TODO dedupe
    if uuid_file:
        for u in uuid_file.readlines():
            u = u.strip()
            if _is_valid_uuid(u):
                uuids.append(u)
            else:
                logger.warning("Invalid uuid %s in file, ignoring." % u)
        
    rf = PSResultFormatter(api.lookup_uuids(uuids), color=ctx.obj['color'],
                                    output_format=ctx.obj['output_format'])
    ctx.obj['output'].write(str(rf))


@click.option('-r', '--hash-file', help="File of hashes, one per line.", type=click.File('r'))
@click.option('-m', '--metadata', is_flag=True, default=False, help="Save file metadata into associated JSON file")
@click.option("--hash-type", help="Hash type to search [sha256|sha1|md5], default=sha256", default="sha256")
@click.argument('hash', 'hash', nargs=-1, callback=validate_hash)
@click.argument('destination', 'destination', nargs=1, type=click.Path(file_okay=False))
@polyswarm.command("download", short_help="download file(s)")
@click.pass_context
def download(ctx, metadata, hash_file, hash_type, hash, destination):
    if not os.path.exists(destination):
        os.makedirs(destination)

    api = ctx.obj['api']

    hashes = list(hash)

    # TODO dedupe
    if hash_file:
        for h in hash_file.readlines():
            h = h.strip()
            if (hash_type == "sha256" and _is_valid_sha256(h)) or \
                    (hash_type == "sha1" and _is_valid_sha1(h)) or \
                    (hash_type == "md5" and _is_valid_md5(h)):
                hashes.append(h)
            else:
                logger.warning("Invalid hash %s in file, ignoring." % h)

    rf = PSDownloadResultFormatter(api.download_files(hashes, destination, metadata, hash_type),
                                   color=ctx.obj['color'], output_format=ctx.obj['output_format'])

    ctx.obj['output'].write((str(rf)))


@click.option('-r', '--hash-file', help="File of hashes, one per line.", type=click.File('r'))
@click.option("--hash-type", help="Hash type to search [sha256|sha1|md5], default=sha256", default="sha256")
@click.argument('hash', 'hash', nargs=-1, callback=validate_hash)
@polyswarm.command("rescan", short_help="rescan files(s) by hash")
@click.pass_context
def rescan(ctx, hash_file, hash_type, hash):
    api = ctx.obj['api']

    hashes = list(hash)

    # TODO dedupe
    if hash_file:
        for h in hash_file.readlines():
            h = h.strip()
            if (hash_type == "sha256" and _is_valid_sha256(h)) or \
                    (hash_type == "sha1" and _is_valid_sha1(h)) or \
                    (hash_type == "md5" and _is_valid_md5(h)):
                hashes.append(h)
            else:
                logger.warning("Invalid hash %s in file, ignoring." % h)

    rf = PSResultFormatter(api.rescan_files(hashes, hash_type), color=ctx.obj['color'],
                                    output_format=ctx.obj['output_format'])
    ctx.obj['output'].write(str(rf))


if __name__ == '__main__':
    polyswarm(obj={})
