#!/usr/bin/env python3
import asyncio
import base64
from io import BytesIO

import click
import logging
import sys
import os
from uuid import UUID

from aiohttp import ServerDisconnectedError

from . import PolyswarmAPI
from .formatting import PSResultFormatter, PSDownloadResultFormatter, PSSearchResultFormatter, PSHuntResultFormatter, \
    PSHuntSubmissionFormatter, PSStreamFormatter

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
            raise click.BadParameter(f'UUID {uuid} not valid, please check and try again.')
    return value


def validate_hash(ctx, param, value):
    for h in value:
        if not (_is_valid_sha256(h) or _is_valid_md5(h) or _is_valid_sha1(h)):
            raise click.BadParameter(f'Hash {h} not valid, must be sha256|md5|sha1 in hexadecimal format')
    return value


def validate_key(ctx, param, value):
    if not is_hex(value) or len(value) != 32:
        raise click.BadParameter("Invalid API key. Make sure you specified your key via -a or environment variable and try again.")
    return value


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("-a", "--api-key", help="Your API key for polyswarm.network (required)", default="", callback=validate_key, envvar="POLYSWARM_API_KEY")
@click.option("-u", "--api-uri", default="https://api.polyswarm.network/v1", envvar="POLYSWARM_API_URI", help="The API endpoint (ADVANCED)")
@click.option("-o", "--output-file", default=sys.stdout, type=click.File("w"), help="Path to output file.")
@click.option("--fmt", "--output-format", default="text", type=click.Choice(['text', 'json']), help="Output format. Human-readable text or JSON.")
@click.option("--color/--no-color", default=True, help="Use colored output in text mode.")
@click.option('-v', '--verbose', default=0, count=True)
@click.option('-c', "--community", default="lima", envvar="POLYSWARM_COMMUNITY", help="Community to use.")
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

    logging.debug(f"Creating API instance: api_key:{api_key}, api_uri:{api_uri}")
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
            logger.warning(f"Path {path} is neither a file nor a directory, ignoring.")

    results = api.scan_files(files)

    for d in directories:
        results.extend(api.scan_directory(d, recursive=recursive))

    return results


async def get_results(ctx, tasks):
    results = []
    failed_bounty, server_disconnects, other_exceptions, success = 0, 0, 0, 0
    for r in asyncio.as_completed(tasks):
        try:
            final = None
            final = await r
            results.append(final)

            zeroth_file = final['files'][0]
            if not zeroth_file.get("bounty_guid"):
                ctx.obj['output'].write(f"Failed to get bounty guid on {final.get('uuid')}\n")

            elif not zeroth_file.get("assertions"):
                ctx.obj['output'].write(f"Failed to get assertions on bounty guid on {zeroth_file.get('bounty_guid')}\n")
            success += 1
        except IndexError:
            ctx.obj['output'].write(f"Failed on bounty uuid {final.get('uuid')}\n")
            failed_bounty += 1
        except ServerDisconnectedError as e:
            ctx.obj['output'].write(f"Server disconnected error {e}\n")
            server_disconnects += 1
        except Exception as e:
            ctx.obj['output'].write(f"Failed on bounty with exception {e}\n")
            other_exceptions +=1
    return results, (failed_bounty, server_disconnects, other_exceptions, success)


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

    rf = PSResultFormatter(results, color=ctx.obj['color'], output_format=ctx.obj['output_format'])
    ctx.obj['output'].write(str(rf))


@click.option('-r', '--hash-file', help="File of hashes, one per line.", type=click.File('r'))
@click.option("--hash-type", help="Hash type to search [sha256|sha1|md5], default=sha256", default="sha256")
@click.argument('hash', nargs=-1, callback=validate_hash)
@polyswarm.command("search", short_help="search for hash")
@click.pass_context
def search(ctx, hash, hash_file, hash_type):
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
                logger.warning(f"Invalid hash {h} in file, ignoring.")

    rf = PSSearchResultFormatter(api.search_hashes(hashes, hash_type), color=ctx.obj['color'],
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
                logger.warning(f"Invalid uuid {u} in file, ignoring.")

    rf = PSResultFormatter(api.lookup_uuids(uuids), color=ctx.obj['color'], output_format=ctx.obj['output_format'])
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
                logger.warning(f"Invalid hash {h} in file, ignoring.")

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
                logger.warning(f"Invalid hash {h} in file, ignoring.")

    rf = PSResultFormatter(api.rescan_files(hashes, hash_type), color=ctx.obj['color'],
                           output_format=ctx.obj['output_format'])
    ctx.obj['output'].write(str(rf))


@polyswarm.group(short_help="interact with live scans")
def live():
    pass


@polyswarm.group(short_help="interact with historical scans")
def historical():
    pass


@click.argument('rule_file', type=click.File('r'))
@live.command("install", short_help="install a new YARA rule file")
@click.pass_context
def live_install(ctx, rule_file):
    api = ctx.obj['api']

    rules = rule_file.read()

    rf = PSHuntSubmissionFormatter(api.new_live_hunt(rules), color=ctx.obj['color'],
                      output_format=ctx.obj['output_format'])
    ctx.obj['output'].write((str(rf)))


@click.option('-i', '--rule-id', type=int, help="ID of the rule file (defaults to latest)")
@click.option("--download-path", "-d", type=click.Path(file_okay=False), help="In addition to fetching the results, download the files that matched.")
@live.command("results", short_help="get results from live hunt")
@click.pass_context
def live_results(ctx, rule_id, download_path):
    api = ctx.obj['api']

    results = api.get_live_results(rule_id)

    rf = PSHuntResultFormatter(results, color=ctx.obj['color'],
                      output_format=ctx.obj['output_format'])

    if download_path and results['status'] == 'OK':
        if not os.path.exists(download_path):
            os.makedirs(download_path)
        hashes = [match['artifact']['sha256'] for match in results['result']]
        api.download_files(hashes, download_path, False, 'sha256')

    ctx.obj['output'].write((str(rf)))


@click.argument('rule_file', type=click.File('r'))
@historical.command("start", short_help="start a new historical hunt")
@click.pass_context
def historical_start(ctx, rule_file):
    api = ctx.obj['api']

    rules = rule_file.read()

    rf = PSHuntSubmissionFormatter(api.new_historical_hunt(rules), color=ctx.obj['color'],
                      output_format=ctx.obj['output_format'])
    ctx.obj['output'].write((str(rf)))


@click.option('-i', '--rule-id', type=int, help="ID of the rule file (defaults to latest)")
@click.option("--download-path", "-d", type=click.Path(file_okay=False), help="In addition to fetching the results, download the files that matched.")
@historical.command("results", short_help="get results from historical hunt")
@click.pass_context
def historical_results(ctx, rule_id, download_path):
    api = ctx.obj['api']

    results = api.get_historical_results(rule_id)

    rf = PSHuntResultFormatter(results, color=ctx.obj['color'],
                      output_format=ctx.obj['output_format'])

    if download_path and results['status'] == 'OK':
        if not os.path.exists(download_path):
            os.makedirs(download_path)

        hashes = [match['artifact']['sha256'] for match in results['result']]
        api.download_files(hashes, download_path, False, 'sha256')

    ctx.obj['output'].write((str(rf)))


@click.option("--download-path", "-d", type=click.Path(file_okay=False), help="In addition to fetching the results, download the archives.")
@polyswarm.command("stream", short_help="access the polyswarm file stream")
@click.pass_context
def stream(ctx, download_path):
    api = ctx.obj['api']

    if download_path is not None:
        if not os.path.exists(download_path):
            os.makedirs(download_path)

    results = api.get_stream(download_path)

    rf = PSStreamFormatter(results, color=ctx.obj['color'],
                      output_format=ctx.obj['output_format'])

    ctx.obj['output'].write((str(rf)))


if __name__ == '__main__':
    polyswarm(obj={})
