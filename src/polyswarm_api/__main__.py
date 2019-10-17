#!/usr/bin/env python3
import click
import logging
import sys
import os
import json

from .api import PolyswarmAPI
from .types.query import MetadataQuery

from .const import MAX_HUNT_RESULTS
from .formatters import formatters

from .utils import validate_key, validate_uuid, is_valid_uuid, \
                   validate_hashes, validate_hash, parse_hashes

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

logger = logging.getLogger(__name__)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option('-a', '--api-key', help='Your API key for polyswarm.network (required)',
              default='', callback=validate_key, envvar='POLYSWARM_API_KEY')
@click.option('-u', '--api-uri', default='https://api.polyswarm.network/v1',
              envvar='POLYSWARM_API_URI', help='The API endpoint (ADVANCED)')
@click.option('-o', '--output-file', default=sys.stdout, type=click.File('w'), help='Path to output file.')
@click.option('--output-format', '--fmt', default='text', type=click.Choice(formatters.keys()),
              help='Output format. Human-readable text or JSON.')
@click.option('--color/--no-color', default=True, help='Use colored output in text mode.')
@click.option('-v', '--verbose', default=0, count=True)
@click.option('-c', '--community', default='lima', envvar='POLYSWARM_COMMUNITY', help='Community to use.')
@click.option('--advanced-disable-version-check/--advanced-enable-version-check', default=False,
              help='Enable/disable GitHub release version check.')
@click.option('--validate', default=False, is_flag=True,
              envvar='POLYSWARM_VALIDATE', help='Validate incoming schemas (note: slow).')
@click.pass_context
def polyswarm(ctx, api_key, api_uri, output_file, output_format, color, verbose, community,
              advanced_disable_version_check, validate):
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

    logging.debug('Creating API instance: api_key:%s, api_uri:%s', api_key, api_uri)
    ctx.obj['api'] = PolyswarmAPI(api_key, api_uri, community=community, validate_schemas=validate)

    ctx.obj['output'] = formatters[output_format](color=color, output=output_file)


@click.option('-f', '--force', is_flag=True, default=False,
              help='Force re-scan even if file has already been analyzed.')
@click.option('-r', '--recursive', is_flag=True, default=False, help='Scan directories recursively')
@click.option('-t', '--timeout', type=click.INT, default=-1, help='How long to wait for results (default: forever, -1)')
@click.argument('path', nargs=-1, type=click.Path(exists=True))
@polyswarm.command('scan', short_help='scan files/directories')
@click.pass_context
def scan(ctx, path, force, recursive, timeout):
    """
    Scan files or directories via PolySwarm
    """
    api = ctx.obj['api']
    output = ctx.obj['output']

    api.timeout = timeout

    paths = path

    directories, files = [], []
    for path in paths:
        if os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            directories.append(path)
        else:
            logger.warning('Path %s is neither a file nor a directory, ignoring.', path)

    for result in api.scan(*files):
        output.scan_result(result)

    for d in directories:
        for result in api.scan_directory(d, recursive=recursive):
            output.scan_result(result)


@click.option('-r', '--url-file', help='File of URLs, one per line.', type=click.File('r'))
@click.option('-f', '--force', is_flag=True, default=False,
              help='Force re-scan even if file has already been analyzed.')
@click.option('-t', '--timeout', type=click.INT, default=-1, help='How long to wait for results (default: forever, -1)')
@click.argument('url', nargs=-1, type=click.STRING)
@polyswarm.command('url', short_help='scan url')
@click.pass_context
def url_scan(ctx, url, url_file, force, timeout):
    """
    Scan files or directories via PolySwarm
    """
    api = ctx.obj['api']
    output = ctx.obj['output']
    api.timeout = timeout

    urls = list(url)

    if url_file:
        urls.extend([u.strip() for u in url_file.readlines()])

    for result in api.scan_urls(*urls):
        output.scan_result(result)


@polyswarm.group(short_help='interact with PolySwarm search api')
def search():
    pass


@click.option('-r', '--hash-file', help='File of hashes, one per line.', type=click.File('r'))
@click.option('--hash-type', help='Hash type to search [default:autodetect, sha256|sha1|md5]', default=None)
@click.option('-m', '--without-metadata', is_flag=True, default=False,
              help='Don\'t request artifact metadata.')
@click.option('-b', '--without-bounties', is_flag=True, default=False,
              help='Don\'t request bounties.')
@click.argument('hashes', nargs=-1)
@search.command('hash', short_help='search for hashes separated by space')
@click.pass_context
def hashes(ctx, hashes, hash_file, hash_type, without_metadata, without_bounties):
    """
    Search PolySwarm for files matching hashes
    """

    api = ctx.obj['api']
    output = ctx.obj['output']

    hashes = parse_hashes(hashes, hash_type, hash_file)
    if hashes:
        results = api.search(*hashes, with_instances=not without_bounties, with_metadata=not without_metadata)

        # for json, this is effectively jsonlines
        for result in results:
            output.search_result(result)
    else:
        raise click.BadParameter('Hash not valid, must be sha256|md5|sha1 in hexadecimal format')


@click.option('-r', '--query-file', help='Properly formatted JSON search file', type=click.File('r'))
@click.option('-m', '--without-metadata', is_flag=True, default=False,
              help='Don\'t request artifact metadata.')
@click.option('-b', '--without-bounties', is_flag=True, default=False,
              help='Don\'t request bounties.')
@click.argument('query_string', nargs=-1)
@search.command('metadata', short_help='search metadata of files')
@click.pass_context
def metadata(ctx, query_string, query_file, without_metadata, without_bounties):

    api = ctx.obj['api']
    output = ctx.obj['output']

    try:
        if len(query_string) >= 1:
            queries = [MetadataQuery(q, False, api) for q in query_string]
        elif query_file:
            # TODO support multiple queries in a file?
            queries = [MetadataQuery(json.load(query_file), True, api)]
        else:
            logger.error('No query specified')
            return 0
    except json.decoder.JSONDecodeError:
        logger.error('Failed to parse JSON')
        return 0
    except UnicodeDecodeError:
        logger.error('Failed to parse JSON due to Unicode error')
        return 0

    for result in api.search_by_metadata(*queries, with_instances=not without_bounties,
                                         with_metadata=not without_metadata):
        output.search_result(result)

    return 0


@click.option('-r', '--uuid-file', help='File of UUIDs, one per line.', type=click.File('r'))
@click.argument('uuid', nargs=-1, callback=validate_uuid)
@polyswarm.command('lookup', short_help='lookup UUID(s)')
@click.pass_context
def lookup(ctx, uuid, uuid_file):
    """
    Lookup a PolySwarm scan by UUID for current status.
    """
    api = ctx.obj['api']
    output = ctx.obj['output']

    uuids = list(uuid)

    # TODO dedupe
    if uuid_file:
        for u in uuid_file.readlines():
            u = u.strip()
            if is_valid_uuid(u):
                uuids.append(u)
            else:
                logger.warning('Invalid uuid %s in file, ignoring.', u)

    for result in api.lookup(*uuids):
        output.scan_result(result)


@click.option('-r', '--hash-file', help='File of hashes, one per line.', type=click.File('r'))
@click.option('-m', '--metadata', is_flag=True, default=False, help='Save file metadata into associated JSON file')
@click.option('--hash-type', help='Hash type to search [default:autodetect, sha256|sha1|md5]', default=None)
@click.argument('hash', nargs=-1, callback=validate_hashes)
@click.argument('destination', nargs=1, type=click.Path(file_okay=False))
@polyswarm.command('download', short_help='download file(s)')
@click.pass_context
def download(ctx, metadata, hash_file, hash_type, hash, destination):
    """
    Download files from matching hashes
    """
    api = ctx.obj['api']
    output = ctx.obj['output']

    hashes = parse_hashes(hash, hash_type, hash_file)

    if hashes:
        for result in api.download(destination, *hashes):
            output.download_result(result)
    else:
        raise click.BadParameter('Hash not valid, must be sha256|md5|sha1 in hexadecimal format')


@click.option('-r', '--hash-file', help='File of hashes, one per line.', type=click.File('r'))
@click.option('--hash-type', help='Hash type to search [default:autodetect, sha256|sha1|md5]', default=None)
@click.argument('hash', nargs=-1, callback=validate_hashes)
@polyswarm.command('rescan', short_help='rescan files(s) by hash')
@click.pass_context
def rescan(ctx, hash_file, hash_type, hash):
    """
    Rescan files with matched hashes
    """
    api = ctx.obj['api']
    output = ctx.obj['output']

    hashes = parse_hashes(hash, hash_type, hash_file)

    if hashes:
        for result in api.rescan(*hashes):
            output.scan_result(result)
    else:
        raise click.BadParameter('Hash not valid, must be sha256|md5|sha1 in hexadecimal format')


@polyswarm.group(short_help='interact with live scans')
def live():
    pass


@polyswarm.group(short_help='interact with historical scans)')
def historical():
    pass


@click.argument('rule_file', type=click.File('r'))
@live.command('install', short_help='install a new YARA rule file')
@click.pass_context
def live_install(ctx, rule_file):
    api = ctx.obj['api']
    output = ctx.obj['output']

    rules = rule_file.read()

    output.hunt_submission(api.live(rules))


@live.command('delete', short_help='Delete the live hunt associate with the given hunt_id')
@click.argument('hunt_id')
@click.pass_context
def live_delete(ctx, hunt_id):
    api = ctx.obj['api']
    output = ctx.obj['output']

    output.hunt_deletion(api.live_delete(hunt_id))


@live.command('list', short_help='List all live hunts performed')
@click.pass_context
def live_list(ctx):
    api = ctx.obj['api']
    output = ctx.obj['output']

    output.hunt_list(api.live_list())


@click.option('-i', '--hunt-id', type=int, help='ID of the rule file (defaults to latest)')
@live.command('results', short_help='get results from live hunt')
@click.option('-m', '--without-metadata', is_flag=True, default=False,
              help='Don\'t request artifact metadata.')
@click.option('-b', '--without-bounties', is_flag=True, default=False,
              help='Don\'t request bounties.')
@click.pass_context
def live_results(ctx, hunt_id, without_metadata, without_bounties):
    api = ctx.obj['api']
    output = ctx.obj['output']

    result = api.live_results(hunt_id, with_metadata=not without_metadata, with_instances=not without_bounties)

    output.hunt_result(result)


@click.argument('rule_file', type=click.File('r'))
@historical.command('start', short_help='start a new historical hunt')
@click.pass_context
def historical_start(ctx, rule_file):
    api = ctx.obj['api']
    output = ctx.obj['output']

    rules = rule_file.read()

    output.hunt_submission(output.hunt_submission(api.historical(rules)))


@historical.command('delete', short_help='Delete the historical hunt associate with the given hunt_id')
@click.argument('hunt_id')
@click.pass_context
def historical_delete(ctx, hunt_id):
    api = ctx.obj['api']
    output = ctx.obj['output']

    output.hunt_deletion(api.historical_delete(hunt_id))


@historical.command('list', short_help='List all historical hunts performed')
@click.pass_context
def historical_list(ctx):
    api = ctx.obj['api']
    output = ctx.obj['output']

    output.hunt_list(api.historical_list())


@click.option('-i', '--hunt-id', type=int, help='ID of the rule file (defaults to latest)')
@click.option('-m', '--without-metadata', is_flag=True, default=False,
              help='Don\'t request artifact metadata.')
@click.option('-b', '--without-bounties', is_flag=True, default=False,
              help='Don\'t request bounties.')
@historical.command('results', short_help='get results from historical hunt')
@click.pass_context
def historical_results(ctx, hunt_id, without_metadata, without_bounties):
    api = ctx.obj['api']
    output = ctx.obj['output']

    result = api.historical_results(hunt_id, with_metadata=not without_metadata, with_instances=not without_bounties)

    output.hunt_result(result)


@click.option('-s', '--since', type=click.IntRange(1, 2880), default=1440,
              help='Request archives X minutes into the past. Default: 1440, Max: 2880')
@click.argument('destination', nargs=1, type=click.Path(file_okay=False))
@polyswarm.command('stream', short_help='access the polyswarm file stream')
@click.pass_context
def stream(ctx, since, destination):
    api = ctx.obj['api']
    out = ctx.obj['output']

    if destination is not None:
        if not os.path.exists(destination):
            os.makedirs(destination)

    for download in api.stream(destination, since=since):
        out.download_result(download)


@click.option('--hash-type', help='Hash type to search [default:autodetect, sha256|sha1|md5]', default=None)
@click.argument('hash', nargs=1, callback=validate_hash)
@polyswarm.command('cat', short_help='cat artifact to stdout')
@click.pass_context
def cat(ctx, hash_type, hash):
    api = ctx.obj['api']
    # handle 2.7
    out = sys.stdout
    if hasattr(sys.stdout, 'buffer'):
        out = sys.stdout.buffer
    result = api.download_to_filehandle(hash, out)


def _fix_result(self, result):
    """
    For now, since the name-ETH address mappings are not added by consumer, we add them using
    a hardcoded dict. This function does that for us. It also adds in a permalink to the scan.
    These changes will be moved into consumer soon.

    :param result: The JSON we got from consumer API
    :return: JSON updated with name-ETH address mappings for microengines and arbiters
    """
    try:
        for file in result['files']:
            if 'assertions' in file:
                for assertion in file['assertions']:
                    assertion['engine'] = self.engine_resolver.get_engine_name(assertion['author'])
            if 'votes' in file:
                for vote in file['votes']:
                    vote['engine'] = self.engine_resolver.get_engine_name(vote['arbiter'])
    except KeyError:
        # ignore if not complete
        return result

    return result


if __name__ == '__main__':
    polyswarm(obj={})
