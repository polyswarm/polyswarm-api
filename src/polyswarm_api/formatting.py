import json
from datetime import datetime
from types import SimpleNamespace as Namespace


def is_colored(fn):
    color = {
                '_error': '\033[91m',
                '_warn': '\033[93m',
                '_info': '\033[92m',
                '_good': '\033[92m',
                '_bad': '\033[91m',
                '_unknown': '\033[94m',
                '_open_group': '\033[94m',
    }[fn.__name__]

    return lambda self, text: (color if self.color else '') + fn(self, text) + ('\033[0m' if self.color else '')


def is_grouped(fn):
    return lambda self, text: self._depth*'\t'+fn(self, text)


class PSResultFormatter(object):
    def __init__(self, results, output_format='text', color=True):
        self.results = results

        self._depth = 0

        self.output_format = output_format

        self.color = color


    # TODO this is all terrible, make this cleaner

    @is_grouped
    @is_colored
    def _info(self, text):
        return '%s' % text

    @is_grouped
    @is_colored
    def _warn(self, text):
        return '%s' % text

    @is_grouped
    @is_colored
    def _error(self, text):
        return '%s' % text

    @is_colored
    def _good(self, text):
        return text

    @is_colored
    def _bad(self, text):
        return text

    @is_colored
    def _unknown(self, text):
        return text

    @is_grouped
    def _normal(self, text):
        return text

    @is_grouped
    @is_colored
    def _open_group(self, title):
        self._depth += 1
        return title

    def _close_group(self):
        self._depth -= 1
        return '\n'

    def __str__(self):
        # for now, we only output assertions. arbiter votes are not considered.
        # json is handled directly in main, to join the lists together
        output = []
        if self.output_format == 'text':
            response_counts = dict()
            for result in self.results:
                if 'files' not in result:
                    if 'uuid' in result:
                        output.append(self._error('(UUID %s does not exist or has no files)\n' % result['uuid']))
                        continue
                    elif 'hash' in result:
                        output.append(self._error('(Hash %s was not found)\n' % result['hash']))
                        continue
                    else:
                        output.append(self._error('(No entry in PSResult, should not happen)\n'))
                        continue
                if 'uuid' not in result:
                    output.append(self._error('(Did not get a UUID for scan)\n'))
                    continue
                output.append(self._normal('Scan report for GUID %s\n=========================================================' % result['uuid']))
                # files in info, lets loop
                for f in result['files']:
                    output.append(self._open_group('Report for artifact %s, hash: %s' %
                                                   (f['filename'], f['hash'])))
                    if 'file_info' in f:
                        # this is in response to a /search/ request, so has some additional file metadata
                        file_info = f['file_info']
                        first_seen = datetime.utcfromtimestamp(file_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                        output.append(self._info('File info: first seen: {first_seen}, mimetype: {mimetype}, '
                                                 'extended_info: {extended_type}, known_filenames: {filenames}'.
                                                 format(first_seen=first_seen,
                                                        mimetype=file_info['mimetype'],
                                                        extended_type=file_info['extended_type'],
                                                        filenames=','.join(file_info['filenames']))))
                    if 'assertions' not in f or len(f['assertions']) == 0:
                        if 'failed' in f and f['failed']:
                            output.append(self._bad('Bounty failed, please resubmit'))
                        elif 'window_closed' in f and f['window_closed']:
                            output.append(self._warn('Bounty closed without any engine assertions. Try again later.'))
                        else:
                            output.append(self._normal('Scan still in progress, please check again later.'))
                    else:
                        for assertion in f['assertions']:
                            if assertion['verdict'] is False:
                                response_counts[assertion['engine']] = response_counts.get(assertion['engine'], 0) + 1
                                output.append('%s: %s' % (self._normal(assertion['engine']), self._good('Clean')))
                            elif assertion['verdict'] is None or assertion['mask'] is False:
                                output.append('%s: %s' % (self._normal(assertion['engine']), self._unknown('Unknown/failed to respond')))
                            else:
                                response_counts[assertion['engine']] = response_counts.get(assertion['engine'], 0) + 1
                                output.append('%s: %s' % (self._normal(assertion['engine']),
                                                          self._bad('Malicious') +
                                                          (self._bad(', metadata: %s' % assertion['metadata'])
                                                          if 'metadata' in assertion and assertion['metadata'] is not None else '')))

                    output.append(self._close_group())
            return '\n'.join(output)
        elif self.output_format == 'json':
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return '(unknown output format)'


class PSDownloadResultFormatter(PSResultFormatter):
    def __str__(self):
        output = []
        if self.output_format == 'text':
            for result in self.results:
                if result['status'] == 'OK':
                    output.append(self._good('Downloaded {file_hash}: {file_path}'.format(file_hash=result['file_hash'],
                                                                                          file_path=result['file_path'])))
                else:
                    output.append(self._bad('Download {file_hash} failed: {reason}'.format(file_hash=result['file_hash'],
                                                                                           reason=result['reason'])))
            return '\n'.join(output) + '\n'
        elif self.output_format == 'json':
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return '(unknown output format)'


class PSSearchResultFormatter(PSResultFormatter):
    def __init__(self, results, output_format='text', color=True):
        super(PSSearchResultFormatter, self).__init__(results, output_format, color)
        self.searches = [query['search'] for query in results]
        self.search_results = json.loads(json.dumps(results), object_hook=lambda d: Namespace(**d))

    def __str__(self):
        if self.output_format == 'text':
            output = []
            if len(self.search_results) == 0:
                return self._bad('(Did not find any files matching any search criteria.)\n')

            for i, result in enumerate(self.search_results):
                search = self.searches[i]
                result = result.result
                if len(result) == 0:
                    output.append(self._bad('(Did not find any files matching {search})\n'.format(search=search)))
                    continue

                output.append(self._good('Found {count} matches to the search query.'.format(count=len(result))))
                output.append(self._normal('Search results for {search}'.format(search=search)))
                for artifact in result:
                    output.append(self._unknown('File %s' % artifact.sha256))
                    output.append(
                        self._info(self._open_group(
                            self._info('File type: mimetype: {mimetype}, extended_info: {extended_type}'.
                                       format(mimetype=artifact.mimetype,
                                              extended_type=artifact.extended_type)))))
                    output.append(self._info('SHA256: {hash}'.format(hash=artifact.sha256)))
                    output.append(self._info('SHA1: {hash}'.format(hash=artifact.sha1)))
                    output.append(self._info('MD5: {hash}'.format(hash=artifact.md5)))
                    output.append(self._info('First seen: {first_seen}'.format(first_seen=artifact.first_seen)))

                    # gather instance data
                    countries, filenames = set(), set()
                    for artifact_instance in artifact.artifact_instances:
                        if artifact_instance.country:
                            countries.add(artifact_instance.country)
                        if artifact_instance.name:
                            filenames.add(artifact_instance.name)
                    output.append(self._info('Observed countries: {countries}'.format(countries=','.join(countries))))
                    output.append(self._info('Observed filenames: {filenames}'.format(filenames=','.join(filenames))))
                    output.append(self._close_group())
            return '\n'.join(output)
        elif self.output_format == 'json':
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return '(unknown output format)'


class PSHuntResultFormatter(PSResultFormatter):
    def __init__(self, results, output_format='text', color=True):
        self.hunt_results = json.loads(json.dumps(results), object_hook=lambda d: Namespace(**d))
        super(PSHuntResultFormatter, self).__init__(results, output_format, color)

    def __str__(self):
        if self.output_format == 'text':
            output = []

            if self.hunt_results.status not in ['PENDING', 'RUNNING', 'SUCCESS', 'FAILED']:
                return self._bad('An unspecified error occurred fetching hunt records.')

            output.append(self._info('Scan status: {status}\n'.format(status=self.hunt_results.status.capitalize())))

            results = self.hunt_results.result.results

            if len(results) == 0:
                output.append(self._bad('(Did not find any results yet for this hunt.)\n'))
                return '\n'.join(output)

            output.append(self._good('Found {count} samples in this hunt.'.format(count=len(results))))

            for result in results:
                output.append(self._good('Match on rule {name}'.format(name=result.rule_name) +
                                         (', tags: {result_tags}'.format(result_tags=result.tags) if result.tags != '' else '')))
                artifact = result.artifact
                output.append(self._unknown('File %s' % artifact.sha256))
                output.append(
                    self._info(self._open_group(
                        self._info('File type: mimetype: {mimetype}, extended_info: {extended_type}'.
                                   format(mimetype=artifact.mimetype,
                                          extended_type=artifact.extended_type)))))
                output.append(self._info('SHA256: {hash}'.format(hash=artifact.sha256)))
                output.append(self._info('SHA1: {hash}'.format(hash=artifact.sha1)))
                output.append(self._info('MD5: {hash}'.format(hash=artifact.md5)))
                output.append(self._info('First seen: {first_seen}'.format(first_seen=artifact.first_seen)))

                # gather instance data
                countries, filenames = set(), set()
                for artifact_instance in artifact.artifact_instances:
                    if artifact_instance.country:
                        countries.add(artifact_instance.country)
                    if artifact_instance.name:
                        filenames.add(artifact_instance.name)
                output.append(self._info('Observed countries: {countries}'.format(countries=','.join(countries))))
                output.append(self._info('Observed filenames: {filenames}'.format(filenames=','.join(filenames))))
                output.append(self._close_group())
            return '\n'.join(output)
        elif self.output_format == 'json':
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return '(unknown output format)'


class PSHuntSubmissionFormatter(PSResultFormatter):
    def __str__(self):
        if self.output_format == 'text':
            if self.results['status'] != 'OK':
                return self._bad('Failed to install rules.\n')
            return self._good('Successfully submitted rules, hunt id: {hunt_id}\n'.
                              format(hunt_id=self.results['result']['hunt_id']))
        elif self.output_format == 'json':
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return '(unknown output format)'


class PSStreamFormatter(PSResultFormatter):
    def __str__(self):
        if self.output_format == 'text':
            if self.results['status'] != 'OK':
                return self._bad('Failed to access stream.\n')
            if len(self.results['result']) == 0:
                return self._bad('No archives have been posted in the supplied timeframe.\n')
            urls = []
            for value in self.results['result'].values():
                urls.extend(value)
            return '\n'.join(urls)
        elif self.output_format == 'json':
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return '(unknown output format)'
