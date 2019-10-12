from . import base

# TODO rewrite some of this to be not terrible
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


class TextFormatter(base.BaseFormatter):
    def __init__(self, color=True, **kwargs):
        self.color = color
        self._depth = 0
        self.color = color

    def format_search_result(self, search):
        if len(search) == 0:
            return self._bad('(Did not find any files matching search: %s.)\n' % repr(search.query))

        output = []
        output.append(self._good('Found {count} matches to the search query.'.format(count=len(search))))
        output.append(self._normal('Search results for {search}'.format(search=repr(search.query))))
        for artifact in search:
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

            countries, filenames,  = artifact.countries, artifact.filenames

            if countries:
                output.append(self._info('Observed countries: {countries}'.format(countries=','.join(countries))))

            if filenames:
                output.append(self._info('Observed filenames: {filenames}'.format(filenames=','.join(filenames))))

            # only report information if we have scanned the file before
            last_scan = artifact.last_scan

            if last_scan:
                detections = artifact.detections
                if len(detections) > 0:
                    output.append(self._normal(self._bad('Detections: {}/{} engines reported malicious'
                                               .format(len(detections), len(last_scan.assertions)))))
                else:
                    output.append(self._info('Detections: {}/{} engines reported malicious'
                                             .format(0, len(last_scan.assertions))))

            output.append(self._close_group())
        return "\n".join(output)

    def format_scan_result(self, result):
        output = []
        bounty = result.result

        if not bounty.uuid:
            return self._error('(Did not get a UUID for scan)\n')

        output.append(self._normal('Scan report for GUID %s\n========================================================='
                                   % bounty.uuid))

        # if this scan result is associated with a particular artifact, only display that artifact
        files = bounty.files
        if result.artifact:
            f = bounty.get_file_by_hash(result.artifact.hash)
            if f:
                files = [f]

        return "\n".join([self._format_bounty_file(f) for f in files])

    def _format_bounty_file(self, f):
        output = [self._open_group('Report for artifact %s, hash: %s' %
                                   (f.filename, f.hash))]
        if not f.ready:
            output.append(self._warn("Scan is still in progress, check back later."))
        elif len(f.assertions) == 0:
            if f.bounty.status == 'Bounty Failed' or f.failed:
                output.append(self._bad('Bounty failed, please resubmit'))
            else:
                output.append(self._bad('Bounty closed without any engine assertions. Try again later.'))
        else:
            detections = f.detections
            assertions = f.assertions

            if len(detections) > 0:
                output.append(self._normal('') + self._bad('{} out of {} engines reported this as malicious'.format(
                    len(detections), len(assertions)
                )))
            else:
                output.append(self._normal('') + self._good('All {} engines reported this as benign or did not respond'.format(
                    len(assertions)
                )))

            for assertion in assertions:
                if assertion.verdict is False:
                    output.append('%s: %s' % (self._normal(assertion.engine_name), self._good('Clean')))
                elif assertion.verdict is None or assertion.mask is False:
                    output.append('%s: %s' % (self._normal(assertion.engine_name), self._unknown('Engine chose not respond to this bounty.')))
                else:
                    output.append('%s: %s' % (self._normal(assertion.engine_name),
                                              self._bad('Malicious') +
                                              (self._bad(', metadata: %s' % assertion.metadata)
                                              if assertion.metadata is not None else '')))

        output.append(self._close_group())
        return '\n'.join(output)

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