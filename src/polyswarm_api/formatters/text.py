import sys
from . import base
from .. import const

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


class TextOutput(base.BaseOutput):
    name = 'text'

    def __init__(self, color=True, output=sys.stdout, **kwargs):
        super(TextOutput, self).__init__(output)
        self.color = color
        self._depth = 0
        self.color = color

    def _get_score_format(self, score):
        if score < 0.15:
            return self._good
        elif score < 0.4:
            return self._warn
        else:
            return self._bad

    def _format_artifact(self, artifact):
        output = []
        output.append(self._unknown('File %s' % artifact.sha256))
        output.append(
            self._info(self._open_group(
                self._info('File type: mimetype: {mimetype}, extended_info: {extended_type}'.
                           format(mimetype=artifact.mimetype,
                                  extended_type=artifact.extended_type)))))
        output.append(self._info('SHA256: {hash}'.format(hash=artifact.sha256)))
        output.append(self._info('SHA1: {hash}'.format(hash=artifact.sha1)))
        output.append(self._info('MD5: {hash}'.format(hash=artifact.md5)))

        if artifact.metadata:
            if artifact.metadata.hash:
                h = artifact.metadata.hash

                if 'ssdeep' in h:
                    output.append(self._info('SSDEEP: {}'.format(h['ssdeep'])))

                if 'tlsh' in h:
                    output.append(self._info('TLSH: {}'.format(h['tlsh'])))

                if 'authentihash' in h:
                    output.append(self._info('Authentihash: {}'.format(h['authentihash'])))
            if artifact.metadata.pefile:
                p = artifact.metadata.pefile

                if 'imphash' in p:
                    output.append(self._info('Imphash: {}'.format(p['imphash'])))

        output.append(self._info('First seen: {first_seen}'.format(first_seen=artifact.first_seen)))

        countries, filenames, = artifact.countries, artifact.filenames

        if countries:
            output.append(self._info('Observed countries: {countries}'.format(countries=','.join(countries))))

        if filenames:
            output.append(self._info('Observed filenames: {filenames}'.format(filenames=','.join(filenames))))

        # only report information if we have scanned the file before
        last_scan = artifact.last_scan

        if last_scan:
            detections = artifact.detections
            output.append(self._info('Scan permalink: {}'.format(artifact.scan_permalink)))
            if len(detections) > 0:
                output.append(self._normal(self._bad('Detections: {}/{} engines reported malicious'
                                                     .format(len(detections), len(last_scan.assertions)))))
            else:
                output.append(self._info('Detections: {}/{} engines reported malicious'
                                         .format(0, len(last_scan.assertions))))

            score = last_scan.polyscore
            if score is not None:
                formatter = self._get_score_format(score)
                output.append(self._normal('PolyScore: '+formatter('{}'.format(score))))

        output.append(self._close_group())
        return '\n'.join(output)

    def _format_hunt_match(self, match):
        output = []
        output.append(self._good('Match on rule {name}'.format(name=match.rule_name) +
                                 (', tags: {result_tags}'.format(
                                     result_tags=match.tags) if match.tags != '' else '')))
        output.append(self._format_artifact(match.artifact))
        return '\n'.join(output)

    def search_result(self, search):
        if search.failed:
            self.out.write(self._bad(search.failure_reason)+'\n')
            return

        output = []
        output.append(self._good('Found {count} matches to the search query.'.format(count=len(search))))
        output.append(self._normal('Search results for {search}'.format(search=repr(search.query))))
        self.out.write("\n".join(output)+'\n')
        for artifact in search:
            self.out.write(self._format_artifact(artifact)+'\n')

    def scan_result(self, result):
        output = []
        bounty = result.result

        if result.failed:
            self.out.write(self._error(result.failure_reason)+'\n')
            return

        output.append(self._normal('Scan report for GUID %s\n========================================================='
                                   % bounty.uuid))

        # if this scan result is associated with a particular artifact, only display that artifact
        files = bounty.files
        if result.artifact:
            f = bounty.get_file_by_hash(result.artifact.hash)
            if f:
                files = [f]

        self.out.write("\n".join([self._format_bounty_file(f) for f in files]) + '\n')

    def _format_bounty_file(self, f):
        output = [self._open_group('Report for artifact %s, hash: %s' %
                                   (f.filename, f.hash))]
        if not f.ready:
            output.append(self._warn('Scan is still in progress, check back later. Reference: %s' % f.permalink))
        elif len(f.assertions) == 0:
            # TODO are these still necessary?
            if f.bounty.status == 'Bounty Failed' or f.failed:
                output.append(self._bad('Bounty failed, please resubmit. Reference: %s' % f.permalink))
            else:
                output.append(self._bad('Bounty closed without any engine assertions. Try again later. Reference: %s' % f.permalink))
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

            output.append('%s: %s' % (self._normal('Scan permalink'), self._good(f.permalink)))

            score = f.polyscore
            if score is not None:
                formatter = self._get_score_format(score)
                output.append(self._normal('PolyScore: '+formatter('{}'.format(score))))

        output.append(self._close_group())
        return '\n'.join(output)

    def hunt_submission(self, result):
        if result.failed:
            self.out.write(self._bad(result.failure_reason)+'\n')
            return
        self.out.write(self._info('Successfully submitted rules, hunt id: {hunt_id}\n'.
                       format(hunt_id=result.result.hunt_id)))

    def hunt_deletion(self, result):
        if result.failed:
            self.out.write(self._bad(result.failure_reason)+'\n')
            return
        self.out.write(self._info('Successfully deleted hunt id: {hunt_id}\n'.
                       format(hunt_id=result.result)))

    def hunt_result(self, result):
        output = []

        if result.failed:
            self.out.write(self._bad(result.failure_reason)+'\n')
            return

        status_response = result.hunt_status

        status = status_response.result

        output.append(self._info('Scan status: {status}\n'.format(status=status.status)))

        output.append(self._good('Found {} samples in this hunt.'.format(status.total)))

        self.out.write('\n'.join(output) + '\n')

        for match in result:
            self.out.write(self._format_hunt_match(match)+'\n')

    def download_result(self, result):
        artifact = result.result

        if result.failed:
            self.out.write(self._bad(result.failure_reason)+'\n')
        else:
            self.out.write(self._good('Successfully downloaded artifact {} to {}\n'.format(artifact.artifact_name,
                                                                                       artifact.path)))
        self.out.flush()

    def hunt_list(self, result):
        for hunt in result:
            self.out.write(self._info('Hunt: {:17}, total results: {:5}, created: {}\n'.format(hunt.id, hunt.total,
                                                                                        hunt.created)))

    def usage_exceeded(self):
        self.out.write(self._bad(const.USAGE_EXCEEDED_MESSAGE)+'\n')

    def invalid_rule(self, e):
        self.out.write(self._bad('Malformed yara file: {}'.format(e.args[0])+'\n'))

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
