import json
from datetime import datetime


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
    return lambda self, text: self._depth*"\t"+fn(self, text)


class PSResultFormatter(object):
    def __init__(self, results, output_format="text", color=True):
        self.results = results

        self._depth = 0

        self.output_format = output_format

        self.color = color


    # TODO this is all terrible, make this cleaner

    @is_grouped
    @is_colored
    def _info(self, text):
        return "%s" % text

    @is_grouped
    @is_colored
    def _warn(self, text):
        return "%s" % text

    @is_grouped
    @is_colored
    def _error(self, text):
        return "%s" % text

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
        return "\n"

    def __str__(self):
        # for now, we only output assertions. arbiter votes are not considered.
        # json is handled directly in main, to join the lists together
        output = []
        if self.output_format == "text":
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
                output.append(self._normal("Scan report for GUID %s\n=========================================================" % result['uuid']))
                # files in info, lets loop
                for f in result['files']:
                    output.append(self._open_group("Report for file %s, hash: %s" %
                                                   (f['filename'], f['hash'])))
                    if 'file_info' in f:
                        # this is in response to a /search/ request, so has some additional file metadata
                        file_info = f['file_info']
                        first_seen = datetime.utcfromtimestamp(file_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                        output.append(self._info("File info: first seen: {}, mimetype: {}, extended_info: {}, known_filenames: {}".format(
                            first_seen, file_info['mimetype'], file_info['extended_type'], ",".join(file_info['filenames'])
                        )))
                    if 'assertions' not in f or len(f['assertions']) == 0:
                        if 'failed' in f and f['failed']:
                            output.append(self._bad("Bounty failed, please resubmit"))
                        elif 'window_closed' in f and f['window_closed']:
                            output.append(self._warn("Bounty closed without any engine assertions. Try again later."))
                        else:
                            output.append(self._normal("Scan still in progress, please check again later."))
                    else:
                        for assertion in f['assertions']:
                            if assertion['verdict'] is False:
                                output.append("%s: %s" % (self._normal(assertion['engine']), self._good("Clean")))
                            elif assertion['verdict'] is None or assertion['mask'] is False:
                                output.append("%s: %s" % (self._normal(assertion['engine']), self._unknown("Unknown/failed to respond")))
                            else:
                                output.append("%s: %s" % (self._normal(assertion['engine']),
                                                          self._bad("Malicious") +
                                                          (self._bad(", metadata: %s" % assertion['metadata'])
                                                          if 'metadata' in assertion and assertion['metadata'] is not None else '')))
                    output.append(self._close_group())
            return "\n".join(output)
        elif self.output_format == "json":
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return "(unknown output format)"


class PSDownloadResultFormatter(PSResultFormatter):
    def __str__(self):
        output = []
        if self.output_format == "text":
            for result in self.results:
                if result['status'] == "OK":
                    output.append(self._good("Downloaded {}: {}".format(result['file_hash'], result['file_path'])))
                else:
                    output.append(self._bad("Download {} failed: {}".format(result['file_hash'], result['reason'])))
            return "\n".join(output) + "\n"
        elif self.output_format == "json":
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return "(unknown output format)"
