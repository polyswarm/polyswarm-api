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
                                response_counts[assertion['engine']] = response_counts.get(assertion['engine'], 0) + 1
                                output.append("%s: %s" % (self._normal(assertion['engine']), self._good("Clean")))
                            elif assertion['verdict'] is None or assertion['mask'] is False:
                                output.append("%s: %s" % (self._normal(assertion['engine']), self._unknown("Unknown/failed to respond")))
                            else:
                                response_counts[assertion['engine']] = response_counts.get(assertion['engine'], 0) + 1
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


class PSSearchResultFormatter(PSResultFormatter):
    def __init__(self, results, output_format="text", color=True):
        self.search_results = json.loads(json.dumps(results), object_hook=lambda d: Namespace(**d))
        super(PSSearchResultFormatter, self).__init__(results, output_format, color)

    def __str__(self):
        if self.output_format == "text":
            output = []
            if len(self.search_results) == 0:
                return self._bad(f"(Did not find any files matching any search criteria.)\n")

            for result in self.search_results:
                search = result.search
                result = result.result
                if len(result) == 0:
                    return self._bad(f"(Did not find any files matching {search})\n")

                output.append(self._good(f"Found {len(result)} matches to the search query."))
                output.append(self._normal(f"Search results for {search}"))
                for artifact in result:
                    output.append(self._unknown(
                        "File %s" % artifact.sha256))
                    output.append(
                        self._info(self._open_group(self._info(f"File type: mimetype: {artifact.mimetype}, extended_info: {artifact.extended_type}"))))
                    output.append(self._info(f"SHA256: {artifact.sha256}"))
                    output.append(self._info(f"SHA1: {artifact.sha1}"))
                    output.append(self._info(f"MD5: {artifact.md5}"))

                    # gather instance data
                    countries, filenames = set(), set()
                    for artifact_instance in artifact.artifact_instances:
                        if artifact_instance.country is not None:
                            countries.add(artifact_instance.country)
                        if artifact_instance.name is not None:
                            filenames.add(artifact_instance.name)
                    output.append(self._info(f"Observed countries: {','.join(countries)}"))
                    output.append(self._info(f"Observed filenames: {','.join(filenames)}"))
                    output.append(self._close_group())
            return "\n".join(output)
        elif self.output_format == "json":
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return "(unknown output format)"


class PSHuntResultFormatter(PSResultFormatter):
    def __init__(self, results, output_format="text", color=True):
        self.hunt_results = json.loads(json.dumps(results), object_hook=lambda d: Namespace(**d))
        super(PSHuntResultFormatter, self).__init__(results, output_format, color)

    def __str__(self):
        if self.output_format == "text":
            output = []

            if self.hunt_results.status != "OK":
                return self._bad("An unspecified error occurred fetching hunt records.")

            results = self.hunt_results.result

            if len(results) == 0:
                return self._bad(f"(Did not find any results yet for this hunt.)\n")

            output.append(self._good(f"Found {len(results)} samples in this hunt."))

            for result in results:
                output.append(self._good(f"Match on rule {result.rule_name}" + (f", tags: {result.tags}" if result.tags != "" else "")))
                artifact = result.artifact
                output.append(self._unknown(
                    "File %s" % artifact.sha256))
                output.append(
                    self._info(self._open_group(self._info(f"File type: mimetype: {artifact.mimetype}, extended_info: {artifact.extended_type}"))))
                output.append(self._info(f"SHA256: {artifact.sha256}"))
                output.append(self._info(f"SHA1: {artifact.sha1}"))
                output.append(self._info(f"MD5: {artifact.md5}"))

                # gather instance data
                countries, filenames = set(), set()
                for artifact_instance in artifact.artifact_instances:
                    if artifact_instance.country is not None:
                        countries.add(artifact_instance.country)
                    if artifact_instance.name is not None:
                        filenames.add(artifact_instance.name)
                output.append(self._info(f"Observed countries: {','.join(countries)}"))
                output.append(self._info(f"Observed filenames: {','.join(filenames)}"))
                output.append(self._close_group())
            return "\n".join(output)
        elif self.output_format == "json":
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return "(unknown output format)"


class PSHuntSubmissionFormatter(PSResultFormatter):
    def __str__(self):
        if self.output_format == "text":
            if self.results['status'] != 'OK':
                return self._bad("Failed to install rules.\n")
            return self._good(f"Successfully submitted rules, rule_id: {self.results['result']['rule_id']}\n")

        elif self.output_format == "json":
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return "(unknown output format)"


class PSStreamFormatter(PSResultFormatter):
    def __str__(self):
        if self.output_format == "text":
            if self.results['status'] != 'OK':
                return self._bad("Failed to access stream.\n")
            if len(self.results['result']) == 0:
                return self._bad("No archives have been posted in the supplied timeframe.\n")
            urls = []
            for value in self.results['result'].values():
                urls.extend(value)
            return "\n".join(urls)
        elif self.output_format == "json":
            return json.dumps(self.results, indent=4, sort_keys=True)
        else:
            return "(unknown output format)"