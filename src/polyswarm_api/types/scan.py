from .base import BasePSJSONType, ArtifactType
from . import schemas
from . import hash
from .. import const


class Assertion(BasePSJSONType):
    SCHEMA = schemas.assertion_schema

    def __init__(self, scanfile, json, polyswarm=None):
        super(Assertion, self).__init__(json, polyswarm)
        self.scanfile = scanfile
        self.author = json['author']

        # TODO this needs to go away, but we are forced to until we do this resolution server-side
        # this should be removed after next deploy
        # we also are forced to modify the json in place so that this information is included in JSON formatting
        # TODO deprecate engine_name
        if 'author_name' in json:
            self.engine_name = json['author_name']
            self.author_name = json['author_name']
        elif 'engine_name' in json:
            self.engine_name = json['engine_name']
            self.author_name = json['engine_name']
        else:
            # TODO deprecate
            self.engine_name = self.polyswarm._resolve_engine_name(self.author) if self.polyswarm else self.author
            self.json['engine_name'] = self.engine_name
            self.author_name = self.engine_name


        self.bid = int(json['bid'])
        self.mask = json['mask']
        # deal with metadata being a string instead of null
        self.metadata = json['metadata'] if json['metadata'] else {}
        self.verdict = json['verdict']

    def __str__(self):
        return "Assertion-%s: %s" % (self.engine_name, self.verdict)


class Vote(BasePSJSONType):
    SCHEMA = schemas.vote_schema

    def __init__(self, scanfile, json, polyswarm=None):
        super(Vote, self).__init__(json, polyswarm)
        self.scanfile = scanfile
        self.arbiter = json['arbiter']
        self.vote = json['vote']

    def __str__(self):
        return "Vote-%s: %s" % (self.arbiter, self.vote)


class Scan(BasePSJSONType):
    SCHEMA = schemas.bounty_file_schema

    def __init__(self, bounty, json, polyswarm=None):
        super(Scan, self).__init__(json, polyswarm)
        self.bounty = bounty
        self.assertions = [Assertion(self, a, polyswarm) for a in json['assertions']]
        self.bounty_guid = json['bounty_guid']
        self.bounty_status = json['bounty_status']
        self.failed = json['failed']
        self.filename = json['filename']
        self.hash = hash.Hash(json['hash'], 'sha256', polyswarm)
        self.result = json['result']
        self.size = json['size']
        self.votes = [Vote(self, v, polyswarm) for v in json['votes']]
        self.window_closed = json['window_closed']
        self.ready = self.window_closed
        self.submission_guid = json.get('submission_guid', None)
        self._permalink = "{}/{}".format(const.DEFAULT_PERMALINK_BASE, self.submission_guid) if self.submission_guid\
            else None

    @property
    def detections(self):
        return [a for a in self.assertions if a.mask and a.verdict]

    @property
    def permalink(self):
        if self._permalink:
            return self._permalink
        return self.bounty.permalink

    def __str__(self):
        return "Scan <%s>" % self.hash


class Bounty(BasePSJSONType):
    SCHEMA = schemas.bounty_schema

    def __init__(self, instance, json, polyswarm=None):
        super(Bounty, self).__init__(json, polyswarm)
        self.instance = instance
        self.artifact_type = ArtifactType.from_string(json['artifact_type']) if json.get('artifact_type') else \
            ArtifactType.FILE
        self.status = json['status']
        self.uuid = json.get('uuid')
        self._permalink = json['permalink'] if json.get('permalink') else None
        self.files = [Scan(self, f, polyswarm) for f in json['files']]
        self.failed = self.status == 'Bounty Failed'

    @property
    def permalink(self):
        # default to first bounty, but in general Bounty and can associated with multiple submissions
        # this will be removed in near future
        if not self._permalink and len(self.files) > 0:
            return self.files[0].permalink
        return self._permalink

    def get_file_by_hash(self, h):
        # TODO this ignores a case where bounties could contain the same file multiple times
        # do we care?
        for f in self.files:
            if f.hash == h:
                return f
        return None

    @property
    def ready(self):
        # TODO we still need a better way to check for submission completion
        files = self.files

        if len(files) == 0:
            return True

        # this assumes that if any file reports closed, they all are. This should always be true
        return files[0].window_closed or self.failed

    def __str__(self):
        return "Bounty-%s [%s]" % (self.uuid, ",".join(str(s) for s in self.files))
