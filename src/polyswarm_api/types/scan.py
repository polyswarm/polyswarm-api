from .base import BasePSJSONType, ArtifactType
from . import schemas
from . import hash
from .. import const
from ..log import logger
from ..exceptions import NotFoundException


class PolyScore(BasePSJSONType):
    SCHEMA = schemas.polyscore_schema

    def __init__(self, json, polyswarm=None):
        super(PolyScore, self).__init__(json, polyswarm)

        self.scores = json['scores']

    def get_score_by_id(self, instance_id):
        return self.scores.get(str(instance_id), None)


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

    def __init__(self, bounty, json, polyswarm=None, polyscore=False):
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
        self.submission_guid = json.get('submission_uuid', None)
        self.instance_id = int(json['id'])
        self._permalink = "{}/{}".format(const.DEFAULT_PERMALINK_BASE, self.submission_guid) if self.submission_guid\
            else None

        self._polyscore = None

        if self.ready and polyswarm and polyscore:
            self.fetch_polyscore()

    @property
    def detections(self):
        return [a for a in self.assertions if a.mask and a.verdict]

    @property
    def permalink(self):
        if self._permalink:
            return self._permalink
        return None

    def fetch_polyscore(self):
        if not self.polyswarm:
            logger.warning('Need associated polyswarm object to fetch polyscore')
            return None

        if not self.submission_guid:
            logger.warning('Need submission GUID to get polyscore')
            return None

        try:
            resp = next(self.polyswarm.score(self.submission_guid))
        except NotFoundException:
            logger.warning("Failed to either find UUID {} or generate a score for it.".format(self.submission_guid))
            return None

        self._polyscore = resp.result

        # TODO this should probably just be in the result?
        # how do we want to handle JSON serialization here once we start breaking things
        # into multiple requests?
        self.json['polyscore'] = self._polyscore.json

        return self._polyscore.get_score_by_id(self.instance_id)

    @property
    def polyscore(self):
        if self._polyscore:
            return self._polyscore.get_score_by_id(self.instance_id)

        return self.fetch_polyscore()

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
        self.failed = self.status == 'Bounty Failed'

    def __str__(self):
        return "Bounty-%s" % self.uuid
