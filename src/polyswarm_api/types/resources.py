import logging
from ordered_set import OrderedSet

try:
    import yara
except ImportError:
    yara = None

from polyswarm_api import exceptions
from polyswarm_api import types
from polyswarm_api import const
from polyswarm_api.types import base


logger = logging.getLogger(__name__)


#####################################################################
# Resources returned by the API
#####################################################################


class Submission(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = types.schemas.bounty_schema

    def __init__(self, json, polyswarm=None):
        super(Submission, self).__init__(json, polyswarm)
        self.status = json['status']
        self.uuid = json['uuid']
        self.community = json.get('community')
        self.country = json.get('country')
        self.files = [ArtifactInstance(f, polyswarm) for f in json['instances']]

        self._permalink = None

    @property
    def failed(self):
        return self.status == 'Bounty Failed'

    @property
    def ready(self):
        return self.status == 'Bounty Awaiting Arbitration' or self.status == 'Bounty Done'

    @property
    def permalink(self):
        if not self._permalink and self.uuid:
            self._permalink = const.DEFAULT_PERMALINK_BASE + '/' + self.uuid
        return self._permalink

    def __str__(self):
        return "Submission-%s" % self.uuid


class PolyScore(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = types.schemas.polyscore_schema

    def __init__(self, json, polyswarm=None):
        super(PolyScore, self).__init__(json, polyswarm)

        self.scores = json['scores']

    def get_score_by_id(self, instance_id):
        return self.scores.get(str(instance_id), None)


class Engine(base.BasePSJSONType, base.BasePSResourceType):
    def __init__(self, json, polyswarm=None):
        super(Engine, self).__init__(json, polyswarm)
        self.address = json['address'].lower()
        self.name = json.get('name')


class ArtifactInstance(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = types.schemas.artifact_instance_schema

    def __init__(self, json, polyswarm=None):
        super(ArtifactInstance, self).__init__(json, polyswarm)
        self.id = json['id']
        self.submission_id = json['submission_id']
        self.submission_uuid = json['submission_uuid']
        self.artifact_id = json['id']
        self.account_id = json['account_id']
        self.assertions = [Assertion(self, a, polyswarm) for a in json['assertions']]
        self.country = json['country']
        self.community = json['community']
        self.created = types.date.parse_isoformat(json['created'])
        self.extended_type = json['extended_type']
        self.failed = json['failed']
        self.filename = json['filename']
        self.first_seen = json['first_seen']
        self.last_seen = types.date.parse_isoformat(json['last_seen'])
        self.md5 = json['md5']
        self.metadata = ArtifactMetadata(self, json.get('artifact_metadata', {}), polyswarm)
        self.mimetype = json['mimetype']
        self.result = json['result']
        self.sha1 = json['sha1']
        self.sha256 = json['sha256']
        self.size = json['size']
        self.type = json['type']
        self.votes = [Vote(self, v, polyswarm) for v in json['votes']]
        self.window_closed = json['window_closed']

        self._submission = None
        self._polyscore = None
        self._permalink = None
        self._detections = None
        self._valid_assertions = None

    def __str__(self):
        return "ArtifactInstance-<%s>" % self.hash

    @property
    def detections(self):
        if not self._detections:
            self._detections = [a for a in self.assertions if a.mask and a.verdict]
        return self._detections

    @property
    def valid_assertions(self):
        if not self._valid_assertions:
            self._valid_assertions = [a for a in self.assertions if a.mask]
        return self._valid_assertions

    @property
    def polyscore(self):
        if self.polyswarm and not self._polyscore and self.submission_uuid:
            polyscore = next(self.polyswarm.score(self.submission_uuid))
            self._polyscore = polyscore.get_score_by_id(self.id)
        return self._polyscore

    @property
    def submission(self):
        if self.polyswarm and not self._submission and self.submission_uuid:
            self._submission = next(self.polyswarm.lookup(self.submission_uuid))
        return self._submission

    @property
    def permalink(self):
        if not self._permalink and self.submission_uuid:
            self._permalink = const.DEFAULT_PERMALINK_BASE + '/' + self.submission_uuid
        return self._permalink


class Artifact(base.Hashable, base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = types.schemas.artifact_schema

    def __init__(self, json, polyswarm=None):
        """
        A representation of artifact data retrieved from the polyswarm API


        :param path: Path to the artifact
        :param content: Content of the artifact
        :param artifact_name: Name of the artifact (filename, or otherwise)
        :param artifact_type: base.ArtifactType of the artifact
        :param polyswarm: Current PolyswarmAPI instance
        :param json: JSON used to
        :param analyze:
        """
        super(Artifact, self).__init__(json, polyswarm)

        self.mimetype = json['mimetype']
        self.extended_type = json['extended_type']
        self.first_seen = types.date.parse_isoformat(json['first_seen'])
        self.id = json['id']
        self.sha256 = base.Hash(json['sha256'], 'sha256', polyswarm)
        self.sha1 = base.Hash(json['sha1'], 'sha1', polyswarm)
        self.md5 = base.Hash(json['md5'], 'md5', polyswarm)

        self.instances = list(
            sorted(
                [ArtifactInstance(instance,polyswarm=polyswarm) for instance in json.get('artifact_instances', [])],
                key=lambda x: x.submitted, reverse=True
            ))

        # for now, we don't have a special Metadata object, but if something differentiates this
        # in the future from a simple dict, we can
        self.metadata = ArtifactMetadata(self, json.get('artifact_metadata', {}), polyswarm)

        self._polyscore = None

    @property
    def hash(self):
        return self.sha256

    @property
    def hash_type(self):
        return "sha256"

    def __str__(self):
        return "Artifact <%s>" % self.hash

    @classmethod
    def from_json(cls, json, polyswarm=None):
        pass

    def download(self, out_path=None):
        """
        Download an artifact

        :param out_path: output path for artifact
        :return: LocalArtifact instance
        """
        if not any([self.sha256, self.md5, self.sha1]):
            raise exceptions.InvalidArgumentException('At least one hash type must be defined.')
        result = self.polyswarm.download(self)
        result.artifact = self
        return result

    @property
    def similar(self):
        return []

    @property
    def last_scan(self):
        if len(self.scans) > 0:
            return self.scans[0]
        return None

    @property
    def first_scan(self):
        if len(self.scans) > 0:
            return self.scans[-1]
        return None

    @property
    def scans(self):
        # do not report scans as they are running, only once window has closed
        return list(filter(None, [instance for instance in self.instances
                                  if instance.window_closed and not instance.failed]))

    @property
    def scan_permalink(self):
        if len(self.bounties) == 0:
            return None
        return self.instances[0].submission_uuid

    @property
    def bounties(self):
        return [instance.bounty for instance in self.instances if instance.bounty]

    @property
    def filenames(self):
        """ Unique filenames in all observed instances"""
        return list(OrderedSet([instance.name for instance in self.instances if instance.name]))

    @property
    def countries(self):
        return list(OrderedSet([instance.country for instance in self.instances if instance.country]))

    @property
    def detections(self):
        latest = self.last_scan
        if latest:
            return [a for a in latest.assertions if a.mask and a.verdict]
        else:
            return []

    @property
    def polyscore(self):
        if self._polyscore:
            return self._polyscore

        # need polyswarm API to look this up
        if not self.polyswarm:
            return None

        latest = self.last_scan

        if not latest:
            return None

        return latest.polyscore


class ArtifactArchive(base.Hashable, base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = types.schemas.artifact_archive_schema

    def __init__(self, json, polyswarm=None):
        super(ArtifactArchive, self).__init__(json, polyswarm)
        self.id = json['id']
        self.community = json['community']
        self.created = types.date.parse_isoformat(json['created'])
        self.s3_path = json['s3_path']


class Hunt(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = types.schemas.hunt_status

    def __init__(self, json, polyswarm=None):
        super(Hunt, self).__init__(json, polyswarm)
        # active only present for live hunts
        self.id = json['id']
        self.created = types.date.parse_isoformat(json['created'])
        self.status = json['status']
        self.active = json.get('active')


class HuntResult(base.BasePSJSONType, base.BasePSResourceType):
    SCHEMA = types.schemas.hunt_result

    def __init__(self, json, polyswarm=None):
        super(HuntResult, self).__init__(json, polyswarm)
        self.id = json['id']
        self.rule_name = json['rule_name']
        self.tags = json['tags']
        self.created = types.date.parse_isoformat(json['created'])
        self.sha256 = json['sha256']
        self.historicalscan_id = json['historicalscan_id']
        self.livescan_id = json['livescan_id']
        self.artifact = Artifact(json['artifact'], polyswarm)


#####################################################################
# Nested Resources
#####################################################################

class Assertion(base.BasePSJSONType):
    SCHEMA = types.schemas.assertion_schema

    def __init__(self, scanfile, json, polyswarm=None):
        super(Assertion, self).__init__(json, polyswarm)
        self.scanfile = scanfile
        self.author = json['author']
        self.author_name = json['author_name']
        self.engine_name = json['engine'].get('name')
        self.bid = int(json['bid'])
        self.mask = json['mask']
        # deal with metadata being a string instead of null
        self.metadata = json['metadata'] if json['metadata'] else {}
        self.verdict = json['verdict']

    def __str__(self):
        return "Assertion-%s: %s" % (self.engine_name, self.verdict)


class Vote(base.BasePSJSONType):
    SCHEMA = types.schemas.vote_schema

    def __init__(self, scanfile, json, polyswarm=None):
        super(Vote, self).__init__(json, polyswarm)
        self.scanfile = scanfile
        self.arbiter = json['arbiter']
        self.vote = json['vote']

    def __str__(self):
        return "Vote-%s: %s" % (self.arbiter, self.vote)


class ArtifactMetadata(base.BasePSJSONType):
    SCHEMA = types.schemas.artifact_metadata

    def __init__(self, artifact, json, polyswarm=None):
        super(ArtifactMetadata, self).__init__(json, polyswarm)

        self.artifact = artifact
        self.hash = json.get('hash', {})
        self.exiftool = json.get('exiftool', {})
        self.lief = json.get('lief', {})
        self.pefile = json.get('pefile', {})
