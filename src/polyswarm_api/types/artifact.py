from ordered_set import OrderedSet

from ..exceptions import NotFoundException, InvalidArgument, ArtifactDeleted
from ..log import logger
from .base import BasePSJSONType, ArtifactType
from .hash import all_hashes, Hash, Hashable
from io import BytesIO
import os
from . import schemas
from .scan import Bounty
from . import date


def requires_analysis(func):
    def wrapper(a, *args, **kwargs):
        if not a.analyzed:
            a.analyze_artifact()
        return func(a, *args, **kwargs)
    return wrapper


def not_deleted(func):
    def wrapper(a, *args, **kwargs):
        if a.deleted:
            raise ArtifactDeleted("Tried to use deleted LocalArtifact")
        return func(a, *args, **kwargs)
    return wrapper


class ArtifactMetadata(BasePSJSONType):
    SCHEMA = schemas.artifact_metadata

    def __init__(self, artifact, json, polyswarm=None):
        super(ArtifactMetadata, self).__init__(json, polyswarm)

        self.artifact = artifact
        self.hash = json.get('hash', {})
        self.exiftool = json.get('exiftool', {})
        self.lief = json.get('lief', {})
        self.pefile = json.get('pefile', {})


class ArtifactInstance(BasePSJSONType):
    SCHEMA = schemas.artifact_instance_schema

    def __init__(self, artifact, json, polyswarm=None):
        super(ArtifactInstance, self).__init__(json, polyswarm)
        self.artifact_id = json['artifact_id']
        self.bounty_id = json['bounty_id']
        # rename this to make it clearer, and avoid the word 'Result' which has a specific meaning in this project
        # using Scan here instead of Bounty
        self.bounty = Bounty(self, json['bounty_result'], polyswarm=polyswarm) if json['bounty_result'] else None
        self.community = json['community']
        self.consumer_guid = json.get('consumer_guid', None)
        self.country = json['country']
        self.id = json['id']
        self.name = json['name']
        self.submitted = date.parse_date(json['submitted'])
        self.artifact = artifact


class Artifact(Hashable, BasePSJSONType):
    SCHEMA = schemas.artifact_schema

    def __init__(self, json, polyswarm=None):
        """
        A representation of artifact data retrieved from the polyswarm API


        :param path: Path to the artifact
        :param content: Content of the artifact
        :param artifact_name: Name of the artifact (filename, or otherwise)
        :param artifact_type: ArtifactType of the artifact
        :param polyswarm: Current PolyswarmAPI instance
        :param json: JSON used to
        :param analyze:
        """
        super(Artifact, self).__init__(json, polyswarm)

        self.mimetype = json['mimetype']
        self.extended_type = json['extended_type']
        self.first_seen = date.parse_date(json['first_seen'])
        self.id = json['id']
        self.sha256 = Hash(json['sha256'], 'sha256', polyswarm)
        self.sha1 = Hash(json['sha1'], 'sha1', polyswarm)
        self.md5 = Hash(json['md5'], 'md5', polyswarm)

        self.instances = list(sorted([ArtifactInstance(self, instance,
                                           polyswarm=polyswarm) for instance in json.get('artifact_instances', [])],
                                     key=lambda x: x.submitted, reverse=True))

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
        if not any([self._sha256, self._md5, self._sha1]):
            raise NotFoundException
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
        return list(filter(None, [bounty.get_file_by_hash(self) for bounty in self.bounties if bounty.ready
                                  and not bounty.failed]))

    @property
    def scan_permalink(self):
        if len(self.bounties) == 0:
            return None
        return self.bounties[0].permalink

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
        if not latest:
            return []

        if latest:
            return latest.detections
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



class LocalArtifact(Hashable):
    """ Artifact for which we have local content """
    def __init__(self, path=None, content=None, artifact_name=None, artifact_type=ArtifactType.FILE,
                 artifact=None, polyswarm=None, lookup=False, analyze=True):
        """
        A representation of an artifact we have locally

        :param path: Path to the artifact
        :param content: Content of the artifact
        :param artifact_name: Name of the artifact
        :param artifact_type: Type of artifact
        :param remote: Associated Artifact object of polyswarm API data
        :param polyswarm: PolyswarmAPI instance
        :param lookup: Boolean, if True will look up associated Artifact data
        :param analyze: Boolean, if True will run analyses on artifact on startup (Note: this may still run later if False)
        """
        if not (path or content):
            raise InvalidArgument("Must provide artifact content, either via path or content argument")

        self.deleted = False
        self.analyzed = False

        self.path = path
        self.content = content

        self.artifact = artifact
        self.artifact_type = artifact_type
        self._artifact_name = artifact_name

        self.polyswarm = polyswarm

        if lookup:
            self.artifact = self.lookup(True)

        if analyze:
            self.analyze_artifact()

        super(LocalArtifact, self).__init__()

    @property
    @requires_analysis
    def hash(self):
        return self.sha256

    @property
    def hash_type(self):
        return "sha256"

    @property
    def artifact_name(self):
        if self._artifact_name:
            return self._artifact_name
        if self.artifact_type == ArtifactType.URL and self.content:
            return self.content
        return self.hash

    @property
    @not_deleted
    def file_handle(self):
        # will always have one or the other
        if self.content:
            return BytesIO(self.content)
        return open(self.path, 'rb')

    @not_deleted
    def analyze_artifact(self):
        fh = self.file_handle

        self._calc_hashes(fh)
        fh.seek(0)

        self._calc_hashes(fh)
        fh.seek(0)

        self._run_analyzers(fh)

        fh.close()
        self.analyzed = True

    def _calc_hashes(self, fh):
        self.sha256, self.sha1, self.md5 = all_hashes(fh)

    def _calc_features(self, fh):
        # TODO implement feature extraction here. This will be used by search_features function.
        return {}

    def _run_analyzers(self, fh):
        # TODO implement custom analyzer support, so users can implement plugins here.
        return {}

    def lookup(self, refresh=False):
        if self.artifact and not refresh:
            return self.artifact

        if not self.polyswarm:
            logger.warning("Tried to lookup artifact, but no polyswarm instance was associated")
            return None

        res = next(self.polyswarm.search([self]))

        if res.result and len(res.result) > 0:
            return res.result[0]
        return None

    def delete(self):
        if self.path:
            os.remove(self.path)
        if self.content:
            self.content = b''
        self.deleted = True

    def __str__(self):
        return "Artifact <%s>" % self.hash


def to_artifact(a, polyswarm=None):
    if isinstance(a, LocalArtifact):
        return a
    # if local path, FILE is assumed
    return LocalArtifact(path=a, analyze=False, polyswarm=polyswarm)
