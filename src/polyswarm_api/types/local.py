import logging
import json
import os
from io import BytesIO

from jsonschema import validate, ValidationError

from polyswarm_api import exceptions
from polyswarm_api.types import base
from polyswarm_api.types import schemas
from polyswarm_api.types.models import yara

logger = logging.getLogger(__name__)


class Query(base.BasePSType):
    def __init__(self, polyswarm=None):
        super(Query, self).__init__(polyswarm)


class MetadataQuery(Query):
    """ Class representing a MetadataQuery """
    def __init__(self, query, raw=False, polyswarm=None):
        super(MetadataQuery, self).__init__(polyswarm)
        if not raw:
            query = {
                'query': {
                    'query_string': {
                        'query': query
                    }
                }
            }
        self.query = query
        self.validate()

    def validate(self):
        try:
            validate(self.query, schemas.search_schema)
        except ValidationError:
            raise exceptions.InvalidJSONResponseException("Failed to validate json against schema",
                                                          self.query, schemas.search_schema)

    def __repr__(self):
        return json.dumps(self.query)


def requires_analysis(func):
    def wrapper(a, *args, **kwargs):
        if not a.analyzed:
            a.analyze_artifact()
        return func(a, *args, **kwargs)
    return wrapper


def not_deleted(func):
    def wrapper(a, *args, **kwargs):
        if a.deleted:
            raise exceptions.ArtifactDeletedException("Tried to use deleted LocalArtifact")
        return func(a, *args, **kwargs)
    return wrapper


class LocalArtifact(base.Hashable):
    """ Artifact for which we have local content """
    def __init__(self, path=None, content=None, artifact_name=None, artifact_type=base.ArtifactType.FILE,
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
            raise exceptions.InvalidArgumentException("Must provide artifact content, either via path or content argument")

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
        if self.artifact_type == base.ArtifactType.URL and self.content:
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
        self.sha256, self.sha1, self.md5 = base.all_hashes(fh)

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


class YaraRuleset(base.BasePSJSONType):
    def __init__(self, ruleset, path=None, polyswarm=None):
        super(YaraRuleset, self).__init__(polyswarm)

        if not (path or ruleset):
            raise exceptions.InvalidArgumentException("Must provide artifact content, either via path or content argument")

        if ruleset:
            self.ruleset = ruleset
        else:
            self.ruleset = open(path, "r").read()

    def validate(self):
        if not yara:
            raise exceptions.exceptions.NotImportedException("Cannot validate rules locally without yara-python")

        try:
            yara.compile(source=self.ruleset)
        except yara.SyntaxError as e:
            raise exceptions.exceptions.InvalidYaraRulesException(*e.args)

        return True