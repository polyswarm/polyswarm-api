from jsonschema import validate, ValidationError
from enum import Enum

from ..log import logger
from .. import exceptions


class BasePSType(object):
    def __init__(self, polyswarm=None):
        self.polyswarm = polyswarm


class BasePSJSONType(BasePSType):
    SCHEMA = {
        'type': ['object', 'array']
    }

    def __init__(self, json=None, polyswarm=None):
        super(BasePSJSONType, self).__init__(polyswarm)
        # this is expensive on thousands of objects
        # avoid if disabled
        if polyswarm and polyswarm.validate:
            self.validate(json)
        self.json = json

    def validate(self, json, schema=None):
        if not schema:
            schema = self.SCHEMA

        try:
            validate(json, schema)
        except ValidationError:
            raise exceptions.InvalidJSONResponse("Failed to validate json against schema", json, self.SCHEMA)


# TODO make polyswarmartifact support 2.7 so this is not necessary
class ArtifactType(Enum):
    FILE = 0
    URL = 1

    @staticmethod
    def from_string(value):
        if value is not None:
            try:
                return ArtifactType[value.upper()]
            except KeyError:
                logger.critical('%s is not a supported artifact type', value)

    @staticmethod
    def to_string(artifact_type):
        return artifact_type.name.lower()

    def decode_content(self, content):
        if content is None:
            return None

        if self == ArtifactType.URL:
            try:
                return content.decode('utf-8')
            except UnicodeDecodeError:
                raise exceptions.DecodeError('Error decoding URL')
        else:
            return content