import logging

from jsonschema import validate, ValidationError

from .. import exceptions

logger = logging.getLogger(__name__)


class BasePSType(object):
    def __init__(self, polyswarm=None):
        self.polyswarm = polyswarm


class BasePSResourceType(BasePSType):
    @classmethod
    def parse_result(cls, api_instance, result, **kwargs):
        logger.debug('Parsing resource %s', cls.__name__)
        return cls(result, polyswarm=api_instance, **kwargs)

    @classmethod
    def parse_result_list(cls, api_instance, json_data, **kwargs):
        return [cls.parse_result(api_instance, entry, **kwargs) for entry in json_data]


class BasePSJSONType(BasePSResourceType):
    SCHEMA = {
        'type': ['object', 'array']
    }

    def __init__(self, json=None, polyswarm=None):
        super(BasePSJSONType, self).__init__(polyswarm=polyswarm)
        self._json = None
        if json is not None:
            self.json = json

    @property
    def json(self):
        return self._json

    @json.setter
    def json(self, value):
        # this is expensive on thousands of objects
        # avoid if disabled
        if self.polyswarm and self.polyswarm.validate:
            self._validate(value)
        self._json = value

    def _validate(self, json, schema=None):
        if not schema:
            schema = self.SCHEMA

        try:
            validate(json, schema)
        except ValidationError:
            raise exceptions.InvalidJSONResponseException("Failed to validate json against schema", json, self.SCHEMA)


# TODO better way to do this with ABC?
class Hashable:
    @property
    def hash(self):
        return self.sha256

    @property
    def hash_type(self):
        return 'sha256'

    def __eq__(self, other):
        return self.hash == other


class AsInteger:
    def __int__(self):
        return int(self.id)
