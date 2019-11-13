import logging

from jsonschema import validate, ValidationError

from .. import exceptions

logger = logging.getLogger(__name__)


class BasePSType(object):
    def __init__(self, polyswarm=None):
        self.polyswarm = polyswarm


class BasePSJSONType(BasePSType):
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
             self.validate(value)
        self._json = value

    def validate(self, json, schema=None):
        if not schema:
            schema = self.SCHEMA

        try:
            validate(json, schema)
        except ValidationError:
            raise exceptions.InvalidJSONResponseException("Failed to validate json against schema", json, self.SCHEMA)


class BasePSResourceType(BasePSType):
    @classmethod
    def parse_result(cls, api_instance, json_result, **kwargs):
        return cls(json_result, polyswarm=api_instance, **kwargs)

    @classmethod
    def parse_result_list(cls, api_instance, json_data, **kwargs):
        return [cls.parse_result(api_instance, entry, **kwargs) for entry in json_data]


# TODO make polyswarmartifact support 2.7 so this is not necessary


# TODO better way to do this with ABC?
class Hashable(BasePSType):
    @property
    def hash(self):
        raise NotImplementedError

    @property
    def hash_type(self):
        raise NotImplementedError

    def __eq__(self, other):
        return self.hash == other
