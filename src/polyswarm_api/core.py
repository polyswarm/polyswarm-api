import logging

from dateutil import parser

logger = logging.getLogger(__name__)


class BaseResource:
    def __init__(self, api=None):
        self.api = api

    def deserialize(self, contents):
        raise NotImplementedError('desserialize() is not implemented for this resource: %s', self.__class__)

    @classmethod
    def parse_result(cls, api, result, **kwargs):
        logger.debug('Parsing resource %s', cls.__name__)
        return cls(result, api=api, **kwargs)

    @classmethod
    def parse_result_list(cls, api_instance, json_data, **kwargs):
        return [cls.parse_result(api_instance, entry, **kwargs) for entry in json_data]


class BaseJsonResource(BaseResource):
    def __init__(self, json=None, api=None):
        super(BaseJsonResource, self).__init__(api=api)
        self.json = json

    def __reduce__(self):
        return (type(self), (self.__dict__.get('json'), self.api))


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


def parse_isoformat(date_string):
    """ Parses the current date format version """
    if date_string:
        return parser.isoparse(date_string)
    else:
        return None