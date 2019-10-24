import json
from jsonschema import validate, ValidationError

from .base import BasePSType
from .schemas import search_schema
from .. import exceptions


class Query(BasePSType):
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
            validate(self.query, search_schema)
        except ValidationError:
            raise exceptions.InvalidJSONResponse("Failed to validate json against schema", self.query, search_schema)

    def __repr__(self):
        return json.dumps(self.query)
