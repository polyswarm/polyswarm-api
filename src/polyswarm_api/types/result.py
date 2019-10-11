from .base import BasePSJSONType
from .artifact import Artifact, Bounty
from . import schemas
from .. import exceptions
from ..log import logger

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


class ApiResponse(BasePSJSONType):
    """ The base API response class. All results from PolyswarmAPI are subclasses of this """
    SCHEMA = schemas.api_response_schema

    def __init__(self, result, polyswarm=None):
        self.status_code = result.status_code

        try:
            json = result.json()
        except JSONDecodeError as e:
            logger.error("Server returned non-JSON response.")
            raise e

        try:
            super(ApiResponse, self).__init__(json, polyswarm)
        except exceptions.InvalidJSONResponse as e:
            logger.error("Invalid JSON result object provided by server.")
            raise e

        self.status = json['status']
        self.result = json['result']
        self.errors = json.get('errors', None)
        self.total = json.get('total', None)
        self.limit = json.get('limit', None)
        self.page = json.get('page', None)
        self.order_by = json.get('order_by', None)
        self.direction = json.get('direction', None)

    @property
    def _bad_status_exception(self):
        print(self.result)
        return exceptions.ServerErrorException("Got unexpected result code %s" % self.status_code)


class DownloadResult(ApiResponse):
    SCHEMA = {'type': 'null'}
    """ This is an artificially constructed result object, to track downloads. """
    def __init__(self, artifacts, status='OK', polyswarm=None):
        # no associated json
        super(ApiResponse, self).__init__(None, polyswarm)
        self.status = status
        self.result = artifacts


class SearchResult(ApiResponse):
    """ This is a result object for representing searches """
    def __init__(self, query, result, polyswarm=None):
        self.query = query

        super(SearchResult, self).__init__(result, polyswarm)

        if self.status_code == 404:
            self.result = []
        elif self.status_code // 100 == 2:
            self.result = [Artifact(j, polyswarm) for j in self.result]
        else:
            raise self._bad_status_exception

    # convenience function, make SearchResult act as list
    def __len__(self):
        return len(self.result)

    def __getitem__(self, i):
        return self.result[i]

    def __setitem__(self, key, value):
        self.result[key] = value


class ScanResult(ApiResponse):
    def __init__(self, result, artifact=None, polyswarm=None):
        super(ScanResult, self).__init__(result, polyswarm)
        self.artifact = artifact
        if self.status_code // 100 == 2:
            if self.result:
                self.result = Bounty(None, self.result, polyswarm=polyswarm)
        else:
            raise self._bad_status_exception

    @property
    def ready(self):
        if not self.result:
            return False

        return self.result.ready

class SubmitResult(ApiResponse):
    def __init__(self, artifact, result, polyswarm=None):
        super(SubmitResult, self).__init__(result, polyswarm)
        self.artifact = artifact
        if self.status_code // 100 != 2:
            raise self._bad_status_exception

    def wait_for_scan(self):
        # this function will always only return one item
        return next(self.polyswarm.wait_for(self.result))


class HuntSubmissionResult(ApiResponse):
    pass


class HuntLookupResult(ApiResponse):
    pass


class HuntDeletionResult(ApiResponse):
    pass


class HuntCreationResult(ApiResponse):
    pass
