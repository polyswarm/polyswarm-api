from itertools import chain

from .base import BasePSJSONType, BasePSType
from .artifact import Artifact, Bounty
from .hunt import Hunt, HuntStatus
from .scan import PolyScore

from . import schemas
from .. import exceptions
from ..log import logger
from ..const import USAGE_EXCEEDED_MESSAGE

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
            logger.error('Invalid JSON result object provided by server.')
            raise e

        if self.status_code == 429:
            raise exceptions.UsageLimitsExceeded(USAGE_EXCEEDED_MESSAGE)

        self.status = json['status']
        self.result = json['result']
        self.errors = json.get('errors', None)
        self.total = json.get('total', None)
        self.limit = json.get('limit', None)
        self.page = json.get('page', None)
        self.order_by = json.get('order_by', None)
        self.direction = json.get('direction', None)

        # This are set by subclasses during parsing of the API response
        self.failed = False
        self.failure_reason = ''

    @property
    def _bad_status_message(self):
        return "Got unexpected result code: {}, message: {}".format(self.status_code, self.result)

    def _set_failure(self, reason='Unspecified error occurred'):
        self.failed = True
        self.failure_reason = reason


class IndexableResult(ApiResponse):
    # convenience function, make SearchResult act as list
    def __len__(self):
        return len(self.result)

    def __getitem__(self, i):
        return self.result[i]

    def __setitem__(self, key, value):
        self.result[key] = value


class DownloadResult(ApiResponse):
    """ This is an artificially constructed result object, to track downloads. """
    def __init__(self, artifact, result, polyswarm=None):
        self.polyswarm = polyswarm
        self.status_code = result.status_code

        self.failed = False
        self.failure_reason = ''

        if self.status_code == 404:
            self._set_failure('Artifact {} not found.'.format(artifact.artifact_name))
        elif self.status_code // 100 != 2:
            raise exceptions.ServerErrorException(self._bad_status_message)

        self.status = 'OK'
        self.result = artifact
        self.errors = None
        self.total = None
        self.limit = None
        self.page = None
        self.order_by = None
        self.direction = None


class SearchResult(IndexableResult):
    """ This is a result object for representing searches """
    def __init__(self, query, result, polyswarm=None):
        self.query = query

        super(SearchResult, self).__init__(result, polyswarm)

        if self.status_code == 404 or len(self.result) == 0:
            self.result = []
            # ordinarily we shouldn't do this, TODO fix in AI
            self.json['result'] = []
            self._set_failure('Did not find any files matching search: %s.' % repr(query))
        elif self.status_code // 100 == 2:
            self.result = [Artifact(j, polyswarm) for j in self.result]
        else:
            raise exceptions.ServerErrorException(self._bad_status_message)


class ScanResult(ApiResponse):
    def __init__(self, result, artifact=None, polyswarm=None, timeout=False):
        super(ScanResult, self).__init__(result, polyswarm)
        self.timeout = timeout
        self.artifact = artifact
        if self.status_code // 100 == 2:
            if self.result:
                self.result = Bounty(None, self.result, polyswarm=polyswarm)

                if not self.result.uuid:
                    self._set_failure('Did not get a UUID for scan.')
                elif self.result.failed:
                    self._set_failure('Bounty creation failed for submission {}. '
                                      'Please resubmit.'.format(self.result.uuid))
                elif self.timeout:
                    self._set_failure('Did not get a response for {} in time, check again later.'
                                      .format(self.result.uuid))
            else:
                self._set_failure('Did not get a result.')
        elif self.status_code == 404:
            self._set_failure("UUID not found.")
        else:
            raise exceptions.ServerErrorException(self._bad_status_message)

    @property
    def ready(self):
        if not self.result or isinstance(self.result, str):
            return False

        return self.result.ready


class SubmitResult(ApiResponse):
    def __init__(self, artifact, result, polyswarm=None):
        super(SubmitResult, self).__init__(result, polyswarm)
        self.artifact = artifact

        if self.status_code == 404:
            # happens if rescan file wasn't found
            self._set_failure('Artifact {} not found'.format(self.artifact))
        elif self.status_code // 100 != 2:
            raise exceptions.ServerErrorException(self._bad_status_message)

    def wait_for_scan(self):
        # this function will always only return one item
        return next(self.polyswarm.wait_for(self.result))


class HuntSubmissionResult(ApiResponse):
    def __init__(self, rules, result, polyswarm=None):
        super(HuntSubmissionResult, self).__init__(result, polyswarm)
        self.rules = rules

        if self.status_code == 400:
            self._set_failure('Syntax error in submission. Please check your rules, '
                              'or install the yara-python package for more details.')
        elif self.status_code // 100 != 2:
            raise exceptions.ServerErrorException(self._bad_status_message)
        else:
            self.result = Hunt(self.result, polyswarm)


class HuntResultPart(IndexableResult):
    def __init__(self, hunt, result, polyswarm=None):
        self.hunt = hunt

        super(HuntResultPart, self).__init__(result, polyswarm)

        if self.status_code // 100 == 2:
            self.result = HuntStatus(self.result, polyswarm)
            if self.result.status not in ['PENDING', 'RUNNING', 'SUCCESS', 'FAILED']:
                self._set_failure('An unspecified error occurred fetching hunt records.')
            elif self.result.total == 0:
                self._set_failure('Did not find any results yet for this hunt. Hunt status: {}'
                                  .format(self.result.status))

        elif self.status_code == 404:
            self.result = []
            self._set_failure('Hunt {}not found.'.format(str(hunt.hunt_id)+' ' if hunt else ''))
        else:
            raise exceptions.ServerErrorException(self._bad_status_message)


class ResultAggregator(BasePSType):
    RESULT_CLS = None

    """ This is a special class that aggregates multiple iterable results into one """
    def __init__(self, request_list, polyswarm=None, **kwargs):
        super(ResultAggregator, self).__init__(polyswarm)
        self.request_list = request_list
        self.kwargs = kwargs
        self.parts = []
        self.resolved = False
        self.failed = False
        self.failure_reason = ''

    def __iter__(self):
        def iterator():
            if self.resolved:
                for part in self.parts:
                    for res in part:
                        yield res
            else:
                for req in self.request_list:
                    res = self.RESULT_CLS(result=req.result(), polyswarm=self.polyswarm, **self.kwargs)
                    self.parts.append(res)
                    for result in res:
                        yield result
                self.resolved = True
        return iterator()

    @property
    def result(self):
        return self.__iter__()


class HuntResult(ResultAggregator):
    RESULT_CLS = HuntResultPart

    def __init__(self, hunt, request_list, polyswarm=None):
        super(HuntResult, self).__init__(request_list, polyswarm=polyswarm, hunt=hunt)
        self.hunt = hunt
        self.hunt_status = HuntResultPart(hunt, self.request_list[0].result(), polyswarm)
        self.failed = self.hunt_status.failed
        self.failure_reason = self.hunt_status.failure_reason


class HuntDeletionResult(ApiResponse):
    def __init__(self, hunt_id, result, polyswarm=None):
        super(HuntDeletionResult, self).__init__(result, polyswarm)

        if self.status_code == 404:
            self._set_failure('Hunt not found.')
        elif self.status_code // 100 != 2:
            raise exceptions.ServerErrorException(self._bad_status_message)

        self.result = hunt_id


class HuntListResult(IndexableResult):
    def __init__(self, result, polyswarm=None):
        super(HuntListResult, self).__init__(result, polyswarm)

        if self.status_code // 100 != 2:
            raise exceptions.ServerErrorException(self._bad_status_message)

        self.result = [HuntStatus(r, polyswarm) for r in self.result]


class StreamResult(IndexableResult):
    def __init__(self, result, polyswarm=None):
        super(StreamResult, self).__init__(result, polyswarm)

        if self.status_code // 100 != 2:
            raise exceptions.ServerErrorException(self._bad_status_message)

        self.result = self.result.get('stream', [])


class ScoreResult(ApiResponse):
    def __init__(self, result, polyswarm=None):
        super(ScoreResult, self).__init__(result, polyswarm)

        if self.status_code == 404:
            self._set_failure('Did not find UUID or score not found')
        elif self.status_code // 100 != 2:
            raise exceptions.ServerErrorException(self._bad_status_message)

        self.result = PolyScore(self.result, polyswarm)
