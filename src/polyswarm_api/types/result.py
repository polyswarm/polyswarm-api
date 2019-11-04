import os
import os.path

from .base import BasePSJSONType, BasePSType
from .artifact import Artifact, Submission, PolyScore, LocalArtifact
from .hunt import Hunt, HuntStatus

from . import schemas
from .. import const
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

    def __init__(self, *args, **kwargs):
        super(ApiResponse, self).__init__(*args, **kwargs)
        self.status_code = None
        self.status = None
        self.result = None
        self.errors = None
        self.total = None
        self.limit = None
        self.page = None
        self.order_by = None
        self.direction = None

    def parse_result(self, result):
        try:
            self.json = result.json()
        except JSONDecodeError as e:
            logger.error("Server returned non-JSON response.")
            raise e

        self.status_code = result.status_code
        if self.status_code == 429:
            raise exceptions.UsageLimitsExceeded(USAGE_EXCEEDED_MESSAGE)

        self.result = self.json.get('result')
        self.status = self.json.get('status')
        self.errors = self.json.get('errors')
        self.total = self.json.get('total')
        self.limit = self.json.get('limit')
        self.page = self.json.get('page')
        self.order_by = self.json.get('order_by')
        self.direction = self.json.get('direction')
        try:
            response = ApiResponse(result, self.polyswarm)
        except exceptions.InvalidJSONResponse as e:
            logger.error('Invalid JSON result object provided by server.')
            raise e

        return response

    @property
    def _bad_status_exception(self):
        return exceptions.ServerErrorException("Got unexpected result code: {}, message: {}".format(self.status_code,
                                                                                                  self.result))


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
    def __init__(self, output_file, file_handle=None, polyswarm=None, create=False):
        super(DownloadResult, self).__init__(polyswarm=polyswarm)
        self.output_file = output_file
        self.file_handle = file_handle
        self.create = create

    def parse_result(self, result):
        self.status_code = result.status_code
        if self.status_code == 404:
            self.status = 'Not found.'
        elif self.status_code // 100 != 2:
            raise self._bad_status_exception
        self.status = 'OK'

        path, file_name = os.path.split(self.output_file)
        self.result = LocalArtifact(path=self.output_file, artifact_name=file_name, analyze=False, polyswarm=self)

        if result.status_code == 200:
            if self.file_handle:
                for chunk in result.raw_result.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
                    self.file_handle.write(chunk)
            else:
                if self.create:
                    os.makedirs(path, exist_ok=True)
                with open(self.output_file, 'wb') as file_handle:
                    for chunk in result.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
                        file_handle.write(chunk)
        else:
            self.result.content = b'error'


class SearchResult(IndexableResult):
    """ This is a result object for representing searches """
    def __init__(self, query, polyswarm=None):
        super(SearchResult, self).__init__(polyswarm)
        self.query = query

    def parse_result(self, result):
        super(SearchResult, self).parse_result(result)
        if self.status_code == 404:
            self.result = []
            # ordinarily we shouldn't do this, TODO fix in AI
            self.json['result'] = []
        elif self.status_code // 100 == 2:
            # special case this error
            self.result = [Artifact(j, self.polyswarm) for j in self.result]
        else:
            raise self._bad_status_exception


class ScanResult(ApiResponse):
    def parse_result(self, result):
        super(ScanResult, self).parse_result(result)
        if self.status_code // 100 == 2:
            if self.result:
                self.result = Submission(None, self.result, polyswarm=self.polyswarm)
        elif self.status_code == 404:
            self.result = "UUID not found"
        else:
            raise self._bad_status_exception

    @property
    def ready(self):
        if not self.result or isinstance(self.result, str):
            return False

        return self.result.status == 'Bounty Awaiting Arbitration'


class SubmitResult(ApiResponse):
    def __init__(self, artifact, polyswarm=None):
        super(SubmitResult, self).__init__(polyswarm=polyswarm)
        self.artifact = artifact

    def parse_result(self, result):
        super(SubmitResult, self).parse_result(result)

        if self.status_code == 404:
            # happens if rescan file wasn't found
            self.status = 'Not found'
        elif self.status_code // 100 != 2:
            raise self._bad_status_exception

    def wait_for_scan(self):
        # this function will always only return one item
        return next(self.polyswarm.wait_for(self.result))


class HuntSubmissionResult(ApiResponse):
    def __init__(self, rules, polyswarm=None):
        super(HuntSubmissionResult, self).__init__(polyswarm)
        self.rules = rules

    def parse_result(self, result):
        super(HuntSubmissionResult, self).parse_result(result)
        if self.status_code == 400:
            self.result = 'Syntax error in submission. Please check your rules, or install the yara-python package for more details.'
        elif self.status_code // 100 != 2:
            raise self._bad_status_exception
        else:
            self.result = Hunt(self.result, self.polyswarm)


class HuntResult(IndexableResult):
    def parse_result(self, result):
        super(HuntResult, self).parse_result(result)

        if self.status_code // 100 == 2:
            self.result = HuntStatus(self.result, self.polyswarm)
        elif self.status_code == 404:
            self.result = []
        else:
            raise self._bad_status_exception


class HuntDeletionResult(ApiResponse):
    def __init__(self, hunt_id, result, polyswarm=None):
        super(HuntDeletionResult, self).__init__(result, polyswarm)

        if self.status_code // 100 != 2 and self.status_code != 404:
            raise self._bad_status_exception

        self.result = hunt_id


class HuntListResult(IndexableResult):
    def __init__(self, result, polyswarm=None):
        super(HuntListResult, self).__init__(result, polyswarm)

        if self.status_code // 100 != 2:
            raise self._bad_status_exception

        self.result = [HuntStatus(r, polyswarm) for r in self.result]


class StreamResult(IndexableResult):
    def parse_result(self, result):
        super(StreamResult, self).parse_result(result)

        if self.status_code // 100 != 2:
            raise self._bad_status_exception

        self.result = self.result.get('stream', [])


class ScoreResult(ApiResponse):
    def __init__(self, result, polyswarm=None):
        super(ScoreResult, self).__init__(result, polyswarm)

        if self.status_code == 404:
            raise exceptions.NotFoundException('Did not find UUID or score not found')
        elif self.status_code // 100 != 2:
            raise self._bad_status_exception

        self.result = PolyScore(self.result, polyswarm)


class EngineNamesResult(ApiResponse):
    def parse_result(self, result):
        super(EngineNamesResult, self).parse_result(result)
        self.result = self.json.get('results')
        self.result = dict([(engine.get('address').lower(), engine.get('name')) for engine in self.result])
