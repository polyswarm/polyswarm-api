import logging
import os
import os.path

from .base import BasePSJSONType
from .models import Submission, PolyScore, ArtifactInstance, ArtifactArchive
from polyswarm_api.types.local import LocalArtifact
from polyswarm_api.types.models import Hunt, HuntResult

from . import schemas
from .. import const


logger = logging.getLogger(__name__)


class ApiResponse(BasePSJSONType):
    """ The base API response class. All results from PolyswarmAPI are subclasses of this """
    SCHEMA = schemas.api_response_schema

    def __init__(self, *args, **kwargs):
        super(ApiResponse, self).__init__(*args, **kwargs)
        self.failed = False
        self.failure_reason = ''

    def parse_result(self, result):
        raise NotImplementedError()

    def _set_failure(self, reason='Unspecified error occurred'):
        self.failed = True
        self.failure_reason = reason


class DownloadParser(ApiResponse):
    """ This is an artificially constructed result object, to track downloads. """
    def __init__(self, output_file, file_handle=None, polyswarm=None, create=False):
        super(DownloadParser, self).__init__(polyswarm=polyswarm)
        self.output_file = output_file
        self.file_handle = file_handle
        self.create = create

    def parse_result(self, result):
        path, file_name = os.path.split(self.output_file)
        parsed_result = LocalArtifact(path=self.output_file, artifact_name=file_name, analyze=False, polyswarm=self)

        if self.file_handle:
            for chunk in result.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
                self.file_handle.write(chunk)
        else:
            if self.create:
                # TODO: this should be replaced with os.makedirs(path, exist_ok=True)
                # once we drop support to python 2.7
                if not os.path.exists(path):
                    os.makedirs(path)
            with open(self.output_file, 'wb') as file_handle:
                for chunk in result.iter_content(chunk_size=const.DOWNLOAD_CHUNK_SIZE):
                    file_handle.write(chunk)
        return parsed_result


class SearchParser(ApiResponse):
    """ This is a result object for representing searches """
    def __init__(self, query, polyswarm=None):
        super(SearchParser, self).__init__(polyswarm)
        self.query = query

    def parse_result(self, result):
        return [ArtifactInstance(j, self.polyswarm) for j in result]


class SubmitParser(ApiResponse):
    def __init__(self, polyswarm=None):
        super(SubmitParser, self).__init__(polyswarm=polyswarm)

    def parse_result(self, result):
        parsed_result = Submission(result, polyswarm=self.polyswarm)

        if not parsed_result.uuid:
            self._set_failure('Did not get a UUID for scan.')
        elif parsed_result.failed:
            self._set_failure('Bounty creation failed for submission {}. '
                              'Please resubmit.'.format(parsed_result.uuid))
        return parsed_result


class HuntParser(ApiResponse):
    def parse_result(self, result):
        return Hunt(result, self.polyswarm)


class HuntListParser(ApiResponse):
    def parse_result(self, result):
        return [Hunt(r, self.polyswarm) for r in result]


class HuntResultListParser(ApiResponse):
    def parse_result(self, result):
        return [HuntResult(r, self.polyswarm) for r in result]


class HuntDeletionParser(ApiResponse):
    def parse_result(self, result):
        return result['hunt_id']


class StreamParser(ApiResponse):
    def parse_result(self, result):
        return [ArtifactArchive(r, self.polyswarm) for r in result]


class ScoreParser(ApiResponse):
    def parse_result(self, result):
        return PolyScore(result, self.polyswarm)


class EngineNamesParser(ApiResponse):
    def parse_result(self, result):
        return dict([(engine.get('address').lower(), engine.get('name')) for engine in result])
