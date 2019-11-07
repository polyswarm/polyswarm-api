class PolyswarmAPIException(Exception):
    pass


class RequestFailedException(PolyswarmAPIException):
    def __init__(self, request, *args, **kwargs):
        super(RequestFailedException, self).__init__(*args, **kwargs)
        self.request = request


class UsageLimitsExceeded(RequestFailedException):
    pass


class BadFormatException(PolyswarmAPIException):
    pass


class ServerErrorException(PolyswarmAPIException):
    pass


class InvalidHashException(PolyswarmAPIException):
    pass


class NotFoundException(PolyswarmAPIException):
    pass


class MissingAPIInstance(PolyswarmAPIException):
    pass


class InvalidJSONResponse(PolyswarmAPIException):
    pass


class DecodeError(PolyswarmAPIException):
    pass


class InvalidArgument(PolyswarmAPIException):
    pass


class ArtifactDeleted(PolyswarmAPIException):
    pass


class InvalidYaraRules(PolyswarmAPIException):
    pass


class NotImportedException(PolyswarmAPIException):
    pass
