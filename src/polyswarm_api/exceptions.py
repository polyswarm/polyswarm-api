class PolyswarmAPIException(Exception):
    pass

#########################################
# Request layer exceptions
#########################################

class RequestFailedException(PolyswarmAPIException):
    def __init__(self, request, *args, **kwargs):
        super(RequestFailedException, self).__init__(*args, **kwargs)
        self.request = request


class UsageLimitsExceededException(RequestFailedException):
    pass


class BadFormatException(PolyswarmAPIException):
    pass


class ServerErrorException(PolyswarmAPIException):
    pass


class NotFoundException(RequestFailedException):
    pass


#########################################
# Types layer exceptions
#########################################


class TypeException(PolyswarmAPIException):
    pass


class InvalidHashException(TypeException):
    pass


class MissingAPIInstanceException(TypeException):
    pass


class InvalidJSONResponseException(TypeException):
    pass


class DecodeErrorException(TypeException):
    pass


class InvalidArgumentException(TypeException):
    pass


class ArtifactDeletedException(TypeException):
    pass


class InvalidYaraRulesException(TypeException):
    pass


class NotImportedException(TypeException):
    pass
