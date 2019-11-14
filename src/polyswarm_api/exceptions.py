class PolyswarmException(Exception):
    pass


#########################################
# API layer exceptions
#########################################

class PolyswarmAPIException(PolyswarmException):
    pass


class TimeoutException(PolyswarmAPIException):
    pass


#########################################
# Request layer exceptions
#########################################

class RequestFailedException(PolyswarmException):
    def __init__(self, request, *args, **kwargs):
        super(RequestFailedException, self).__init__(*args, **kwargs)
        self.request = request


class UsageLimitsExceededException(RequestFailedException):
    pass


class NotFoundException(RequestFailedException):
    pass


#########################################
# Types layer exceptions
#########################################


class TypeException(PolyswarmException):
    pass


class MissingAPIInstanceException(TypeException):
    pass


class InvalidJSONResponseException(TypeException):
    pass


class DecodeErrorException(TypeException):
    pass


class InvalidValueException(TypeException):
    pass


class ArtifactDeletedException(TypeException):
    pass


class InvalidYaraRulesException(TypeException):
    pass


class NotImportedException(TypeException):
    pass
