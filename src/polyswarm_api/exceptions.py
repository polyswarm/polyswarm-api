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

class RequestException(PolyswarmException):
    def __init__(self, request, *args):
        super().__init__(*args)
        self.request = request


class UsageLimitsExceededException(RequestException):
    pass


class NotFoundException(RequestException):
    pass


class KnownGoodWithheldException(NotFoundException):
    """404 for a known-good binary: the platform never stores or serves its bytes.

    Subclasses ``NotFoundException`` so every existing ``except NotFoundException``
    handler keeps working unchanged; catch this subclass only when the caller wants
    to tell "withheld by design" apart from a plain "not found". The metadata the
    platform holds about the artifact is still readable through the search /
    instance endpoints.
    """

    def __init__(self, request, *args, sources=None):
        super().__init__(request, *args)
        # Known-good feeds that flagged the hash (e.g. ``['nsrl']``); empty list
        # when the server named none.
        self.sources = sources or []


class NoResultsException(RequestException):
    pass


class FailedInstanceException(RequestException):
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


#########################################
# Warnings
#########################################

class APIWarning(Warning):
    pass
