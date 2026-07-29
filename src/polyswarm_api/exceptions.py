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


def _normalise_sources(sources):
    """Coerce a server-supplied ``sources`` payload into a list of feed names.

    ``.sources`` is published as a list of strings and consumers iterate it
    (``for feed in exc.sources``), so the raw payload can't be handed through
    untouched: a bare ``'nsrl'`` would iterate as characters, and the
    list-of-feed-dicts shape the instance-level ``known_good`` field uses would
    yield dicts. A string becomes a one-element list, a list keeps only its
    string entries, and any other shape (mapping, ``None``, number) becomes
    ``[]``. Nothing is lost — the raw envelope stays readable at
    ``exc.request.errors``.
    """
    if isinstance(sources, str):
        return [sources]
    if isinstance(sources, list):
        return [source for source in sources if isinstance(source, str)]
    return []


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
        # Known-good feeds that flagged the hash (e.g. ``['nsrl']``); always a list
        # of strings — normalised here, at the boundary, so the documented shape
        # holds whatever the envelope carried. Empty when the server named none.
        self.sources = _normalise_sources(sources)


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
