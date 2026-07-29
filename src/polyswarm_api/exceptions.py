import logging

logger = logging.getLogger(__name__)


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
    untouched: a bare ``'nsrl'`` would iterate as characters.

    Both shapes the platform uses for this one concept yield feed names. The
    error envelope sends a list of strings; the instance-level ``known_good``
    field sends a list of feed dicts, which ``resources.py`` unpacks via
    ``feed['tool']`` into ``ArtifactInstance.known_good_sources``. If the
    envelope ever reuses that serialiser, dropping the dicts would empty
    ``.sources`` and take this exception's whole added value with it — with no
    diagnostic, and no way for a caller to tell "the server named no feeds"
    from "the server named feeds in a shape we discarded".

    A string becomes a one-element list; anything else (mapping, ``None``,
    number) becomes ``[]`` — and says so at debug level, because the argument
    above cuts both ways: a discard nobody can see is the failure mode this
    normalisation exists to avoid. Nothing is lost either way — the raw envelope
    stays readable at ``exc.request.errors``.
    """
    if isinstance(sources, str):
        return [sources]
    if isinstance(sources, list):
        names = []
        for source in sources:
            if isinstance(source, str):
                names.append(source)
            elif isinstance(source, dict) and isinstance(source.get('tool'), str):
                names.append(source['tool'])
            else:
                logger.debug('Dropping unrecognised known-good sources entry: %r', source)
        return names
    if sources is not None:
        logger.debug('Dropping unrecognised known-good sources payload: %r', sources)
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
