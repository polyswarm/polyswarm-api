class PolyswarmAPIException(Exception):
    pass


class RequestFailedException(PolyswarmAPIException):
    pass


class BadFormatException(PolyswarmAPIException):
    pass


class ServerErrorException(PolyswarmAPIException):
    pass
