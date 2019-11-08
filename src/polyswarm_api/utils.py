import logging

logger = logging.getLogger(__name__)

# TODO this is a hack around bad behavior in API. Fix this in AI.
bool_to_int = {True: 1, False: ""}


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]
