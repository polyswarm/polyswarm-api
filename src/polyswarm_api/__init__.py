# https://www.python.org/dev/peps/pep-0008/#module-level-dunder-names
__version__ = '4.4.0'
__release_url__ = 'https://api.github.com/repos/polyswarm/polyswarm-api/releases/latest'

from . import api
from . import exceptions
from .api import PolyswarmAPI
from .session import PolyswarmSession
from .aio import PolySwarmAsyncAPI, AsyncPolyswarmSession

__all__ = [
    'PolyswarmAPI',
    'PolyswarmSession',
    'PolySwarmAsyncAPI',
    'AsyncPolyswarmSession',
    '__version__',
]
