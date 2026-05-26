"""Async PolySwarm API client package.

Re-exports the async client from :mod:`polyswarm_api.aio.api`. The
package layout mirrors the sync side: the class lives in ``aio/api.py``,
not in ``__init__.py``.

The other re-exports below preserve the import surface that the
develop-branch ``aio/__init__.py`` exposed before the codegen split, so
downstream callers (and monkey-patches) that imported any of these from
``polyswarm_api.aio`` keep working without change.
"""

from polyswarm_api.aio.api import PolySwarmAsyncAPI
from polyswarm_api.aio.core import AsyncPolyswarmRequest, AsyncPolyswarmSession
from polyswarm_api.aio.upload import async_upload_file, async_upload_logo

__all__ = [
    "PolySwarmAsyncAPI",
    "AsyncPolyswarmRequest",
    "AsyncPolyswarmSession",
    "async_upload_file",
    "async_upload_logo",
]
