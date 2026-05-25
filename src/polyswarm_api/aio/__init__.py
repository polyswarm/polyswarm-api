"""Async PolySwarm API client package.

Re-exports the async client from :mod:`polyswarm_api.aio.api`. The package
layout mirrors the sync side: the class lives in ``aio/api.py``, not in
``__init__.py``.

``async_upload_file`` is re-exported here as a documented monkey-patch
site — see ``specs/05-downstream-contract.md``. Downstream code that
patches ``polyswarm_api.aio.async_upload_file`` keeps working.
"""

from polyswarm_api.aio.api import PolySwarmAsyncAPI
from polyswarm_api.aio.upload import async_upload_file

__all__ = ["PolySwarmAsyncAPI", "async_upload_file"]
