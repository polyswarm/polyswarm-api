"""Async PolySwarm API client package.

Re-exports the async client from :mod:`polyswarm_api.aio.api`. The package
layout mirrors the sync side: the class lives in ``aio/api.py``, not in
``__init__.py``.
"""

from polyswarm_api.aio.api import PolySwarmAsyncAPI

__all__ = ["PolySwarmAsyncAPI"]
