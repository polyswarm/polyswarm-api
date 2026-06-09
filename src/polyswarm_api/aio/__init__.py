"""Async PolySwarm API client package.

Re-exports the async client and session. The package layout mirrors
the sync side: classes live in ``aio/api.py`` and ``aio/session.py``,
not in ``__init__.py``.

The 4.0 surface:

- ``PolySwarmAsyncAPI`` — the async client.
- ``AsyncPolyswarmSession`` — the async transport. Subclass + inject
  via ``PolySwarmAsyncAPI(session=…)`` to customize HTTP behaviour.

See ``specs/05-downstream-contract.md`` for the contract and migration
notes from 3.x.
"""

from polyswarm_api.aio.api import PolySwarmAsyncAPI
from polyswarm_api.aio.session import AsyncPolyswarmSession

__all__ = [
    "PolySwarmAsyncAPI",
    "AsyncPolyswarmSession",
]
