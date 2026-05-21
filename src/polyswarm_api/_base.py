"""Shared infrastructure for the sync and async PolySwarm API clients.

The sync ``PolyswarmAPI`` (``polyswarm_api.api``) and async
``PolySwarmAsyncAPI`` (``polyswarm_api.aio``) both subclass
``PolyswarmAPIBase``. The base holds the constructor, instance state,
and (over time) every endpoint method as a one-line wrapper around
``self._single(...)`` or ``self._paginate(...)``. Sync subclass
implements those via the sync HTTP transport; async via the async one.

This first PR lands the shared base + the response-parsing inheritance
(``AsyncPolyswarmRequest`` now inherits from ``PolyswarmRequest``).
Bulk endpoint-method consolidation follows in subsequent PRs tracked
by DN-8225.
"""
from __future__ import annotations

import logging

from polyswarm_api import settings

logger = logging.getLogger(__name__)


class PolyswarmAPIBase:
    """Shared base for ``PolyswarmAPI`` and ``PolySwarmAsyncAPI``.

    Holds the constructor signature, instance attributes (``uri``,
    ``community``, ``timeout``, ``session``), and the eventual single
    home for every endpoint method. Subclasses implement
    ``_single`` / ``_paginate`` / ``_sleep`` to plug the sync vs async
    HTTP transport in.

    Not instantiable directly — use ``polyswarm_api.PolyswarmAPI`` (sync)
    or ``polyswarm_api.aio.PolySwarmAsyncAPI`` (async).
    """

    def __init__(self, key, uri=None, community=None, timeout=None, verify=True, **kwargs):
        key_masked = '******' + (key[-4:] if key and len(key) > 16 else '')
        logger.info(
            'Creating %s instance | api-key: %s, api-uri: %s, community: %s',
            type(self).__name__, key_masked, uri, community,
        )
        self.uri = uri or settings.DEFAULT_GLOBAL_API
        self.community = community or settings.DEFAULT_COMMUNITY
        self.timeout = timeout or settings.DEFAULT_HTTP_TIMEOUT
        self.verify = verify
        self._engines = None
        # Subclasses set self.session.
        self.session = None

    def __repr__(self):
        clsname = f'{type(self).__module__}.{type(self).__name__}'
        attrs = f'uri={self.uri!r}, community={self.community!r}, timeout={self.timeout!r}'
        return f'<{clsname}({attrs}) at 0x{id(self):x}>'

    # ── Subclasses override these ────────────────────────────────────

    def _single(self, request):
        """Execute the (unexecuted) ``PolyswarmRequest`` and return its result.

        * Sync subclass: returns the value directly.
        * Async subclass: returns a coroutine yielding the value.
        """
        raise NotImplementedError

    def _paginate(self, request):
        """Execute the request and return an iterator over its results.

        * Sync subclass: returns a generator.
        * Async subclass: returns an async generator.
        """
        raise NotImplementedError

    def _sleep(self, seconds):
        """Block for ``seconds``. Sync uses ``time.sleep``; async ``asyncio.sleep``."""
        raise NotImplementedError
