"""Shared infrastructure for the sync and async PolySwarm API clients.

The sync ``PolyswarmAPI`` (``polyswarm_api.api``) and async
``PolySwarmAsyncAPI`` (``polyswarm_api.aio``) both subclass
``PolyswarmAPIBase``. The base holds the constructor, instance state,
and (over time) every endpoint method as a one-line wrapper around
``self._single(...)`` or ``self._paginate(...)``. Sync subclass
implements those via the sync HTTP transport; async via the async one.

The trick that lets a single method body work for both: base methods
are regular ``def`` (not ``async def``) and ``return
self._single(...)``. Sync ``_single`` returns the parsed value; async
``_single`` returns a coroutine; the base method just passes that
through. Sync callers use the value directly, async callers ``await``
it. For paginated endpoints, the same applies with generators vs
async generators (``for`` / ``async for``).

This first PR lands the shared base + the response-parsing inheritance
(``AsyncPolyswarmRequest`` now inherits from ``PolyswarmRequest``) +
the metadata mapping/properties endpoints as a representative slice.
Bulk endpoint-method consolidation follows in subsequent PRs tracked
by DN-8225.
"""
from __future__ import annotations

import logging

from polyswarm_api import resources, settings

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

    _request_cls = None  # subclass sets to PolyswarmRequest / AsyncPolyswarmRequest

    def _coerce_request(self, request, result_parser=None, parser_kwargs=None):
        """Normalise the various inputs to ``_single`` / ``_paginate`` into
        a request instance of the subclass's ``_request_cls``.

        ``request`` is one of:

        * an unexecuted ``PolyswarmRequest`` returned by a resource
          classmethod (``resources.Foo.create(self, …)``) — rebuilt as
          the subclass's ``_request_cls`` so the right transport is used;
        * a request-parameters dict (legacy / inline endpoint bodies).
        """
        from polyswarm_api.core import PolyswarmRequest
        parser_kwargs = parser_kwargs or {}
        if isinstance(request, PolyswarmRequest):
            return self._request_cls(
                self,
                request.request_parameters,
                result_parser=request.result_parser,
                **request.parser_kwargs,
            )
        if isinstance(request, dict):
            return self._request_cls(
                self, request, result_parser=result_parser, **parser_kwargs,
            )
        raise TypeError(
            f'_single / _paginate expect a PolyswarmRequest or request-parameters '
            f'dict, got {type(request).__name__}',
        )

    # ── Shared endpoint surface ─────────────────────────────────────
    #
    # Each method is defined ONCE here and works for both sync and async
    # subclasses. The trick: bodies are sync-shaped (``return
    # self._single(...)``), and ``_single`` / ``_paginate`` are
    # overridden per subclass to return either a value/generator (sync)
    # or a coroutine/async generator (async). The caller awaits or
    # iterates over the result as appropriate.

    # ── Metadata ────────────────────────────────────────────────────

    def metadata_mapping(self):
        """Get available metadata field names and types.

        Sync: returns a ``MetadataMapping`` resource.
        Async: returns a coroutine; ``await`` it for the same.
        """
        logger.info('Retrieving the metadata mapping')
        return self._single(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataMapping.RESOURCE_ENDPOINT}'},
            result_parser=resources.MetadataMapping,
        )

    def metadata_field_properties_write(self, field_path, description,
                                        example=None, category=None, aliases=None):
        """Upsert a metadata field properties entry (the single write path).

        :param field_path: Dotted ES leaf path (e.g. 'polyunite.malware_family').
        :param description: Human-readable description of the field.
        :param example: Optional example search string.
        :param category: Optional category grouping the field belongs to.
        :param aliases: Optional list of friendly-name shortcuts.
        :return: A ``MetadataFieldProperties`` resource.
        """
        logger.info('Writing metadata field properties %s', field_path)
        return self._single(
            {'method': 'POST',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'json': {'field_path': field_path,
                      'description': description,
                      'example': example,
                      'category': category,
                      'aliases': aliases}},
            result_parser=resources.MetadataFieldProperties,
        )

    def metadata_field_properties_get(self, field_path):
        """Get a metadata field properties entry by ``field_path``."""
        logger.info('Getting metadata field properties %s', field_path)
        return self._single(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'params': {'field_path': field_path}},
            result_parser=resources.MetadataFieldProperties,
        )

    def metadata_field_properties_delete(self, field_path):
        """Delete a metadata field properties entry."""
        logger.info('Deleting metadata field properties %s', field_path)
        return self._single(
            {'method': 'DELETE',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'params': {'field_path': field_path}},
            result_parser=resources.MetadataFieldProperties,
        )

    def metadata_field_properties_list(self):
        """List all metadata field properties entries.

        Sync: returns a generator. Async: returns an async generator.
        Iterate with ``for`` or ``async for`` accordingly.
        """
        logger.info('Listing metadata field properties')
        return self._paginate(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}/list'},
            result_parser=resources.MetadataFieldProperties,
        )
