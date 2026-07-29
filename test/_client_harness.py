"""The parametrised ``ClientTestCase`` harness for the respx-mocked tier.

Shared by every respx test module (see specs/04-testing.md, invariant 5): one
test body runs against **both** transports, because ``__init_subclass__`` emits
``<Name>Sync`` and ``<Name>Async`` siblings for each subclass. That's what keeps
the mocked tier from growing parallel sync / async bodies — and what keeps the
generated sync mirrors (``session.py`` / ``api.py``) covered by the same
assertions as their canonical async sources.

Not collected by pytest itself (``python_files`` only matches ``*_test.py`` /
``test_*.py``), same as ``_e2e_helpers.py``. ``metadata_field_properties_test.py``
is the canonical example of using it.
"""
import asyncio
import json
from unittest import TestCase

import httpx
import respx

from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api.api import PolyswarmAPI


BASE_URL = 'http://localhost:9696/v3'
API_KEY = '1' * 32
COMMUNITY = 'gamma'


class _MockBoundary:
    """Register expected HTTP exchanges via ``respx``. Both sync and
    async clients now run on httpx, so a single mock library covers
    both. Tests call ``add(method, url, json=..., status=...)``.
    """

    def __init__(self, client_kind: str):
        self.client_kind = client_kind
        self._router = respx.mock(assert_all_called=False)

    def __enter__(self):
        self._router.start()
        return self

    def __exit__(self, *exc):
        self._router.stop()
        self._router.reset()

    def add(self, method: str, url: str, json: dict, status: int = 200):
        self._router.route(method=method, url=url).mock(
            return_value=httpx.Response(status, json=json),
        )

    @property
    def last_request_url(self) -> str:
        return str(self._router.calls[0].request.url)

    @property
    def last_request_body(self):
        """The JSON body of the most recent request (None if it carried none)."""
        content = self._router.calls[-1].request.content
        return json.loads(content) if content else None


class _AsyncToSync:
    """Run async client methods from sync test bodies via ``asyncio.run``.

    Each attribute access returns a sync callable that drives the
    matching async method on a fresh event loop per call — keeps the
    unittest-style test bodies unchanged.
    """

    def __init__(self, async_api: PolySwarmAsyncAPI):
        self._api = async_api

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        attr = getattr(self._api, name)

        def sync_call(*args, **kwargs):
            result = attr(*args, **kwargs)
            if asyncio.iscoroutine(result):
                return asyncio.run(result)
            # Async generator → drain it.
            async def _drain():
                return [item async for item in result]
            return asyncio.run(_drain())

        return sync_call


class ClientTestCase(TestCase):
    """Base test case. Each subclass is auto-replaced by ``<Name>Sync``
    and ``<Name>Async`` siblings so every test method runs once against
    each client. The original subclass is hidden from pytest.
    """

    _client_kind = 'sync'

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, '_client_kind_variant', False):
            return
        import sys
        module = sys.modules.get(cls.__module__)
        if module is None:
            return
        cls.__test__ = False
        for label, kind in (('Sync', 'sync'), ('Async', 'async')):
            variant_name = f'{cls.__name__}{label}'
            variant = type(variant_name, (cls,), {
                '_client_kind': kind,
                '_client_kind_variant': True,
                '__test__': True,
                '__module__': cls.__module__,
                '__qualname__': variant_name,
            })
            setattr(module, variant_name, variant)

    def setUp(self):
        if self._client_kind == 'sync':
            self.api = PolyswarmAPI(API_KEY, uri=BASE_URL, community=COMMUNITY)
        else:
            self.api = _AsyncToSync(
                PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community=COMMUNITY),
            )
        self.mock = _MockBoundary(self._client_kind)
        self.mock.__enter__()

    def tearDown(self):
        self.mock.__exit__(None, None, None)
