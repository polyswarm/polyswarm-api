"""Tests for the metadata_field_properties SDK methods.

Each test method runs twice — once against the sync ``PolyswarmAPI``
(HTTP boundary mocked by ``responses``) and once against the async
``PolySwarmAsyncAPI`` (HTTP boundary mocked by ``respx``). The
parametrisation is automatic: ``ClientTestCase`` 's ``__init_subclass__``
hook emits ``<Name>Sync`` and ``<Name>Async`` sibling classes for every
subclass declared. The base subclass is hidden from pytest via
``__test__ = False``.
"""
import asyncio
from unittest import TestCase

import httpx
import respx
import responses

from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api.api import PolyswarmAPI


_BASE_URL = 'http://localhost:9696/v3'
_RESOURCE_URL = f'{_BASE_URL}/search/metadata/properties'


def _sample_row(field_path='polyunite.malware_family'):
    return {
        'field_path': field_path,
        'description': 'Identified malware family',
        'example': 'polyunite.malware_family:lockbit',
        'category': 'polyunite',
        'aliases': None,
        'created': '2026-05-20T00:00:00',
        'updated': '2026-05-20T00:00:00',
    }


# ── Per-test mocking + client construction harness ───────────────────


class _MockBoundary:
    """Register the same expected HTTP exchanges with both ``responses``
    (for the sync ``requests`` transport) and ``respx`` (for the async
    ``httpx`` transport). Tests call ``add(method, url, json=...,
    status=...)``; the harness routes it to whichever mock matches the
    current client kind.
    """

    def __init__(self, client_kind: str):
        self.client_kind = client_kind
        self._respx_router = respx.mock(assert_all_called=False) if client_kind == 'async' else None
        self._calls = []  # list of (method, url) for tests that assert on call URLs

    def __enter__(self):
        if self.client_kind == 'sync':
            self._responses = responses.RequestsMock(assert_all_requests_are_fired=False)
            self._responses.start()
        else:
            self._respx_router.start()
        return self

    def __exit__(self, *exc):
        if self.client_kind == 'sync':
            self._responses.stop()
            self._responses.reset()
        else:
            self._respx_router.stop()
            self._respx_router.reset()

    def add(self, method: str, url: str, json: dict, status: int = 200):
        if self.client_kind == 'sync':
            self._responses.add(method, url, json=json, status=status)
        else:
            self._respx_router.route(method=method, url=url).mock(
                return_value=httpx.Response(status, json=json),
            )

    @property
    def last_request_url(self) -> str:
        if self.client_kind == 'sync':
            return self._responses.calls[0].request.url
        return str(self._respx_router.calls[0].request.url)


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
            self.api = PolyswarmAPI('1' * 32, uri=_BASE_URL, community='gamma')
        else:
            self.api = _AsyncToSync(
                PolySwarmAsyncAPI('1' * 32, uri=_BASE_URL, community='gamma'),
            )
        self.mock = _MockBoundary(self._client_kind)
        self.mock.__enter__()

    def tearDown(self):
        self.mock.__exit__(None, None, None)


# ── Tests ────────────────────────────────────────────────────────────


class MetadataFieldPropertiesTestCase(ClientTestCase):
    def test_write(self):
        row = _sample_row()
        self.mock.add('POST', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        result = self.api.metadata_field_properties_write(
            field_path=row['field_path'],
            description=row['description'],
            example=row['example'],
            category=row['category'],
        )
        assert result.field_path == row['field_path']
        assert result.description == row['description']
        assert result.example == row['example']
        assert result.category == row['category']

    def test_get(self):
        row = _sample_row()
        self.mock.add('GET', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        result = self.api.metadata_field_properties_get(field_path=row['field_path'])
        assert result.field_path == row['field_path']
        assert 'field_path=polyunite.malware_family' in self.mock.last_request_url

    def test_delete(self):
        row = _sample_row()
        self.mock.add('DELETE', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        result = self.api.metadata_field_properties_delete(field_path=row['field_path'])
        assert result.field_path == row['field_path']

    def test_list(self):
        rows = [_sample_row('apkid.files.filename'), _sample_row('artifact.id')]
        self.mock.add('GET', f'{_RESOURCE_URL}/list', json={'result': rows, 'status': 'OK'})
        result = list(self.api.metadata_field_properties_list())
        assert len(result) == 2
        assert result[0].field_path == 'apkid.files.filename'
        assert result[1].field_path == 'artifact.id'
