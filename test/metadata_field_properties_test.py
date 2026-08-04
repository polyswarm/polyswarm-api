"""Tests for the metadata_field_properties SDK methods.

Each test method runs twice — once against the sync ``PolyswarmAPI``
and once against the async ``PolySwarmAsyncAPI``. Both transports are
``httpx``-backed, so the HTTP boundary is mocked by ``respx`` in either
case. The parametrisation is automatic: ``ClientTestCase`` (shared harness
in ``test/_client_harness.py``) emits ``<Name>Sync`` and ``<Name>Async``
sibling classes for every subclass declared, and hides the base subclass
from pytest via ``__test__ = False``.
"""
from test._client_harness import BASE_URL, ClientTestCase


_RESOURCE_URL = f'{BASE_URL}/search/metadata/properties'


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

    def test_write_omits_unset_optionals(self):
        # 3.x dropped None-valued fields in _params; the 4.0 client must omit
        # unset optionals from the POST body too, not send explicit nulls.
        row = _sample_row()
        self.mock.add('POST', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        self.api.metadata_field_properties_write(
            field_path=row['field_path'],
            description=row['description'],
            example=row['example'],
            # category and aliases intentionally left unset (default None)
        )
        body = self.mock.last_request_body
        assert body['field_path'] == row['field_path']
        assert body['description'] == row['description']
        assert body['example'] == row['example']
        assert 'category' not in body, body
        assert 'aliases' not in body, body

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
