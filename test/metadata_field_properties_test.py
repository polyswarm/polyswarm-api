"""Tests for the metadata_field_properties SDK methods.

Uses the `responses` library to mock the HTTP boundary, so these tests run
without needing a live artifact-index stack.
"""
import responses
from unittest import TestCase

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


class MetadataFieldPropertiesSyncTest(TestCase):
    def setUp(self):
        self.api = PolyswarmAPI('1' * 32, uri=_BASE_URL, community='gamma')

    @responses.activate
    def test_create(self):
        row = _sample_row()
        responses.add(
            responses.POST, _RESOURCE_URL,
            json={'result': row, 'status': 'OK'},
            status=200,
        )
        result = self.api.metadata_field_properties_create(
            field_path=row['field_path'],
            description=row['description'],
            example=row['example'],
            category=row['category'],
        )
        assert result.field_path == row['field_path']
        assert result.description == row['description']
        assert result.example == row['example']
        assert result.category == row['category']

    @responses.activate
    def test_get(self):
        row = _sample_row()
        responses.add(
            responses.GET, _RESOURCE_URL,
            json={'result': row, 'status': 'OK'},
            status=200,
        )
        result = self.api.metadata_field_properties_get(field_path=row['field_path'])
        assert result.field_path == row['field_path']
        # Verify the field_path is in the query string.
        request_url = responses.calls[0].request.url
        assert 'field_path=polyunite.malware_family' in request_url

    @responses.activate
    def test_update(self):
        row = _sample_row()
        row['description'] = 'new desc'
        responses.add(
            responses.PUT, _RESOURCE_URL,
            json={'result': row, 'status': 'OK'},
            status=200,
        )
        result = self.api.metadata_field_properties_update(
            field_path=row['field_path'],
            description='new desc',
        )
        assert result.description == 'new desc'
        request_url = responses.calls[0].request.url
        assert 'field_path=polyunite.malware_family' in request_url

    @responses.activate
    def test_delete(self):
        row = _sample_row()
        responses.add(
            responses.DELETE, _RESOURCE_URL,
            json={'result': row, 'status': 'OK'},
            status=200,
        )
        result = self.api.metadata_field_properties_delete(field_path=row['field_path'])
        assert result.field_path == row['field_path']

    @responses.activate
    def test_list(self):
        rows = [_sample_row('apkid.files.filename'), _sample_row('artifact.id')]
        responses.add(
            responses.GET, f'{_RESOURCE_URL}/list',
            json={'result': rows, 'status': 'OK'},
            status=200,
        )
        result = list(self.api.metadata_field_properties_list())
        assert len(result) == 2
        assert result[0].field_path == 'apkid.files.filename'
        assert result[1].field_path == 'artifact.id'
