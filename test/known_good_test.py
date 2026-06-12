"""Tests for the known_good SDK methods.

Each test runs twice — once against the sync ``PolyswarmAPI`` and once against the
async ``PolySwarmAsyncAPI`` — via the parametrised ``ClientTestCase`` harness
(reused from metadata_field_properties_test). The HTTP boundary is mocked by
``respx`` for both transports.
"""
from test.metadata_field_properties_test import ClientTestCase

_BASE_URL = 'http://localhost:9696/v3'
_RESOURCE_URL = f'{_BASE_URL}/known-good'

SHA = 'a' * 64


def _sample_row(sha256=SHA, sources=None):
    return {
        'id': '12345678901234567',
        'sha256': sha256,
        'artifact_instance_id': '98765432109876543',
        'sources': sources if sources is not None else ['nsrl'],
        'created': '2026-06-11T00:00:00',
    }


class KnownGoodTestCase(ClientTestCase):
    def test_create(self):
        row = _sample_row()
        self.mock.add('POST', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        result = self.api.known_good_create(sha256=SHA, source='nsrl')
        assert result.sha256 == SHA
        assert result.sources == ['nsrl']
        assert result.artifact_instance_id == '98765432109876543'
        body = self.mock.last_request_body
        assert body['sha256'] == SHA
        assert body['source'] == 'nsrl'
        # community rides in the POST body (the server reads it from query OR json)
        assert body['community'] == 'gamma'

    def test_create_omits_unset_optionals(self):
        row = _sample_row()
        self.mock.add('POST', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        self.api.known_good_create(sha256=SHA, source='nsrl')
        body = self.mock.last_request_body
        for optional in ('sha1', 'md5', 'filename', 'mimetype', 'metadata'):
            assert optional not in body, body

    def test_create_with_metadata_and_hashes(self):
        row = _sample_row()
        self.mock.add('POST', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        self.api.known_good_create(
            sha256=SHA, source='winget', sha1='b' * 40, md5='c' * 32,
            filename='setup.exe', mimetype='application/x-dosexec',
            metadata={'product': 'Example'})
        body = self.mock.last_request_body
        assert body['source'] == 'winget'
        assert body['sha1'] == 'b' * 40
        assert body['md5'] == 'c' * 32
        assert body['filename'] == 'setup.exe'
        assert body['mimetype'] == 'application/x-dosexec'
        assert body['metadata'] == {'product': 'Example'}

    def test_get(self):
        row = _sample_row(sources=['nsrl', 'winget'])
        self.mock.add('GET', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        result = self.api.known_good_get(sha256=SHA)
        assert result.sha256 == SHA
        assert result.sources == ['nsrl', 'winget']
        url = self.mock.last_request_url
        assert f'sha256={SHA}' in url
        assert 'community=gamma' in url

    def test_delete(self):
        self.mock.add('DELETE', _RESOURCE_URL, json={'result': {'sha256': SHA, 'deleted': True}, 'status': 'OK'})
        result = self.api.known_good_delete(sha256=SHA)
        assert result.sha256 == SHA
        # delete is by sha256 (query string) — the same key used to retrieve, routed
        # by the base _delete_params via RESOURCE_ID_KEYS=['sha256'] with no override
        # and no community/body involved.
        url = self.mock.last_request_url
        assert f'sha256={SHA}' in url
        assert 'community=' not in url
        # delete carries no request body — sha256 rides entirely in the query string
        assert self.mock.last_request_body is None
