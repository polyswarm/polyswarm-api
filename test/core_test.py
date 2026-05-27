"""Pure-unit tests for the 4.0 core module.

No httpx, no async, no fixtures. Covers:

- ``PolyswarmRequest`` dataclass construction and projections.
- ``parse_response`` against fake response objects (HEAD, 2xx with
  parser, 2xx without parser, 204, 404, 422, 429, 500, non-JSON 5xx,
  non-JSON 404).
- A sampling of resource builders to confirm they produce the expected
  ``PolyswarmRequest`` shape.

These tests run in microseconds and don't break when the test framework
changes (respx, VCR). They're the first line of defence for the SDK's
description + parsing layer.
"""

import json
import pytest

from polyswarm_api import exceptions, resources
from polyswarm_api.core import (
    BaseJsonResource,
    HttpxResponseAdapter,
    PolyswarmRequest,
    is_valid_md5,
    is_valid_sha1,
    is_valid_sha256,
    parse_response,
)


SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'


class _FakeApi:
    uri = 'https://api.example.test'
    community = 'gamma'


class _FakeResponse:
    """Minimal stand-in for httpx.Response that ``parse_response`` reads."""

    def __init__(self, status_code=200, body=None, headers=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}

    def json(self):
        if isinstance(self._body, (bytes, str)):
            return json.loads(self._body)
        return self._body


# ── PolyswarmRequest dataclass ─────────────────────────────────────


class TestPolyswarmRequest:
    def test_minimal_construction(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='https://x/y')
        assert req.method == 'GET'
        assert req.url == 'https://x/y'
        assert req.params is None
        assert req.result_parser is None
        assert req.status_code is None
        assert req._result is None

    def test_to_httpx_kwargs_omits_none(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u')
        assert req.to_httpx_kwargs() == {}

    def test_to_httpx_kwargs_includes_present_fields(self):
        req = PolyswarmRequest(
            api=_FakeApi(),
            method='POST',
            url='u',
            params={'a': 1},
            json={'k': 'v'},
            headers={'X': 'y'},
            timeout=30,
        )
        kwargs = req.to_httpx_kwargs()
        assert kwargs == {
            'params': {'a': 1},
            'json': {'k': 'v'},
            'headers': {'X': 'y'},
            'timeout': 30,
        }

    def test_to_httpx_kwargs_normalises_bools_in_params(self):
        req = PolyswarmRequest(
            api=_FakeApi(), method='GET', url='u',
            params={'flag': True, 'other': False, 'n': 1},
        )
        assert req.to_httpx_kwargs()['params'] == {
            'flag': 'True', 'other': 'False', 'n': 1,
        }

    def test_suppressed_headers(self):
        req = PolyswarmRequest(
            api=_FakeApi(), method='GET', url='u',
            headers={'Authorization': None, 'X-Keep': 'yes'},
        )
        assert req.suppressed_headers() == {'Authorization'}
        # to_httpx_kwargs strips the None-valued header
        assert req.to_httpx_kwargs()['headers'] == {'X-Keep': 'yes'}

    def test_suppressed_headers_empty_when_no_none(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               headers={'X': 'y'})
        assert req.suppressed_headers() == set()

    def test_data_and_files_passthrough(self):
        req = PolyswarmRequest(
            api=_FakeApi(), method='POST', url='u',
            data={'form': 'value'},
            files={'file': ('name', b'bytes')},
        )
        kw = req.to_httpx_kwargs()
        assert kw['data'] == {'form': 'value'}
        assert kw['files'] == {'file': ('name', b'bytes')}

    def test_content_passthrough(self):
        req = PolyswarmRequest(api=_FakeApi(), method='PUT', url='u',
                               content=b'raw-bytes')
        assert req.to_httpx_kwargs()['content'] == b'raw-bytes'

    def test_input_json_is_snapshotted_at_construction(self):
        # `parse_response` overwrites `.json` with the response body
        # (legacy 3.x semantics). `_next_page` clones the descriptor
        # for pagination — it must use the original send-body snapshot,
        # not the post-execute `.json`, or the next-page GET would
        # ship the previous page's response body as a request body.
        original_body = {'send': 'me'}
        req = PolyswarmRequest(api=_FakeApi(), method='POST', url='u',
                               json=original_body)
        assert req._input_json == original_body
        # Simulate parse_response overwriting .json with the response.
        req.json = {'result': [], 'has_more': False}
        # _input_json is unaffected.
        assert req._input_json == original_body


# ── parse_response — happy paths ───────────────────────────────────


class _SampleResource(BaseJsonResource):
    """Minimal JSON-resource for parsing tests."""

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.id = content.get('id')
        self.value = content.get('value')


class TestParseResponse:
    def test_head_2xx_sets_result_to_status_code(self):
        req = PolyswarmRequest(api=_FakeApi(), method='HEAD', url='u')
        parse_response(_FakeResponse(status_code=200), req)
        assert req.status_code == 200
        assert req._result == 200

    def test_head_404_does_not_raise(self):
        # HEAD: status code IS the result; 404 must not raise so callers
        # like ``exists_hash`` can read "absent" without try/except.
        req = PolyswarmRequest(api=_FakeApi(), method='HEAD', url='u')
        parse_response(_FakeResponse(status_code=404), req)
        assert req._result == 404

    def test_2xx_without_parser_is_fire_and_forget(self):
        # No result_parser → body intentionally discarded (e.g. Webhook.test)
        req = PolyswarmRequest(api=_FakeApi(), method='POST', url='u')
        parse_response(_FakeResponse(status_code=200, body={'status': 'OK'}), req)
        assert req.status_code == 200
        assert req._result is None  # parser is None, body discarded

    def test_2xx_json_resource_single_result(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               result_parser=_SampleResource)
        body = {'status': 'OK', 'result': {'id': 1, 'value': 'a'}}
        parse_response(_FakeResponse(status_code=200, body=body), req)
        assert isinstance(req._result, _SampleResource)
        assert req._result.id == 1
        assert req._result.value == 'a'
        # The ``.json`` field is overwritten with the response body.
        assert req.json == body

    def test_2xx_json_resource_list_results(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               result_parser=_SampleResource)
        body = {
            'status': 'OK',
            'result': [{'id': 1, 'value': 'a'}, {'id': 2, 'value': 'b'}],
            'has_more': False,
            'total': 2,
            'limit': 50,
            'offset': 0,
        }
        parse_response(_FakeResponse(status_code=200, body=body), req)
        assert len(req._result) == 2
        assert req._paginated is True
        assert req.total == 2
        assert req.limit == 50
        assert req.offset == 0
        assert req.has_more is False

    def test_2xx_alternate_results_key(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               result_parser=_SampleResource)
        body = {'status': 'OK', 'results': [{'id': 1}]}
        parse_response(_FakeResponse(status_code=200, body=body), req)
        assert len(req._result) == 1

    def test_2xx_missing_result_key_raises(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               result_parser=_SampleResource)
        with pytest.raises(exceptions.RequestException):
            parse_response(
                _FakeResponse(status_code=200, body={'status': 'OK'}),
                req,
            )


# ── parse_response — error paths ───────────────────────────────────


class TestParseResponseErrors:
    def test_404_raises_not_found(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               result_parser=_SampleResource)
        with pytest.raises(exceptions.NotFoundException) as ei:
            parse_response(
                _FakeResponse(status_code=404, body={'status': 'fail',
                                                    'result': 'missing'}),
                req,
            )
        assert ei.value.request is req

    def test_422_raises_failed_instance(self):
        req = PolyswarmRequest(api=_FakeApi(), method='POST', url='u',
                               result_parser=_SampleResource)
        with pytest.raises(exceptions.FailedInstanceException):
            parse_response(
                _FakeResponse(status_code=422, body={'status': 'fail',
                                                    'result': 'bad input'}),
                req,
            )

    def test_429_raises_usage_limits(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               result_parser=_SampleResource)
        with pytest.raises(exceptions.UsageLimitsExceededException):
            parse_response(
                _FakeResponse(status_code=429, body={'status': 'fail',
                                                    'result': 'slow down'}),
                req,
            )

    def test_500_raises_request_exception(self):
        req = PolyswarmRequest(api=_FakeApi(), method='POST', url='u',
                               result_parser=_SampleResource)
        with pytest.raises(exceptions.RequestException):
            parse_response(
                _FakeResponse(status_code=500, body={'status': 'error',
                                                    'result': 'boom'}),
                req,
            )

    def test_500_raises_even_without_parser(self):
        # Regression: fire-and-forget endpoints (no result_parser) must
        # still surface non-2xx as exceptions, not swallow them.
        req = PolyswarmRequest(api=_FakeApi(), method='POST', url='u')
        with pytest.raises(exceptions.RequestException):
            parse_response(
                _FakeResponse(status_code=500, body={'status': 'error',
                                                    'result': 'boom'}),
                req,
            )

    def test_204_with_parser_raises_no_results(self):
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               result_parser=_SampleResource)
        with pytest.raises(exceptions.NoResultsException):
            parse_response(
                _FakeResponse(status_code=204, body=None),
                req,
            )

    def test_404_non_json_body(self):
        # JSONDecodeError + 404 → NotFoundException (endpoint doesn't exist).
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               result_parser=_SampleResource)
        bad_response = _FakeResponse(status_code=404, body=b'<html>404</html>')
        with pytest.raises(exceptions.NotFoundException):
            parse_response(bad_response, req)

    def test_500_non_json_body(self):
        # JSONDecodeError + non-404 → RequestException with diagnostic.
        req = PolyswarmRequest(api=_FakeApi(), method='GET', url='u',
                               result_parser=_SampleResource)
        bad_response = _FakeResponse(status_code=500, body=b'gateway timeout')
        with pytest.raises(exceptions.RequestException):
            parse_response(bad_response, req)


# ── Resource builders ──────────────────────────────────────────────


class TestResourceBuilders:
    """Sampling of builders across the resource domains, asserting the
    PolyswarmRequest shape they produce. Pure data — no execution.
    """

    def test_artifact_instance_exists_hash(self):
        api = _FakeApi()
        req = resources.ArtifactInstance.exists_hash(api, SHA256, 'sha256')
        assert req.method == 'HEAD'
        assert req.url == f'{api.uri}/search/hash/sha256'
        assert req.params == {
            'hash': SHA256, 'community': api.community,
            'require_scan': 'false',
        }
        assert req.result_parser is None  # exists is HEAD, no parser

    def test_artifact_instance_search_hash(self):
        api = _FakeApi()
        req = resources.ArtifactInstance.search_hash(api, SHA256, 'sha256')
        assert req.method == 'GET'
        assert req.url == f'{api.uri}/search/hash/sha256'
        assert req.result_parser is resources.ArtifactInstance

    def test_artifact_instance_rescan_carries_scan_config_in_data(self):
        api = _FakeApi()
        req = resources.ArtifactInstance.rescan(api, SHA256, 'sha256',
                                                scan_config='more-time')
        assert req.method == 'POST'
        assert req.data == {'community': api.community,
                            'scan-config': 'more-time'}

    def test_ioc_iocs_by_hash_picks_path_on_beta(self):
        api = _FakeApi()
        std = resources.IOC.iocs_by_hash(api, SHA256, 'sha256')
        beta = resources.IOC.iocs_by_hash(api, SHA256, 'sha256', beta=True)
        assert std.url == f'{api.uri}/ioc/sha256/{SHA256}'
        assert beta.url == f'{api.uri}/ioc-beta/sha256/{SHA256}'

    def test_local_artifact_download_archive_strips_auth(self):
        # ``Authorization: None`` is the "suppress for this request"
        # sentinel — the session honours it for off-domain downloads.
        api = _FakeApi()
        req = resources.LocalArtifact.download_archive(api, 'https://s3/x')
        assert req.method == 'GET'
        assert req.url == 'https://s3/x'
        assert req.headers == {'Authorization': None}
        assert req.suppressed_headers() == {'Authorization'}

    def test_local_artifact_download_threads_parser_kwargs(self):
        api = _FakeApi()
        req = resources.LocalArtifact.download(
            api, SHA256, 'sha256', folder='/tmp/x',
        )
        assert req.parser_kwargs['folder'] == '/tmp/x'
        assert req.parser_kwargs['handle'] is None

    def test_webhook_test_uses_post_with_id_param(self):
        api = _FakeApi()
        req = resources.Webhook.test(api, 'wh-123')
        assert req.method == 'POST'
        assert req.url.endswith('/notification/webhook/test')
        assert req.params == {'id': 'wh-123'}
        # No parser — fire-and-forget endpoint.
        assert req.result_parser is None

    def test_basejsonresource_get_delete_list_create_update(self):
        # The generic CRUD builders on BaseJsonResource should produce
        # the right method/url for any subclass that defines
        # RESOURCE_ENDPOINT.
        api = _FakeApi()
        endpoint = resources.LLMPromptConfig.RESOURCE_ENDPOINT
        assert resources.LLMPromptConfig.list(api).method == 'GET'
        assert resources.LLMPromptConfig.list(api).url.endswith(endpoint + '/list')
        assert resources.LLMPromptConfig.create(api, name='n').method == 'POST'
        assert resources.LLMPromptConfig.get(api, id='1').method == 'GET'
        assert resources.LLMPromptConfig.update(api, id='1', name='n').method == 'PUT'
        assert resources.LLMPromptConfig.delete(api, id='1').method == 'DELETE'


# ── Helpers ────────────────────────────────────────────────────────


class TestHashValidators:
    def test_sha256(self):
        assert is_valid_sha256(SHA256) is True
        assert is_valid_sha256(SHA256[:-1]) is False
        assert is_valid_sha256('z' * 64) is False

    def test_sha1(self):
        assert is_valid_sha1('a' * 40) is True
        assert is_valid_sha1('a' * 39) is False

    def test_md5(self):
        assert is_valid_md5('a' * 32) is True
        assert is_valid_md5('a' * 31) is False


class TestHttpxResponseAdapter:
    def test_iter_content_single_chunk(self):
        class _R:
            status_code = 200
            headers = {}
            url = 'u'
            content = b'short'
        a = HttpxResponseAdapter(_R())
        assert list(a.iter_content(64)) == [b'short']

    def test_iter_content_multi_chunks(self):
        class _R:
            status_code = 200
            headers = {}
            url = 'u'
            content = b'01234567'
        a = HttpxResponseAdapter(_R())
        assert list(a.iter_content(3)) == [b'012', b'345', b'67']

    def test_json(self):
        class _R:
            status_code = 200
            headers = {}
            url = 'u'
            content = b'{"k": 1}'
        a = HttpxResponseAdapter(_R())
        assert a.json() == {'k': 1}
