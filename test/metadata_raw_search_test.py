"""Pure-unit tests for the ``metadata_raw_search`` builder and its parse.

Request-shape assertions belong in this tier rather than respx
(``specs/04-testing.md`` invariant 7): ``MetadataRawSearch.search`` is pure
data, so the body-vs-query routing reads straight off the ``PolyswarmRequest``
with no httpx. The live lifecycle test is in ``client_scan_test.py`` /
``async_client_test.py``.

The routing is load-bearing rather than stylistic: the server reads
``community``/``communities`` out of a POST body when it resolves scope, so a
client that folded the community into the body would pick its scope with a key
the server's own grammar then rejects.

Both transports share this builder, so one assertion covers each of them.

Assertions read ``request_parameters``, the projection of what is *sent*.
``PolyswarmRequest.json`` is reused for the parsed *response* and is None
until the call runs - see ``core_test`` for that trap.
"""
from polyswarm_api import resources
from polyswarm_api.core import parse_response


_EMPTY_HITS = {'total': {'value': 0, 'relation': 'eq'}, 'hits': []}


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
        return self._body


def _build(body, community=None):
    return resources.MetadataRawSearch.search(_FakeApi(), body, community)


def _parsed(result):
    req = _build({'query': {'match_all': {}}})
    parse_response(_FakeResponse(body={'status': 'OK', 'result': result}), req)
    return req._result


# ── Request shape ────────────────────────────────────────────────────


class TestMetadataRawSearchRequest:
    def test_the_body_reaches_the_server_verbatim(self):
        body = {
            'query': {'bool': {'must': [{'term': {'scan.mimetype': 'application/zip'}}]}},
            'aggs': {'families': {'terms': {'field': 'polyunite.malware_family', 'size': 20}}},
            'size': 0,
            'sort': [{'artifact.created': {'order': 'desc'}}],
        }
        assert _build(body).request_parameters['json'] == body

    def test_the_community_rides_the_query_string_not_the_body(self):
        sent = _build({'query': {'match_all': {}}}).request_parameters
        assert sent['params'] == {'community': 'gamma'}
        assert 'community' not in sent['json']
        assert 'communities' not in sent['json']

    def test_an_explicit_community_overrides_the_clients(self):
        sent = _build({'query': {'match_all': {}}}, community='delta').request_parameters
        assert sent['params']['community'] == 'delta'

    def test_it_posts_to_the_raw_search_endpoint(self):
        sent = _build({'query': {'match_all': {}}}).request_parameters
        assert sent['method'] == 'POST'
        assert sent['url'] == 'https://api.example.test/search/metadata/raw'


# ── Parse ────────────────────────────────────────────────────────────


class TestMetadataRawSearchParse:
    def test_hits_and_aggregations_are_both_reachable(self):
        parsed = _parsed({
            'hits': {'total': {'value': 2, 'relation': 'eq'},
                     'hits': [{'_source': {'artifact': {'sha256': 'a' * 64}}}]},
            'aggregations': {'families': {'buckets': [{'key': 'lockbit', 'doc_count': 2}]}},
        })
        assert parsed.json['hits']['total']['value'] == 2
        assert parsed.json['aggregations']['families']['buckets'][0]['key'] == 'lockbit'

    def test_a_partial_answer_keeps_its_reasons(self):
        # A truncated answer is still a 200, so this list is the only thing
        # separating it from a complete one. Dropping it in the parse layer
        # would turn "we could not establish this is complete" into a number.
        reasons = ['the search stopped at terminate_after']
        assert _parsed({'hits': _EMPTY_HITS, 'partial': reasons}).json['partial'] == reasons

    def test_a_complete_answer_carries_no_marker(self):
        assert 'partial' not in _parsed({'hits': _EMPTY_HITS}).json
