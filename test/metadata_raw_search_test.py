"""Tests for the metadata_raw_search SDK method.

Request-shape tests, in the respx tier rather than the e2e one. What they
pin — that the query body reaches the server byte-for-byte and that the
community rides the query string instead of the body — is invisible from
the far side of a live call, which only shows that *some* scoped search
ran. The live lifecycle test lives in ``client_scan_test.py`` /
``async_client_test.py``.

The distinction is load-bearing rather than stylistic: the server reads
``community``/``communities`` out of a POST body when deciding scope, so a
client that folded the community into the body would have its scope chosen
by a key the server's own grammar then rejects.

Each test runs twice, once per transport — see ``test/_client_harness.py``.
"""
from test._client_harness import BASE_URL, COMMUNITY, ClientTestCase


_RESOURCE_URL = f'{BASE_URL}/search/metadata/raw'


def _envelope(hits=None, aggregations=None, **extra):
    result = {'hits': hits if hits is not None else {'total': {'value': 0, 'relation': 'eq'},
                                                     'hits': []}}
    if aggregations is not None:
        result['aggregations'] = aggregations
    result.update(extra)
    return {'result': result, 'status': 'OK'}


# ── Tests ────────────────────────────────────────────────────────────


class MetadataRawSearchTestCase(ClientTestCase):
    def test_the_body_reaches_the_server_verbatim(self):
        body = {
            'query': {'bool': {'must': [{'term': {'scan.mimetype': 'application/zip'}}]}},
            'aggs': {'families': {'terms': {'field': 'polyunite.malware_family', 'size': 20}}},
            'size': 0,
            'sort': [{'artifact.created': {'order': 'desc'}}],
        }
        self.mock.add('POST', _RESOURCE_URL, json=_envelope(aggregations={'families': {}}))
        self.api.metadata_raw_search(body)
        assert self.mock.last_request_body == body

    def test_the_community_rides_the_query_string_not_the_body(self):
        # The server reads community/communities out of the POST body when it
        # resolves scope, and its grammar rejects those keys for that reason.
        self.mock.add('POST', _RESOURCE_URL, json=_envelope())
        self.api.metadata_raw_search({'query': {'match_all': {}}})
        assert f'community={COMMUNITY}' in self.mock.last_request_url
        assert 'community' not in self.mock.last_request_body
        assert 'communities' not in self.mock.last_request_body

    def test_an_explicit_community_overrides_the_clients(self):
        self.mock.add('POST', _RESOURCE_URL, json=_envelope())
        self.api.metadata_raw_search({'query': {'match_all': {}}}, community='delta')
        assert 'community=delta' in self.mock.last_request_url

    def test_hits_and_aggregations_are_both_reachable(self):
        hits = {'total': {'value': 2, 'relation': 'eq'},
                'hits': [{'_source': {'artifact': {'sha256': 'a' * 64}}}]}
        aggs = {'families': {'buckets': [{'key': 'lockbit', 'doc_count': 2}]}}
        self.mock.add('POST', _RESOURCE_URL, json=_envelope(hits=hits, aggregations=aggs))
        result = self.api.metadata_raw_search({'aggs': {'families': {'terms': {'field': 'f'}}}})
        assert result.json['hits']['total']['value'] == 2
        assert result.json['aggregations']['families']['buckets'][0]['key'] == 'lockbit'

    def test_a_partial_answer_keeps_its_marker(self):
        # A truncated answer is still a 200, so the only thing separating it
        # from a complete one is this key. Dropping it in the parse layer would
        # turn "we could not establish this is complete" into a hard number.
        self.mock.add('POST', _RESOURCE_URL,
                      json=_envelope(partial=['the search stopped at terminate_after']))
        result = self.api.metadata_raw_search({'query': {'match_all': {}}})
        assert result.json['partial'] == ['the search stopped at terminate_after']

    def test_a_complete_answer_carries_no_marker(self):
        self.mock.add('POST', _RESOURCE_URL, json=_envelope())
        result = self.api.metadata_raw_search({'query': {'match_all': {}}})
        assert 'partial' not in result.json

    def test_it_posts_to_the_raw_search_endpoint(self):
        self.mock.add('POST', _RESOURCE_URL, json=_envelope())
        self.api.metadata_raw_search({'query': {'match_all': {}}})
        assert self.mock.last_request_url.startswith(_RESOURCE_URL)
