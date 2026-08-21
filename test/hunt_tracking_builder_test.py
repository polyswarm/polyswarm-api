"""Pure-unit request-shape tests for the hunt-page tracking builders.

No HTTP at all (the pure-unit tier — see specs/04-testing.md): these pin the
request *construction* for the new surfaces — and specifically the two shapes
that are entirely consequences of ``core._params`` plumbing rather than
anything visible at the call site:

* ``YaraRulesetFavorite`` empties ``RESOURCE_ID_KEYS``, which is the ONLY
  thing routing ``id`` (and ``favorite``/``community``) into the PUT's JSON
  body instead of the query string — the server reads the toggle exclusively
  from the body; and
* booleans serialise as ``1``/``0`` ints, not JSON ``true``/``false``
  (``core._params`` coerces before body/query routing) — the server's
  boolean parser accepts exactly that, so the int-vs-bool body contract is
  load-bearing.

Endpoint *behaviour* is covered by the live-e2e VCR lifecycle tests
(``test_rules`` / ``test_async_rules``).
"""
from polyswarm_api import resources


class _FakeApi:
    uri = 'https://api.example.test'
    community = 'gamma'


class TestYaraRulesetFavoriteBuilder:
    def test_update_routes_everything_to_the_put_body(self):
        api = _FakeApi()
        req = resources.YaraRulesetFavorite.update(
            api, id=5, favorite=True, community=api.community)
        assert req.method == 'PUT'
        assert req.url == f'{api.uri}/hunt/rule/favorite'
        # RESOURCE_ID_KEYS = [] is load-bearing: with the base ['id'] the id
        # would ride the query string on a PUT, and the server only reads the
        # body. favorite serialises as int 1, not JSON true.
        assert req.params is None
        assert req.input_json == {'id': '5', 'favorite': 1, 'community': 'gamma'}
        assert req.result_parser is resources.YaraRulesetFavorite

    def test_unfavorite_serialises_false_as_zero(self):
        req = resources.YaraRulesetFavorite.update(
            _FakeApi(), id=5, favorite=False, community='gamma')
        assert req.input_json['favorite'] == 0


class TestLiveHuntResultCountsBuilder:
    def test_get_routes_since_and_community_to_the_query(self):
        api = _FakeApi()
        req = resources.LiveHuntResultCounts.get(
            api, since=86400, community=api.community)
        assert req.method == 'GET'
        assert req.url == f'{api.uri}/hunt/live/results/count'
        assert req.params == {'since': 86400, 'community': 'gamma'}
        assert req.input_json is None
        assert req.result_parser is resources.LiveHuntResultCounts

    def test_get_omits_unset_since(self):
        # None is dropped, so the server applies its own default window.
        req = resources.LiveHuntResultCounts.get(
            _FakeApi(), since=None, community='gamma')
        assert req.params == {'community': 'gamma'}


class TestRulesetListFilterBuilder:
    def test_list_routes_filters_to_the_query_with_int_bools(self):
        api = _FakeApi()
        req = resources.YaraRuleset.list(
            api, name='alpha', status='active', favorites_only=True,
            has_new_results=True, since=86400, include_counts=True,
            community=api.community)
        assert req.method == 'GET'
        assert req.url == f'{api.uri}/hunt/rule/list'
        assert req.params == {
            'name': 'alpha', 'status': 'active', 'favorites_only': 1,
            'has_new_results': 1, 'since': 86400, 'include_counts': 1,
            'community': 'gamma'}

    def test_list_omits_every_unset_filter(self):
        # The no-filter request is byte-compatible with the pre-filter
        # contract: nothing but community rides the query string.
        req = resources.YaraRuleset.list(
            _FakeApi(), name=None, status=None, favorites_only=None,
            has_new_results=None, since=None, include_counts=None,
            community='gamma')
        assert req.params == {'community': 'gamma'}


class TestLiveFeedScopeBuilder:
    def test_list_routes_livescan_id_to_the_query_as_digit_string(self):
        # *_id kwargs stringify (core._params); the server casts back to int.
        req = resources.LiveHuntResult.list(
            _FakeApi(), since=60, livescan_id=45392847561029383,
            rule_name=None, family=None, polyscore_lower=None,
            polyscore_upper=None, community='gamma')
        assert req.url == 'https://api.example.test/hunt/live/list'
        assert req.params == {'since': 60, 'livescan_id': '45392847561029383',
                              'community': 'gamma'}
