"""Pure-unit request-shape tests for the hunt-page tracking builders.

No HTTP at all (the pure-unit tier — see specs/04-testing.md): these pin the
request *construction* for the new surfaces — and specifically the two shapes
that are entirely consequences of ``core._params`` plumbing rather than
anything visible at the call site:

* ``YaraRulesetFavorite`` narrows ``RESOURCE_ID_KEYS`` to ``['community']``,
  which is what splits the request: the server reads BOTH ``id`` and
  ``favorite`` from the JSON body (the default ``['id']`` would move ``id``
  into the query string and the server would 400), while ``community`` rides
  the query string to match where the ruleset GET/list calls send it; and
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
    def test_update_splits_community_to_query_and_toggle_to_body(self):
        api = _FakeApi()
        req = resources.YaraRulesetFavorite.update(
            api, id=5, favorite=True, community=api.community)
        assert req.method == 'PUT'
        assert req.url == f'{api.uri}/hunt/rule/favorite'
        # RESOURCE_ID_KEYS = ['community'] is load-bearing: with the base
        # ['id'] the id would ride the query string on a PUT, and the server
        # reads the toggle's id exclusively from the body — a 400. community
        # goes to the query to match the ruleset GET/list placement (the
        # server accepts it from either side, never both at once). favorite
        # serialises as int 1, not JSON true.
        assert req.params == {'community': 'gamma'}
        assert req.input_json == {'id': '5', 'favorite': 1}
        assert req.result_parser is resources.YaraRulesetFavorite

    def test_unfavorite_serialises_false_as_zero(self):
        req = resources.YaraRulesetFavorite.update(
            _FakeApi(), id=5, favorite=False, community='gamma')
        assert req.input_json['favorite'] == 0


class TestRulesetListFilterBuilder:
    def test_list_routes_filters_to_the_query_with_int_bools(self):
        api = _FakeApi()
        req = resources.YaraRuleset.list(
            api, name='alpha', status='active', favorites_only=True,
            has_new_results=True, community=api.community)
        assert req.method == 'GET'
        assert req.url == f'{api.uri}/hunt/rule/list'
        assert req.params == {
            'name': 'alpha', 'status': 'active', 'favorites_only': 1,
            'has_new_results': 1, 'community': 'gamma'}

    def test_list_omits_every_unset_filter(self):
        # The no-filter request is byte-compatible with the pre-filter
        # contract: nothing but community rides the query string.
        req = resources.YaraRuleset.list(
            _FakeApi(), name=None, status=None, favorites_only=None,
            has_new_results=None, community='gamma')
        assert req.params == {'community': 'gamma'}


class TestYaraRulesetStoredCounterParse:
    """Parse-side pins for the stored counter — the recorded cassettes carry
    only null counters (the refresh job does not run on the e2e stack), so
    the populated shape is otherwise asserted nowhere."""

    def test_counter_and_staleness_marker_parse(self):
        row = resources.YaraRuleset(
            {'id': '5', 'new_results_count': 3,
             'new_results_counted_at': '2026-08-25T12:00:00+00:00'}, api=None)
        assert row.new_results_count == 3
        assert row.new_results_counted_at is not None
        assert row.new_results_counted_at.isoformat() == '2026-08-25T12:00:00+00:00'

    def test_absent_counter_is_none_never_zero(self):
        # An older server (or a never-refreshed row) leaves both None —
        # "no answer", distinct from a refreshed 0.
        row = resources.YaraRuleset({'id': '5'}, api=None)
        assert row.new_results_count is None
        assert row.new_results_counted_at is None


class TestProvenanceAndCounterAbsentArms:
    """The None arms the cassettes cannot carry: every recorded hunt resolves
    its provenance (true/false) and every recorded ruleset has answers, so
    the "None is unknown / no answer — NEVER a value" halves of the tri-state
    and counter contracts are pinned here, purely on the parse."""

    def test_hunt_without_provenance_parses_all_three_none(self):
        # A pre-migration or raw-yara hunt: no rule_id, no anchor. None means
        # UNKNOWN — a consumer rendering it as "unchanged" is the exact bug
        # the tri-state exists to prevent.
        hunt = resources.HistoricalHunt(
            {'id': '9', 'created': '2026-08-25T12:00:00+00:00',
             'status': 'PENDING', 'progress': 0.0, 'results_csv_uri': None},
            api=None)
        assert hunt.rule_id is None
        assert hunt.rule_modified is None
        assert hunt.source_rule_changed is None

    def test_ruleset_counters_absent_is_none_never_zero(self):
        # rule_count / historical_hunt_count: "no answer" must not read as 0.
        row = resources.YaraRuleset({'id': '5'}, api=None)
        assert row.rule_count is None
        assert row.historical_hunt_count is None


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
