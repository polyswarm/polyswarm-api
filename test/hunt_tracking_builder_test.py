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
import asyncio

from polyswarm_api import core, resources
from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api.api import PolyswarmAPI


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


class TestRulesetListExplicitFalseFilters:
    """An explicit ``False`` filter serialises to ``0`` on the query string.

    ``core._params`` coerces bools to ints before routing, so these land as
    ``0`` rather than ``False``. The server's boolean argument parser accepts
    exactly ``0``/``1``/``false``/``true`` and maps ``0`` to false, so an
    explicit False really does mean unfiltered — but only the ``True`` and
    omitted arms were covered, and an inverted filter is the one failure mode
    that silently returns the wrong rows."""

    def test_explicit_false_serialises_to_zero(self):
        request = resources.YaraRuleset.list(
            _FakeApi(), favorites_only=False, has_new_results=False,
            community='gamma')
        assert request.params['favorites_only'] == 0
        assert request.params['has_new_results'] == 0


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

class TestResultBound:
    """``core._as_result_bound`` — one definition of "is there a bound"."""

    def test_no_bound_forms(self):
        for no_bound in (None, 0, -1):
            assert core._as_result_bound(no_bound) is None

    def test_a_real_bound_passes_through_unclamped(self):
        assert core._as_result_bound(5) == 5
        assert core._as_result_bound(10_000) == 10_000


class TestLiveFeedMaxResults:
    """``live_feed(max_results=)`` stops the generator at the bound.

    Pinned here rather than against the stack: producing more feed rows than a
    page holds on the shared e2e stack would mean generating real live-hunt
    volume. ``_paginate`` is the seam — it is what would otherwise keep
    following cursors — so it is what this stands in for."""

    @staticmethod
    def _api_yielding(count):
        api = PolyswarmAPI.__new__(PolyswarmAPI)
        api.uri = _FakeApi.uri
        api.community = _FakeApi.community
        api._paginate = lambda *a, **kw: iter(range(count))
        return api

    def test_unbounded_by_default_yields_everything(self):
        assert list(self._api_yielding(7).live_feed()) == list(range(7))

    def test_the_bound_truncates(self):
        assert list(self._api_yielding(7).live_feed(max_results=3)) == [0, 1, 2]

    def test_a_bound_larger_than_the_feed_is_not_padding(self):
        assert list(self._api_yielding(2).live_feed(max_results=9)) == [0, 1]

    def test_a_negative_bound_is_no_bound(self):
        assert list(self._api_yielding(4).live_feed(max_results=-1)) == list(range(4))

    def test_zero_is_no_bound_not_a_bound_of_one(self):
        # 0 means no bound, as it does for `since` on the same call. Testing
        # `is not None` instead makes max_results=0 yield exactly one result.
        assert list(self._api_yielding(7).live_feed(max_results=0)) == list(range(7))

class TestLiveFeedLimitOnTheWire:
    """``max_results`` is a total, so it must not reach the wire as ``limit``.

    The page stays the server's to choose and the read keeps paginating in
    those chunks; sending the total as a page size also 400s above whatever
    per-page cap the deployment configures.
    """

    @staticmethod
    def _params(**kwargs):
        api = PolyswarmAPI.__new__(PolyswarmAPI)
        api.uri = _FakeApi.uri
        api.community = _FakeApi.community
        captured = {}

        def capture(request, *a, **kw):
            captured.update(request.params)
            return iter(())

        api._paginate = capture
        list(api.live_feed(**kwargs))
        return captured

    def test_no_limit_is_ever_sent(self):
        for kwargs in ({}, {'max_results': 5}, {'max_results': 10_000},
                       {'max_results': 0}, {'max_results': -1}):
            assert 'limit' not in self._params(**kwargs)


class TestLiveFeedSinceOnTheWire:
    """``since=0`` has to REACH the server to mean what it means.

    The contract is that absent-or-0 applies no time filter, and the server
    implements it with a truthiness test. That only holds because ``_params``
    drops ``None`` and not ``0``: were falsy values dropped, ``since=0`` and
    ``since=5`` would build the same request and the parameter would be
    unusable for anything but its default."""

    def test_zero_is_sent_and_absent_is_omitted(self):
        sent = resources.LiveHuntResult.list(_FakeApi(), since=0, community='gamma')
        assert sent.params['since'] == 0
        omitted = resources.LiveHuntResult.list(_FakeApi(), since=None, community='gamma')
        assert 'since' not in omitted.params

class TestAsyncLiveFeedMaxResults:
    """The CANONICAL async bound loop, not the generated mirror.

    Every other max_results test drives ``PolyswarmAPI`` — the unasync output.
    The ``async for`` + ``yielded``/``return`` shape is precisely the part
    unasync REWRITES rather than copies, so a mirror-only test would keep
    passing if the canonical source's loop were wrong."""

    @staticmethod
    def _api_yielding(count):
        api = PolySwarmAsyncAPI.__new__(PolySwarmAsyncAPI)
        api.uri = _FakeApi.uri
        api.community = _FakeApi.community
        captured = {}

        async def paginate(request, *a, **kw):
            captured.update(request.params)
            for item in range(count):
                yield item

        api._paginate = paginate
        return api, captured

    @staticmethod
    def _collect(agen):
        async def run():
            return [item async for item in agen]

        return asyncio.run(run())

    def test_the_bound_truncates(self):
        api, _ = self._api_yielding(7)
        assert self._collect(api.live_feed(max_results=3)) == [0, 1, 2]

    def test_no_bound_yields_everything(self):
        for no_bound in (None, 0, -1):
            api, _ = self._api_yielding(4)
            assert self._collect(api.live_feed(max_results=no_bound)) == list(range(4))

    def test_no_limit_is_ever_sent(self):
        for kwargs in ({}, {'max_results': 5}, {'max_results': 0}):
            api, captured = self._api_yielding(0)
            self._collect(api.live_feed(**kwargs))
            assert 'limit' not in captured
