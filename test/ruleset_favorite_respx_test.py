"""The favorite toggle's transport contract, respx-mocked on BOTH clients
(``ClientTestCase`` — specs/04-testing.md invariant 5).

Two things live here because the shared e2e stack cannot pin either:

* the ``FAVORITE_LIMIT`` refusal — producing a genuinely full budget on the
  shared stack would mean holding all five team slots, racing every other
  run; and
* the query/body split — the toggle's payload (``id``, ``favorite``) must
  ride the JSON body (the server reads both from it; an ``id`` moved into
  the query string by the default ``RESOURCE_ID_KEYS`` is a 400), while
  ``community`` rides the query string to match the ruleset GET/list
  placement. The e2e stack is single-community and its ids always exist, so
  neither mis-split shows up there.
"""
import pytest

from polyswarm_api import exceptions

from test._client_harness import BASE_URL, COMMUNITY, ClientTestCase

_FAVORITE_URL = f'{BASE_URL}/hunt/rule/favorite'


class RulesetFavoriteTestCase(ClientTestCase):
    def test_favorite_limit_refusal_is_machine_readable(self):
        # There is deliberately no typed exception (specs/05): the
        # machine-readable contract is the raw envelope at
        # ``exc.request.errors`` — the code plus the same counters a
        # successful toggle returns.
        envelope = {
            'status': 'error',
            'result': 'Favorite limit reached (5 of 5 used).',
            'errors': {'code': 'FAVORITE_LIMIT',
                       'favorites_used': 5, 'favorites_limit': 5},
        }
        self.mock.add('PUT', f'{_FAVORITE_URL}?community={COMMUNITY}',
                      json=envelope, status=400)
        with pytest.raises(exceptions.RequestException) as excinfo:
            self.api.ruleset_favorite(5, True)
        errors = excinfo.value.request.errors
        assert errors['code'] == 'FAVORITE_LIMIT'
        assert errors['favorites_used'] == 5
        assert errors['favorites_limit'] == 5

    def test_community_rides_the_query_and_the_toggle_rides_the_body(self):
        ok = {'status': 'OK',
              'result': {'id': '5', 'favorite': True, 'favorited_at': None,
                         'favorites_used': 1, 'favorites_limit': 5}}
        self.mock.add('PUT', f'{_FAVORITE_URL}?community={COMMUNITY}', json=ok)
        result = self.api.ruleset_favorite(5, True)
        assert result.favorite is True
        assert f'community={COMMUNITY}' in self.mock.last_request_url
        body = self.mock.last_request_body
        # The client's wire coercions apply to the body: ids stringify and
        # bools ride as 1/0 (the server's cast=bool accepts both) — pinned so
        # a coercion change is a deliberate one.
        assert body == {'id': '5', 'favorite': 1}
        assert 'community' not in body
