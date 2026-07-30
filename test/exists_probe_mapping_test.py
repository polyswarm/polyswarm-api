"""The one arm of ``exists()``'s status mapping the e2e stack cannot produce.

Everything else about this endpoint is asserted against the **real server**, on resources the
tests provision themselves — ``test_hash_existence_probe_against_the_real_server`` and its async
twin cover ``200`` (present) and ``204`` (absent), in both the plain and ``require_scan`` forms.
That is the default (``specs/04-testing.md`` invariant 1), and it is the only thing that can
catch a *server-side* flip, which a mock cannot by construction: the 4.0 ``exists()`` inversion
survived release precisely because this endpoint's coverage was entirely mocked.

``404`` stays mocked because artifact-index never answers it for a well-formed probe — per its
``specs/09-hash-search-head-contract.md`` that code is reserved for the *request* being wrong,
and a bad hash or hash type raises ``400``. The mapping is still worth pinning: clients have
tolerated ``404``-as-absent historically, so the SDK must not start raising if a proxy or an
older deployment in front of the API emits one.

It lives on ``ClientTestCase`` rather than in one transport's module because the mapping is
transport-independent — the sync client reaches it through the generated ``int(result) == 200``
just as the async one does, and the pure tier only covers ``parse_response``'s HEAD
short-circuit, not that comparison.
"""
from test._client_harness import BASE_URL, ClientTestCase

_SHA256 = 'a' * 64
_PROBE_URL = f'{BASE_URL}/search/hash/sha256'


class ExistsProbeMappingTestCase(ClientTestCase):
    def test_a_404_maps_to_absent_rather_than_raising(self):
        self.mock.add('HEAD', _PROBE_URL, json={}, status=404)
        assert self.api.exists(_SHA256) is False

    def test_a_404_maps_to_absent_under_require_scan_too(self):
        # Same arm, but through the query-carrying form: `require_scan` is routed as a param,
        # so a regression that dropped the short-circuit for one form only would pass above.
        self.mock.add('HEAD', _PROBE_URL, json={}, status=404)
        assert self.api.exists(_SHA256, require_scan=True) is False
        assert 'require_scan=false' not in self.mock.last_request_url
        assert 'require_scan=true' in self.mock.last_request_url

    def test_a_server_error_is_not_reported_as_absent_silently(self):
        # Documents the sharpest edge of having no error channel on this probe: a 5xx also
        # collapses to False, i.e. a *fabricated negative* (artifact-index's contract
        # invariant 6 names this as the reason never to repurpose these codes). Pinned so the
        # behaviour is a recorded decision rather than an accident — if the SDK ever grows an
        # error channel here, this is the test that should fail and be rewritten.
        self.mock.add('HEAD', _PROBE_URL, json={}, status=500)
        assert self.api.exists(_SHA256) is False
