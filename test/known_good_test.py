"""Pure-unit request-shape tests for the ``KnownGood`` resource builders.

No HTTP at all (the pure-unit tier — see specs/04-testing.md): these pin the
request *construction* — which fields ride in the JSON body vs the query
string, that unset optionals are omitted rather than sent as explicit nulls,
and that DELETE carries no body. Endpoint *behaviour* is covered by the
live-e2e VCR lifecycle tests (``test_known_good_lifecycle`` in
client_scan_test.py / ``test_async_known_good_lifecycle`` in
async_client_test.py), which run the same calls against the real
``/known-good`` endpoint and replay from cassettes in unit runs.
"""
from polyswarm_api import resources

SHA = 'a' * 64


class _FakeApi:
    uri = 'https://api.example.test'
    community = 'gamma'


class TestKnownGoodBuilders:
    def test_create_routes_everything_to_the_body(self):
        api = _FakeApi()
        req = resources.KnownGood.create(
            api, sha256=SHA, source='nsrl', community=api.community,
            sha1='b' * 40, md5='c' * 32, filename='setup.exe',
            mimetype='application/x-dosexec', metadata={'product': 'Example'})
        assert req.method == 'POST'
        assert req.url == f'{api.uri}/known-good'
        # POST routes every field — including community — into the JSON body.
        assert req.params is None
        assert req.input_json == {
            'sha256': SHA, 'source': 'nsrl', 'community': 'gamma',
            'sha1': 'b' * 40, 'md5': 'c' * 32, 'filename': 'setup.exe',
            'mimetype': 'application/x-dosexec', 'metadata': {'product': 'Example'},
        }
        assert req.result_parser is resources.KnownGood

    def test_create_omits_unset_optionals(self):
        # None-valued optionals are dropped, not serialised as nulls.
        api = _FakeApi()
        req = resources.KnownGood.create(
            api, sha256=SHA, source='nsrl', community=api.community,
            sha1=None, md5=None, filename=None, mimetype=None, metadata=None)
        assert req.input_json == {'sha256': SHA, 'source': 'nsrl', 'community': 'gamma'}

    def test_get_routes_key_and_community_to_the_query(self):
        api = _FakeApi()
        req = resources.KnownGood.get(api, sha256=SHA, community=api.community)
        assert req.method == 'GET'
        assert req.url == f'{api.uri}/known-good'
        assert req.params == {'sha256': SHA, 'community': 'gamma'}
        assert req.input_json is None

    def test_delete_routes_sha256_to_the_query_with_no_body(self):
        # sha256 ∈ RESOURCE_ID_KEYS routes to the query string via the base
        # _delete_params — no override, no community, no request body.
        api = _FakeApi()
        req = resources.KnownGood.delete(api, sha256=SHA)
        assert req.method == 'DELETE'
        assert req.url == f'{api.uri}/known-good'
        assert req.params == {'sha256': SHA}
        assert req.input_json is None


class TestKnownGoodParsing:
    def test_parses_full_row(self):
        row = {'id': '12345678901234567', 'sha256': SHA,
               'artifact_instance_id': '98765432109876543',
               'sources': ['nsrl', 'commercial'], 'created': '2026-06-11T00:00:00'}
        kg = resources.KnownGood(row)
        assert kg.id == '12345678901234567'
        assert kg.sha256 == SHA
        assert kg.artifact_instance_id == '98765432109876543'
        assert kg.sources.sort() == ['commercial', 'nsrl']
        assert kg.created.year == 2026

    def test_parses_minimal_delete_row(self):
        # The delete response carries only {sha256, deleted} — absent fields
        # parse to safe defaults (no KeyError, created stays None).
        kg = resources.KnownGood({'sha256': SHA, 'deleted': True})
        assert kg.sha256 == SHA
        assert kg.sources == []
        assert kg.created is None
        assert kg.id is None


def _instance_content(**overrides):
    """Minimal valid ArtifactInstance response row (required keys only)."""
    content = {
        'sha256': SHA, 'md5': 'c' * 32, 'sha1': 'b' * 40,
        'mimetype': 'application/x-dosexec', 'size': 68, 'extended_type': '',
        'first_seen': '2020-01-01T00:00:00', 'upload_url': '', 'metadata': [],
    }
    content.update(overrides)
    return content


class TestArtifactInstanceKnownGoodField:
    """The known_good field on an artifact-instance response (the search/scan
    result shape), distinct from the KnownGood CRUD resource above."""

    def test_known_good_feeds_are_parsed_and_sources_derived(self):
        feeds = [
            {'tool': 'commercial', 'tool_metadata': {'product': 'Example'},
             'created': '2026-06-11T00:00:00', 'updated': '2026-06-11T00:00:00'},
            {'tool': 'nsrl', 'tool_metadata': {},
             'created': '2026-06-11T00:00:00', 'updated': '2026-06-11T00:00:00'},
        ]
        inst = resources.ArtifactInstance(_instance_content(known_good=feeds))
        # The raw feed list is preserved verbatim...
        assert inst.known_good == feeds
        # ...and the feed (source) names are exposed sorted + de-duplicated.
        assert inst.known_good_sources.sort() == ['commercial', 'nsrl']

    def test_absent_known_good_parses_to_none(self):
        # Older servers omit the field entirely (additive, backward-compatible):
        # it parses to None with no sources, not a KeyError.
        inst = resources.ArtifactInstance(_instance_content())
        assert inst.known_good is None
        assert inst.known_good_sources == []

    def test_null_known_good_parses_to_none(self):
        # A normal (non-known-good) artifact has known_good explicitly null.
        inst = resources.ArtifactInstance(_instance_content(known_good=None))
        assert inst.known_good is None
        assert inst.known_good_sources == []


class TestArtifactInstanceStateField:
    """The state field on an artifact-instance response — the friendly
    bounty-state NAME, additive alongside the numeric bounty_state."""

    def test_state_is_parsed(self):
        inst = resources.ArtifactInstance(_instance_content(state='KNOWN_GOOD'))
        assert inst.state == 'KNOWN_GOOD'

    def test_absent_state_parses_to_none(self):
        # Older servers omit the field entirely (additive, backward-compatible).
        inst = resources.ArtifactInstance(_instance_content())
        assert inst.state is None

    def test_null_state_parses_to_none(self):
        inst = resources.ArtifactInstance(_instance_content(state=None))
        assert inst.state is None
