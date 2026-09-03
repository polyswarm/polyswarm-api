import asyncio
import logging
import os
import time

import pytest

_VCR_DIR = os.path.join(os.path.dirname(__file__), "vcr")

# Test log verbosity, controllable per-run via the TESTS_LOG_LEVEL env var
# (default INFO). At INFO the suite emits the useful app request/response lines
# but not the DEBUG firehose that bloats CI logs ~1000x. Set TESTS_LOG_LEVEL=DEBUG
# to log everything (including the replay/transport libraries below).
_TESTS_LOG_LEVEL = os.getenv("TESTS_LOG_LEVEL", "INFO").upper()

# Live-log streaming (log_cli). OFF by default: when on, pytest not only streams log
# records but forces every test onto its own nodeid line (verbose-style) — ~130
# lines of noise on a green xdist run. Off, the run prints dots + an end summary,
# and a failing test still shows its captured logs at _TESTS_LOG_LEVEL plus the
# traceback. Set TESTS_LOG_CLI=1 to stream live when debugging a live-stack run.
_TESTS_LOG_CLI = os.getenv("TESTS_LOG_CLI", "").lower() in ("1", "true", "yes", "on")

# Replay/transport libraries are extremely chatty at DEBUG — vcr.matchers alone
# logs a full comparison for every recorded request on every call (~24% of the
# old log) and vcr.cassette/vcr.request dump entire response bodies. Pin them to
# WARNING unless DEBUG was explicitly requested, so they never drown the app's
# own logs (and a real cassette-miss / transport error is >=WARNING, so it still
# surfaces). This caps verbosity only; it does not hide app warnings/errors.
_NOISY_LIBS = ("vcr", "httpx", "httpcore", "asyncio")

# VCR replay/record toggle. Default "on" = record-on-once + replay against
# cassettes. Set TESTS_VCR=off to bypass VCR entirely (live, no replay, no
# recording) — used by the e2e CI command that runs this suite against the live
# stack. The test modules read this to no-op ``@vcr.use_cassette``; the fixture
# below also keeps the poll sleeps real when it's off, since a live run must
# pace itself against the real services.
_TESTS_VCR_ON = os.getenv("TESTS_VCR", "on").lower() != "off"


@pytest.fixture
def uid(request):
    """A deterministic, test-unique namespace token for the async (pytest-style)
    suite — the test's own node name (e.g. ``test_async_search_by_ioc``).

    Deterministic per test so the request is reproducible and the recorded VCR
    cassette replays; unique per test so created resources never collide on the
    shared e2e stack (enabling ``pytest -n auto``). The sync ``unittest.TestCase``
    suite can't take fixtures as params, so it uses ``self._testMethodName``
    instead — same value, same guarantees.
    """
    return request.node.name


def pytest_configure(config):
    # Captured-log level — what pytest records and then prints under a FAILING test
    # ("Captured log call"). Drive it from TESTS_LOG_LEVEL so failures carry the
    # app's request/response context while a green run stays quiet. Honors an
    # explicit --log-level on the CLI.
    if config.option.log_level is None:
        config.option.log_level = _TESTS_LOG_LEVEL
    # Live logging is enabled iff log_cli (ini, now false) is true OR this option is
    # set — so setting it here is what turns on the verbose per-test streaming.
    # Leave it None by default (dots + summary); opt in with TESTS_LOG_CLI=1. An
    # explicit --log-cli-level on the CLI is honored (already non-None -> untouched).
    if _TESTS_LOG_CLI and config.option.log_cli_level is None:
        config.option.log_cli_level = _TESTS_LOG_LEVEL
    noisy_level = "DEBUG" if _TESTS_LOG_LEVEL == "DEBUG" else "WARNING"
    for name in _NOISY_LIBS:
        logging.getLogger(name).setLevel(noisy_level)


@pytest.fixture(autouse=True)
def _skip_poll_sleep_on_replay(request, monkeypatch):
    """Make poll-loop sleeps free on VCR *replay*.

    Several e2e tests poll an async backend pipeline (search_by_ioc,
    iocs_by_hash, stream, live, metadata_search, tool_metadata,
    sandbox_task_*) with a ~1s sleep between polls so a *live recording*
    paces the e2e correctly. On replay VCR serves every recorded response
    instantly, so those sleeps are pure dead wall-clock — ~50s for each
    reverse-IOC test alone (49/59 recorded polls x 1s).

    ``record_mode='once'`` (the suite default) replays iff the cassette
    already exists, so "cassette present" == "replaying". When replaying,
    no-op ``time.sleep`` / ``asyncio.sleep`` for the duration of the test;
    when recording (cassette absent) leave the real delays in place so the
    e2e isn't hammered and pacing is preserved. ``monkeypatch`` auto-reverts
    after each test.
    """
    if not _TESTS_VCR_ON:
        return  # VCR bypassed (TESTS_VCR=off) — hitting live, keep real pacing
    cassette = os.path.join(_VCR_DIR, f"{request.node.name}.vcr")
    if not os.path.exists(cassette):
        return  # recording, or a non-cassette test — keep real sleeps

    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)

    async def _noop_async_sleep(*_a, **_k):
        return None

    monkeypatch.setattr(asyncio, "sleep", _noop_async_sleep)


# Long-pole-first scheduling hint. The live (TESTS_VCR=off) run is bound by the
# slowest xdist worker's serial chain, and a handful of tests block on real
# pipeline latency (scan settle, sandbox completion, IOC/metadata/feed polls)
# while the ~100 unit/respx tests finish near-instantly. Running the heavy tests
# first (so they start at t=0 and the fast ones backfill the tail) keeps workers
# from idling on a straggler. Fragments are ranked roughly by observed cost.
#
# This is a pure scheduling hint — tests are isolation-safe and order-independent,
# so correctness doesn't depend on it. The sort key is derived only from nodeid,
# so it's deterministic and identical across all xdist workers (xdist requires a
# consistent collection order; a non-deterministic key would error). On replay
# the sleeps are no-op'd anyway, so this only matters for the live run.
_LONG_POLE_FRAGMENTS = (
    "live",             # test_live / test_async_live — live-feed polling
    "iocs_by_hash",     # forward-IOC settle + metadata poll
    "search_by_ioc",    # reverse-IOC metadata poll
    "metadata_search",  # ES index-lag poll
    "sample",           # sandbox completion + metadata
    "stream",           # global archiver batching
    "rescan",           # rescan retry loop + settle
    # Exact, because every substring of these two is also a prefix of
    # test_ruleset_* — "rules", "test_rules" and "_rules" each caught the
    # instant unit tests as well. A "::" fragment is matched as a nodeid
    # SUFFIX (see _long_pole_rank), which is the only form that can name a
    # test whose name is a prefix of another's.
    "::test_rules",       # live enable/stop + ~6 poll loops
    "::test_async_rules", # the async twin
    "hash_search",      # search-index lag
    "existence_probe",  # submit + settle + search-index lag (the HEAD probe tests)
    "sandboxtask",      # sandbox completion + index lag
)


def _long_pole_rank(item):
    name = item.nodeid
    for rank, frag in enumerate(_LONG_POLE_FRAGMENTS):
        # A "::" fragment names one test exactly; anything else is a substring
        # hint that may legitimately span several.
        if name.endswith(frag) if frag.startswith('::') else frag in name:
            return rank
    return len(_LONG_POLE_FRAGMENTS)  # unit/respx tests backfill the tail


def pytest_collection_modifyitems(config, items):
    # Stable sort by long-pole rank so within-rank collection order is preserved.
    items.sort(key=_long_pole_rank)
