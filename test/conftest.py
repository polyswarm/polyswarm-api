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


def pytest_configure(config):
    # Honor an explicit --log-cli-level / --log-level on the CLI; otherwise drive
    # both the live and captured log level from TESTS_LOG_LEVEL.
    if config.option.log_cli_level is None:
        config.option.log_cli_level = _TESTS_LOG_LEVEL
    if config.option.log_level is None:
        config.option.log_level = _TESTS_LOG_LEVEL
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
