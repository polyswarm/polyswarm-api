import asyncio
import os
import time

import pytest

_VCR_DIR = os.path.join(os.path.dirname(__file__), "vcr")


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
    cassette = os.path.join(_VCR_DIR, f"{request.node.name}.vcr")
    if not os.path.exists(cassette):
        return  # recording, or a non-cassette test — keep real sleeps

    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)

    async def _noop_async_sleep(*_a, **_k):
        return None

    monkeypatch.setattr(asyncio, "sleep", _noop_async_sleep)
