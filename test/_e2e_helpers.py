"""Shared, transport-agnostic helpers for the live e2e test suites.

These give every data-creating test a *deterministic-per-test, unique-per-test*
namespace so the suite is self-contained and parallel-safe:

* deterministic per test  -> the request is reproducible, so a recorded VCR
  cassette replays (the unit CI jobs run ``TESTS_VCR`` on / replay).
* unique per test          -> nothing collides on the shared e2e stack, so tests
  can run concurrently (``pytest -n auto``) without interfering.

The e2e stack has only the ``eicar`` engine, which flags an artifact malicious
iff the EICAR string is a *substring* of its bytes (``EICAR_STRING in contents``).
So a unique malicious artifact is ``EICAR + uid`` — still detected, but a fresh
sha (which also means no seeded sandbox task exists to overwrite a mock
``cape_sandbox_v2`` blob in the reverse-IOC ES view).

``uid`` is the test's own name: ``self._testMethodName`` for the sync
``unittest.TestCase`` suite, or the ``uid`` fixture (``request.node.name``) for
the async pytest-style suite.
"""
import asyncio
import hashlib
import os
import re
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

# The raw EICAR string — read once from the fixture. The only thing the e2e
# 'eicar' engine matches (substring), so unique content must embed it.
with open(os.path.join(os.path.dirname(__file__), 'malicious'), 'rb') as _fh:
    EICAR_STRING = _fh.read()


def malicious_artifact(uid):
    """Return ``(content, sha256)`` for a unique-but-still-malicious artifact.

    ``EICAR + uid`` keeps ``EICAR_STRING in contents`` true (so the eicar engine
    flags it) while making the sha unique per test. Deterministic in ``uid`` so
    the recorded cassette replays.
    """
    content = EICAR_STRING + b'\n' + uid.encode()
    return content, hashlib.sha256(content).hexdigest()


@contextmanager
def artifact_file(content):
    """Write ``content`` to a temp file and yield its path (for ``api.submit``)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = os.path.join(tmp_dir, 'artifact')
        with open(path, 'wb') as fh:
            fh.write(content)
        yield path


def uid_ip(uid):
    """A deterministic, test-unique, globally-routable IOC IP.

    ``filter_known_good_iocs`` drops private/reserved addresses, so we stay in
    the public 9.42.0.0/16 block (IBM netblock, as the original hard-coded
    ``9.42.0.x`` IPs did). The last two octets derive from a hash of ``uid`` so
    every test gets its own IP, stable across runs; avoids ``.0``/``.255``.
    """
    h = int(hashlib.sha256(uid.encode()).hexdigest(), 16)
    return f'9.42.{(h >> 8) % 256}.{(h % 254) + 1}'


def uid_host(uid):
    """A deterministic, test-unique known-good-host domain."""
    return f'{re.sub(r"[^a-z0-9]+", "-", uid.lower()).strip("-")}.sdk.test'


def uid_yara(uid):
    """A YARA ruleset that matches ONLY this test's artifact.

    The artifact embeds ``uid`` (see ``malicious_artifact``), so a rule keying on
    that literal matches just this run's submission — isolating a live/historical
    hunt from every other test's EICAR artifact (a generic EICAR-substring rule
    would match them all).
    """
    ident = re.sub(r'\W', '_', uid)
    return f'rule sdk_{ident} {{ strings: $u = "{uid}" condition: $u }}'


def assert_scanned(instance):
    """Assert a submitted/rescanned artifact actually ran through the scan
    pipeline: the entry isn't failed and carries engine **assertions and/or**
    arbiter **votes**.

    The e2e runs the single ``eicar`` microengine, so a scanned EICAR artifact
    surfaces at least one assertion (and an arbiter vote once the bounty window
    settles). Call this on a window-closed result (i.e. after
    ``api.wait_for(...)``) — see ``submit_and_scan`` / ``rescan_and_scan`` in the
    sync/async suites, which is where the "a file goes in and gets scanned" path
    is exercised and verified.
    """
    assert instance is not None, 'expected a scan result, got None'
    assert not instance.failed, (
        'scan failed: %r' % getattr(instance, 'failed_reason', None))
    assert instance.assertions or instance.votes, (
        'a completed scan must carry engine assertions and/or arbiter votes — '
        'got neither (is the scan pipeline running?)')


def _vcr_off():
    """True on the live run (``TESTS_VCR=off``). Test-internal concurrency is
    gated on this. On VCR *replay* we stay serial: vcrpy patches the HTTP
    transport with ``mock.patch``, which isn't thread-safe — concurrent requests
    flake with ``'_patch' object has no attribute 'target'`` — and replay no-ops
    the poll sleeps anyway, so serial replay is already instant and matches the
    order the cassette was recorded in (so no re-record is needed). The
    concurrency only buys wall-clock against the live stack.
    """
    return os.getenv('TESTS_VCR', 'on').lower() == 'off'


def run_concurrently(fns):
    """Run zero-arg callables concurrently on the live run, serially on replay
    (see ``_vcr_off``). Results are returned in input order; exceptions
    propagate. Use for independent same-test submits/dispatches whose ordering
    doesn't matter to the assertions."""
    if _vcr_off() and len(fns) > 1:
        with ThreadPoolExecutor(max_workers=len(fns)) as pool:
            return [f.result() for f in [pool.submit(fn) for fn in fns]]
    return [fn() for fn in fns]


async def run_concurrently_async(coros):
    """Async counterpart of ``run_concurrently``: ``asyncio.gather`` on the live
    run, awaited serially on replay. Consumes the passed coroutine objects
    either way; results are returned in input order."""
    if _vcr_off() and len(coros) > 1:
        return await asyncio.gather(*coros)
    return [await c for c in coros]


def poll_equals(read, want, tries=30, delay=1.0):
    """Poll a zero-arg ``read`` until it returns ``want`` (or tries run out),
    returning the last value read. For read-after-write assertions against
    replica-backed GET endpoints (specs/04 in the server repo): on the e2e
    stack the replica IS the primary so the first read usually wins, but a
    real-replica stack lags — without the poll those assertions are
    lag-flaky, and the changed-since-freeze one flakes in the silent
    direction (stale source body reads as "unchanged"). Not-found during the
    lag window counts as "not yet". Sleeps are free on VCR replay
    (``_skip_poll_sleep_on_replay``)."""
    from polyswarm_api import exceptions as _exceptions
    value = None
    for _ in range(tries):
        try:
            value = read()
        except (_exceptions.NotFoundException, _exceptions.NoResultsException):
            value = None
        if value == want:
            return value
        time.sleep(delay)
    return value


async def poll_equals_async(read, want, tries=30, delay=1.0):
    """The asyncio twin of ``poll_equals`` (``read`` is a zero-arg coroutine
    function)."""
    from polyswarm_api import exceptions as _exceptions
    value = None
    for _ in range(tries):
        try:
            value = await read()
        except (_exceptions.NotFoundException, _exceptions.NoResultsException):
            value = None
        if value == want:
            return value
        await asyncio.sleep(delay)
    return value
