# Testing — pure unit, mocked I/O, recorded cassettes

## Scope

How the test suite is organised. Three layers: pure unit tests (no HTTP at all — exercising resource builders and `parse_response`), `respx`-mocked I/O tests, and `vcrpy` cassette-replay tests. The `ClientTestCase` parametrisation harness runs the mocked-I/O bodies against both transports.

## Invariants

1. **E2e-first: endpoint behaviour is tested against the real server, not a mocked response.** New endpoint tests call the live e2e stack and record a VCR cassette so unit runs replay it offline. Mock the HTTP boundary (`respx`) **only** when exercising the scenario on the e2e stack is disproportionately costly (e.g. forcing transport-level failures, retry exhaustion, pagination-cursor pathologies the server won't produce) or the dependency is an external system that isn't part of the stack. A fabricated `respx` response asserts what we *think* the server returns; a cassette asserts what it *actually* returned.
2. **Tests must pass against the live e2e stack with VCR off.** VCR is an efficiency cache, not a load-bearing requirement. Don't hardcode `record_mode='none'`. If a test only works against the recorded cassette, that's a test bug.
3. **Cassette re-recording is delete-driven, and recording is live-only.** `rm test/vcr/<name>.vcr && pytest …<test>` re-records against the live e2e. `record_mode='once'` (the default) makes this work without flag-flipping. Cassettes are always produced by running the test against the live stack — never copied from a sibling test's cassette and never hand-edited (beyond scrubbing sensitive values).
4. **One cassette serves both transports.** Sync and async tests targeting the same scenario use the same on-the-wire request shape (because both clients run on `httpx`). The VCR matcher is configured so cassettes survive `httpx`'s param-ordering differences from the original `requests`-recorded format — see "VCR matcher convention" below.
5. **`respx` tests (where justified under invariant 1) use the parametrised `ClientTestCase` harness** *when the scenario is transport-agnostic*. It auto-emits `<Name>Sync` and `<Name>Async` siblings so one body runs against both clients; don't hand-write parallel sync / async respx bodies for the same scenario. Two exemptions: live/VCR tests can't use it at all (`_AsyncToSync` is respx-only, so they follow the `client_scan_test.py` / `async_client_test.py` pattern), and a case that is *inherently* one-transport — an async-only streaming or cancellation behaviour, or a mapping arm asserted once because it is transport-independent — belongs beside its transport's own module. The direct-`respx` bodies in `client_scan_test.py` / `async_client_test.py` are those cases. Most predate the harness and do not argue their exemption — treat the rule as forward-looking: a **new** respx body that is transport-agnostic goes on the harness, and one that does not should say why in its docstring. Don't read the existing set as a worked example of the rule.
6. **The HTTP mocking library follows the transport.** Both clients use `httpx`, so `respx` is the mocking library.
7. **Prefer the pure-unit tier for builder + parse logic.** `PolyswarmRequest` builders are pure data; `parse_response` is a pure function. They're testable without httpx, async, or fixtures. Use this tier for any bug that can be reproduced without network involvement — including request-shape assertions (body vs query routing, None-omission, bodyless DELETE) that a cassette can't express directly.
8. **The live VCR-off run is parallel (`pytest -n 8`).** New tests must be isolation-safe: own uniquely-keyed resources (deterministic per-test `uid` — `malicious_artifact(uid)`, `uid_ip` / `uid_host` / `uid_yara`; hash-keyed resources derive their sha from the test's own EICAR variant via `malicious_artifact(uid)`), assert only on their own data, and share no mutable state, so xdist workers never collide. See "Running the suite in parallel" below.

## Files

- `test/conftest.py` — pytest configuration.
- `test/core_test.py` — pure-unit tests for `parse_response`, `PolyswarmRequest`, and resource builders. No httpx, no fixtures.
- `test/exists_probe_mapping_test.py` — the `exists()` status mapping arms the e2e stack cannot produce (`404`→`False`, plus the fabricated-negative `5xx` case recorded as a decision), on the shared harness so both transports are covered. The `200`/`204` arms are live, in `client_scan_test.py` / `async_client_test.py`.
- `test/_client_harness.py` — the parametrised `ClientTestCase` harness (`_MockBoundary` / `_AsyncToSync`), importable by any `respx` module that wants one body to cover both transports (invariant 5). Not every `respx` user needs it: `client_scan_test.py` / `async_client_test.py` drive `respx` directly for a number of cases (~27 bodies between them), most of which predate the harness — see invariant 5 for which of those are legitimately exempt and which are just older than the rule. Not collected itself — it matches neither `*_test.py` nor `test_*.py`, so pytest never picks it up (the leading `_` is a naming convention, not the mechanism), same as `_e2e_helpers.py`.
- `test/metadata_field_properties_test.py` — the canonical example of the parametrised `ClientTestCase` harness with `respx`-backed mocking.
- `test/client_scan_test.py` — sync, VCR-backed integration tests (not yet on the parametrised harness — follow-up work).
- `test/async_client_test.py` — async, VCR-backed integration tests (not yet on the parametrised harness — follow-up work).
- `test/jmespath_test.py` — unit tests for `BaseJsonResource.jmespath`.
- `test/vcr/*.vcr` — recorded cassettes.
- `test/malicious` — fixture file for upload tests (`test/eicar.yara` was retired when the rules tests moved to per-test `uid_yara` bodies).
- `test/hunt_tracking_builder_test.py` — pure-unit request-shape and parse tests for the hunt-page tracking builders/resources.
- `test/ruleset_favorite_respx_test.py` — dual-transport (`ClientTestCase`) respx suite for the favorite toggle: the `FAVORITE_LIMIT` refusal envelope and the query/body split.

## Three test layers

The SDK is tested at three levels:

| Layer | Tool | What it covers | When to use |
|---|---|---|---|
| **Pure unit** | none | Resource-builder shape (`Foo.bar(api, ...)` returns a `PolyswarmRequest` with method/url/params as expected). `parse_response` behaviour (`parse_response(fake_response, request)` populates fields or raises). `jmespath`, helpers. | Anything that can be tested without HTTP. Fast, deterministic, no fixtures. |
| **Mocked I/O** | `respx` | End-to-end call against a mocked httpx transport. The full pipeline runs (api → session → execute → parse_response → resource constructor), but no real network — the response is fabricated by the test. | **Only** when the live e2e stack can't reasonably produce the scenario: transport-level failures, retry exhaustion, pagination-cursor pathologies, external systems that aren't part of the stack. |
| **Cassette replay** | `vcrpy` | Records real HTTP exchanges against the live e2e; replays them on subsequent runs. | **The default for endpoint behaviour.** Real-server correctness, server-shape regression detection. |

The pure-unit tier exists because the 4.0 redesign made it possible: resource builders and `parse_response` are pure functions of their inputs. Use it aggressively — a unit test for "did this builder produce the right URL?" runs in microseconds and doesn't break when the test framework changes.

**VCR-backed live-e2e tests are the default for new endpoint tests** (invariant 1): they exercise the real server implementation and the cassette pins the actual contract, while replay keeps unit runs fast and offline. `respx` is reserved for scenarios the e2e stack can't produce (or only at disproportionate cost); pure-unit covers request-shape and parse logic without any HTTP. The canonical split for a new endpoint: a live-e2e VCR lifecycle test (behaviour, real contract) + pure-unit builder tests (body-vs-query routing, None-omission) — see `test_known_good_lifecycle` + `test/known_good_test.py`.

### The transport arm

The SDK's own **transport arm** is worth naming, because the obvious reading gets it wrong. The streaming download path (`_execute_download`) never runs `parse_response` — it reads the error body itself and calls `_raise_for_status` — so its non-2xx mapping *looks* like a scenario only respx can reach. It is not: a **cassette-backed** endpoint test drives it end to end, because the caller-visible outcome (the typed exception, its payload, and an empty destination directory) **is** the mapping. The known-good download refusal is covered exactly that way, in `client_scan_test.py` and `async_client_test.py`, so both `_execute_download` implementations — the canonical async source and its generated sync mirror — run against a real recorded envelope.

A respx body for that same arm was written first and deleted once the live coverage existed: keeping both left a second tier whose stated justification ("unreachable at the e2e tier") was no longer true, which reads as licence to reach for respx on any transport arm. Reach for it when the stack genuinely cannot produce the response — a connection reset, a retry ladder, a truncated body.

### E2e sample-generation conventions

- **The EICAR variant is the default sample-generation strategy.** Any test that needs an artifact — or just a sha256 — derives it from its own EICAR variant via `malicious_artifact(uid)` (`EICAR + uid` → unique content + sha, deterministic per test so cassettes replay). Don't invent parallel strategies (digest-of-test-name, random bytes, checked-in binaries) — one convention keeps every sha attributable to a test and keeps the eicar engine able to flag every sample.
- **All tests use only the `eicar` engine.** It's the single microengine (+ arbiter) in the e2e stack; tests must not depend on any other engine existing, and local stacks must not grow extra engines for testing. Anything that needs an assertion/verdict gets it from eicar flagging an EICAR-variant sample.

## The parametrised `ClientTestCase` harness

Implemented in `test/_client_harness.py`, importable by any `respx` module that wants one body over both transports; `metadata_field_properties_test.py` is the canonical user, joined by `exists_probe_mapping_test.py` (the `exists()` `404`→`False` arm, which was async-only until the harness existed — the mapping is transport-independent, so one body covers both) and `ruleset_favorite_respx_test.py` (the favorite toggle's refusal envelope + query/body split). The remaining `respx` bodies are the single-transport cases invariant 5 exempts. The shape:

```python
# test/_client_harness.py
from polyswarm_api.api import PolyswarmAPI
from polyswarm_api.aio import PolySwarmAsyncAPI

class _MockBoundary:
    """Wraps respx to mock both sync and async httpx transports.
    Tests call mock.add(method, url, json=…, status=…)."""

class _AsyncToSync:
    """Drives async-client methods from sync test bodies via asyncio.run.
    Each attribute access spins up a fresh event loop per call so unittest-
    style test bodies (result = self.api.foo(...)) stay unchanged."""

class ClientTestCase(TestCase):
    """Base test case. __init_subclass__ auto-emits <Name>Sync and
    <Name>Async siblings for every concrete subclass so each test method
    runs once against PolyswarmAPI and once against PolySwarmAsyncAPI.
    The original subclass is hidden from pytest via __test__ = False."""

    _client_kind = 'sync'

    def setUp(self):
        if self._client_kind == 'sync':
            self.api = PolyswarmAPI(...)
        else:
            self.api = _AsyncToSync(PolySwarmAsyncAPI(...))
        self.mock = _MockBoundary(self._client_kind)
        self.mock.__enter__()

    def tearDown(self):
        self.mock.__exit__(None, None, None)


# A concrete test class in any *_test.py module — same body runs twice.
# from test._client_harness import BASE_URL, ClientTestCase

class MetadataFieldPropertiesTestCase(ClientTestCase):
    def test_get(self):
        row = _sample_row()
        self.mock.add('GET', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        result = self.api.metadata_field_properties_get(field_path=row['field_path'])
        assert result.field_path == row['field_path']
```

What collects:

```
$ pytest test/metadata_field_properties_test.py --collect-only
…
MetadataFieldPropertiesTestCaseSync::test_get
MetadataFieldPropertiesTestCaseSync::test_write
…
MetadataFieldPropertiesTestCaseAsync::test_get
MetadataFieldPropertiesTestCaseAsync::test_write
…
```

Each test body is written **sync-shaped** (`result = self.api.foo(...)`). The async sibling drives it through `_AsyncToSync`, which calls `asyncio.run(...)` on the async result.

When the API method returns an async generator (paginated endpoint), `_AsyncToSync` drains it via `[item async for item in result]`. The test sees a list either way.

### `_MockBoundary` contract

```python
mock.add(method: str, url: str, json: dict, status: int = 200)
    Register a matched (method, url) → json response.

mock.last_request_url -> str
    The URL of the most recent request the mocked client made. Tests use
    this to assert query-string composition.
```

The implementation uses `respx.mock(assert_all_called=False)` for both `sync` and `async` because both clients run on `httpx`. No `responses` library is involved.

### Why `_AsyncToSync` over `pytest-asyncio` here

The async tests use `pytest-asyncio` in `asyncio_mode = "auto"` (configured in `pyproject.toml`). Two reasons we use the sync-facade pattern in `ClientTestCase` instead:

1. **Unittest TestCase compatibility.** `__init_subclass__` parametrisation requires the test bodies to be sync (TestCase doesn't natively support `async def test_*`). The facade keeps the harness compatible with unittest.
2. **Per-call event loop isolation.** Each call spins up a fresh event loop via `asyncio.run`. There's no cross-call state to leak — important for VCR replay determinism.

For tests that are inherently async (concurrency, cancellation, owned-vs-injected-client lifecycle), use `async def test_*` directly with `@pytest.mark.asyncio` (or auto mode) — the parametrised harness is for endpoint-level coverage, not lifecycle coverage.

**`_AsyncToSync` is respx-only.** The harness builds the `PolySwarmAsyncAPI` once in `setUp` (where its `httpx.AsyncClient` is constructed without an active event loop) and drives every subsequent test call via `asyncio.run(...)`. respx intercepts at the httpx transport layer, so it survives the fresh event loop per call. **A live HTTP integration test cannot reuse this harness** — `httpx.AsyncClient`'s connection pool is tied to the loop it was built against, and `asyncio.run` builds a new loop per call. If you reach for the harness for non-respx integration coverage, expect either RuntimeError (loop closed) or per-call connection churn. Add the integration test as a standalone `async def test_*` instead.

## VCR cassette workflow

`vcrpy` records each HTTP request/response pair on the first run and replays on subsequent runs. The cassette file (`test/vcr/<test_name>.vcr`) is checked in.

### Recording a new test

1. Write the test that calls the real endpoint.
2. Decorate the test method with `@vcr.use_cassette()`. The default path is `test/vcr/<test_name>.vcr`.
3. Run the test. With `record_mode='once'` (default), the cassette doesn't exist yet → VCR records the live exchange.
4. Inspect the cassette. Commit it.

### Re-recording an existing cassette

```bash
rm test/vcr/<cassette_name>.vcr
pytest test/<test_file>.py::TestClass::test_method
```

The deletion + re-run fires the live request again. **Never edit cassette YAML by hand** unless you're scrubbing sensitive header values; the recorded interactions are source-of-truth for the server's response shape.

### VCR matcher convention

For sync (recorded with `requests`-era cassettes):

```python
vcr = vcr_.VCR(
    cassette_library_dir='test/vcr',
    path_transformer=vcr_.VCR.ensure_suffix('.vcr'),
    # default matchers — includes 'query' (param-set match), not 'uri'
)
```

For async (and increasingly the canonical config):

```python
vcr = vcr_.VCR(
    cassette_library_dir='test/vcr',
    path_transformer=vcr_.VCR.ensure_suffix('.vcr'),
    match_on=['method', 'scheme', 'host', 'port', 'path', 'query'],
)
```

Why not `match_on=['method', 'uri']` (literal URI string)? `httpx` serialises query params in a slightly different order than `requests` did. With strict URI matching, cassettes recorded against `requests` mismatch on order even though the request is semantically identical. The `query` matcher compares params as a set, sidestepping the ordering issue.

### Boolean param normalisation

The HTTP session layer (`_normalise_bool_params` in `core.py`) converts Python booleans to capitalised strings (`'True'` / `'False'`) before they go on the wire. `httpx` writes them lowercase by default; the `requests` library used `str(bool)`. Existing cassettes were recorded against the capitalised form. The normalisation keeps them replaying without re-recording.

### Cassette filenames

Per-test: `<test_method_name>.vcr`. The `path_transformer=ensure_suffix('.vcr')` makes the `@vcr.use_cassette()` decorator pick the right filename automatically.

A single test method's cassette can hold multiple interactions (e.g. `test_submission` records `submit` → `upload` → `wait_for` → `lookup` chain). VCR plays them back in the order they were recorded.

### Sharing cassettes between sync and async

Where a sync test and an async test exercise the same scenario, they can share a cassette. The naming convention is to keep two files (`test_X.vcr` and `test_async_X.vcr`) but the content is identical. The parametrised `ClientTestCase` harness sidesteps this entirely — one test name, both clients use it.

For tests still split across `client_scan_test.py` / `async_client_test.py`, both clients send the same request shape — but each side still records its **own** cassette (per invariant 3, cassettes are produced by running the test live, never copied from the sibling). The shared matcher just means a sync-recorded cassette *would* replay for the async body; don't rely on that — record both.

## VCR-off mode (`TESTS_VCR=off`)

The implemented switch is the `TESTS_VCR` env knob: when `TESTS_VCR=off`, both VCR-configured test modules replace `vcr.use_cassette` with a no-op decorator at import time, so the whole suite runs live — no replay, no recording. `test/conftest.py` also keys off it (real poll pacing, concurrent helpers fan out). This is what the e2e CI job runs (it's baked into the test image: `ENV TESTS_VCR=off` in `docker/Dockerfile`):

```bash
TESTS_VCR=off pytest test/ -n 8 --dist worksteal --timeout=600 --timeout-method=thread
```

This proves the SDK works without the cache. The invariant: **every test must pass in VCR-off mode against the live e2e stack**. If a test only works against a recorded cassette, it's a bug in the test.

En-masse re-recording during major SDK changes is delete-driven and stays in default (VCR-on) mode: delete the affected cassettes, run the suite against a **freshly booted** e2e stack, commit the new cassettes. (Fresh boot matters: create-style tests are first-run-safe — their deterministic per-test keys already exist on a reused stack.)

## Running the suite in parallel (`pytest -n`)

The VCR-off live run executes the full `test/` suite 8-way against the live e2e stack via `pytest-xdist`. This is the default in the test image — the `docker/Dockerfile` CMD is `pytest test/ -n 8 --dist worksteal --timeout=600 --timeout-method=thread`. Measured A/B against the same live e2e stack (VCR off, full suite, 127 tests):

| Mode | Wall clock | Result |
|---|---|---|
| Serial (no `-n`) | ~7 min (428.77s) | 127/127 passed |
| Parallel (`-n 8`) | ~2 min (125.77s) | 127/127 passed |

That's a **3.41× speedup** (~5 min saved), zero flaky failures — every test passed, including the global-state ones (`test_stream`, `test_live`) and the forward `iocs_by_hash` / `test_async_iocs_by_hash` pair. (Serial wall-clock varies ~7–9 min with stack warmth/load; the 3.41× is the clean same-session number.)

### Why it's safe to parallelise

The suite is isolation-safe by construction: each test creates uniquely-keyed resources (deterministic per-test `uid`, `uid_ip` / `uid_host` / `uid_yara`, `malicious_artifact(uid)`), asserts only on its own data, and shares no mutable state, so workers never collide. xdist and asyncio coexist fine — each worker gets its own event loop. The global-mechanism tests (`test_stream`, `test_live`) are each scoped to their own sha / `livescan_id`, so they don't collide across workers either.

The speedup comes from collapsing *sequential* waits. Serial wall-clock is dominated by polling — scan `window_closed` settling, sandbox completion, IOC/metadata persistence. Scan settling is a **global** chain event (the block advances for all in-flight scans at once via the periodic job-phase), so N concurrent scans wait for the *same* close and finish together instead of serially.

### Why `-n` lives on the runner CLI, not in `addopts`

`-n` is deliberately kept out of `[tool.pytest.ini_options].addopts` in `pyproject.toml` and passed on the runner command line instead, so local and IDE runs stay serial (xdist scrambles `-s` live-log ordering and complicates breakpoints). Only the live CI image opts into parallelism. `pytest-xdist` and `pytest-timeout` are in the `[tests]` extra.

### Log output: dots by default, live logs opt-in

The suite prints **one progress char per test** (xdist dots) plus an end-of-run summary — not a line per test. Two things must be off for that, and both were easy to get wrong:

- **`-v` is not in `addopts`** — verbose mode prints every test's nodeid on its own line.
- **Live logging (`log_cli`) is off by default** — `log_cli = false` in `pyproject.toml`, and `test/conftest.py` does **not** set the `log_cli_level` *option*. This is the subtle one: pytest enables live logging when `log_cli` is true **or** the `log_cli_level` option is set, and live logging *also* forces every test onto its own nodeid line (verbose-style) **regardless of `-v`**. So live logging on a green 8-way run added ~130 noise lines to the harness log even with `-v` removed — the option must be left unset, not just `-v` dropped.

A **failing** test still prints its full traceback and its **captured** logs (the "Captured log call" section, rendered at `log_level` = `TESTS_LOG_LEVEL`, default `INFO`), plus the `-ra` short-summary recap. So the run is quiet on green and detailed on failure.

Opt back into live streaming when debugging a live-stack run with **`TESTS_LOG_CLI=1`** (or an explicit `--log-cli-level=…` on the CLI). `TESTS_LOG_LEVEL=DEBUG` raises both the captured and the live level and unpins the noisy replay/transport libraries (`vcr`, `httpx`, `httpcore`, `asyncio`). See `test/conftest.py`.

### Why `--timeout-method=thread` and `--timeout=600`

The timeout is a backstop for the live run: VCR-off keeps real poll/sleep pacing, so a non-terminating test would otherwise hang to the CI job limit. `--timeout-method=thread` is the only method that fires reliably here — the signal method can't interrupt a hang inside the asyncio event loop, whereas a watchdog thread fires regardless of loop state, dumps every thread's stack (showing where execution is stuck), then terminates. **Caveat:** the thread method ends the *whole session* on a per-test timeout rather than failing one test, so a hang fails the job with a stack dump instead of running to the job limit. The per-test budget was raised 300 → 600s to give headroom under 8× pipeline contention.

### No mitigations were needed

An earlier plan hedged that `-n 8` might need (a) poll windows scaled by `PYTEST_XDIST_WORKER_COUNT`, (b) the global-mechanism tests serial-grouped via `@pytest.mark.xdist_group`, and (c) more Flask/Celery worker capacity in the e2e harness. **None proved necessary** — `-n 8` passed 127/127 clean with default `--dist load` distribution:

- The failure class that motivated poll-scaling (a `-n 3` flake where the `cape_sandbox_v2` metadata-persist lagged past the poll window) was already closed earlier in the same change by a **settle-then-attach + 90-iteration poll** fix on the forward `iocs_by_hash` path. With that in place the test is stable at 8× concurrency.
- The global tests don't collide (each scoped to its own sha / `livescan_id`), so serial-grouping was unnecessary.
- The default distribution didn't starve the stack at 8 workers, so no capacity increase in the e2e harness was required.

### Scheduling, ordering, and intra-test concurrency

The runner uses `--dist worksteal` (idle workers steal queued tests from busy ones — ≥ static `load` for tail balance; `loadscope` is avoided because it groups by module and would *concentrate* the heavy live tests on fewer workers). `conftest.py`'s `pytest_collection_modifyitems` then front-loads the long-pole live tests so they start at t=0 and the ~100 unit/respx tests backfill the tail. Both are deterministic (keyed on `nodeid`) so every xdist worker collects the same order.

A few tests submit/dispatch several artifacts in one body; `run_concurrently` / `run_concurrently_async` (in `_e2e_helpers.py`) fan those out **only on the live run** and stay serial on replay — vcrpy patches the transport via `mock.patch`, which isn't thread-safe, and replay no-ops the sleeps anyway, so serial replay is both deterministic and instant (no cassette re-record needed).

**These are correctness/scheduling/cleanup wins, not the wall-clock lever.** The suite's floor is the per-scan settle (`window_closed`), which every settle-bound test on a worker's serial chain pays in full. That floor is **not** the xdist scheduling or the job-phase cadence (lowering the e2e periodicity 10→3 provably didn't move it — a single-scan settle stayed ~32s). It is set deterministically at bounty creation by **`bounty_duration`** (the assertion-window length, ~25s of the ~32s) **+ `ARBITER_VOTE_DELAY`** (~1s). `bounty_duration` is an **artifact-index `ScanConfig` field** — the `default` config the suite submits with — so the lever lives in the e2e/artifact-index config, not in this repo. The full bounty lifecycle and these knobs are documented authoritatively in artifact-index `specs/02-bounty-scan-lifecycle.md`.

### The scan-settle floor (the real speedup lever)

The e2e stack shrinks the floor for the live suite: `BOUNTY_DURATION=2` (seeds the `default`/`feed` `ScanConfig`s, via artifact-index `cli/db.py`) + `ARBITER_VOTE_DELAY=0` + the job-phase periodicity at 1s, collapsing the per-scan settle from ~32s to ~10s (measured: a single scan went 32s → ~10s). For the full `-n 8 --dist worksteal` suite that took **~129s → ~30–65s** (warm ~32s, cold ~67s) — a ~2–4× cut on top of the parallelism, and ~6–13× versus the original ~429s serial. `bounty_duration=2` sits right at the eicar engine's ~2s assertion latency but is validated stable under 8-way load, so scans still produce real assertions **and** an arbiter vote; `assert_scanned` is the guardrail that fails loudly if the window is ever cut too short. Beyond this, the only further lever is sharing one settled artifact across read-only tests (per-worker fixture) to cut how many settles land on the critical chain.

If a future test family must run on a single worker (a global-mechanism test that can't tolerate cross-worker concurrency), mark its tests `@pytest.mark.xdist_group("<name>")` and switch the CMD from `--dist worksteal` to `--dist loadgroup`.

### Testing a paired server-side change locally (`build → tag latest → e2e run -pin`)

Some SDK behaviour depends on the **server** (artifact-index / polyswarmd3), and a fix there (e.g. the `BOUNTY_DURATION`-driven seed, or a read-your-writes cache fix) can't be exercised against the registry image the e2e stack pulls by default. To run the live suite against **local, uncommitted** server changes — without pushing or waiting on CI:

1. Build the service image from its repo, matching its CI `build` job (`extends: .build-docker`; image `${REGISTRY_URL}/<BASE_IMAGE_NAME>`, built from `docker/Dockerfile`). Private PolySwarm deps need the `PIP_INDEX_URL` build-arg from `~/.config/secrets/terminal.env` (interactive shells) or `~/.config/secrets/claude.env` / `~/.netrc`:
   ```bash
   set -a; . ~/.config/secrets/terminal.env; set +a
   cd ../artifact-index && docker build -f docker/Dockerfile \
     --build-arg PIP_INDEX_URL="$PIP_INDEX_URL" \
     -t 077282062506.dkr.ecr.us-east-2.amazonaws.com/artifact-index:latest .
   ```
2. Boot the stack with `e2e run -pine` (`--skip-pull --image-default-tag --no-commands --expose-ports`): `-p` keeps your local `:latest` from being overwritten by an ECR pull, `-i` pins the compose default tag, `-n` skips the SDK command step so you run the suite yourself, and `-e` publishes host ports — required for running the suite from the host (the tests target `artifact-index-e2e:9696`, which resolves to `127.0.0.1` via `/etc/hosts` but only answers when ports are published). Then `TESTS_VCR=off pytest test/ -n 8 --dist worksteal --timeout=600 --timeout-method=thread` against it. (All *other* images must already be cached locally — warm them with one normal run first.) The authoritative writeup lives in the e2e repo's `specs/04-images-and-registry.md`.
3. Between iterations, tear down before re-booting — a leftover container collides with the fresh boot: `docker ps -aq --filter name=e2e | xargs -r docker rm -f`. **If the stack lands in a bad state, restart it whole** (teardown + fresh `e2e run -pine`) rather than repairing services in place — simpler and faster, and create-style tests are first-run-safe on a fresh DB.

## The e2e stack is not prod: no read replica, collapsed delays

A live-stack difference that bites tests which drive server-side **read-after-write** flows. In production artifact-index reads through a real **read replica** (a separate, asynchronously-replicated DB behind `DB_URI_RO`) with a sub-50ms lag, and has a family of `DELAYED_IN_REPLICA_*` delays sized around it — the canonical "wait for propagation" delay is `DELAYED_IN_REPLICA_RETRY_DELAY` (**3s**, a safe upper bound), and the sandbox promotion's *pre-emptive* ETA is `DELAYED_IN_REPLICA_RETRY_LONG_DELAY` (**30s** of generous headroom, not the lag itself). The e2e stack has **no replica** — `DB_URI_RO` points at the same Postgres as the primary — so it collapses those delays to **~1s** for speed. The authoritative writeup is artifact-index `specs/04-read-replica-and-environments.md`; what matters here is that **e2e's timing margins are much tighter than prod's**, so a server sequence that prod's 30s margin makes safe can race under e2e load.

**Concrete impact — the synthetic sandbox completion must model a real sandbox's cadence.** With no cape/triage VMs in e2e, `_complete_sandbox_task` (`client_scan_test.py` / `async_client_test.py`) drives a SandboxTask to `SUCCEEDED` by replaying the sandbox worker's HTTP calls: upload a `report` artifact, then post `COLLECTING_DATA` (status=8). On the backend those two land as **independent, unordered** tasks on the same `ai_sandbox_done` queue — the report-create writes `SandboxTask.artifact_metadata_id`, and the `COLLECTING_DATA → SUCCEEDED` promotion only fires when it reads that FK as set. The promotion's safety net is dispatched with `eta = +DELAYED_IN_REPLICA_RETRY_LONG_DELAY` (30s prod / 1s e2e). A real sandbox has a natural gap between finishing its upload and signalling done; posting status=8 **back-to-back** does not, so under load both promotion attempts can evaluate the FK before it commits → `SUCCEEDED` never happens → the `SandboxTaskSearchHash` row is never written → `sandbox_task_latest` raises "No tasks found". That was the `test_async_iocs_by_hash` flake at `BOUNTY_DURATION=2`.

The fix is a deliberate **~2s gap** (`time.sleep(2)` / `await asyncio.sleep(2)`) before the status=8 post in both `_complete_sandbox_task` helpers — it restores the real-world sequencing so the FK commits and the delayed promotion fires first, leaving status=8 a no-op backstop (exactly how prod's 30s margin behaves). **Don't remove it**, and apply the same modelling to any new helper that drives a server read-after-write flow. This sleep does **not** slow the replay suite: `conftest._skip_poll_sleep_on_replay` no-ops `time.sleep`/`asyncio.sleep` whenever a cassette is present, so it's real only on the live/recording run — which is the rule below ("don't `time.sleep()` in tests") read precisely: it bans gratuitous waits in test bodies, not live-pacing waits inside the poll/completion helpers.

## Adding a new test

Decision tree (e2e-first — see invariant 1):

1. **Pure logic test?** (No HTTP, no resource side effects — including request-builder shape and `parse_response`.) → Plain unittest / pytest function. See `jmespath_test.py`, `core_test.py`, `known_good_test.py`.
2. **Endpoint behaviour?** → **VCR-backed live-e2e test — the default.** Write the test against the real endpoint, record once against a fresh e2e stack, commit the cassette. Sync body in `client_scan_test.py`, async in `async_client_test.py`. Need a sample or a sha? Derive it from the test's own EICAR variant (`malicious_artifact(uid)`); anything needing a verdict gets it from the `eicar` engine.
3. **Scenario the e2e stack can't produce** (transport failures, retry exhaustion, cursor pathologies, external systems)? → Parametrised `ClientTestCase` with `_MockBoundary` (`respx`), imported from `test/_client_harness.py`. See `metadata_field_properties_test.py` (endpoint shape). A **transport arm is not on that list**: the stack drives one perfectly well, because the caller-visible outcome is the mapping — see §The transport arm. Body covers both sync and async automatically. Justify in the test docstring why the scenario can't run on e2e.

Always:

- Test method name matches the cassette filename (`@vcr.use_cassette()` auto-derives).
- Assert on resource attributes, not raw JSON, except where the test is specifically about JSON shape.
- Don't `time.sleep()` in **test bodies** — VCR replays instantly, so polling loops complete in microseconds. Live re-recording blocks on real platform timing, which is expected. (Live-pacing sleeps that belong inside the poll/completion *helpers* — e.g. the real-world gap in `_complete_sandbox_task`, see "The e2e stack is not prod" above — are fine: `conftest._skip_poll_sleep_on_replay` no-ops them on replay, so they're real only on the live run.)

## Outstanding test work

`client_scan_test.py` (sync) and `async_client_test.py` (async) still have parallel test bodies for the bulk of the endpoint surface. Rolling them onto the `ClientTestCase` parametrisation is mechanical — same shape as the metadata test — and is the next chunk of test consolidation work.

Each migration:

1. Move the test body into a `ClientTestCase` subclass.
2. Convert `async with self._api() as api: ...` to `self.api...` (the harness owns construction).
3. Convert `async for x in api.foo(...)` to `for x in api.foo(...)` — the `_AsyncToSync` proxy materialises async generators when called from sync context, and `_paginate` already returns sync generators for the sync client.
4. Delete the corresponding entry from both `client_scan_test.py` and `async_client_test.py`.
5. Run the suite. Cassettes that no longer match get re-recorded against e2e.
