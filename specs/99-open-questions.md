# Open Questions

## Scope

Known follow-ups and unresolved questions that haven't been decided yet. Each item is something a future PR will need to address; this file is the parking lot. Move items out (to the relevant spec) once they're resolved.

## Test-suite parametrisation rollout

**Status:** partial.

The parametrised `ClientTestCase` harness in `test/metadata_field_properties_test.py` is the canonical pattern for running each test against both sync and async clients. `client_scan_test.py` (sync) and `async_client_test.py` (async) still have parallel test bodies for the bulk of the endpoint surface.

**Action:** migrate each test pair into a `ClientTestCase` subclass, delete the original sync / async copies, re-record cassettes where the request shape differs. Mechanical work, ~one chunk per resource family.

**Decision point:** when a test scenario does something inherently async (concurrency, cancellation, owned-vs-injected client lifecycle), it stays as a standalone `async def test_*` — those don't fit the parametrised harness. Document that in `04-testing.md` with worked examples once we have any.

## Test parallelism against the live e2e (`pytest -n`)

**Status:** planned — the suite is already isolation-safe; gated on e2e pipeline capacity.

**Goal:** run ≥8 tests concurrently against the live stack so the VCR-off `e2e` CI job (currently ~9 min serial) finishes in ~2–3 min.

**Why it's feasible.** The suite is self-contained: each test creates uniquely-identified resources (`malicious_artifact(uid)`, `uid_ip` / `uid_host` / `uid_yara`, all deterministic per `request.node.name`), asserts only on its own data, and shares no mutable test state. `pytest -n auto` on *replay* already passes (32 workers), and `pytest-xdist` is in the `[tests]` extra — so test-level isolation is done.

**Why it isn't just `-n 8`.** The gating factor is the e2e stack's async-pipeline throughput, not the test code. A `-n 3` VCR-off live run flaked the forward `iocs_by_hash` test: the `cape_sandbox_v2` Celery metadata-persist lagged past the 90-iteration poll window under 3× concurrent load. The stack runs only a handful of Flask/Celery workers, so 8 concurrent test workers will starve the scan / metadata / sandbox / ES pipelines unless (a) poll windows scale with load and (b) the stack gets more worker capacity.

**Upside.** Serial wall-clock is dominated by *sequential* waits — scan `window_closed` (~32s each), sandbox completion, IOC/metadata polls. Scan settling is a **global** event (the chain block advances for all in-flight scans at once via the periodic job-phase), so N concurrent scans wait for the *same* close and finish together. Parallelism collapses those sequential waits → an estimated 3–4× speedup.

**Plan:**

1. **Runner (this repo):** add `-n 8 --dist loadgroup` to the `docker/Dockerfile` CMD; keep `--timeout-method=thread` (the only pytest-timeout method that fires under xdist + asyncio). Unit/replay CI jobs stay unchanged (already parallel-safe).
2. **Poll resilience (this repo):** centralize the poll budget and scale `tries` by `PYTEST_XDIST_WORKER_COUNT` (e.g. ×`max(1, workers // 2)`) so a 90s-serial metadata/IOC poll gets headroom under load — directly closing the `-n 3` forward-IOC failure class. Polls are no-ops on replay, so only the live run pays the cost.
3. **Serial-group the global-mechanism tests (this repo):** mark `test_stream` (global archiver batching) and `test_live` (global live feed) `@pytest.mark.xdist_group("serial")` so they share one worker while everything else parallelizes. Both are already scoped to their own sha / livescan_id, so the grouping is defensive and can be relaxed after measuring.
4. **Stack capacity (paired change in the e2e harness — not this repo):** raise the artifact-index Flask + Celery worker concurrency so 8 concurrent workloads don't queue. Without this, `-n 8` stays flaky regardless of the test-side work. Flag it for the harness owner.
5. **Validate:** a full VCR-off `-n 8` run green + a measured speedup vs serial; iterate the poll-scaling factor if flaky. No cassette re-record needed — xdist changes only the live run; replay is deterministic and already `-n auto` green.

**Risks / notes:** stack starvation → poll timeouts (mitigated by 2 + 4); global-mechanism contention (mitigated by 3); xdist + asyncio coexist (each worker gets its own event loop; `uid` is deterministic-per-test, so resources never collide across workers — proven on replay).

## `sandbox_url` finalize-param inconsistency — RESOLVED

**Status:** fixed in this PR.

Earlier in PR #298 `sandbox_url` finalized with `params={"sandbox_task_id": ...}` while `sandbox_file` used `params={"id": ...}`, and **both** finalize PUTs dropped the `community` JSON body. That was a PR-introduced regression, not historical behaviour: 3.x finalized both flows via `SandboxTask.update_file(self, id=task.id, community=self.community)` — `id` in the query string and `community` in the body for *both*. `sandbox_task_id` is the param the GET *status* endpoint takes, not the finalize PUT; the two had been conflated.

Both flows now share a single `_finalize_sandbox_task(task)` helper that PUTs `params={"id": str(int(task))}` with `json={"community": self.community}`, so the finalize shape can't drift between them again. (`sandbox_url`'s *create* body was also missing `community`; it now matches `sandbox_file`.) Covered by respx tests asserting the finalize request method/url/params/body for both methods.

## `sandbox_providers` executed-request quirk

**Status:** preserved for backward compatibility.

The endpoint returns the executed `PolyswarmRequest` itself so callers can read `.json`. Pre-existing quirk; new code shouldn't pattern after it.

**Action:** decide on a future major version whether to convert `sandbox_providers` to return the parsed resource list (breaking change). Not blocking.

## `engines` property → method (downstream call-site updates)

**Status:** shipped in 4.0 (breaking).

`engines` changed from a cached *property* to a method on both clients — `api.engines()` (sync) / `await api.engines()` (async). Python properties can't `await`, so adding the async client forced the change; the codegen escape hatch that used to patch a sync-only property is gone, and sync/async are now fully unasync-mirrored with no per-symbol patches. See `05-downstream-contract.md`.

**Action:** update downstream consumers that read `api.engines` as an attribute to call it instead (`for e in api.engines` → `for e in api.engines()`). Known caller: **polyswarm-cli** — grep it for `.engines` and ship a paired update before/with the 4.0 release so the CLI doesn't break. `refresh_engine_cache()` is unchanged.

**Decision point:** none — the v4 break is intended; this entry just tracks the downstream follow-up.

## Pagination heuristic — `_single` vs `_paginate`

**Status:** decided per-endpoint, no fully formal rule.

The choice is based on caller expectations:

- Callers that index (`api.foo()[0]`) need a list-returning `_single` (or wrap in `list()`).
- Callers that iterate (`for x in api.foo()`) work with either.
- Async callers that `async for x in api.foo()` need `_paginate` (so the method itself is an async generator and no `await` is needed).

There's no automatic detection — it's per-method. Documented in `03-endpoints.md`.

**Action:** keep an eye on whether new endpoints add ambiguity. If a clear rule emerges (e.g. "any method whose docstring says 'Generator of X' is `_paginate`"), formalise it.

## Boolean param wire format

**Status:** normalised via `_normalise_bool_params` in `core.py`.

`httpx` writes `True` / `False` as lowercase `true` / `false` by default; `requests` used `str(bool)` (capitalised). Existing VCR cassettes were recorded against the capitalised form. The normalisation runs on both sync and async sessions to keep cassettes replaying.

**Action:** longer-term, decide whether the SDK should normalise this at all or just pass through whatever httpx serialises. Cassettes are an internal concern; consumers don't care about wire format. We could drop the normalisation if we re-record all cassettes once.

**Decision point:** doing nothing has zero risk; doing it costs the maintenance burden of `_normalise_bool_params`. The normalisation pays for itself the next time we change clients or transport library, so keep it.

## VCR-off CI matrix — RESOLVED

**Status:** configured.

The invariant "tests must pass against the live e2e stack with VCR off" is now exercised by the GitLab `e2e` CI job: it builds a `polyswarm-api` image (`docker/Dockerfile`, `ENV TESTS_VCR=off`) and runs the full suite against the running e2e stack with VCR bypassed — `TESTS_VCR=off` makes `@vcr.use_cassette` a no-op and keeps the real poll/sleep pacing (see `test/conftest.py`). The fast unit jobs still run cassette-replay; the live job catches drift the cassettes would mask.

## `requests` → `httpx` constructor kwarg translation

**Status:** documented in `05-downstream-contract.md`.

`PolyswarmAPI(**kwargs)` forwards to `httpx.Client` instead of `requests.Session`. Most kwargs translate; some have minor renames (`proxies` dict shape, `verify` SSL context).

**Action:** add a worked migration example for the most common kwargs. Possibly add explicit pass-throughs (`PolyswarmAPI(timeout=…, verify=…, transport=…)`) so callers don't have to know which kwargs httpx accepts.

## Endpoint deprecations

**Status:** none formally tracked.

Some endpoint methods are likely legacy (early-API artifacts, replaced by newer methods, deprecated server-side). There's no `DeprecationWarning` mechanism in the SDK today.

**Action:** when a method is deprecated server-side, the SDK should warn at call time. Define a convention (`warnings.warn(DeprecationWarning, …)`) and add to relevant methods as we identify them.

## Auth surface evolution

**Status:** `Authorization: <api-key>` only.

The server may move to OAuth / signed requests / per-request auth tokens in the future. The SDK assumes a single API key for the lifetime of a session instance.

**Action:** if / when the auth model evolves, design the integration point on `PolyswarmSession` / `AsyncPolyswarmSession` (token refresh hook? credential plugin? `auth=` constructor parameter?) and update `05-downstream-contract.md`.

## Streaming downloads — `HttpxResponseAdapter` fully buffers

**Status:** download responses buffer the entire body before chunking.

`core.py::HttpxResponseAdapter.__init__` reads `response.content` (the full body, eagerly) and then `iter_content(chunk_size)` slices that in-memory buffer. The session also goes through `client.request(...)` / `client.send(req)`, never `client.stream(...)`. So every download endpoint — `download`, `download_to_handle`, `download_archive`, `download_sandbox_artifact`, `download_zip` (bundle), `download_report` (report / LLM-report), `download_logo`, and the `stream` archive feed — spikes memory proportional to the artifact size before the destination file sees the first byte. Pre-4.0 (`requests`-backed) streamed straight from the socket.

This is a regression in memory profile but not in correctness — small artifacts behave identically, and the bytes ultimately reach the destination handle.

**Action:** refactor the session to detect streaming parsers (`request.result_parser is not None and not issubclass(request.result_parser, BaseJsonResource)`), open the response via `await self._client.stream(method, url, **kwargs)` as an async context manager, wrap it in an async-aware adapter whose `iter_content` yields from `response.aiter_bytes(chunk_size)`, and close the response after `parse_response` finishes. The sync mirror gets the same shape via unasync rewrites of `aiter_bytes` → `iter_bytes`, `async with` → `with`, `aclose` → `close`.

**Decision point:** the refactor crosses the sync/async boundary because `LocalArtifact.__init__` is currently sync-only and calls `iter_content` synchronously. Either keep the sync `iter_content` path (with the adapter caching chunks lazily) or split `LocalArtifact.parse_result` into an async-aware variant. Either is non-trivial; documenting + deferring is the right call for the 4.0 release.

## Tests blocked on upstream artifact-index issues

**Status:** 2 unique tests (4 cassettes including sync+async pairs) currently skip with `@pytest.mark.skip` — both environment-dependent (need sandbox workers / microengine cluster locally), not upstream bugs. Every other endpoint test is hermetic and self-provisions via SDK calls against a freshly-provisioned `make reset-database` e2e.

### ✅ Fixed by upstream artifact-index PR #1877: `tool_metadata` round-trip

The previous 500 on `GET /v3/artifact/metadata/list` was two stacked bugs in `views/v3/artifact.py::MetadataListView`:

1. The view used `app.session_ro.query(...)` directly instead of `utils.db.ro_session()`. The RO session has `autobegin=False`, so executing the query without an explicit transaction raised `InvalidRequestError("Autobegin is disabled on this Session…")` and the middleware mapped it to 500.
2. `instance_id` arrived as a string but the column is BIGINT, so once #1 was fixed Postgres raised `operator does not exist: bigint = character varying`.

Both fixed in artifact-index #1877. SDK side: `test_tool_metadata` (sync + async) is un-skipped and self-provisioning via `submit() → tool_metadata_create() → poll tool_metadata_list()`.

### ✅ Resolved: `iocs_by_hash` / `search_by_ioc` un-skipped

Earlier diagnosis (last_scanned_instance pointing at the wrong sibling) turned out to be wrong. The real causes were two non-bug behaviours that just needed test-side adjustments:

- **`filter_known_good_iocs` drops "known-good" IPs.** The original test used `1.2.3.4`, which is in the `ioc_known` table from neighbouring known-host tests (and survives via the `ioc_cache` even after the row is deleted from the DB, because cache invalidation is async via `long_running.reload_ioc_cache.apply_async`). Filtered as expected — that's correct security behaviour. Switching the test IP to `9.42.0.1`/`9.42.0.2`/`9.42.0.3`/`9.42.0.4` (public IBM netblock, never marked known-good) avoids the filter.
- **`persist_external_metadata` lag.** The Celery task that writes `cape_sandbox_v2` metadata into the ArtifactInstance graph takes ~30s under suite load (single Celery worker, queue contention from the sandbox / metadata / persist queues all converging). The original poll was 15s. Bumped to 60s.

Both tests now self-provision and pass cleanly. Cassettes recorded with the fixed IPs replay deterministically.

### 1. `sandboxtask_latest` (sync + async) — `SandboxTaskSearchHash` only populates on SUCCEEDED tasks

[`artifact_index/services/sandbox.py::update_sandbox_search`](https://github.com/polyswarm/artifact-index/blob/master/src/artifact_index/services/sandbox.py) only writes to `SandboxTaskSearchHash` when `task.status == 'SUCCEEDED'`. On a fresh e2e without active cape/triage workers, queued tasks stay PENDING forever, so `latest` returns 404 "No tasks found".

This is environment, not bug — but it does mean the test can't be hermetic without a worker stub. The sync `sandboxtask_list` IS hermetic and passes: it queries `SandboxTask` directly, no SearchHash dependency.

### 2. `live` (sync + async) — requires the bounty / microengine pipeline

`live_start` returns a `LiveYaraRuleset` with `livescan_id=None` because the local e2e has no microengines processing submissions. The lifecycle calls (`ruleset_create`, `live_start`, `live_stop`) all return 200, but the feed never receives results and `livescan_id` doesn't get assigned. Same shape as #1 — environment, not bug.

## What works (the other 42 cassettes)

After the test refactor — provision-via-SDK in the test body, captured-returned-ids, structural rather than count assertions, deterministic test inputs (fixed IPs to avoid VCR-replay mismatch) — every endpoint test outside the two environment-dependent groups above regenerates cleanly against `make reset-database` + the provisioning script. The cassettes get re-recorded on every `rm test/vcr/*.vcr && pytest test/`. Subsequent runs replay deterministically because each test is its own self-contained transaction against the e2e.

The pattern (see `test/client_scan_test.py` / `test/async_client_test.py`):

```python
@vcr.use_cassette()
def test_rescans(self):
    api = PolyswarmAPI(self.test_api_key, uri=…, community='gamma')
    api.submit('test/malicious')          # provision: artifact exists
    result = api.rescan(SHA256)           # then exercise the endpoint
    …
```

Cleanup with `try/finally` + `except NotFoundException: pass` tolerates the ioc-cache divergence (GET-by-host can serve a cached id that DELETE-by-id no longer finds). When that artifact-index bug is fixed the `except` becomes redundant.
