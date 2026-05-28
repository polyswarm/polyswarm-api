# Open Questions

## Scope

Known follow-ups and unresolved questions that haven't been decided yet. Each item is something a future PR will need to address; this file is the parking lot. Move items out (to the relevant spec) once they're resolved.

## Test-suite parametrisation rollout

**Status:** partial.

The parametrised `ClientTestCase` harness in `test/metadata_field_properties_test.py` is the canonical pattern for running each test against both sync and async clients. `client_scan_test.py` (sync) and `async_client_test.py` (async) still have parallel test bodies for the bulk of the endpoint surface.

**Action:** migrate each test pair into a `ClientTestCase` subclass, delete the original sync / async copies, re-record cassettes where the request shape differs. Mechanical work, ~one chunk per resource family.

**Decision point:** when a test scenario does something inherently async (concurrency, cancellation, owned-vs-injected client lifecycle), it stays as a standalone `async def test_*` — those don't fit the parametrised harness. Document that in `04-testing.md` with worked examples once we have any.

## `sandbox_url` finalize-param inconsistency

**Status:** pre-existing behaviour preserved across the 4.0 redesign.

`sandbox_file` and `sandbox_url` both PUT to `{SandboxTask.RESOURCE_ENDPOINT}/instance` to finalize the submission, but they pass the task identifier under different param names:

- `sandbox_file` → `params={"id": str(int(task))}`
- `sandbox_url` → `params={"sandbox_task_id": str(int(task))}`

Both shapes have shipped this way historically; no VCR cassette covers the `sandbox_url` finalize path, so we can't confirm from replay alone which (if either) is wrong.

**Action:** record a cassette against the live e2e for `sandbox_url`'s full flow, then either confirm the divergence is required or reconcile on `id` (matching `sandbox_file`).

**Decision point:** don't reconcile blindly — there's a real (if small) risk that the URL-sandbox endpoint variant rejects `id`.

## `sandbox_providers` executed-request quirk

**Status:** preserved for backward compatibility.

The endpoint returns the executed `PolyswarmRequest` itself so callers can read `.json`. Pre-existing quirk; new code shouldn't pattern after it.

**Action:** decide on a future major version whether to convert `sandbox_providers` to return the parsed resource list (breaking change). Not blocking.

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

## VCR-off CI matrix

**Status:** not configured.

The invariant says "tests must pass against the live e2e stack with VCR off". There's no CI job that runs this; cassette-replay is the only mode CI exercises.

**Action:** add a CI matrix entry that runs `pytest` with `test/vcr/` temporarily renamed. It exercises the SDK against the live e2e and catches drift early.

**Decision point:** which e2e environment does CI hit, and how is the API key managed? Likely a secret + a stage-equivalent endpoint.

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

**Status:** 5 unique tests (10 cassettes including sync+async pairs) currently skip with `@pytest.mark.skip` referencing specific upstream issues. All other endpoint tests are now hermetic — they provision their own state via SDK calls in setUp and run cleanly against a freshly-provisioned `make reset-database` e2e.

### 1. `tool_metadata` (sync + async) — `GET /v3/artifact/metadata/list` 500s

The POST half (`tool_metadata_create`) works (200) and writes a `Metadata` row plus queues `persist_external_metadata` via Celery. The GET (`tool_metadata_list?instance_id=X`) returns 500 "Something went wrong" — that string is the catch-all in [`artifact_index/views/v3/utils/decorators.py`](https://github.com/polyswarm/artifact-index/blob/master/src/artifact_index/views/v3/utils/decorators.py) middleware. The actual exception is `logger.exception`-ed but only visible in the artifact-index console.

Reproducible via curl: `POST /v3/artifact/metadata` 200, then `GET /v3/artifact/metadata/list?instance_id=<id>` 500. Filed as upstream artifact-index follow-up.

### 2. `iocs_by_hash` / `search_by_ioc` (sync + async) — IOC views don't surface posted metadata

After `tool_metadata_create(instance.id, 'cape_sandbox_v2', {'extracted_c2_ips': ['1.2.3.4'], ...})`, the metadata IS attached to the instance (confirmed by `GET /v3/search/hash/sha256?hash=…` returning the cape_sandbox_v2 blob in the `metadata` list). But `GET /v3/ioc/sha256/<hash>` returns empty `ips`/`ttps`, and `GET /v3/ioc/search?ip=1.2.3.4` returns no results.

Two likely root causes under investigation (both upstream):

- **Stale memoize cache.** `get_fields_with_tag(FieldTag.IP_IOC)` is `@app.cache.memoize`d with `AI_CACHE_LIFETIME = 6h`. If artifact-index started before the `metadata_field_properties` seed loaded (or the cache entry was set when the table was empty), the memoize serves an empty list for 6 hours. The PR-1870 cache-bust hook fires on CRUD writes but not on the direct-DB `sync-metadata-fields` loader that provisioning calls.
- **`extract_iocs` walk drops the cape_sandbox_v2 root.** The field path tagged `ip-ioc` in the seed is `cape_sandbox_v2.extracted_c2_ips`, but the metadata blob is shaped `{tool: 'cape_sandbox_v2', tool_metadata: {extracted_c2_ips: [...]}}`. The view wraps as `{metadata['tool']: metadata['tool_metadata']}` = `{cape_sandbox_v2: {extracted_c2_ips: [...]}}` then walks `cape_sandbox_v2.extracted_c2_ips`, which SHOULD find the IPs — but doesn't in practice.

Filed as upstream artifact-index follow-up. Restarting artifact-index after a fresh provision may rule out (a).

### 3. `sandboxtask_latest` (sync + async) — `SandboxTaskSearchHash` only populates on SUCCEEDED tasks

[`artifact_index/services/sandbox.py::update_sandbox_search`](https://github.com/polyswarm/artifact-index/blob/master/src/artifact_index/services/sandbox.py) only writes to `SandboxTaskSearchHash` when `task.status == 'SUCCEEDED'`. On a fresh e2e without active cape/triage workers, queued tasks stay PENDING forever, so `latest` returns 404 "No tasks found".

This is environment, not bug — but it does mean the test can't be hermetic without a worker stub. The sync `sandboxtask_list` IS hermetic and passes: it queries `SandboxTask` directly, no SearchHash dependency.

### 4. `live` (sync + async) — requires the bounty / microengine pipeline

`live_start` returns a `LiveYaraRuleset` with `livescan_id=None` because the local e2e has no microengines processing submissions. The lifecycle calls (`ruleset_create`, `live_start`, `live_stop`) all return 200, but the feed never receives results and `livescan_id` doesn't get assigned. Same shape as #3 — environment, not bug.

## What works (the other 36 cassettes)

After the test refactor — provision-via-SDK-in-setUp, capture-returned-ids, structural rather than count assertions — every endpoint test outside the four upstream-blocked groups above regenerates cleanly against `make reset-database` + the provisioning script. The cassettes get re-recorded on every `rm test/vcr/*.vcr && pytest test/`. Subsequent runs replay deterministically because each test is its own self-contained transaction against the e2e.

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
