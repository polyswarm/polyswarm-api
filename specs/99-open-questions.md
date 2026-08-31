# Open Questions

## Scope

Known follow-ups and unresolved questions that haven't been decided yet. Each item is something a future PR will need to address; this file is the parking lot. Move items out (to the relevant spec) once they're resolved.

## Test-suite parametrisation rollout

**Status:** partial.

The parametrised `ClientTestCase` harness in `test/_client_harness.py` (originally written in, and still exercised by, `test/metadata_field_properties_test.py`) is the canonical pattern for running each test against both sync and async clients. `client_scan_test.py` (sync) and `async_client_test.py` (async) still have parallel test bodies for the bulk of the endpoint surface.

**Action:** migrate each test pair into a `ClientTestCase` subclass, delete the original sync / async copies, re-record cassettes where the request shape differs. Mechanical work, ~one chunk per resource family.

**Decision point:** when a test scenario does something inherently async (concurrency, cancellation, owned-vs-injected client lifecycle), it stays as a standalone `async def test_*` — those don't fit the parametrised harness. Document that in `04-testing.md` with worked examples once we have any.

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

## Pagination — the absent / non-advancing cursor guard

**Status:** decided + verified safe.

`_consume_results` stops paginating when the server reports `has_more` but the `offset` cursor is `None`/absent or repeats a value already seen (and it's also bounded by `_MAX_PAGES`). This is **strictly safer** than 3.x, and cannot truncate any feed that actually paginated before:

- Offset-paginated feeds — including the `stream` archive feed (`/consumer/download/stream`) and the live-hunt feed, which go through artifact-index's `@paginated()` offset envelope — return an **advancing numeric `offset`**, so the guard never fires for them (offset semantics are identical to 3.x).
- A `has_more`-with-no-`offset` (or repeating-`offset`) envelope would have made the 3.x `consume_results`/`next_page` re-send the **identical** request and loop forever; the guard turns that latent infinite loop into a clean stop. There is no "rolling feed advanced by re-sending an offset-less request" mode — 3.x had no mechanism for it (it only ever re-sent `offset=self.offset`).

Covered by `test_async_pagination_bounded_when_cursor_absent` and the stuck-cursor / page-walk guards.

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

## Streaming downloads — ✅ resolved (streaming restored)

**Status:** resolved. Downloads stream straight to their destination again — parity with the pre-4.0 `requests` path; no full-body buffering. `HttpxResponseAdapter` is gone.

The 4.0 transport originally buffered (the adapter read `response.content` whole, then `iter_content` sliced the in-memory buffer). The fix moved the body-consume loop into the **session** — the async-canonical layer that unasync mirrors to sync — because it has to drive an async stream, which `LocalArtifact.__init__`'s sync loop could not. `session.execute` now:

- detects a streaming parser (`request.result_parser is not None and not issubclass(request.result_parser, BaseJsonResource)`) and routes to `_execute_download`;
- opens the response with `self._client.send(req, stream=True)` (status/headers available, body not read) — which also covers the auth-stripped off-domain S3 case (`download_archive`), since header suppression already goes through `build_request` + pop;
- maps non-2xx via the shared `core._raise_for_status` (identical typed exceptions to the JSON path) after `aread()`-ing the small error body;
- treats a **204 as "no matching artifact"** (the request succeeded but returned nothing) and raises `NoResultsException` — mirroring the shared `parse_response` 204 rule that the streaming path otherwise bypasses, so an absent download surfaces "no results" instead of silently writing a successful empty file (regression-guarded by `test_async_download_204_raises_no_results`);
- has the parser class resolve a destination handle (`LocalArtifact.open_destination`), streams the body in chunk by chunk (`response.aiter_bytes(DOWNLOAD_CHUNK_SIZE)`), wraps the written handle (`LocalArtifact.from_written`), and removes a partially-written file it created;
- closes the response in a `finally` (`aclose`).

The sync mirror is generated via the unasync token additions `aiter_bytes → iter_bytes` and `aread → read` (`aclose → close` already existed). A `folder`/file-handle destination never holds the whole artifact in memory; a caller-supplied in-memory handle (e.g. `BytesIO`) still lands in memory by the caller's own choice of sink. Regression-guarded by `test_async_download_streams_in_chunks`. See `01-architecture.md` §helpers and `02-resources.md` §"Streaming / non-JSON responses".

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

The local e2e has no microengines processing submissions, so a live hunt never receives results and its feed stays empty — which is why the rules tests assert a zero-result `livescan_id` feed rather than a populated one. Same shape as #1 — environment, not bug.

(This previously said `livescan_id` itself is never assigned. That is no longer true and may never have been: `live_start` does get a `livescan_id`, the rules tests now assert it as a hard contract, and `test/vcr/test_rules.vcr` records a real one. Only the *results* are missing on this stack.)

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
