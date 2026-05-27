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

## Cassettes that need an e2e refresh

**Status:** 25 cassettes stale; e2e missing the data they assert against.

In the most recent delete-and-rerun pass, 22 of 47 cassettes regenerated cleanly against the local e2e. The remaining 25 stay pinned at their pre-existing recordings because the live e2e currently:

- returns 500 on `/v3/search/metadata/query`, `/v3/ioc/search`, `/v3/artifact/metadata/list` (server bugs at record time);
- returns 400 "Bad JSON" on `/v3/artifact/metadata` POST;
- has no test ioc with `id=1` (breaks `update_known_good_host`, `delete_known_good_host`);
- has no sandbox tasks (breaks the `sandbox_*_list` / `_latest` / `_submit` tests);
- has no historical hunt to look up (breaks `historical_results`);
- has no EICAR-prefab sample (breaks `rescans`, `hash_search`, `iocs_by_hash`);
- has an empty stream feed (breaks `stream`);
- has a different ruleset count than the cassette expects (`rules`).

These tests still pass via cassette replay; they're only stuck on the *re-record* path until the e2e data is primed or the server-side 500s are fixed.

**Action:** prime the local e2e with the expected test data (EICAR artifact, ioc id=1, sample sandbox task, sample historical hunt, etc.), confirm the failing server endpoints return 2xx, then delete the stale cassettes and rerun the affected tests. Until then, the cassette suite is the only working representation of the contract for these endpoints.

**Affected cassettes** (sync + async pairs where present): `*_check_known_host`, `*_delete_known_good_host`, `*_update_known_good_host`, `*_hash_search`, `*_historical_results`, `*_iocs_by_hash`, `*_live`, `*_metadata_search`, `*_rescans`, `*_rules`, `*_sample` (async-only is fine), `*_sandboxtask_latest`, `*_sandboxtask_list`, `*_sandboxtask_submit`, `*_search_by_ioc`, `*_stream`, `*_tool_metadata`.

**Decision point:** not blocking. The invariant "tests must pass against the live e2e stack with VCR off" remains aspirational until the e2e data + server-side issues are resolved.
