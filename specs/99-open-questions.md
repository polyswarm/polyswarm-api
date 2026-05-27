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

## Cassettes that need an e2e refresh

**Status:** 24 cassettes stale; tests are non-hermetic against the live e2e.

After two delete-and-rerun passes, 23 of 47 cassettes regenerate cleanly. The remaining 24 fail because the corresponding tests aren't hermetic — they assume specific pre-existing e2e state that can't be reproduced without admin-level fixture priming. Concretely:

- **Hard-coded primary keys.** `update_known_good_host(1)` / `delete_known_good_host(1)` assume an IOC at id=1. The e2e's auto-increment counter has moved past 1 across prior runs, and there's no way to force a specific id from the SDK side.
- **Order-coupled state assertions.** `test_add_known_good_host` asserts the response, but successive runs leave IOCs in the e2e; on the second run the POST returns 400 "IOC with that host already exists" instead of the expected resource shape.
- **Count assertions on shared resources.** `test_rules` does `assert len(rules) == 1` after one `ruleset_create`. The e2e accumulates rulesets across runs; cleanup is blocked when a ruleset has an active live hunt (`Can not delete a ruleset with an active live hunt`).
- **Missing fixture artifacts.** Sandbox tests (`sandboxtask_submit`, `sandboxtask_latest`, `sandboxtask_list`) assume a sandbox task exists. `historical_results` assumes a historical hunt exists. `live` reads `livescan_id` from a fresh `LiveYaraRuleset`, which the e2e doesn't assign synchronously.
- **Eventual-consistency assertions.** `iocs_by_hash` and `search_by_ioc` call `tool_metadata_create` then immediately query the IOC index. The e2e accepts the create (200) but the index doesn't return results in the same request cycle.
- **Surviving server bugs.** POST `/v3/artifact/metadata` returns 400 "Bad JSON" (sync `iocs_by_hash`), GET `/v3/artifact/metadata/list` returns 500 (`tool_metadata`).

The 24 cassettes are stale-but-passing under VCR replay. They captured a known good state of the e2e during the original recording session.

**Affected cassettes** (sync + async pairs where present): `*_add_known_good_host`, `*_check_known_host`, `*_delete_known_good_host`, `*_update_known_good_host`, `*_historical_results`, `*_iocs_by_hash`, `*_live`, `*_rules`, `*_sandboxtask_latest`, `*_sandboxtask_list`, `*_sandboxtask_submit`, `*_search_by_ioc`, `*_tool_metadata`.

**Action:**
1. **Test refactor (preferred).** Make each test hermetic — capture the IOC id returned by `add_known_good_host` and feed it back into the update/delete calls instead of hard-coding `1`; capture the ruleset count *before* `ruleset_create` and assert relative growth; provision sandbox/historical fixtures via SDK calls inside the test.
2. **E2e fixture priming.** Provide an admin endpoint or migration that seeds a known initial state (IOC id=1, sample sandbox task, sample historical hunt) and resets between test sessions.
3. **Fix the surviving 400 / 500 on the metadata endpoints.**

**Decision point:** not blocking the SDK rewrite. The cassette replay path is the only representation of the contract for these endpoints today. The invariant "tests must pass against the live e2e stack with VCR off" remains aspirational until either the tests are refactored or the e2e priming work is done.
