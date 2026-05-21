# Architecture — `PolyswarmAPIBase` + sync/async pattern

## Scope

How requests flow from a caller through the SDK to the server and back. Covers the shared base class, the `_single` / `_paginate` / `_sleep` hooks, the request-execution pipeline, and the response-parsing pipeline. Per-endpoint detail is in [`03-endpoints.md`](./03-endpoints.md); per-resource detail in [`02-resources.md`](./02-resources.md).

## Invariants

1. **One endpoint method, one implementation — for single-step bodies.** Every endpoint method whose body is `return self._single(...)` or `return self._paginate(...)` lives on `PolyswarmAPIBase`. Adding the same method to both `PolyswarmAPI` and `PolySwarmAsyncAPI` for those cases is a bug.
2. **Base methods are regular `def`, not `async def`.** The body returns whatever `self._single(...)` / `self._paginate(...)` returned; the subclass decides whether that's a value, a coroutine, a generator, or an async generator.
3. **Multi-statement bodies live on the subclasses.** If a method reads a `_single` / `_paginate` result and acts on it — reads an attribute, branches on state, feeds it into a second request — it cannot share a body across transports (the async `_single` returns a coroutine, not a value). Such methods live on `PolyswarmAPI` (sync) and `PolySwarmAsyncAPI` (async) as a pair, with the sync body as the source of truth and the async body inserting `await` at each call. See the carve-out table at the bottom of this doc.
4. **`PolyswarmRequest` is always one HTTP call** (or one templated call in the paginated case — the same builder is re-issued with new `offset`/`limit`). Composing two HTTP calls inside a single request type is not allowed.
5. **The only sync/async-specific code on the subclasses is**: `__init__`, the context-manager protocol, `_single`, `_paginate`, `_sleep`, plus the carve-out set documented below and in [`03-endpoints.md`](./03-endpoints.md).
6. **`httpx` is the single HTTP library.** Sync uses `httpx.Client`; async uses `httpx.AsyncClient`. Both produce `httpx.Response`, so the response-parsing layer is shared via inheritance.
7. **Resource classmethods return UNEXECUTED `PolyswarmRequest` objects.** `BaseJsonResource.create` / `get` / etc. and per-resource builders (`ArtifactInstance.search_hash`, …) hand back a builder; the API client owns execution. This is what makes the sync/async unification possible — the same builder can run on either transport.
8. **Public method signatures and response-resource shapes do not change without a major version bump.** See [`05-downstream-contract.md`](./05-downstream-contract.md).
9. **Sync is the source of truth.** When the sync and async sides diverge (return shape, exception class, side-effect timing), the sync side wins. Align async to sync; never the reverse.

## Files

- `src/polyswarm_api/_base.py` — `PolyswarmAPIBase`.
- `src/polyswarm_api/api.py` — `PolyswarmAPI(PolyswarmAPIBase)` and sync-only carve-out methods.
- `src/polyswarm_api/aio/api.py` — `PolySwarmAsyncAPI(PolyswarmAPIBase)` and async-only carve-outs.
- `src/polyswarm_api/aio/__init__.py` — thin re-export of `PolySwarmAsyncAPI` from `aio/api.py`.
- `src/polyswarm_api/core.py` — `PolyswarmRequest`, `PolyswarmSession`, `HttpxResponseAdapter`, `BaseResource` / `BaseJsonResource`, helpers (`_normalise_bool_params`, `RequestParamsEncoder`).
- `src/polyswarm_api/aio/core.py` — `AsyncPolyswarmSession`, `AsyncPolyswarmRequest(PolyswarmRequest)`.

## The shared base — `PolyswarmAPIBase`

`_base.py` holds:

- **Constructor and instance state** — `uri`, `community`, `timeout`, `verify`, `_engines`. Subclasses extend `__init__` to construct their own HTTP client.
- **Request helpers** — `_coerce_request` (rebuilds an unexecuted `PolyswarmRequest` as the subclass's `_request_cls`), `_request_cls` (sync `PolyswarmRequest` or async `AsyncPolyswarmRequest`).
- **Abstract hooks** — `_single`, `_paginate`, `_sleep`. Defined on the base as `NotImplementedError`; each subclass provides the transport-specific implementation.
- **All endpoint methods** — ~100 single-line wrappers around `_single` / `_paginate`. See [`03-endpoints.md`](./03-endpoints.md) for the catalogue.

## How a single method body works for both transports

```python
class PolyswarmAPIBase:
    def search(self, hash_, hash_type=None):
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self._paginate(resources.ArtifactInstance.search_hash(
            self, hash_.hash, hash_.hash_type,
        ))
```

Step by step:

1. `resources.ArtifactInstance.search_hash(self, …)` returns an **unexecuted** `PolyswarmRequest` — a builder that carries the method, URL, params, and `result_parser`.
2. `self._paginate(request)` is dispatched to the subclass:
   - **Sync** (`PolyswarmAPI._paginate`): rebuilds the request as a sync `PolyswarmRequest`, calls `.execute()`, and **`yield`s** items. Because it's a generator function, calling it returns a generator object immediately (without running the body).
   - **Async** (`PolySwarmAsyncAPI._paginate`): rebuilds as an `AsyncPolyswarmRequest`, awaits `.execute()`, then `async for` over `consume_results()` and `yield`s. Because it's an async generator function, calling it returns an async generator object immediately.
3. The base `search` method just returns whatever `self._paginate(...)` returned — a generator (sync) or an async generator (async).
4. The caller iterates:
   - Sync: `for instance in api.search(hash_): …`
   - Async: `async for instance in api.search(hash_): …`

For single-result endpoints, `_single` is sync (returns the parsed value) on the sync subclass and `async def` (returns a coroutine) on the async one. The base method returns that coroutine; the async caller `await`s it.

**Why this works without `async def` on the base method:** Python doesn't care what kind of object a regular `def` returns. The base returns a coroutine in the async case — the caller awaiting it is what consumes the coroutine. No `async def` declaration is needed at the call site.

## `_single` / `_paginate` contract

Each subclass provides both. They accept either:

- An unexecuted `PolyswarmRequest` (returned by a resource classmethod); OR
- A request-parameters `dict` (for endpoint bodies that build the request inline) plus a `result_parser=` kwarg.

`_coerce_request` (on the base) normalises both forms to a subclass-appropriate request instance (sync `PolyswarmRequest` or async `AsyncPolyswarmRequest`). The same builder shape thus works for either transport.

### Sync

```python
class PolyswarmAPI(PolyswarmAPIBase):
    _request_cls = polyswarm_api.core.PolyswarmRequest

    def _single(self, request, result_parser=None, **kwargs):
        req = self._coerce_request(request, result_parser, kwargs).execute()
        return req.result()

    def _paginate(self, request, result_parser=None, **kwargs):
        req = self._coerce_request(request, result_parser, kwargs).execute()
        if req._paginated:
            yield from req.consume_results()
        else:
            result = req._result
            if isinstance(result, list):
                yield from result
            elif result is not None:
                yield result
```

### Async

```python
class PolySwarmAsyncAPI(PolyswarmAPIBase):
    _request_cls = AsyncPolyswarmRequest

    async def _single(self, request, result_parser=None, **kwargs):
        req = await self._coerce_request(request, result_parser, kwargs).execute()
        return req.result()

    async def _paginate(self, request, result_parser=None, **kwargs):
        req = await self._coerce_request(request, result_parser, kwargs).execute()
        if req._paginated:
            async for item in req.consume_results():
                yield item
        else:
            result = req._result
            if isinstance(result, list):
                for item in result:
                    yield item
            elif result is not None:
                yield result
```

### Why `_paginate` even for non-paginated lists

Some endpoints return a list inline (no `has_more`). `_paginate` handles both: paginated requests stream from `consume_results()`; non-paginated lists are yielded one item at a time. The user-visible behaviour is the same: `for x in api.foo()` (sync) / `async for x in api.foo()` (async).

The choice between `_single` and `_paginate` for a given endpoint is documented per-method in [`03-endpoints.md`](./03-endpoints.md). Rule of thumb: if any caller iterates the result (sync `for` or async `async for`), use `_paginate`. If callers consume a single resource, use `_single`.

## Request execution pipeline

`PolyswarmRequest.execute()` (sync):

1. Sets a default `timeout` on `request_parameters` if not already set.
2. Calls `self.session.request(**request_parameters)`. `session` is a `PolyswarmSession` (sync wrapper over `httpx.Client`).
3. Wraps the raw `httpx.Response` in `HttpxResponseAdapter` if the `result_parser` is a non-`BaseJsonResource` (download / streaming) — it needs `iter_content` (requests-style).
4. Calls `self.parse_result(response)`.

`AsyncPolyswarmRequest.execute()` (async, inherits from `PolyswarmRequest`):

1. Same setdefault on timeout.
2. `await self.session.request(method, url, **params)`. `session` is an `AsyncPolyswarmSession` (wrapper over `httpx.AsyncClient`).
3. Same `HttpxResponseAdapter` wrap for non-JSON parsers.
4. Calls inherited `self.parse_result(response)`.

The `parse_result` body is **shared** via inheritance — `AsyncPolyswarmRequest` doesn't redefine it.

## Response parsing pipeline

`PolyswarmRequest.parse_result(response)` (shared between sync and async):

1. Records `self.status_code` from the response.
2. For `HEAD` requests: `_result = status_code` and short-circuits.
3. For 4xx / 5xx: extracts the JSON body, maps to an exception class:
   - `429` → `UsageLimitsExceededException` (with a "purchase a larger package" message).
   - `404` → `NotFoundException`.
   - `422` → `FailedInstanceException`.
   - everything else → `RequestException`.
4. For `204 No Content`: raises `NoResultsException` (because the typed `result_parser` expected something).
5. For 2xx + a `BaseJsonResource` parser:
   - Extracts `self.json` from the body.
   - Detects pagination by `'has_more' in self.json` (GET only). Sets `_paginated`, `total`, `limit`, `offset`, `order_by`, `direction`, `has_more`.
   - Picks `self.json['result']` or `self.json['results']` (whichever is present).
   - If the payload is a list, runs `result_parser.parse_result_list(api, list, …)`; else `result_parser.parse_result(api, single, …)`.
6. For 2xx + a non-`BaseJsonResource` parser (file downloads etc.): calls `result_parser.parse_result(api, response, …)` directly. The response was already adapted to expose `iter_content`.

## Pagination — `consume_results` / `next_page`

`PolyswarmRequest.consume_results()` (sync generator):

```python
def consume_results(self):
    request = self
    while True:
        try:
            for item in request._result:
                yield item
        except TypeError:
            yield request._result
            return
        if not request.has_more:
            return
        request = request.next_page()
```

`next_page()` (sync) copies the request params, injects `offset` + `limit` from the current page's metadata, builds a new `PolyswarmRequest`, executes, and returns it.

`AsyncPolyswarmRequest.consume_results()` (async generator) and `next_page()` are the only methods that genuinely needed an async-specific rewrite — they involve `await` on the next-page fetch. The body shape is the same as sync.

## HTTP transport — `PolyswarmSession` / `AsyncPolyswarmSession`

Both sessions wrap `httpx.{,Async}Client` and expose:

- `.request(method, url, **kwargs)` → `httpx.Response` (or coroutine yielding one).
- `.verify`, `.headers`, `.close()` / `.aclose()` for the surface that `PolyswarmRequest` consumes.

The sync `PolyswarmSession`:

- Accepts `retries`, `verify`, `timeout`, `user_agent`, and arbitrary `**httpx_kwargs`.
- Auth header is set at session construction (`Authorization: <api-key>`).
- Strips `stream=` (httpx doesn't take that as a `.request()` kwarg) and `headers={k: None}` entries (used to remove session-level headers in the requests world).
- Calls `_normalise_bool_params(params)` to write Python booleans as `'True'` / `'False'` (capitalised, matching `str(bool)`). httpx writes them lowercase by default; existing VCR cassettes were recorded against the capitalised form, so the normalisation keeps them replaying.

The async session is the same shape, just `async`. Same param normalisation.

## Resource integration

A method like `search_hash` lives as a classmethod on `ArtifactInstance`:

```python
class ArtifactInstance(BaseJsonResource):
    RESOURCE_ENDPOINT = '/search/instances'

    @classmethod
    def search_hash(cls, api, hash_value, hash_type):
        return core.PolyswarmRequest(
            api,
            {
                'method': 'GET',
                'url': f'{api.uri}/search/hash/{hash_type}',
                'params': {'hash': hash_value, 'community': api.community},
            },
            result_parser=cls,
        )
```

It returns an unexecuted `PolyswarmRequest`. The API method picks the right hook:

```python
class PolyswarmAPIBase:
    def search(self, hash_, hash_type=None):
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        return self._paginate(resources.ArtifactInstance.search_hash(
            self, hash_.hash, hash_.hash_type,
        ))
```

The same `search_hash` classmethod is reachable from both transports because the API client wraps the unexecuted request in its own `_request_cls` before executing. Detail: [`02-resources.md`](./02-resources.md).

## Sync/async carve-outs

Some methods genuinely diverge per subclass; they're not on the base. Two categories:

### Transport-level carve-outs

| Method | Why it's not on the base |
|---|---|
| `__init__`, `close` / `aclose`, `__enter__` / `__exit__` / `__aenter__` / `__aexit__` | Each constructs its own HTTP client and exposes a sync vs async context-manager protocol. |
| `_single`, `_paginate`, `_sleep`, `_exec` | These are the abstract transport hooks themselves. |
| `wait_for(scan, timeout=…)` | Polling loop with `time.sleep` (sync) vs `asyncio.sleep` (async). |
| `report_wait_for(report_id, timeout=…)` | Same — polling loop. |
| `submit(artifact, …)`, `sandbox_file(…)`, `sandbox_url(…)` | File-upload paths. Sync uses `LocalArtifact.upload_file()` (which calls `httpx.put` directly). Async uses `polyswarm_api.aio.upload.async_upload_file()`. |
| `refresh_engine_cache`, `engines` property | The sync `@property` reads `self._engines` and calls `refresh_engine_cache()` if missing. The async version can't do that from a regular `@property`. |
| `sandbox_providers()` | Returns the executed `PolyswarmRequest` directly so callers read `.json` (sync shape). Async mirrors this — `await api.sandbox_providers()` then read `.json`. |

### Multi-statement endpoint carve-outs

Methods whose body reads a `_single` result and acts on it. The shared-base pass-through trick only works for single-statement `return self._single(...)` bodies; these methods would silently break on async (coroutine instead of value), so each lives as a sync+async pair.

| Method | Shape |
|---|---|
| `exists` | one `_single`, branches on returned status code |
| `download`, `download_id`, `download_sandbox_artifact`, `download_archive` | one `_single`, then `artifact.handle.close()` |
| `sample_bundle_download` | two `_single`s, state-branch between them |
| `llm_report_download` | two `_single`s |
| `report_download` | `report_get()` + state-branch + `_single(report.download_report)` |
| `report_template_logo_download` / `_delete` / `_upload` | two `_single`s (fetch template, then act on it) |

Adding a new method whose body needs to consume a `_single` result follows the same pattern: write the sync body on `PolyswarmAPI`, write the async twin on `PolySwarmAsyncAPI` with `await` inserted at each `_single` call. Don't try to share it via the base — invariant #3.

[`03-endpoints.md`](./03-endpoints.md) catalogues each method and notes whether it's on the base.

## Error model

All HTTP-level errors map to subclasses of `PolyswarmException`. The `result` attribute on the exception is the originating `PolyswarmRequest` (so callers can read `.status_code`, `.json`, `.request_parameters`). See [`05-downstream-contract.md`](./05-downstream-contract.md) §Exceptions for the full hierarchy and what each one means.

`InvalidValueException` is raised by client-side validation (bad hash, missing argument) without an HTTP round-trip — its `.result` is `None`.
