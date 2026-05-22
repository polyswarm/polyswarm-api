# Architecture — async-canonical with unasync codegen

## Scope

How requests flow from a caller through the SDK to the server and back. Covers the canonical async source, the unasync codegen that produces the sync mirror, the request-execution and response-parsing pipelines, and the shared resource bases. Per-endpoint detail is in [`03-endpoints.md`](./03-endpoints.md); per-resource detail in [`02-resources.md`](./02-resources.md).

## Invariants

1. **Async is the source of truth.** Every endpoint method, transport hook, and request-lifecycle helper lives as `async def` (or `async` generator) under [`src/polyswarm_api/aio/`](../src/polyswarm_api/aio/). The sync mirror at [`src/polyswarm_api/api.py`](../src/polyswarm_api/api.py), [`src/polyswarm_api/core.py`](../src/polyswarm_api/core.py), and [`src/polyswarm_api/upload.py`](../src/polyswarm_api/upload.py) is **generated**. Never hand-edit the generated files — CI rejects stale mirrors.
2. **Both transports are native.** The sync code is real sync code (not an event-loop wrapper around async). It runs against `httpx.Client`; async runs against `httpx.AsyncClient`. There's no per-call dispatch overhead and no nested-event-loop hazard.
3. **`PolyswarmRequest` is one HTTP call.** Paginated endpoints re-issue the same templated request with `offset` / `limit` mutations — still one call per page. Multi-step workflows live as multi-statement methods on the API client, not inside the request class.
4. **Transport-agnostic bases have single class identity.** [`BaseJsonResource`](../src/polyswarm_api/_bases.py), `BaseResource`, `Hashable`, `HttpxResponseAdapter`, and the helpers live in [`_bases.py`](../src/polyswarm_api/_bases.py) — a hand-written module that's *not* unasync-processed. Both the sync and async cores import from it, so `issubclass(parser, BaseJsonResource)` checks work uniformly.
5. **Public method signatures and response-resource shapes do not change without a major version bump.** See [`05-downstream-contract.md`](./05-downstream-contract.md).

## Files

| Path | Hand-written? | Notes |
|---|---|---|
| `src/polyswarm_api/_bases.py` | yes | Transport-agnostic shared bases (`BaseJsonResource`, etc.). |
| `src/polyswarm_api/aio/__init__.py` | yes | Public re-export shim. |
| `src/polyswarm_api/aio/api.py` | yes (canonical) | The `PolySwarmAsyncAPI` class — all endpoint methods. |
| `src/polyswarm_api/aio/core.py` | yes (canonical) | `AsyncPolyswarmSession`, `AsyncPolyswarmRequest`. |
| `src/polyswarm_api/aio/upload.py` | yes (canonical) | `async_upload_file` module-level callable. |
| `src/polyswarm_api/api.py` | **generated** | `PolyswarmAPI` — unasync mirror of `aio/api.py`. |
| `src/polyswarm_api/core.py` | **generated** | `PolyswarmSession`, `PolyswarmRequest` — unasync mirror of `aio/core.py`. |
| `src/polyswarm_api/upload.py` | **generated** | `upload_file` — unasync mirror of `aio/upload.py`. |
| `src/polyswarm_api/resources.py` | yes | Transport-agnostic resource builders. Imports from `_bases` and `core`. |
| `scripts/regenerate_sync.py` | yes | Codegen driver. |

## How a method body works on both transports

Take [`metadata_mapping`](../src/polyswarm_api/aio/api.py) in the canonical async source:

```python
async def metadata_mapping(self):
    logger.info('Retrieving the metadata mapping')
    return await self._single(
        {'method': 'GET',
         'url': f'{self.uri}{resources.MetadataMapping.RESOURCE_ENDPOINT}'},
        result_parser=resources.MetadataMapping,
    )
```

`scripts/regenerate_sync.py` runs unasync with a rename map and produces the sync mirror in [`src/polyswarm_api/api.py`](../src/polyswarm_api/api.py):

```python
def metadata_mapping(self):
    logger.info('Retrieving the metadata mapping')
    return self._single(
        {'method': 'GET',
         'url': f'{self.uri}{resources.MetadataMapping.RESOURCE_ENDPOINT}'},
        result_parser=resources.MetadataMapping,
    )
```

`async def` → `def`. `await` removed. Same logic, native sync. The caller:

```python
# sync
result = sync_api.metadata_mapping()

# async
result = await async_api.metadata_mapping()
```

For paginated endpoints, `async for ... yield ...` in the canonical becomes `for ... yield ...` in the mirror — both produce iterables natural to their transport.

## The codegen

`scripts/regenerate_sync.py` is the only piece of bespoke tooling. It:

1. Globs `src/polyswarm_api/aio/*.py` (excluding `__init__.py`).
2. Runs `unasync.unasync_files(...)` with a rename map covering:
   - Class names: `PolySwarmAsyncAPI` → `PolyswarmAPI`, `AsyncPolyswarmRequest` → `PolyswarmRequest`, `AsyncPolyswarmSession` → `PolyswarmSession`.
   - httpx types: `AsyncClient` → `Client`, `AsyncHTTPTransport` → `HTTPTransport`.
   - typing helpers: `AsyncGenerator` → `Iterator`, etc.
   - asyncio: `asyncio` → `time` (so `asyncio.sleep` becomes `time.sleep` and `import asyncio` becomes `import time`).
   - upload: `async_upload_file` → `upload_file`.
   - import path: `polyswarm_api.aio.` → `polyswarm_api.`.
3. Post-processes the output:
   - **Engines property.** unasync can't express divergent property bodies. The async canonical raises `AttributeError`; a post-processing step swaps that block for a working cached property in the sync mirror.
   - **Duplicate `import time`.** `import asyncio` → `import time` may collide with an existing `import time`. Post-processing dedupes.
   - **Generated header.** A `# DO NOT EDIT` block is prepended to each generated file.
4. Runs `ruff format` over the generated files so the output bytes are stable regardless of unasync's textual quirks.

CI enforces freshness via [`.gitlab-ci.yml`](../.gitlab-ci.yml)'s `test-unasync-mirror` job: it runs the script and `git diff --exit-code` — non-empty diff means someone edited the async source without regenerating, and the build fails with a clear message.

A pre-commit hook ([`.pre-commit-config.yaml`](../.pre-commit-config.yaml)) runs the same script on any change under `aio/` so contributors notice locally.

## The escape hatch — `engines` property

This is the one place where sync and async legitimately need different code:

- Async: `@property def engines(self): raise AttributeError(...)` — Python properties can't `await`.
- Sync: `@property def engines(self): if not self._engines: self.refresh_engine_cache(); return self._engines` — works fine.

The canonical async file carries the AttributeError version. `scripts/regenerate_sync.py` recognises the exact block text and substitutes the working sync property after unasync runs. If the canonical block drifts, the script raises with a clear message; that's the cue to update the substitution in the script.

This is the *only* divergent block in the codebase. The rest of the sync/async divergence is mechanical (keyword swaps).

## Request execution pipeline

`AsyncPolyswarmRequest.execute()` (canonical, in [`aio/core.py`](../src/polyswarm_api/aio/core.py)):

1. Sets a default `timeout` on `request_parameters` if not already set.
2. Calls `await self.session.request(method, url, **params)`. `session` is an `AsyncPolyswarmSession` (wrapper over `httpx.AsyncClient`).
3. Wraps the raw `httpx.Response` in `HttpxResponseAdapter` if the `result_parser` is a non-`BaseJsonResource` (file downloads).
4. Calls `self.parse_result(response)`.

`PolyswarmRequest.execute()` (sync, generated): same code with `await` removed. Calls `httpx.Client.request` synchronously.

## Response parsing pipeline

`parse_result(response)` (same logic on both sides; it's pure post-processing of a fully-buffered response):

1. Records `self.status_code` from the response.
2. For `HEAD` requests: `_result = status_code` and short-circuits.
3. For 4xx / 5xx: extracts the JSON body, maps to an exception class:
   - `429` → `UsageLimitsExceededException`.
   - `404` → `NotFoundException`.
   - `422` → `FailedInstanceException`.
   - everything else → `RequestException`.
4. For `204 No Content`: raises `NoResultsException`.
5. For 2xx without a parser: discards the body (fire-and-forget endpoints).
6. For 2xx + a `BaseJsonResource` parser: extracts pagination metadata (`has_more`, `total`, `offset`, …), then calls `result_parser.parse_result_list` (for lists) or `result_parser.parse_result` (for single resources).
7. For 2xx + a non-`BaseJsonResource` parser (file downloads): calls `result_parser.parse_result` directly with the adapted response.

The `issubclass(parser, BaseJsonResource)` check works across modules because `BaseJsonResource` lives in `_bases.py` with a single class identity — both `aio/core.py` and the generated `core.py` import from there.

## Pagination

`consume_results()` (async generator on canonical; generator on sync mirror):

```python
async def consume_results(self):
    request = self
    while True:
        try:
            for result in request._result:
                yield result
        except TypeError:
            yield request._result
            return
        if not request.has_more:
            return
        request = await request.next_page()
```

`next_page()` copies the request params, injects `offset` + `limit` from the current page's metadata, builds and executes a new request.

## Transport sessions

`AsyncPolyswarmSession` (canonical) and `PolyswarmSession` (generated) are thin wrappers over `httpx.AsyncClient` / `httpx.Client`. They:

- Inject the `Authorization` header at construction.
- Strip `stream=` from kwargs (httpx doesn't accept it).
- Strip `None`-valued headers (the requests library used `None` to drop a header; httpx rejects them).
- Normalise bool params to capitalised strings (`'True'` / `'False'`) — matches the `requests` library output that existing VCR cassettes were recorded against.

## Resource integration

A resource classmethod returns an unexecuted request:

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

Resource builders always construct a sync `core.PolyswarmRequest` (because `resources.py` is transport-agnostic and the sync class is the conventional default). The async client's `_coerce_request` rebuilds it as `AsyncPolyswarmRequest` — duck-typed on `request_parameters` / `result_parser` / `parser_kwargs` attributes, no `isinstance` check needed.

## Error model

All HTTP-level errors map to subclasses of `PolyswarmException`. The `result` attribute on the exception is the originating request object (so callers can read `.status_code`, `.json`, `.request_parameters`). See [`05-downstream-contract.md`](./05-downstream-contract.md) §Exceptions.

`InvalidValueException` is raised by client-side validation (bad hash, missing argument) without an HTTP round-trip — its `.result` is `None`.

## Adding a new endpoint

1. Open [`aio/api.py`](../src/polyswarm_api/aio/api.py) (the canonical).
2. Write `async def my_endpoint(self, ...): return await self._single(...)` (or `async for item in self._paginate(...): yield item` for paginated).
3. Run `python scripts/regenerate_sync.py` (or rely on pre-commit).
4. Commit both `aio/api.py` and the regenerated `api.py`.

For multi-step endpoints that consume `_single` results (close a handle, branch on state, issue a second call), write the body as you would in any async function — unasync handles the translation.

## Why this shape

The previous architecture (a shared `PolyswarmAPIBase` with polymorphic `_single`) relied on a clever trick: a regular `def` method that returns `self._single(...)` works for both transports because the async `_single` returns a coroutine that the caller awaits. That trick is fragile — multi-statement bodies break silently on async (the rest of the body operates on a coroutine instead of a value). It also defeats static type checkers and IDE tooling.

unasync codegen replaces the trick. Every method on the canonical side is `async def` with whatever body it needs; the sync mirror is mechanically derived. Type checkers see real async on one side and real sync on the other. No polymorphism, no convention to police.
