# Architecture — three layers, two transports

## Scope

How a call flows from the user's code through the SDK to the server and back. Covers the layered structure (description → transport → client), the canonical async source + generated sync mirror, the request/response pipeline, and the customization point.

## Invariants

1. **Description is transport-agnostic.** `PolyswarmRequest` is a dataclass — no `execute`, no `await`, no httpx in its method body. Resource classmethods construct one and hand it back. Importing `polyswarm_api.core` or `polyswarm_api.resources` does not touch the network.
2. **Parsing is a pure function.** `parse_response(response, request)` reads an httpx response and populates the request's response-state fields (or raises a typed exception). No I/O. Testable in isolation against fake response objects.
3. **The session is the transport.** Exactly one class per transport (`AsyncPolyswarmSession` / `PolyswarmSession`) owns an httpx client and exposes every HTTP-I/O operation the SDK does: `execute(request)` and `upload_file(url, artifact, …)`. No other module reads or writes HTTP.
4. **Async is the source of truth; sync is generated.** Hand-written async sources live under `src/polyswarm_api/aio/`. `scripts/regenerate_sync.py` runs unasync to mirror them to `src/polyswarm_api/{session,api,…}.py`. Generated files carry a `# DO NOT EDIT` header and CI rejects stale mirrors.
5. **The client owns the session and drives pagination.** `PolySwarmAsyncAPI` / `PolyswarmAPI` hold a session, expose ~80 endpoint methods + a small set of carve-outs, and orchestrate pagination through the session.
6. **Customization is via session injection.** Subclass `AsyncPolyswarmSession` / `PolyswarmSession`, override the relevant method, pass via `PolySwarmAsyncAPI(session=…)`. There are no module-level monkey-patch sites.
7. **Single class identity across transports for shared types.** `BaseJsonResource`, `Hashable`, `PolyswarmRequest`, etc. live in `core.py` (hand-written) — both transports import the same class, so `issubclass` checks work uniformly.
8. **Public method signatures and response-resource shapes do not change without a major version bump.** See [`05-downstream-contract.md`](./05-downstream-contract.md).

## Files

| Path | Hand-written? | Notes |
|---|---|---|
| `src/polyswarm_api/core.py` | yes | Transport-agnostic foundations. `PolyswarmRequest`, `parse_response`, `BaseJsonResource`, `Hashable`, helpers. |
| `src/polyswarm_api/resources.py` | yes | Per-domain wrappers. Builders return `PolyswarmRequest`. |
| `src/polyswarm_api/exceptions.py` | yes | Hierarchy. |
| `src/polyswarm_api/settings.py` | yes | Default URI, timeouts, etc. |
| `src/polyswarm_api/aio/__init__.py` | yes | Re-exports. |
| `src/polyswarm_api/aio/session.py` | yes (canonical async) | `AsyncPolyswarmSession`. |
| `src/polyswarm_api/aio/api.py` | yes (canonical async) | `PolySwarmAsyncAPI` + endpoint methods. |
| `src/polyswarm_api/session.py` | **generated** | Sync mirror of `aio/session.py`. |
| `src/polyswarm_api/api.py` | **generated** | Sync mirror of `aio/api.py`. |
| `scripts/regenerate_sync.py` | yes | Codegen driver. |

## The layers

### Layer 1 — pure / shared (`core.py`)

Hand-written. No I/O. Three sub-concerns:

**Description**: `PolyswarmRequest` — a dataclass with fields for the request shape (method, url, params, headers, content, data, files, timeout, and the send body — taken as the `json=` kwarg and relocated to `input_json` in `__post_init__`) and the parser (`result_parser`, `parser_kwargs`). It also carries mutable response-state fields (`raw_result`, `status_code`, `_result`, `_paginated`, pagination cursors, and `json` — the parsed response body) that the session populates after a call. The dataclass has no `execute` method; running the request is the session's job.

**Parsing**: `parse_response(response, request)` — a pure function. Reads `response.status_code`, dispatches on `request.method` (HEAD → status as result), checks for 4xx/5xx (extract JSON body, raise typed exception), dispatches on `request.result_parser` (None → discard; `BaseJsonResource` subclass → JSON parse + pagination metadata; else → pass response to parser directly). Populates the request's mutable fields. No httpx-specific behaviour beyond reading `.status_code`, `.json()`, `.headers` — a fake response object works for unit testing.

**Resource bases**: `BaseResource`, `BaseJsonResource`. The latter has classmethod builders (`create` / `get` / `head` / `update` / `delete` / `list`) that each return a `PolyswarmRequest` descriptor. Per-domain resources in `resources.py` inherit from `BaseJsonResource` and may add custom classmethods (`ArtifactInstance.search_hash`, `IOC.iocs_by_hash`, etc.) — all returning descriptors.

**Helpers**: `Hashable` + `Hash` + `is_valid_sha1/sha256/md5`, `parse_isoformat`, `_normalise_bool_params`, `RequestParamsEncoder`, `as_result_bound` + `page_size_for` + `MAX_PAGE_SIZE` (the one definition of a caller's result bound and the page it implies, shared by both transports), `_raise_for_status` (the shared non-2xx → typed-exception mapper, used by both `parse_response` and the session's streaming-download path). Downloads stream straight to their destination from the session — there is no response adapter; see [`99-open-questions.md`](./99-open-questions.md) §"Streaming downloads".

### Layer 2 — transport (`session.py` / `aio/session.py`)

Hand-written async (`aio/session.py`); generated sync mirror (`session.py`). One class per transport with three I/O methods:

```python
class AsyncPolyswarmSession:
    async def execute(self, request: PolyswarmRequest) -> PolyswarmRequest:
        """Normal authenticated round-trip. Sends via the owned
        httpx.AsyncClient, calls parse_response, populates the request
        with the response state, returns it. Typed exceptions raised
        by parse_response already carry ``.request = request`` (set in
        the exception constructor); the session re-raises them as-is."""

    async def upload_file(self, upload_url, artifact, attempts=3, **kwargs):
        """PUT a file to a pre-signed URL. Strips the session-level
        Authorization header so the PolySwarm API key doesn't leak to
        the object store. Retries on transient HTTP errors."""

    async def aclose(self): ...
```

The session is the only place HTTP I/O happens. Everything above (`api.py`) calls into it; everything below (`core.py`, `resources.py`) is pure description.

Session-level header suppression for `execute`: a caller-supplied `request.headers` entry with value `None` removes that header from the outgoing request. Used by the engines-list endpoint and download endpoints that hit pre-signed S3 URLs. Implemented as: build the request via `client.build_request`, pop the suppressed names off the resulting `Headers`, send via `client.send`.

### Layer 3 — client (`api.py` / `aio/api.py`)

Hand-written async (`aio/api.py`); generated sync mirror (`api.py`). One class per transport.

```python
class PolySwarmAsyncAPI:
    def __init__(self, key=None, uri=None, community=None, timeout=None,
                 verify=True, *, session=None, **httpx_kwargs):
        # Either `key` (builds default session) or `session=` (pre-built).
        ...

    # Transport hooks — thin wrappers over the session.
    async def _single(self, request): ...
    async def _paginate(self, request): ...
    async def _consume_results(self, request): ...   # pagination loop
    async def _next_page(self, request): ...

    # ~80 endpoint methods, each a one-liner over _single / _paginate.
    async def lookup(self, scan):
        return await self._single(resources.ArtifactInstance.lookup_uuid(self, scan))

    async def search(self, hash_, hash_type=None):
        hash_ = Hash.from_hashable(hash_, hash_type=hash_type)
        async for item in self._paginate(
            resources.ArtifactInstance.search_hash(self, hash_.hash, hash_.hash_type),
        ):
            yield item

    # Multi-step methods (file uploads, polling) — still plain async methods.
    async def submit(self, artifact, ...): ...
    async def wait_for(self, scan, timeout=...): ...
    async def engines(self): ...            # cached listing; you await it
    async def refresh_engine_cache(self): ...
```

Endpoint methods are one-liners (or async generators with `async for ... yield`). Multi-step "carve-outs" exist for the same multi-step real-world flows we had under the codegen architecture — they're just multi-statement async methods now, mirrored by unasync.

## The codegen workflow

`scripts/regenerate_sync.py` reads canonical async files under `aio/` and writes sync mirrors to the root via unasync's token-rewrite. Rename map covers:

- Class names: `AsyncPolyswarmSession` → `PolyswarmSession`, `PolySwarmAsyncAPI` → `PolyswarmAPI`.
- httpx types: `AsyncClient` → `Client`, `AsyncHTTPTransport` → `HTTPTransport`.
- Async control flow: `async def` → `def`, `await` removed, `async for` → `for`, `aclose` → `close`.
- Misc: `asyncio` → `time` (so `asyncio.sleep` becomes `time.sleep`), `polyswarm_api.aio.` → `polyswarm_api.`.

No per-symbol escape hatches: every method mirrors cleanly through unasync, including `engines`. (Before 4.0 `engines` was a cached *property*; Python properties can't `await`, so when the async client landed it became a cached `async def` method — `await api.engines()` / `api.engines()` — which unasync rewrites like any other method. This is a breaking change for callers; see [`05-downstream-contract.md`](./05-downstream-contract.md). The previous design kept the property on the sync side via an exact-text post-processing patch; that patch and its drift-detection are now gone.)

Post-processing is purely mechanical: dedupe duplicate `import time` lines (a side-effect of the `asyncio → time` rename when `import time` was already present) and add the `# DO NOT EDIT` header to each generated file.

CI (`.gitlab-ci.yml::test-unasync-mirror`) reruns the script and `git diff --exit-code` to catch stale mirrors. Pre-commit (`.pre-commit-config.yaml`) runs the same on local changes under `aio/`.

## Call flow — a typical endpoint

```python
# user code
api = PolySwarmAsyncAPI(api_key)
async for instance in api.search(hash):
    ...
```

```
1. user calls api.search(hash)
       │
       ▼
2. PolySwarmAsyncAPI.search() in aio/api.py
       │  hash_ = Hash.from_hashable(...)
       │  async for item in self._paginate(
       │      resources.ArtifactInstance.search_hash(self, hash_.hash, hash_.hash_type)
       │  ):  yield item
       ▼
3. resources.ArtifactInstance.search_hash(api, ...) in resources.py
       │  returns PolyswarmRequest(method='GET', url=..., params=..., result_parser=cls)
       │  PURE DATA — no httpx, no session, no await
       ▼
4. _paginate(request) in aio/api.py
       │  req = await self.session.execute(request)
       │  (then dispatch on req._paginated → consume_results or yield singletons)
       ▼
5. AsyncPolyswarmSession.execute(request) in aio/session.py
       │  kwargs = request.to_httpx_kwargs()
       │  request.raw_result = await self._client.request(...)
       │  parse_response(request.raw_result, request)   ← pure function call
       │  return request   (now carrying ._result, ._paginated, etc.)
       ▼
6. parse_response(response, request) in core.py
       │  PURE — reads response.status_code / .json(),
       │  populates request fields, raises typed exceptions on non-2xx.
       ▼
7. Back in _paginate: dispatch on req._paginated:
       │    if paginated: async for x in self._consume_results(req): yield x
       │    else: yield singletons or unpack list
       ▼
8. _consume_results / _next_page (in aio/api.py)
       │  bounded loop (<= _MAX_PAGES), stops on has_more=False or a
       │  non-advancing/absent offset:
       │     yield items from current page
       │     next_req = PolyswarmRequest(...) cloned with offset/limit
       │                advanced + json=input_json (the send body)
       │     req = await self.session.execute(next_req)
```

Four files touched on the happy path. Each touch has one responsibility.

## Customization via session injection

Downstream code that needs to alter HTTP behaviour subclasses the session class:

```python
from polyswarm_api.aio import PolySwarmAsyncAPI, AsyncPolyswarmSession

class CustomSession(AsyncPolyswarmSession):
    async def upload_file(self, upload_url, artifact, attempts=3, **kwargs):
        # custom retry, alternate credentials, distributed tracing, ...
        return await super().upload_file(upload_url, artifact, attempts, **kwargs)

api = PolySwarmAsyncAPI(session=CustomSession(api_key, verify=False))
```

Per-instance scope, type-checked, IDE-discoverable. No global module mutation.

Common customization targets:
- `execute` — instrument every authenticated call (timing, tracing, custom retries).
- `upload_file` — custom S3 credentials, retry policy, proxy configuration.
- `_put_off_domain` (the shared helper) — change the auth-strip behaviour applied to pre-signed-URL PUTs.
- `__init__` — replace the underlying `httpx.{Async,}Client` with a custom one (alternate transport, mock, etc.).

The api client's constructor takes either `key=` (+ optional `httpx_kwargs`) to build the default session, or a pre-built `session=`. `session=` and `httpx_kwargs` are mutually exclusive — passing both raises `InvalidValueException` (configure the injected session directly). When `session=` is given, `key=` is ignored. Omitting `key=` is allowed and builds a keyless session (usable for unauthenticated endpoints).

## Request / response pipeline

`session.execute(request)`:

1. `request.to_httpx_kwargs()` projects the descriptor into a kwargs dict httpx accepts.
2. Extract any `Authorization: None`-style suppression from headers via `request.suppressed_headers()`.
3. Either `client.request(method, url, **kwargs)` (no suppression) or `client.build_request(...)` + pop suppressed headers + `client.send(req)`.
4. Call `parse_response(response, request)`. Typed exceptions raised inside `parse_response` already carry `.request = request` (set by `RequestException.__init__`); the session re-raises them as-is.

A non-`BaseJsonResource` parser is a **download** and instead takes the streaming branch (`_execute_download`): `send(req, stream=True)`, non-2xx mapped via the shared `_raise_for_status`, then `LocalArtifact.open_destination` → stream `aiter_bytes` into the handle → `LocalArtifact.from_written`, closing the response in a `finally`. See [`99-open-questions.md`](./99-open-questions.md) §"Streaming downloads".

`parse_response(response, request)`:

- HEAD: `request._result = response.status_code`; return.
- Non-2xx: extract JSON body into `request.json` / `request.status` / `request.errors`; dispatch on status code to typed exception class (`NotFoundException`, `FailedInstanceException`, `UsageLimitsExceededException`, `RequestException`); raise. The 404 arm also reads the extracted `errors` payload: a dict carrying `code == 'KNOWN_GOOD'` raises the `NotFoundException` subclass `KnownGoodWithheldException` instead.
- 2xx without `result_parser`: return (fire-and-forget endpoints like `notification_webhook_test`).
- 2xx with `BaseJsonResource` parser: extract JSON, populate pagination metadata (`total`, `limit`, `offset`, `has_more`, `_paginated`), dispatch on `result_parser.parse_result_list` (list) or `.parse_result` (single).
- 2xx with non-`BaseJsonResource` parser: pass `(api, response)` directly to `result_parser.parse_result` (used for `LocalArtifact` file downloads).

After parsing, `request.json` holds the parsed **response** body; callers read `request.json['result']` / `exc.request.json[...]`. The **send** body lives in a separate field, `input_json`: the constructor's `json=` kwarg is relocated there by `__post_init__`, which resets `.json` to `None`. So the two never collide — `to_httpx_kwargs` and pagination read `input_json`, while `.json` means "the response" for the descriptor's whole post-construction life. (This de-conflicts what 3.x carried in one overloaded field; there is no in-place send→response overwrite.)

## Pagination

`api._paginate(request)` dispatches:

```python
async def _paginate(self, request):
    req = await self.session.execute(request)
    if req._paginated:
        async for item in self._consume_results(req):
            yield item
    else:
        # non-paginated list response: yield items from the list or yield the
        # single value.
        ...
```

`_consume_results` is a bounded loop — capped at `_MAX_PAGES` and terminated early if the server returns a non-advancing offset, so a misbehaving endpoint (`has_more` stuck true, or a cursor that never moves) can't loop a client forever:

```python
async def _consume_results(self, request):
    seen_offsets = set()
    for _page in range(self._MAX_PAGES):
        try:
            for item in request._result:
                yield item
        except TypeError:
            yield request._result
            return
        if not request.has_more:
            return
        offset = request.offset
        if offset is not None and offset in seen_offsets:
            return                      # offset didn't advance — stop
        seen_offsets.add(offset)
        request = await self._next_page(request)
```

`_next_page` constructs a **new** `PolyswarmRequest` (cloning the prior descriptor's method/url/headers/etc.) for the next page, then awaits a fresh `session.execute`. Two subtleties:

- **Offset is the server's returned cursor, echoed back** — `new_params['offset'] = request.offset` (the `offset` the server put in the previous page's body, an opaque next-page cursor on the artifact-index side), **not** a client-computed `offset + limit`. This matches 3.x's `next_page`. The `seen_offsets` guard in `_consume_results` assumes this: if the server ever echoes the *same* offset instead of advancing, the loop stops rather than re-fetching forever.
- **The body is `input_json`, the send body, not the response** — after execution `request.json` holds the parsed page *response*, so re-sending it would POST the previous page's results as the next request. `_next_page` clones from `input_json` (the send body, set in `__post_init__`) to re-send the caller's original body.

Both paths are covered by respx tests (`test_async_pagination_*` in `async_client_test.py`): the multi-page walk + cursor echo, the `seen_offsets`/absent-cursor early-stop, and the `input_json` body re-send.

## Exception model

Every HTTP-level error maps to a subclass of `PolyswarmException`:

- 404 → `NotFoundException` — or `KnownGoodWithheldException` (its subclass) when the body's `errors` dict carries `code == 'KNOWN_GOOD'`: the artifact is a known-good binary whose bytes are never stored or served. Subclassing keeps every existing `except NotFoundException` caller working; the exception exposes the flagging feeds as `.sources`.
- 422 → `FailedInstanceException`
- 429 → `UsageLimitsExceededException`
- 204 on a request that expects data (JSON-parser GET **or** streaming download) → `NoResultsException` — the server did the work but matched nothing. **HEAD is exempt**: it returns the raw status code as the result (so `exists()` reads a 204 as "known-absent" rather than raising).
- Other non-2xx → `RequestException`. Its message renders the request diagnostics plus the envelope's `errors` slot, in **either** shape: the legacy **list** (one entry per line) or the way-forward **mapping** (`key=value` lines). The mapping shape is not 404-specific — the server can send it on any status — and iterating a mapping yields only its keys, so it must not be rendered like a list or every value is silently dropped from the message. (A bare string is rendered as-is for the same reason: iterating one yields characters.) Note the render itself reaches only **this** arm: `_bad_status_message` has a single call site, so the 404 / 422 / 429 arms build their messages from `request._result` alone and a mapping-shaped `errors` does not appear in them. The payload is still reachable at `exc.request.errors` on every arm.
- Client-side validation failures (bad hash, missing kwarg) → `InvalidValueException`
- Polling timeouts → `TimeoutException`

Each `RequestException` subclass carries `.request = the PolyswarmRequest` that triggered it (set by `RequestException.__init__`). Callers can read `.request.status_code`, `.request.json`, `.request.errors`, etc.

`InvalidValueException` and `TimeoutException` are client-side validation / polling failures and don't carry a request descriptor.

Attachment happens at exception-construction time (inside `parse_response`) — the session does not catch and rewrap. So `exc.request` is set whether the exception bubbles up from `parse_response` directly or via `session.execute`.

## Adding a new endpoint

1. Open `aio/api.py` (the canonical async client).
2. Write `async def my_endpoint(self, ...): return await self._single(resources.X.method(self, …))`. For paginated: `async for item in self._paginate(...): yield item`.
3. If the endpoint needs a new resource builder, add a classmethod on the relevant class in `resources.py` returning a `PolyswarmRequest(method='...', url='...', params=..., result_parser=cls)`.
4. Run `python scripts/regenerate_sync.py` (or rely on the pre-commit hook). Both `api.py` and any session-side touches get mirrored.
5. Add tests in the parametrised `ClientTestCase` harness (`metadata_field_properties_test.py` shape). The test body runs once against `PolyswarmAPI` and once against `PolySwarmAsyncAPI`.
6. Update [`03-endpoints.md`](./03-endpoints.md) to list the method.
7. Commit both `aio/api.py` (and `resources.py` if touched) AND the regenerated `api.py`.

Pre-commit catches forgotten regeneration; CI gates on it too.

## Why this shape

The 3.x architecture had `PolyswarmAPIBase` + polymorphic `_single` (one body, two return types depending on subclass) — clever, but multi-statement bodies silently broke on async. An intermediate redesign introduced async-canonical + unasync codegen, which fixed the async breakage but still mixed *description*, *execution*, and *parsing* in one `PolyswarmRequest` class with a `_coerce_request` rebuild step on the client.

4.0 finishes the direction:

- **One concern per file.** Description in `core.py`, parsing in `core.py` (as a pure function next to its consumers), transport in `session.py`, client surface in `api.py`.
- **One descriptor class.** `PolyswarmRequest` is a dataclass; there's no `AsyncPolyswarmRequest` subclass — the descriptor is transport-agnostic by construction.
- **One I/O entry point.** `session.execute(request)` (plus the two upload variants). Pagination orchestrates by chaining `execute` calls on cloned descriptors.
- **One customization mechanism.** Subclass the session, inject via `session=`. No module-level monkey-patch sites.

The unasync codegen mechanic stays — it's still the right answer for "two transports with parallel code". But what gets mirrored is leaner: just the session and the client, not a transport-specific request class.
