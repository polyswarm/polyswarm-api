# Resources — `BaseJsonResource` + per-domain models

## Scope

How resource classes work: the `BaseResource` / `BaseJsonResource` machinery, the classmethod builder convention (which returns `PolyswarmRequest` descriptors), and the per-domain catalogue. This spec is the place to read before adding a new resource or changing a resource's parsing.

## Invariants

1. **Resource classmethods return `PolyswarmRequest` descriptors — pure data.** They assemble the URL, params, and JSON body, attach a `result_parser`, and hand back a `PolyswarmRequest` dataclass instance. No I/O happens here. No httpx import. No transport awareness. The API client's session (`session.execute(request)`) is what runs the call.
2. **One resource class = one domain.** A resource models a single response shape from the server (e.g. `ArtifactInstance`, `HistoricalHunt`, `MetadataFieldProperties`). Don't conflate domains in a single class.
3. **`RESOURCE_ENDPOINT` is the source of truth for URLs.** Verb-specific endpoint overrides (`_create_endpoint`, etc.) exist but are deprecated — prefer `RESOURCE_ENDPOINT` with optional `endpoint_fmt` for path interpolation. New resources shouldn't override the per-verb hooks.
4. **Resource instance methods only build descriptors.** If a resource exposes an instance method that triggers a follow-up HTTP call (e.g. `BundleTask.download_zip(folder=…)`), it returns an unexecuted `PolyswarmRequest`. The caller wraps in `self._single(...)` on the API client side. **Resources do not own session references or call the session themselves.**
5. **No transport methods on resources.** `LocalArtifact.upload_file` / `SandboxTask.upload_file` / `ReportTemplate.upload_logo` (as inline-execute methods) are gone in 4.0. The session handles uploads: `await api.session.upload_file(instance.upload_url, artifact)`.
6. **Public resource class names and `RESOURCE_ENDPOINT` values are part of the contract.** They appear in callers' code (`isinstance(x, resources.ArtifactInstance)`); renames are breaking changes.

## Files

- `src/polyswarm_api/core.py` — hand-written, transport-agnostic. Home of `BaseResource`, `BaseJsonResource`, `PolyswarmRequest` (dataclass descriptor), `parse_response` (pure function), `Hashable`, `Hash`, validators, helpers. Both transports import from here; not unasync-processed; single class identity across modules.
- `src/polyswarm_api/resources.py` — every per-domain resource class. Transport-agnostic. Imports only from `core` and `exceptions`.

## The class hierarchy

```
BaseResource                          # holds .api, ._content, .parse_result classmethod
└── BaseJsonResource                  # adds .json, RESOURCE_ENDPOINT, jmespath(), _get(),
                                      # CRUD classmethods (create/get/head/update/delete/list)
    ├── ArtifactInstance              # /instance + .submit, .lookup_uuid
    ├── LocalArtifact                 # file handle wrapper (no upload method —
    │                                 #   callers use api.session.upload_file)
    ├── Engine                        # /microengines
    ├── Metadata                      # /search/metadata/query
    ├── MetadataFieldProperties       # /search/metadata/properties
    ├── MetadataMapping               # /search/metadata/mappings
    ├── IOC                           # /ioc (known good / known bad / search)
    ├── LiveYaraRuleset               # /hunt/rule/live
    ├── HistoricalHunt                # /hunt/historical
    ├── HistoricalHuntResult / List   # /hunt/historical/results (+ /results/list)
    ├── LiveHuntResult / List         # /hunt/live (+ /hunt/live/list)
    ├── YaraRuleset                   # /hunt/rule
    ├── Tag, MalwareFamily, TagLink   # /tags/tag, /tags/family, /tags/link
    ├── AssertionsJob, VotesJob       # /consumer/assertions-job, /consumer/votes-job
    ├── SandboxTask, SandboxProvider  # /sandbox/sandboxtask, /sandbox/provider
    ├── ArtifactArchive               # /consumer/download/stream
    ├── BundleTask                    # /bundle
    ├── ToolMetadata, Events          # /artifact/metadata, /activity
    ├── Sample                        # /sample/{sha256}
    ├── ReportTask, ReportTemplate    # /reports, /reports/templates
    ├── ReportLLMPostProcessing       # /reports/llm
    ├── LLMPromptConfig               # /prompt_config
    ├── Webhook                       # /notification/webhook
    └── WhoIs, AccountFeatures        # /public/accounts/whois, /public/accounts

Hash                                  # mixin / standalone hash wrapper (Hashable)
PolyswarmRequest                      # @dataclass — pure description, not a resource
```

`PolyswarmRequest` is intentionally NOT a `BaseResource` — it's a separate concept (an HTTP-call description) and lives next to the resource bases in `core.py` because both are foundational.

## `PolyswarmRequest` — the descriptor

A `@dataclass` defined in `core.py`. Pure data. Constructed by resource classmethods. Holds:

**Request inputs** (set at build time):

```python
api: Any                                # the api client (used by parse_response
                                        # to attach .api on parsed resources;
                                        # the descriptor never calls back into it)
method: str
url: str
params: Any = None                      # dict or list of (k, v) tuples
json: Any = None                        # JSON body for the request
headers: Mapping[str, Any] | None = None
content: bytes | None = None
data: Any = None                        # form-encoded body (httpx 'data=')
files: Any = None                       # multipart upload (httpx 'files=')
timeout: float | None = None
result_parser: type | None = None       # BaseJsonResource subclass / LocalArtifact / etc.
parser_kwargs: dict = field(default_factory=dict)   # extra kwargs forwarded to .parse_result
```

**Response state** (populated by `session.execute` via `parse_response`):

```python
raw_result: Any = None                  # the httpx.Response (the streaming response for downloads)
status_code: int | None = None
status: Any = None                      # JSON-body 'status' field
errors: Any = None                      # JSON-body 'errors' field
_result: Any = None                     # the parsed value (resource instance / list / status code)
_paginated: bool = False
total: int | None = None
limit: int | None = None
offset: int | None = None
order_by: str | None = None
direction: str | None = None
has_more: bool | None = None
```

**Note on `json` vs `input_json`**: the send body and the response body are kept
in separate fields, so neither masks the other. The constructor still takes the
send body as `json=` (back-compat), but `__post_init__` relocates it to
`input_json` and resets `.json` to `None`. `to_httpx_kwargs` and pagination cloning
read `input_json`; after execution `parse_response` fills `.json` with the parsed
**response** body, so `request.json['result']`, `request.json['has_more']`, and
`exc.request.json[...]` all read the response. There is no in-place send→response
overwrite of a single field (this de-conflicts the historic 3.x overload).

Two methods:

- `to_httpx_kwargs(self) -> dict` — projects the descriptor into a `dict` of kwargs
  `httpx.{Async,}Client.request()` accepts. Omits None-valued fields. Used internally
  by `session.execute`.
- `suppressed_headers(self) -> set[str]` — names of headers the caller marked
  with value `None` (the "drop this session-level header" sentinel). The session
  honours these by building the request via `build_request` and popping the names
  before sending. Used to strip `Authorization` when hitting pre-signed S3 URLs.

The descriptor has **no** `.execute()`, `.consume_results()`, `.next_page()`, or
`.parse_result()` method. Executing is the session's job; parsing is the
`parse_response` function's job; pagination orchestration is the API client's
job.

## `parse_response` — the pure parse function

Lives in `core.py`. Signature:

```python
def parse_response(response, request: PolyswarmRequest) -> PolyswarmRequest:
    """Read `response`, populate request fields, raise typed exceptions
    on non-2xx. Pure — no I/O.

    Typed exceptions (`RequestException` and subclasses) carry
    `.request = request` (set in the exception constructor) so callers
    can inspect the descriptor that triggered them.
    """
```

Behaviour:

| Branch | Action |
|---|---|
| `request.method == 'HEAD'` | `request._result = response.status_code`; return. |
| Non-2xx | Extract JSON body into `request.json` / `.status` / `.errors`. Dispatch on status code: 404 → `NotFoundException` (→ `KnownGoodWithheldException` when `errors['code'] == 'KNOWN_GOOD'`), 422 → `FailedInstanceException`, 429 → `UsageLimitsExceededException`, else → `RequestException`. Raise. |
| 2xx, no `result_parser` | Return (fire-and-forget endpoints). |
| 2xx, `result_parser` is `BaseJsonResource` subclass, status 204 | Raise `NoResultsException`. |
| 2xx, `BaseJsonResource` parser | Extract JSON. Populate pagination metadata (`_paginated` / `total` / `limit` / `offset` / `has_more`). Find `result` or `results` key in body. Dispatch on `result_parser.parse_result_list` (list) or `.parse_result` (single). |
| 2xx, non-`BaseJsonResource` parser | Call `result_parser.parse_result(api, response, **parser_kwargs)` directly. Used for file downloads (`LocalArtifact`). |

Testable in isolation: pass a fake response object with `.status_code` / `.json()` / `.headers`; pass a fresh `PolyswarmRequest`; assert fields populated or right exception raised. No httpx, no async, no fixtures.

## `BaseResource`

Tiny base. Constructor signature: `BaseResource(content, *args, api=None, **kwargs)`. Holds:

- `self.api` — the API client that produced this resource. Resources can call back into it (e.g. `task.api.session.upload_file(task.upload_url, artifact)` if a caller needs the resource's owning api).
- `self._content` — the raw payload (JSON dict for JSON resources; empty for downloaded `LocalArtifact`s — the streamed body lives in the handle, not `_content`).

`@classmethod parse_result(cls, api, content, **kwargs)` is what `parse_response` invokes on a successful 2xx. The default builds `cls(content, api=api, **kwargs)`.

## `BaseJsonResource`

Adds:

- `self.json` — alias for `self._content` (the parsed JSON dict).
- `__int__(self)` — returns `int(self.id)` so resources can be passed wherever an ID int is expected.
- `jmespath(self, expr)` — apply a JMESPath expression to `self.json`. Returns `None` for missing paths.
- `_get(self, path, default=None, content=None)` — dotted-path access with list-index support (`'a.b[0].c'`).
- `parse_result_list(cls, api, json_data, **kwargs)` — `[cls.parse_result(api, entry, **kwargs) for entry in json_data]`.

### CRUD classmethods (the builders)

```python
@classmethod
def create(cls, api, **kwargs) -> PolyswarmRequest: ...
@classmethod
def get(cls, api, **kwargs) -> PolyswarmRequest: ...
@classmethod
def head(cls, api, **kwargs) -> PolyswarmRequest: ...
@classmethod
def update(cls, api, **kwargs) -> PolyswarmRequest: ...
@classmethod
def delete(cls, api, **kwargs) -> PolyswarmRequest: ...
@classmethod
def list(cls, api, **kwargs) -> PolyswarmRequest: ...
```

Each one:

1. Calls the corresponding `_<verb>_endpoint(api, **kwargs)` to compute the URL.
2. Calls the corresponding `_<verb>_params(**kwargs)` to compute query string + JSON body.
3. Calls `_<verb>_headers(api)` for header overrides (defaults to None).
4. Constructs `PolyswarmRequest(method=…, url=…, headers=…, params=…, json=…, result_parser=cls)` and returns it.

The hook layout (`_<verb>_endpoint`, `_<verb>_params`, `_<verb>_headers`) is preserved for resources that need per-verb URL customisation. New resources shouldn't override them — prefer `RESOURCE_ENDPOINT` with `endpoint_fmt`.

### URL construction

```python
@classmethod
def _endpoint(cls, api, endpoint_fmt=None, **kwargs):
    if cls.RESOURCE_ENDPOINT is None:
        raise InvalidValueException('RESOURCE_ENDPOINT is not configured for this resource.')
    endpoint = cls.RESOURCE_ENDPOINT
    if endpoint_fmt is not None:
        endpoint = endpoint.format(**endpoint_fmt)
    return f'{api.uri}{endpoint}'
```

`endpoint_fmt={'sha256': sha256}` lets a single `RESOURCE_ENDPOINT = '/sample/{sha256}'` cover URL-parametrised paths. See `Sample.create` for a worked example.

### Param construction

```python
@classmethod
def _params(cls, method, *param_keys, endpoint_fmt=None, **kwargs):
    params, json_params = {}, {}
    for k, v in kwargs.items():
        if v is None:
            continue
        # *_id keys get parsed as ints (or fall back to str)
        # bools serialise as int (0/1)
        # GET / explicit param_keys → query string
        # everything else → JSON body
        ...
    return params, json_params
```

Rules:

- `None` values are dropped (matching the `requests` library behaviour cassettes were recorded against — `httpx` would otherwise send them as empty strings).
- Keys named `id` or `*_id` are coerced to `str(int(v))` if possible, else `str(v)`. Server expects string IDs.
- Booleans are coerced to int (0/1) at the param layer. The session layer additionally normalises any remaining bool values to `'True'` / `'False'` (capitalised) — see `_normalise_bool_params` in [`01-architecture.md`](./01-architecture.md).
- `RESOURCE_ID_KEYS` (default `['id']`) lists keys that must go to the query string for `GET` / `DELETE` / `PUT`.

### Adding a new resource

```python
# resources.py
from .core import BaseJsonResource, Hashable, PolyswarmRequest

class FooBar(BaseJsonResource):
    RESOURCE_ENDPOINT = '/foobar'
    RESOURCE_ID_KEYS = ['foo_id']   # only needed if the identifier isn't 'id'

    # Optional: parametrised path
    # RESOURCE_ENDPOINT = '/foobar/{foo_id}'
    # — combine with endpoint_fmt={'foo_id': foo_id} at the call site

    def __init__(self, content, api=None):
        super().__init__(content, api=api)
        self.foo_id = content['foo_id']
        self.name = content.get('name')
```

Then in the canonical async client [`aio/api.py`](../src/polyswarm_api/aio/api.py):

```python
class PolySwarmAsyncAPI:
    async def foobar_get(self, foo_id):
        return await self._single(resources.FooBar.get(self, foo_id=foo_id))

    async def foobar_write(self, foo_id, payload):
        return await self._single(resources.FooBar.create(
            self, foo_id=foo_id, payload=payload,
        ))

    async def foobar_list(self):
        async for item in self._paginate(resources.FooBar.list(self)):
            yield item
```

Run `python scripts/regenerate_sync.py` (or rely on the pre-commit hook) to regenerate the sync mirror at `polyswarm_api/api.py`. Commit both the canonical edit and the regenerated file. See [`01-architecture.md`](./01-architecture.md) §"The codegen workflow".

Tests go under the parametrised `ClientTestCase` harness — see [`04-testing.md`](./04-testing.md).

## Per-resource notes

### `Hash` / `Hashable`

`Hashable` is a mixin. `Hash.from_hashable(value, hash_type=None)` accepts a `Hash`, an `ArtifactInstance`, a `LocalArtifact`, or a hex string and returns a `Hash` with the right `hash_type` and `hash` attributes. Used everywhere a method takes a `hash_` parameter — see `PolySwarmAsyncAPI.search` / `.exists` / `.download` / `.rescan` and the corresponding generated sync methods on `PolyswarmAPI`.

Supported hash types are listed in `Hashable.SUPPORTED_HASH_TYPES` (`sha1`, `sha256`, `md5`). `validate_hash=True` on construction raises `InvalidValueException` on a mismatch.

### `ArtifactInstance`

Wraps a single scan instance. Carries `id`, `sha256`, `upload_url`, the assertion / detection counts, the scan metadata.

**`known_good` / `known_good_sources`.** When the server flags this sha256 as a
known-good binary, the response carries a `known_good` array — one
`{tool, tool_metadata, created, updated}` entry per flagging feed (`nsrl`,
`microsoft`, `commercial`). `ArtifactInstance.known_good` is that raw list (or `None`
for a normal artifact / a server too old to emit the field — parsed with `.get()`,
so older recorded responses parse to `None` with no behaviour change), and
`known_good_sources` is the sorted, de-duplicated list of feed names derived from
it (`[]` when not known-good). The field is **display-only** metadata; the
known-good *state* rides in the per-resource status the server returns, not here.

**`state`.** The friendly bounty-state NAME the server returns alongside the
numeric `bounty_state` — a string such as `'KNOWN_GOOD'` / `'SETTLED'` / `'STORED'`,
or `None`. Additive and optional (parsed with `.get()`, so a server too old to emit
it parses to `None` with no behaviour change). It lets a consumer recognise a
known-good-bypassed scan via `state == 'KNOWN_GOOD'` even when `known_good` above is
`None` (the sha matched no `KnownGood`). The raw numeric `bounty_state` is unchanged.

`state == 'KNOWN_GOOD'` (equivalently the status the server reports for the instance)
is **the** signal for the *typed refusal* — the platform never stores or serves a
known-good binary, there is deliberately no separate "withheld" field to read, and a
download attempted anyway raises `KnownGoodWithheldException` (see §"Exceptions thrown
by parsing"); the metadata — the flagging feeds plus any scan data already collected —
stays readable. It is not the signal for "bytes are unavailable" in general:
`state == 'NOT_STORED'` (below) also has no bytes — nothing was ever stored for that
instance — but its download 404s **plainly**, without the `KNOWN_GOOD` code, because
nothing is being withheld by policy any more.

Classmethod builders (each returns a `PolyswarmRequest` descriptor):

- `exists_hash(api, hash_value, hash_type, require_scan=False)` — HEAD request, returns the status code as the result. `require_scan=True` narrows the answer to artifacts that were actually scanned. Being catalogued as known-good is **not** a scan — a hash whose only record is a known-good reference answers present without `require_scan` (the reference is a real searchable record) and absent with it.
- `search_hash(api, hash_value, hash_type)` — GET `/search/hash/{hash_type}`.
- `search_url(api, url)` — GET `/search/url`.
- `list_scans(api, hash_value)` — GET `/search/instances`.
- `lookup_uuid(api, scan)` — GET `/instance/{id}`.
- `rescan(api, hash_value, hash_type, scan_config=None)` — POST.
- `rescan_id(api, scan, scan_config=None)` — POST.
- `metadata_rerun(api, hashes, analyses=None, skip_es=None)` — POST.
- `create(api, …)`, `update(api, …)`, `download(cls, api, hash_value, hash_type, …)`, `download_id(cls, api, instance_id, …)`, `download_archive(cls, api, s3_path, …)`, `download_sandbox_artifact(cls, api, sandbox_task_id, instance_id, …)` — used by `submit`, `download*`, `stream` endpoints.

**No instance methods** that issue HTTP. Uploading to the pre-signed S3 URL is done via the session: `await api.session.upload_file(instance.upload_url, artifact)` (or `api.session.upload_file(...)` for sync).

### `LiveHuntResult` / `HistoricalHuntResult`

**`matched_strings`.** The yara strings behind a hunt hit, so a consumer can see *why*
a rule fired rather than only which one did. Additive and optional, parsed with `.get()`
like `known_good` / `state` above — a server too old to emit it parses to `None` with no
behaviour change, and a subscript would raise on every result instead.

It is **three-state** and the states are not interchangeable; the table, the per-entry
dict shape and the lower-bound caveat live in
[`05-downstream-contract.md`](./05-downstream-contract.md)
§"`matched_strings` on hunt results" — read it there rather than inferring from the
attribute. The short version a parser needs: `None` means *not reported* (an older
server, removed evidence, or a **list** endpoint, which omits it rather than fetch a blob
per row), `[]` means *matched with no byte evidence*, and a populated list is evidence.

Both `…List` subclasses inherit this from their parent's `__init__`, so all four
hunt-result classes carry it — but on the list endpoints the value is always `None` by
design.

### `LocalArtifact`

A file-system or in-memory artifact prepared for upload. Constructed via:

- `LocalArtifact.from_path(api, path, artifact_type, artifact_name=None)` — opens a file.
- `LocalArtifact.from_handle(api, handle, artifact_name, artifact_type)` — wraps an open file-like.
- `LocalArtifact.from_content(api, content, artifact_name, artifact_type)` — wraps an in-memory string (URL submissions).

Holds `handle`, `artifact_name`, `artifact_type`, `sha256`, `sha1`, `md5`. Also has classmethod builders `download`, `download_id`, `download_archive`, `download_sandbox_artifact` that return `PolyswarmRequest` descriptors (with `result_parser=LocalArtifact` — the non-JSON parsing path).

**No `upload_file` instance method** in 4.0. To upload: `await api.session.upload_file(instance.upload_url, local_artifact)`.

### `BaseJsonResource` subclasses with custom builders

Several resources add domain-specific classmethods on top of the standard CRUD set:

- `IOC` — `iocs_by_hash`, `ioc_search`, `check_known_hosts`, `create_known_good`, `create_known_bad`, `update_known_good`, `delete_known_good`.
- `LiveYaraRuleset` / `HistoricalHunt` / `YaraRuleset` — standard CRUD plus list/delete-batch variants.
- `SandboxTask` — `create_file`, `update_file`, `latest`, `my_tasks` for the various sandbox-submission shapes. **No `upload_file` instance method** in 4.0.
- `Sample` — `create` with `endpoint_fmt={'sha256': sha256}` for the URL-parametrised path.
- `Webhook` — `test(api, webhook_id)` for the test-payload endpoint.
- `KnownGood` — `RESOURCE_ENDPOINT = '/known-good'`, `RESOURCE_ID_KEYS = ['sha256']`; `create`/`get`-by-sha256/`delete`-by-sha256 (no update). `sha256` is the resource's natural unique key and is the key for both retrieve and delete, so the base `_get_params`/`_delete_params` route it into the query string with **no override**: `get` sends `sha256` + `community`; `delete` sends just `sha256` (no community/body). Internal-only on the server (gated by the `known_good` feature). API methods: `known_good_create` / `known_good_get(sha256)` / `known_good_delete(sha256)`.

These follow the same convention: build a `PolyswarmRequest`, return it.

## Resource-instance methods that issue HTTP

A handful of resources expose instance methods that hand back unexecuted `PolyswarmRequest` descriptors (for follow-up HTTP calls in multi-step flows):

- `BundleTask.download_zip(folder=None)` — returns `PolyswarmRequest(result_parser=LocalArtifact)`. Caller wraps in `self._single(task.download_zip(…))`.
- `ReportLLMPostProcessing.download_report(folder=None)` — same shape.
- `ReportTask.download_report(folder=None)` — same shape.
- `ReportTemplate.download_logo(folder)` — same shape.
- `ReportTemplate.delete_logo()` — same shape.
- `ReportTemplate.upload_logo(logo_file, content_type)` — same shape (builds a descriptor; the actual PUT goes through the API client's authenticated session).

The API method (canonical on [`aio/api.py`](../src/polyswarm_api/aio/api.py), mirrored to sync) drives the multi-step flow:

```python
async def sample_bundle_download(self, id, folder):
    task = await self._single(resources.BundleTask.get(self, id=id, community=self.community))
    if task.state == 'PENDING':
        raise exceptions.InvalidValueException(...)
    if task.state == 'FAILED':
        raise exceptions.InvalidValueException(...)
    result = await self._single(task.download_zip(folder=folder))
    result.handle.close()
    return result
```

unasync mirrors the body to sync mechanically — `async def` → `def`, `await` removed.

## Streaming / non-JSON responses

A non-`BaseJsonResource` `result_parser` (i.e. `LocalArtifact`) marks a **download**. `session.execute` routes these to its streaming branch (`_execute_download`) instead of `parse_response`: it opens the response with `send(req, stream=True)` (so the body isn't read into memory), maps non-2xx via the shared `core._raise_for_status` (identical typed exceptions to the JSON path), then drives the download through two `LocalArtifact` classmethods —

- `open_destination(folder, handle, artifact_name, response)` resolves the filename (explicit > content-disposition > handle name > URL basename) and the destination handle (a file opened under `folder`, or the caller's handle / a `BytesIO`), **without** consuming any body, returning `(handle, name, created)`;
- the session streams the body into that handle chunk by chunk (`response.aiter_bytes(DOWNLOAD_CHUNK_SIZE)`), then `from_written(api, handle, name, …)` wraps the written handle as a `LocalArtifact` (no re-consume).

This keeps the body off the heap for `folder`/file-handle destinations — parity with the pre-4.0 `requests` path. The consume loop lives in the async-canonical session (it must drive an async stream; `LocalArtifact`'s sync loop can't) and is unasync-mirrored to the sync transport via the `aiter_bytes → iter_bytes` / `aread → read` token rewrites. The 4.0-era `HttpxResponseAdapter` that buffered `response.content` is gone. See [`01-architecture.md`](./01-architecture.md) and [`99-open-questions.md`](./99-open-questions.md) §"Streaming downloads".

## Exceptions thrown by parsing

- `NoResultsException` — HTTP 204 with a typed `result_parser`.
- `NotFoundException` — HTTP 404, or a JSON-decode failure on a 404.
- `KnownGoodWithheldException` (a `NotFoundException` subclass) — HTTP 404 whose `errors` payload is a dict with `code == 'KNOWN_GOOD'`: the artifact is a known-good binary and its bytes are withheld by design. Carries `.sources` (the flagging known-good feeds, always a list of strings — normalised in the exception's constructor — and `[]` when none were named or the payload arrived in another shape). Any other 404 — a different code, a legacy list-shaped `errors`, or no `errors` at all — stays a plain `NotFoundException`.
- `FailedInstanceException` — HTTP 422.
- `UsageLimitsExceededException` — HTTP 429.
- `RequestException` — any other non-2xx. Its message appends the envelope's `errors` slot rendered for whichever shape arrived: a **list** renders one entry per line (the legacy shape), a **mapping** renders `key=value` lines (the way-forward shape, which the server can send on any status — not just the 404 the `code` contract was introduced for), and anything else renders as a plain string. This applies to the `RequestException` arm only — see [`01-architecture.md`](./01-architecture.md).

Each is raised by `parse_response`. `RequestException.__init__` attaches the descriptor as `.request`, so callers downstream read `exc.request.status_code`, `exc.request.json`, etc. The session does not catch and rewrap — attachment happens at construction time.

## Unit-testable in isolation

Because resource builders are pure and `parse_response` is a pure function, both can be unit-tested without httpx, without async, without fixtures:

```python
# test resource builder
def test_search_hash_builds_descriptor():
    api = mock.Mock(uri='https://example.com/v3', community='gamma')
    req = ArtifactInstance.search_hash(api, 'abc123', 'sha256')
    assert req.method == 'GET'
    assert req.url == 'https://example.com/v3/search/hash/sha256'
    assert req.params == {'hash': 'abc123', 'community': 'gamma'}
    assert req.result_parser is ArtifactInstance

# test parser
def test_parse_response_404_raises_NotFoundException():
    response = FakeResponse(status_code=404, body={'result': 'not found', 'status': 'error'})
    request = PolyswarmRequest(api=api, method='GET', url='...')
    with pytest.raises(NotFoundException) as ei:
        parse_response(response, request)
    assert request.status_code == 404
    assert ei.value.request is request
```

See `test/core_test.py` for the actual implementation of these tests.

These run in microseconds and exercise the parts of the SDK that are most likely to harbor subtle bugs.
