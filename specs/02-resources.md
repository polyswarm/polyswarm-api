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

- `src/polyswarm_api/core.py` — hand-written, transport-agnostic. Home of `BaseResource`, `BaseJsonResource`, `PolyswarmRequest` (dataclass descriptor), `parse_response` (pure function), `Hashable`, `Hash`, validators, `HttpxResponseAdapter`, helpers. Both transports import from here; not unasync-processed; single class identity across modules.
- `src/polyswarm_api/resources.py` — every per-domain resource class. Transport-agnostic. Imports only from `core` and `exceptions`.

## The class hierarchy

```
BaseResource                          # holds .api, ._content, .parse_result classmethod
└── BaseJsonResource                  # adds .json, RESOURCE_ENDPOINT, jmespath(), _get(),
                                      # CRUD classmethods (create/get/head/update/delete/list)
    ├── ArtifactInstance              # /search/instances + .submit, .lookup_uuid
    ├── LocalArtifact                 # file handle wrapper (no upload method —
    │                                 #   callers use api.session.upload_file)
    ├── Engine                        # /engines
    ├── Metadata                      # /search/metadata
    ├── MetadataFieldProperties       # /search/metadata/properties
    ├── MetadataMapping               # /search/metadata/mappings
    ├── IOC                           # /ioc/* (known good / known bad / search)
    ├── LiveYaraRuleset               # /hunt/rule/live
    ├── HistoricalHunt                # /hunt/historical
    ├── HistoricalHuntResult / List   # /hunt/historical/result(s)
    ├── LiveHuntResult / List         # /hunt/live/result(s)
    ├── YaraRuleset                   # /hunt/rule
    ├── Tag, MalwareFamily, TagLink   # /tags, /families, /tag-link
    ├── AssertionsJob, VotesJob       # /assertions, /votes
    ├── SandboxTask, SandboxProvider  # /sandbox/*
    ├── ArtifactArchive               # /stream
    ├── BundleTask                    # /bundle
    ├── ToolMetadata, Events          # /artifact/metadata/list, /events
    ├── Sample                        # /sample/{sha256}
    ├── ReportTask, ReportTemplate    # /report/*, /report/template/*
    ├── ReportLLMPostProcessing       # /report/llm
    ├── LLMPromptConfig               # /prompt-config
    ├── Webhook                       # /webhooks
    └── WhoIs, AccountFeatures        # /account/whois, /account/features

Hash                                  # mixin / standalone hash wrapper (Hashable)
PolyswarmRequest                      # @dataclass — pure description, not a resource
```

`PolyswarmRequest` is intentionally NOT a `BaseResource` — it's a separate concept (an HTTP-call description) and lives next to the resource bases in `core.py` because both are foundational.

## `PolyswarmRequest` — the descriptor

A `@dataclass` defined in `core.py`. Pure data. Constructed by resource classmethods. Holds:

**Request inputs** (set at build time):

```python
method: str
url: str
headers: dict | None = None
params: dict | list[tuple] | None = None
json: Any = None
content: bytes | None = None
stream: bool = False
result_parser: type | None = None       # BaseJsonResource subclass / LocalArtifact / etc.
parser_kwargs: dict = field(default_factory=dict)   # extra kwargs forwarded to .parse_result
```

**Response state** (populated by `session.execute`):

```python
raw_result: Any = None                  # the httpx.Response
status_code: int | None = None
_result: Any = None                     # the parsed value (resource instance / list / status code)
_paginated: bool = False
total: int | None = None
limit: int | None = None
offset: int | None = None
order_by: str | None = None
direction: str | None = None
has_more: bool | None = None
json_body: dict | None = None           # the parsed JSON dict
status: str | None = None               # JSON-body 'status' field
errors: list | None = None              # JSON-body 'errors' field
```

Two methods:

- `result(self)` — returns `_result`. If `_paginated`, callers should iterate via the API client's `_consume_results` instead.
- `to_httpx_kwargs(self) -> dict` — projects the descriptor into a `dict` of kwargs `httpx.{Async,}Client.request()` accepts. Strips `stream` (httpx doesn't take it). Used internally by `session.execute`.

The descriptor has **no** `.execute()`, `.consume_results()`, `.next_page()`, or `.parse_result()` method. Executing is the session's job; parsing is the `parse_response` function's job; pagination orchestration is the API client's job.

## `parse_response` — the pure parse function

Lives in `core.py`. Signature:

```python
def parse_response(response, request: PolyswarmRequest) -> None:
    """Read `response`, populate request fields, raise typed exceptions
    on non-2xx. Pure — no I/O. The caller (typically session.execute) is
    responsible for attaching `request` as `.result` on any raised
    exception before re-raising.
    """
```

Behaviour:

| Branch | Action |
|---|---|
| `request.method == 'HEAD'` | `request._result = response.status_code`; return. |
| Non-2xx | Extract JSON body into `request.json_body` / `.status` / `.errors`. Dispatch on status code: 404 → `NotFoundException`, 422 → `FailedInstanceException`, 429 → `UsageLimitsExceededException`, else → `RequestException`. Raise. |
| 2xx, no `result_parser` | Return (fire-and-forget endpoints). |
| 2xx, `result_parser` is `BaseJsonResource` subclass, status 204 | Raise `NoResultsException`. |
| 2xx, `BaseJsonResource` parser | Extract JSON. Populate pagination metadata (`_paginated` / `total` / `limit` / `offset` / `has_more`). Find `result` or `results` key in body. Dispatch on `result_parser.parse_result_list` (list) or `.parse_result` (single). |
| 2xx, non-`BaseJsonResource` parser | Call `result_parser.parse_result(api, response, **parser_kwargs)` directly. Used for file downloads (`LocalArtifact`). |

Testable in isolation: pass a fake response object with `.status_code` / `.json()` / `.headers`; pass a fresh `PolyswarmRequest`; assert fields populated or right exception raised. No httpx, no async, no fixtures.

## `BaseResource`

Tiny base. Constructor signature: `BaseResource(content, *args, api=None, **kwargs)`. Holds:

- `self.api` — the API client that produced this resource. Resources can call back into it (e.g. `task.api.session.upload_file(task.upload_url, artifact)` if a caller needs the resource's owning api).
- `self._content` — the raw payload (JSON dict for JSON resources, an HTTP response object for streaming ones).

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

Classmethod builders (each returns a `PolyswarmRequest` descriptor):

- `exists_hash(api, hash_value, hash_type, require_scan=False)` — HEAD request, returns the status code as the result.
- `search_hash(api, hash_value, hash_type)` — GET `/search/hash/{hash_type}`.
- `search_url(api, url)` — GET `/search/url`.
- `list_scans(api, hash_value)` — GET `/search/instances`.
- `lookup_uuid(api, scan)` — GET `/instance/{id}`.
- `rescan(api, hash_value, hash_type, scan_config=None)` — POST.
- `rescan_id(api, scan, scan_config=None)` — POST.
- `metadata_rerun(api, hashes, analyses=None, skip_es=None)` — POST.
- `create(api, …)`, `update(api, …)`, `download(cls, api, hash_value, hash_type, …)`, `download_id(cls, api, instance_id, …)`, `download_archive(cls, api, s3_path, …)`, `download_sandbox_artifact(cls, api, sandbox_task_id, instance_id, …)` — used by `submit`, `download*`, `stream` endpoints.

**No instance methods** that issue HTTP. Uploading to the pre-signed S3 URL is done via the session: `await api.session.upload_file(instance.upload_url, artifact)` (or `api.session.upload_file(...)` for sync).

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

`LocalArtifact.parse_result(api, response, …)` (the default `parse_result` on `BaseResource`) is invoked on a 2xx response when the `result_parser` is `LocalArtifact` (or any non-`BaseJsonResource` parser). It expects `response.iter_content(chunk_size)` — a `requests.Response`-style streaming API.

`httpx.Response` doesn't have `iter_content`; it has `iter_bytes`. `session.execute` detects this case (`not issubclass(result_parser, BaseJsonResource)`) and wraps the response in `HttpxResponseAdapter` before handing it to `parse_response`. The adapter exposes `iter_content(chunk_size)`, `status_code`, `headers`, `url`, `_content`, and `json()`.

This wrap happens identically in sync and async — both transports produce `httpx.Response`, and the adapter is shared (defined in `core.py`).

## Exceptions thrown by parsing

- `NoResultsException` — HTTP 204 with a typed `result_parser`.
- `NotFoundException` — HTTP 404, or a JSON-decode failure on a 404.
- `FailedInstanceException` — HTTP 422.
- `UsageLimitsExceededException` — HTTP 429.
- `RequestException` — any other non-2xx.

Each is raised by `parse_response` (without a `.result` attribute). The session catches them in `execute`, sets `exc.result = request`, and re-raises. Callers downstream read `.result.status_code`, `.result.json_body`, etc.

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
    response = FakeResponse(status_code=404, json_body={'result': 'not found', 'status': 'error'})
    request = PolyswarmRequest(method='GET', url='...')
    with pytest.raises(NotFoundException):
        parse_response(response, request)
    assert request.status_code == 404
```

These run in microseconds and exercise the parts of the SDK that are most likely to harbor subtle bugs.
