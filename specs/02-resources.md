# Resources — `BaseJsonResource` + per-domain models

## Scope

How resource classes work: the `BaseResource` / `BaseJsonResource` machinery, the classmethod builder convention (which now returns **unexecuted** `PolyswarmRequest` objects), and the per-domain catalogue. This spec is the place to read before adding a new resource or changing a resource's parsing.

## Invariants

1. **Resource classmethods return UNEXECUTED `PolyswarmRequest` objects.** They are builders — they assemble the URL, params, and JSON body, attach a `result_parser`, and hand back a `PolyswarmRequest` instance. The API client (`PolyswarmAPIBase._single` / `_paginate`) calls `.execute()`. This is the lynchpin of the sync+async unification.
2. **One resource class = one domain.** A resource models a single response shape from the server (e.g. `ArtifactInstance`, `HistoricalHunt`, `MetadataFieldProperties`). Don't conflate domains in a single class.
3. **`RESOURCE_ENDPOINT` is the source of truth for URLs.** Verb-specific endpoint overrides (`_create_endpoint`, etc.) exist but are deprecated — prefer `RESOURCE_ENDPOINT` with optional `endpoint_fmt` for path interpolation. New resources shouldn't override the per-verb hooks.
4. **Resource methods that issue HTTP calls follow the same pattern as API methods.** `task.download_zip(folder=…)` returns an unexecuted `PolyswarmRequest`; the caller wraps in `self._single(...)` on the API side.
5. **Public resource class names and `RESOURCE_ENDPOINT` values are part of the contract.** They appear in callers' code (`isinstance(x, resources.ArtifactInstance)`); renames are breaking changes.

## Files

- `src/polyswarm_api/core.py` — `BaseResource`, `BaseJsonResource`, `PolyswarmRequest`, `Hashable`, helpers (`is_valid_sha1` / `_sha256` / `_md5`, `parse_isoformat`).
- `src/polyswarm_api/resources.py` — every per-domain resource class.

## The class hierarchy

```
BaseResource                          # holds .api, ._content, .parse_result classmethod
└── BaseJsonResource                  # adds .json, RESOURCE_ENDPOINT, jmespath(), _get(),
                                      # CRUD classmethods (create/get/head/update/delete/list)
    ├── ArtifactInstance              # /search/instances + .submit, .upload_file, .lookup_uuid
    ├── LocalArtifact                 # file handle wrapper, .upload_file (S3 PUT), .download
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
```

## `BaseResource`

Tiny base. Constructor signature: `BaseResource(content, *args, api=None, **kwargs)`. Holds:

- `self.api` — the API client that produced this resource. Resources call back into it (e.g. `task.upload_file(artifact)` uses `self.api.session`).
- `self._content` — the raw payload (JSON dict for JSON resources, an HTTP response object for streaming ones).

`@classmethod parse_result(cls, api, content, **kwargs)` is what `PolyswarmRequest.parse_result` invokes on a successful 2xx. The default builds `cls(content, api=api, **kwargs)`.

## `BaseJsonResource`

Adds:

- `self.json` — alias for `self._content` (the parsed JSON dict).
- `__int__(self)` — returns `int(self.id)` so resources can be passed wherever an ID int is expected.
- `jmespath(self, expr)` — apply a JMESPath expression to `self.json`. Returns `None` for missing paths. Lets callers extract nested fields without manual `_get('a.b.c')` chains. See its docstring for examples.
- `_get(self, path, default=None, content=None)` — dotted-path access with list-index support (`'a.b[0].c'`). Returns `default` on `KeyError` / `IndexError`.
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
4. Wraps it all in a `PolyswarmRequest(api, request_params, result_parser=cls)` and **returns it without executing**.

The hook layout (`_<verb>_endpoint`, `_<verb>_params`, `_<verb>_headers`) is preserved for resources that need per-verb URL customisation. New resources shouldn't override them — prefer `RESOURCE_ENDPOINT` with `endpoint_fmt` (see below).

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

- `None` values are dropped (matching the `requests` library behaviour the test suite was written against — `httpx` would otherwise send them as empty strings).
- Keys named `id` or `*_id` are coerced to `str(int(v))` if possible, else `str(v)`. Server expects string IDs.
- Booleans are coerced to int (0/1) at the param layer. The HTTP session layer additionally normalises any remaining bool values to `'True'` / `'False'` (capitalised) — see `_normalise_bool_params` in [`01-architecture.md`](./01-architecture.md).
- `RESOURCE_ID_KEYS` (default `['id']`) lists keys that must go to the query string for `GET` / `DELETE` / `PUT` (which would otherwise put non-list kwargs in the JSON body). For example, `MetadataFieldProperties.RESOURCE_ID_KEYS = ['field_path']`.

### Adding a new resource

```python
class FooBar(core.BaseJsonResource):
    RESOURCE_ENDPOINT = '/foobar'
    RESOURCE_ID_KEYS = ['foo_id']   # only needed if the identifier isn't 'id'

    # Optional: parametrised path
    # RESOURCE_ENDPOINT = '/foobar/{foo_id}'
    # — combine with endpoint_fmt={'foo_id': foo_id} at the call site
```

Then in `_base.py`:

```python
class PolyswarmAPIBase:
    def foobar_get(self, foo_id):
        return self._single(resources.FooBar.get(self, foo_id=foo_id))

    def foobar_write(self, foo_id, payload):
        return self._single(resources.FooBar.create(
            self, foo_id=foo_id, payload=payload,
        ))

    def foobar_list(self):
        return self._paginate(resources.FooBar.list(self))
```

Tests go under the parametrised `ClientTestCase` harness — see [`04-testing.md`](./04-testing.md).

## Per-resource notes

### `Hash` / `Hashable`

`Hashable` is a mixin. `Hash.from_hashable(value, hash_type=None)` accepts a `Hash`, an `ArtifactInstance`, a `LocalArtifact`, or a hex string and returns a `Hash` with the right `hash_type` and `hash` attributes. Used everywhere a method takes a `hash_` parameter — see `PolyswarmAPIBase.search`, `.exists`, `.download`, `.rescan`.

Supported hash types are listed in `Hashable.SUPPORTED_HASH_TYPES` (`sha1`, `sha256`, `md5`). `validate_hash=True` on construction raises `InvalidValueException` on a mismatch.

### `ArtifactInstance`

Wraps a single scan instance. Carries `id`, `sha256`, `upload_url`, the assertion / detection counts, the scan metadata.

Classmethod builders (each returns an unexecuted `PolyswarmRequest`):

- `exists_hash(api, hash_value, hash_type, require_scan=False)` — HEAD request, returns the status code as the result.
- `search_hash(api, hash_value, hash_type)` — GET `/search/hash/{hash_type}`.
- `search_url(api, url)` — GET `/search/url`.
- `list_scans(api, hash_value)` — GET `/search/instances`.
- `submit(cls, api, artifact, artifact_name, artifact_type, scan_config=None)` — POST a file upload (multipart).
- `lookup_uuid(api, scan)` — GET `/instance/{id}`.
- `rescan(api, hash_value, hash_type, scan_config=None)` — POST.
- `rescan_id(api, scan, scan_config=None)` — POST.
- `metadata_rerun(api, hashes, analyses=None, skip_es=None)` — POST.

Instance method:

- `upload_file(self, artifact, attempts=3, **kwargs)` — issues `httpx.put(self.upload_url, content=…)` to the pre-signed S3 URL the server returned. Executed synchronously regardless of whether the API client is sync or async — see [`03-endpoints.md`](./03-endpoints.md) §"File-upload paths".

### `LocalArtifact`

A file-system or in-memory artifact prepared for upload. Constructed via:

- `LocalArtifact.from_path(api, path, artifact_type, artifact_name=None)` — opens a file.
- `LocalArtifact.from_handle(api, handle, artifact_name, artifact_type)` — wraps an open file-like.
- `LocalArtifact.from_content(api, content, artifact_name, artifact_type)` — wraps an in-memory string (URL submissions).

Holds `handle`, `artifact_name`, `artifact_type`, `sha256`, `sha1`, `md5`. The `download_*` classmethods build `PolyswarmRequest`s for `result_parser=LocalArtifact` (non-JSON parsing path).

### `BaseJsonResource` subclasses with custom builders

Several resources add domain-specific classmethods on top of the standard CRUD set:

- `IOC` — `iocs_by_hash`, `ioc_search`, `check_known_hosts`, `create_known_good`, `create_known_bad`, `update_known_good`, `delete_known_good`.
- `LiveYaraRuleset` / `HistoricalHunt` / `YaraRuleset` — standard CRUD plus list/delete-batch variants.
- `SandboxTask` — `create_file`, `update_file`, `latest`, `my_tasks` for the various sandbox-submission shapes.
- `Sample` — `create` with `endpoint_fmt={'sha256': sha256}` for the URL-parametrised path.
- `Webhook` — `test(api, webhook_id)` for the test-payload endpoint.

These follow the same convention: build a `PolyswarmRequest`, return unexecuted.

## Resource-instance methods that issue HTTP

A small set of resources expose instance methods that hand back unexecuted requests:

- `LocalArtifact.upload_file(artifact, attempts=3)` — uploads to the pre-signed S3 URL. Executed inline (synchronous `httpx.put`), not via `_single` / `_paginate`. See [`03-endpoints.md`](./03-endpoints.md).
- `BundleTask.download_zip(folder=None)` — returns `PolyswarmRequest(result_parser=LocalArtifact)`. Caller wraps in `self._single(task.download_zip(…))`.
- `ReportLLMPostProcessing.download_report(folder=None)` — same shape.
- `ReportTask.download_report(folder=None)` — same shape.
- `ReportTemplate.download_logo(folder)` — same shape.
- `ReportTemplate.delete_logo()` — same shape.
- `ReportTemplate.upload_logo(logo_file, content_type)` — same shape.

The caller (in `_base.py`'s sync-only carve-outs for upload methods, or anywhere on the base for the rest) does:

```python
result = self._single(task.download_zip(folder=folder))
result.handle.close()
return result
```

## Streaming / non-JSON responses

`LocalArtifact.parse_result(api, response, …)` (the default `parse_result` on `BaseResource`) is invoked on a 2xx response when the `result_parser` is `LocalArtifact` (or any non-`BaseJsonResource` parser). It expects `response.iter_content(chunk_size)` — a `requests.Response`-style streaming API.

`httpx.Response` doesn't have `iter_content`; it has `iter_bytes`. `PolyswarmRequest.execute()` detects this case (`not issubclass(result_parser, BaseJsonResource)`) and wraps the response in `HttpxResponseAdapter` before handing it to the parser. The adapter exposes `iter_content(chunk_size)`, `status_code`, `headers`, `url`, `_content`, and `json()`.

This wrap happens identically in sync and async — both transports produce `httpx.Response`, and the adapter is shared (defined in `core.py`).

## Exceptions thrown by parsing

- `NoResultsException` — HTTP 204 with a typed `result_parser`.
- `NotFoundException` — HTTP 404, or a JSON-decode failure on a 404.
- `FailedInstanceException` — HTTP 422.
- `UsageLimitsExceededException` — HTTP 429 (rate-limited or plan exceeded).
- `RequestException` — any other non-2xx, plus JSON-decode failures on non-404s.
- `InvalidValueException` — client-side validation (hash mismatch, missing required field). No HTTP round-trip.

All but `InvalidValueException` carry the originating `PolyswarmRequest` as `exception.result`, so callers can inspect `.status_code`, `.json`, `.request_parameters`.
