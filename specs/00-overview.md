# polyswarm-api — Overview

## Scope

This spec describes what the `polyswarm-api` Python SDK is, what it ships, where it sits relative to the rest of the platform, and how the repository is laid out. Subsequent specs zoom in on a specific area; this one is a map.

## Invariants

- **The SDK is the published surface.** It's released to PyPI as `polyswarm-api`. Anything reachable from the package's `__init__.py`, the `polyswarm_api.aio` namespace, `polyswarm_api.resources`, or `polyswarm_api.exceptions` is part of the public contract. Breaking changes need a major version bump.
- **`master` is the release branch.** A version bump on `master` triggers a PyPI release. Feature PRs always target `develop` (see `AGENTS.md` §Gitflow).
- **The SDK does not run a server.** It's a client. It talks to the platform's REST API.

## What this repo ships

| Artefact | Description |
|---|---|
| `polyswarm_api.PolyswarmAPI` | Synchronous client. The classic surface; what most callers use. |
| `polyswarm_api.aio.PolySwarmAsyncAPI` | Asynchronous client. Same method surface, `await`-able. |
| `polyswarm_api.resources` | Per-domain resource classes (`ArtifactInstance`, `LocalArtifact`, `HistoricalHunt`, `LiveYaraRuleset`, `YaraRuleset`, `MetadataFieldProperties`, `LLMPromptConfig`, …). Data wrappers over the server's JSON responses. |
| `polyswarm_api.exceptions` | Exception hierarchy (`PolyswarmException` → `RequestException`, `NotFoundException`, `FailedInstanceException`, `NoResultsException`, `UsageLimitsExceededException`, `InvalidValueException`, `TimeoutException`). |
| `polyswarm_api.core` | Lower-level plumbing: `PolyswarmRequest`, `BaseJsonResource`, `HttpxResponseAdapter`. Public for advanced consumers that want to subclass / wrap. (Generated sync mirror of `polyswarm_api.aio.core` + re-exports of the shared bases from `polyswarm_api._bases`.) |
| `polyswarm_api.aio.upload.async_upload_file` / `async_upload_logo` | Module-level async upload helpers. Downstream consumers monkey-patch these; the call signatures are part of the contract. |
| `polyswarm_api.upload.upload_file` / `upload_logo` | Generated sync mirrors of the async upload helpers. |

## Where it sits

```
   ┌────────────────────────┐
   │   PyPI consumers       │   CLI, downstream services, third-party integrators.
   │   sync   │   async     │   They import PolyswarmAPI or PolySwarmAsyncAPI.
   └─────┬──────────┬───────┘
         │          │
         ▼          ▼
   ┌────────────────────────┐
   │   polyswarm-api (this) │   Sync + async HTTP clients, request/response
   │   PolyswarmAPI         │   parsing, retry/auth/pagination logic.
   │   PolySwarmAsyncAPI    │   Sync mirror is generated from the canonical
   └─────────┬──────────────┘   async source by scripts/regenerate_sync.py.
             │  httpx (sync + async)
             ▼
   ┌────────────────────────┐
   │   artifact-index       │   Server-side REST API. Companion repo.
   │   (REST API)           │   `/v3/...` endpoints.
   └────────────────────────┘
```

The SDK is the only Python surface a consumer needs in order to talk to the platform. It owns:

- HTTP transport (request, retry, auth header injection).
- Response shape parsing (JSON → resource objects, error codes → exceptions).
- Pagination (`has_more` / `offset` / `limit` consumption, transparent next-page fetch).
- The unified sync+async pattern (see [`01-architecture.md`](./01-architecture.md)).

The SDK does **not** own:

- The REST API contract — that lives in the artifact-index repo.
- CLI ergonomics — that lives in the polyswarm-cli repo. The CLI imports this SDK.
- Server-side data model, business logic, authentication storage.

## Repository layout

```
polyswarm-api/
├── AGENTS.md                       # orientation; gitflow, conventions, pointers to specs/
├── CLAUDE.md                       # symlink to AGENTS.md
├── specs/                          # contract / design / invariant docs (this directory)
├── .github/
│   └── workflows/
│       └── claude-code-review.yml  # automated PR review against specs/ + AGENTS.md
├── pyproject.toml                  # version, deps, [tool.bumpversion]
├── scripts/
│   └── regenerate_sync.py          # unasync codegen driver
├── src/polyswarm_api/
│   ├── __init__.py                 # public exports + __version__
│   ├── _bases.py                   # hand-written, shared: BaseJsonResource, Hashable,
│   │                               #   HttpxResponseAdapter, helpers
│   ├── api.py                      # GENERATED sync PolyswarmAPI (unasync mirror of aio/api.py)
│   ├── core.py                     # GENERATED sync PolyswarmRequest, PolyswarmSession
│   │                               #   (unasync mirror of aio/core.py; also re-exports
│   │                               #   bases from _bases.py for back-compat)
│   ├── upload.py                   # GENERATED sync upload_file / upload_logo
│   ├── resources.py                # per-domain data wrappers (transport-agnostic)
│   ├── settings.py                 # constants (default URI, timeouts, poll frequency)
│   ├── exceptions.py               # exception hierarchy
│   └── aio/
│       ├── __init__.py             # re-exports PolySwarmAsyncAPI + the transport types
│       │                           #   and upload monkey-patch sites from the modules below
│       ├── api.py                  # CANONICAL async PolySwarmAsyncAPI — every endpoint method
│       ├── core.py                 # CANONICAL AsyncPolyswarmSession, AsyncPolyswarmRequest
│       └── upload.py               # CANONICAL async_upload_file (monkey-patch site,
│                                   #   see 05-downstream-contract)
└── test/
    ├── conftest.py
    ├── client_scan_test.py             # sync, VCR-backed integration tests
    ├── async_client_test.py            # async, VCR-backed integration tests
    ├── metadata_field_properties_test.py  # parametrised sync+async via ClientTestCase harness
    ├── jmespath_test.py
    └── vcr/                            # *.vcr cassettes
```

## Architectural snapshot

The async client at [`aio/api.py`](../src/polyswarm_api/aio/api.py) is the canonical source. The sync client at [`api.py`](../src/polyswarm_api/api.py) is generated from it by `scripts/regenerate_sync.py` (an `unasync`-driven codegen — `async def` → `def`, `await` removed, `asyncio.sleep` → `time.sleep`, etc.). The generated files carry a `# DO NOT EDIT` header.

```
              aio/api.py  (canonical)                  api.py     (generated)
              ─────────────────────                    ──────────────────────
              class PolySwarmAsyncAPI:                 class PolyswarmAPI:
                _request_cls = AsyncPolyswarmRequest    _request_cls = PolyswarmRequest
                                                        (mechanical mirror of the
                async def metadata_mapping(self):       canonical async source)
                  return await self._single(...)       def metadata_mapping(self):
                                                          return self._single(...)
                async def search(self, ...):
                  async for x in self._paginate(...):  def search(self, ...):
                    yield x                              for x in self._paginate(...):
                                                            yield x

              aio/core.py  (canonical)                 core.py    (generated)
              ─────────────────────                    ──────────────────────
              AsyncPolyswarmSession                    PolyswarmSession
                (httpx.AsyncClient)                      (httpx.Client)
              AsyncPolyswarmRequest                    PolyswarmRequest
                (async execute / consume_results)        (sync mirror)

              aio/upload.py (canonical)                upload.py  (generated)
              ─────────────────────                    ──────────────────────
              async_upload_file                        upload_file
              async_upload_logo                        upload_logo

              _bases.py  (hand-written, shared)
              ────────────────────────────────
              BaseResource, BaseJsonResource, Hashable, HttpxResponseAdapter,
              parse_isoformat, is_hex/sha1/md5/sha256, _normalise_bool_params,
              RequestParamsEncoder.
              Both sync and async cores import from here so issubclass()
              checks across modules see a single class identity.
```

`PolySwarmAsyncAPI` and `PolyswarmAPI` are **independent classes** mechanically aligned by codegen. There is no shared base class; the historical `PolyswarmAPIBase` is gone. Detailed treatment in [`01-architecture.md`](./01-architecture.md).

## Specs you should read next

- New endpoint? → [`03-endpoints.md`](./03-endpoints.md).
- Touching the request/response pipeline? → [`01-architecture.md`](./01-architecture.md).
- Adding a resource class? → [`02-resources.md`](./02-resources.md).
- Writing tests? → [`04-testing.md`](./04-testing.md).
- Worried about breaking downstream callers? → [`05-downstream-contract.md`](./05-downstream-contract.md).
