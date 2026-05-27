# polyswarm-api — Overview

## Scope

What the `polyswarm-api` Python SDK is, what it ships, where it sits in the platform, and how the repository is laid out. Subsequent specs zoom in on a single area; this one is the map.

## Invariants

- **The SDK is the published surface.** Released to PyPI as `polyswarm-api`. Anything reachable from the package's `__init__.py`, the `polyswarm_api.aio` namespace, `polyswarm_api.resources`, or `polyswarm_api.exceptions` is part of the public contract. Breaking changes need a major version bump.
- **`master` is the release branch.** A version bump on `master` triggers a PyPI release. Feature PRs always target `develop` (see `AGENTS.md` §Gitflow).
- **The SDK does not run a server.** It's a client. It talks to the platform's REST API.

## What this repo ships

| Artefact | Description |
|---|---|
| `polyswarm_api.PolyswarmAPI` | Synchronous client. What CLI tools and sync scripts use. |
| `polyswarm_api.aio.PolySwarmAsyncAPI` | Asynchronous client. Same method surface, `await`-able. |
| `polyswarm_api.PolyswarmSession` / `polyswarm_api.aio.AsyncPolyswarmSession` | Transport classes. Own the underlying `httpx.{,Async}Client`, expose `execute(request)` and `upload_file(url, artifact, …)`. Subclass and inject to customize transport behaviour. |
| `polyswarm_api.resources` | Per-domain resource classes (`ArtifactInstance`, `LocalArtifact`, `HistoricalHunt`, `LiveYaraRuleset`, `YaraRuleset`, `MetadataFieldProperties`, `LLMPromptConfig`, …). Wrappers over the server's JSON responses. Builder classmethods (`create` / `get` / `update` / `delete` / `list` / etc.) return `PolyswarmRequest` descriptors. |
| `polyswarm_api.core.PolyswarmRequest` | Pure description of an HTTP call (method, URL, params, body, parser). Constructed by resource builders; handed to a session for execution. No I/O on the descriptor itself. |
| `polyswarm_api.exceptions` | Exception hierarchy (`PolyswarmException` → `RequestException`, `NotFoundException`, `FailedInstanceException`, `NoResultsException`, `UsageLimitsExceededException`, `InvalidValueException`, `TimeoutException`). |

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

- HTTP transport (request, retry, auth header injection, off-domain upload with auth stripping).
- Response shape parsing (JSON → resource objects, error codes → exceptions).
- Pagination (`has_more` / `offset` / `limit` consumption, transparent next-page fetch).
- The unified sync+async pattern via async-canonical source + unasync codegen.

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
├── .gitlab-ci.yml                  # test + codegen-staleness CI
├── .pre-commit-config.yaml         # pre-commit hook for codegen
├── pyproject.toml                  # version, deps, [tool.bumpversion]
├── scripts/
│   └── regenerate_sync.py          # unasync codegen driver
├── src/polyswarm_api/
│   ├── __init__.py                 # public exports + __version__
│   ├── core.py                     # HAND-WRITTEN, transport-agnostic:
│   │                               #   - PolyswarmRequest (dataclass descriptor)
│   │                               #   - parse_response (pure function)
│   │                               #   - HttpxResponseAdapter (pure adapter)
│   │                               #   - BaseResource, BaseJsonResource
│   │                               #   - Hashable, Hash, hash validators
│   │                               #   - helpers (parse_isoformat, encoders, normalisers)
│   ├── resources.py                # HAND-WRITTEN. Per-domain wrappers. Builders
│   │                               # return PolyswarmRequest descriptors.
│   ├── exceptions.py               # HAND-WRITTEN. Exception hierarchy.
│   ├── settings.py                 # HAND-WRITTEN. Default URI, timeouts, etc.
│   ├── session.py                  # GENERATED from aio/session.py.
│   │                               #   PolyswarmSession (httpx.Client wrapper).
│   │                               #   .execute(request), .upload_file, .close
│   ├── api.py                      # GENERATED from aio/api.py.
│   │                               #   PolyswarmAPI (owns a PolyswarmSession,
│   │                               #   ~80 endpoint methods + carve-outs).
│   └── aio/
│       ├── __init__.py             # re-exports PolySwarmAsyncAPI, AsyncPolyswarmSession
│       ├── session.py              # CANONICAL async. AsyncPolyswarmSession class.
│       └── api.py                  # CANONICAL async. PolySwarmAsyncAPI class.
└── test/
    ├── conftest.py
    ├── client_scan_test.py             # sync, VCR-backed integration tests
    ├── async_client_test.py            # async, VCR-backed integration tests
    ├── metadata_field_properties_test.py  # parametrised sync+async via ClientTestCase harness
    ├── jmespath_test.py
    └── vcr/                            # *.vcr cassettes
```

Six SDK modules (`core`, `resources`, `exceptions`, `settings`, plus the `session` + `api` pair), where the `session` / `api` pair has a canonical async source under `aio/` and a generated sync mirror at the root. Each file has a single concern.

## Architectural snapshot

Three layers, two transports.

```
              ┌───────────────────────────────────────────────────┐
              │  PURE / SHARED  (hand-written, no I/O)            │
              │                                                   │
              │  core.py                                          │
              │    PolyswarmRequest      (dataclass descriptor)   │
              │    parse_response        (pure function)          │
              │    BaseJsonResource      (resource hierarchy)     │
              │    Hashable, Hash, validators                     │
              │                                                   │
              │  resources.py                                     │
              │    ArtifactInstance, LocalArtifact, …             │
              │    (classmethods build descriptors)               │
              │                                                   │
              │  exceptions.py, settings.py                       │
              └───────────────────────────────────────────────────┘
                   ▲                              ▲
                   │ imports                      │ imports
                   │                              │
        ┌──────────┴───────────┐         ┌────────┴───────────┐
        │  TRANSPORT (async)   │         │  TRANSPORT (sync)  │
        │  aio/session.py      │ ──┐  ┌─ │  session.py [gen]  │
        │  AsyncPolyswarm-     │   │  │  │  PolyswarmSession  │
        │  Session             │   │  │  │  .execute()        │
        │  .execute()          │   │  │  │  .upload_file()    │
        │  .upload_file()      │   │  │  │  .close()          │
        │  .aclose()           │   │  │  │  (httpx.Client)    │
        │  (httpx.AsyncClient) │   │  │  │                    │
        └──────────────────────┘   │  │  └────────────────────┘
                                   │  │
                       scripts/regenerate_sync.py (unasync)
                                   │  │
        ┌──────────────────────┐   │  │  ┌────────────────────┐
        │  CLIENT (async)      │   │  │  │  CLIENT (sync)     │
        │  aio/api.py          │ ──┘  └─ │  api.py [generated]│
        │  PolySwarmAsyncAPI   │         │  PolyswarmAPI      │
        │  (owns a session,    │         │  (owns a session,  │
        │  ~80 endpoint methods│         │   ~80 endpoint mtd.│
        │  + carve-outs)       │         │  + carve-outs)     │
        └──────────────────────┘         └────────────────────┘
```

- **Pure layer** has no transport awareness. Both transports import from it. unasync does not process it.
- **Transport layer** is a single class per transport. Owns the httpx client. Has every HTTP-I/O operation (`execute`, `upload_file`). The sync mirror is generated from the canonical async by unasync.
- **Client layer** owns a session, drives pagination, exposes the endpoint method surface. Sync mirror generated from canonical async.

Customization point: subclass `AsyncPolyswarmSession` (or `PolyswarmSession`), override `execute` / `upload_file`, inject via `PolySwarmAsyncAPI(session=MySession(...))`.

## Specs you should read next

- New endpoint? → [`03-endpoints.md`](./03-endpoints.md).
- Touching the request/response pipeline? → [`01-architecture.md`](./01-architecture.md).
- Adding a resource class? → [`02-resources.md`](./02-resources.md).
- Writing tests? → [`04-testing.md`](./04-testing.md).
- Worried about breaking downstream callers? → [`05-downstream-contract.md`](./05-downstream-contract.md).
