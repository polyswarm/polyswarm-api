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
| `polyswarm_api.core` | Lower-level plumbing: `PolyswarmRequest`, `BaseJsonResource`, `HttpxResponseAdapter`. Public for advanced consumers that want to subclass / wrap. |
| `polyswarm_api.aio.upload.async_upload_file` | Module-level async upload helper. Downstream consumers monkey-patch this; the call signature is part of the contract. |

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
   │   PolyswarmAPIBase     │   parsing, retry/auth/pagination logic.
   └─────────┬──────────────┘
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
├── src/polyswarm_api/
│   ├── __init__.py                 # public exports + __version__
│   ├── _base.py                    # PolyswarmAPIBase — every endpoint method
│   ├── api.py                      # sync PolyswarmAPI(PolyswarmAPIBase)
│   ├── core.py                     # PolyswarmRequest, PolyswarmSession, BaseJsonResource, HttpxResponseAdapter
│   ├── resources.py                # per-domain data wrappers
│   ├── settings.py                 # constants (default URI, timeouts, poll frequency)
│   ├── exceptions.py               # exception hierarchy
│   └── aio/
│       ├── __init__.py             # async PolySwarmAsyncAPI(PolyswarmAPIBase)
│       ├── core.py                 # AsyncPolyswarmSession, AsyncPolyswarmRequest(PolyswarmRequest)
│       └── upload.py               # async_upload_file (monkey-patch site, see 05-downstream-contract)
└── test/
    ├── conftest.py
    ├── client_scan_test.py             # sync, VCR-backed integration tests
    ├── async_client_test.py            # async, VCR-backed integration tests
    ├── metadata_field_properties_test.py  # parametrised sync+async via ClientTestCase harness
    ├── jmespath_test.py
    └── vcr/                            # *.vcr cassettes
```

## Architectural snapshot

Both clients subclass `PolyswarmAPIBase`. Every endpoint method lives **once** on the base. The sync/async difference is contained to three hooks the subclasses override:

```
                  PolyswarmAPIBase
                  ─────────────────
                  • ~100 endpoint methods
                  • _coerce_request, _build_request_kwargs (shared)
                  • _single, _paginate, _sleep   (abstract — overridden by subclasses)
                          ▲
                          │
            ┌─────────────┴─────────────┐
            │                           │
   PolyswarmAPI (sync)        PolySwarmAsyncAPI (async)
   ──────────────────         ─────────────────────────
   • httpx.Client             • httpx.AsyncClient
   • sync _single → value     • async _single → coroutine
   • sync _paginate → gen     • async _paginate → asyncgen
   • _sleep → time.sleep      • _sleep → asyncio.sleep
   • wait_for, submit, …      • wait_for, submit, …       (sync/async-specific)
```

The trick that lets one method body work for both transports: the base method is regular `def`, not `async def`, and it just returns whatever the subclass's hook returned. Detailed treatment in [`01-architecture.md`](./01-architecture.md).

## Specs you should read next

- New endpoint? → [`03-endpoints.md`](./03-endpoints.md).
- Touching the request/response pipeline? → [`01-architecture.md`](./01-architecture.md).
- Adding a resource class? → [`02-resources.md`](./02-resources.md).
- Writing tests? → [`04-testing.md`](./04-testing.md).
- Worried about breaking downstream callers? → [`05-downstream-contract.md`](./05-downstream-contract.md).
