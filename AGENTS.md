# AGENTS.md — polyswarm-api

Orientation document for AI agents and humans new to the repo. Update it when major workflow decisions land.

This file points at the right places to read for context, lays out the gitflow / VCR / commit conventions, and outlines the shared sync+async architecture. **Detailed contracts, invariants, and per-area design live under [`specs/`](./specs/)** — read those before changing the corresponding code.

## Reading order for a new contributor

1. This file (gitflow + conventions + architectural shape).
2. [`specs/00-overview.md`](./specs/00-overview.md) — what the SDK is and how the pieces fit.
3. The spec(s) for the area you're changing — see [`specs/`](./specs/) index below.
4. The code in `src/polyswarm_api/` itself; the specs are authoritative on intent, the code on detail.

## Specs index

| Spec | Scope |
|---|---|
| [`specs/00-overview.md`](./specs/00-overview.md) | What this repo ships, where it sits in the platform, repo layout |
| [`specs/01-architecture.md`](./specs/01-architecture.md) | `PolyswarmAPIBase` + sync/async pattern, request/response pipeline, `_single` / `_paginate` contract |
| [`specs/02-resources.md`](./specs/02-resources.md) | `BaseJsonResource`, classmethod builder convention, per-domain resource catalogue |
| [`specs/03-endpoints.md`](./specs/03-endpoints.md) | Endpoint catalogue: single vs paginated, sync/async-specific carve-outs (polling, uploads), URL builders |
| [`specs/04-testing.md`](./specs/04-testing.md) | `responses` / `respx` / VCR conventions, `ClientTestCase` parametrisation, record-on-delete workflow |
| [`specs/05-downstream-contract.md`](./specs/05-downstream-contract.md) | What the published surface looks like to consumers (the CLI, downstream services), backward-compat invariants |
| [`specs/99-open-questions.md`](./specs/99-open-questions.md) | Known follow-ups and unresolved questions |

Specs respect a strict convention: each one is independently readable, opens with **Scope** and **Invariants**, and lists the files / symbols it talks about. Update the spec in the same PR as the code change; if a PR drifts from the spec, the spec is wrong until proven otherwise.

## Gitflow — **read this before opening a PR**

This repo follows a strict `feature → develop → master` flow:

```
feature/*  ─┐
            └─► develop  ─►  master
```

**Rules:**

- **Feature PRs target `develop`**, never `master`. Branch off `develop`, push, open a PR with `develop` as the base. CI runs on the PR. Reviewers merge to `develop`.
- **`develop → master` PRs are how `master` advances.** They're opened by a maintainer when a release-worthy batch of work is on `develop`. Most contributors never open one of these.
- **Direct PRs to `master`** are wrong. If you opened one, close it, branch off `develop` instead, and re-open against `develop`.
- **PyPI release happens automatically** when `pyproject.toml`'s `version` changes on `master`. Don't bump the version inside a feature PR unless the maintainer specifically asks — version bumps belong to the `develop → master` step.

**Why this matters:** `master` is the published surface of the SDK. PyPI consumers see whatever shows up there. Skipping `develop` skips the integration soak that protects against accidentally shipping a half-baked change.

### Checking the base before pushing

Before pushing a feature branch, sanity-check what `gh pr create` will target:

```bash
gh pr create --base develop --head <your-branch> --title "<…>" --body "<…>"
```

If you ever omit `--base`, the gh CLI defaults to the repo's default branch — which on this repo is `develop`, but it's worth being explicit.

### Past incident

PR #295 was merged directly to `master` and had to be reverted (#296) and re-opened against `develop`. The version file wasn't touched, so no PyPI release fired — but the rollback was still disruptive. Don't repeat it.

## Architectural shape (the short version)

Detailed treatment is in [`specs/01-architecture.md`](./specs/01-architecture.md). The summary:

- **`PolyswarmAPIBase`** (`src/polyswarm_api/_base.py`) holds every endpoint method. Both sync `PolyswarmAPI` and async `PolySwarmAsyncAPI` subclass it.
- Each base method is a one-liner: `return self._single(resources.X.method(self, …))` or `return self._paginate(…)`. The body is regular `def` (not `async def`).
- Sync subclass: `_single` returns the value, `_paginate` is a generator function. Caller writes `result = api.foo()` or `for x in api.foo()`.
- Async subclass: `_single` is `async def` (returns a coroutine), `_paginate` is an async generator function. Caller writes `result = await api.foo()` or `async for x in api.foo()`.
- The async caller's `await` consumes the coroutine that the base method passed through. No metaclass magic.

The only sync/async-specific code lives in `_single` / `_paginate` / `_sleep` on each subclass, plus a small set of methods that genuinely diverge (polling helpers, file uploads, the `engines` property — see [`specs/03-endpoints.md`](./specs/03-endpoints.md)).

`httpx` is the single HTTP library — `requests` is no longer a runtime dependency. The sync transport uses `httpx.Client`, async uses `httpx.AsyncClient`. Both produce `httpx.Response` objects with the same synchronous `.json()` / `.raise_for_status()` surface, so the response-parsing layer is shared via inheritance (`AsyncPolyswarmRequest` extends `PolyswarmRequest`).

## When adding a new resource

Mirror the existing patterns (`LLMPromptConfig`, `MetadataFieldProperties`, `YaraRuleset`):

1. `class FooBar(core.BaseJsonResource): RESOURCE_ENDPOINT = '/…'`. If the resource's identifier isn't `id`, set `RESOURCE_ID_KEYS = ['your_key']` so the base class routes it into the query string for `GET` / `DELETE` / `PUT`.
2. Add convenience methods on **`PolyswarmAPIBase`** (`_base.py`). Each is a one-liner: `return self._single({'method': '…', 'url': '…', …}, result_parser=resources.FooBar)`. **Do not** add separate sync and async versions in `api.py` / `aio/__init__.py` — the base method works for both.
3. For paginated list endpoints, call `self._paginate(...)` instead. Sync callers iterate with `for`; async callers with `async for`.
4. Test with the parametrised `ClientTestCase` harness in `test/metadata_field_properties_test.py` — your tests run against both clients automatically. See [`specs/04-testing.md`](./specs/04-testing.md).
5. Update [`specs/03-endpoints.md`](./specs/03-endpoints.md) (and any other relevant spec) in the same PR.

## VCR cassette workflow

`client_scan_test.py` and `async_client_test.py` use VCR cassettes (`vcrpy`) for tests that hit real PolySwarm endpoints. Cassettes live in `test/vcr/` and use `record_mode='once'` (the default): the first run records, subsequent runs replay.

**To re-record a cassette against the live e2e stack:**

```bash
rm test/vcr/<cassette_name>.vcr
pytest test/<test_file>.py::TestClass::test_method
```

The deletion makes VCR record a fresh cassette; the test runs against whatever e2e environment your settings point at.

**VCR matcher convention** (see [`specs/04-testing.md`](./specs/04-testing.md) for the full details): use `[method, scheme, host, port, path, query]` rather than the literal `uri` matcher — the `query` matcher compares params as a set, so cassettes survive httpx's different param-ordering.

**Invariant: tests must pass against the live e2e stack with VCR off.** VCR is an efficiency cache, not a load-bearing requirement. Don't hardcode `record_mode='none'`. If a test only works against the recorded cassette, that's a bug in the test.

## Commit + PR hygiene

- Conventional commit prefixes (`feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`).
- Small, scoped commits — each one should be independently reviewable.
- **Don't reference ticket IDs or internal project codes in commit messages, PR titles, or PR descriptions.** This repo is public; published artefacts shouldn't leak internal references. Track tickets in the internal tracker, not the git history.
- **Don't name private companion repos in PR descriptions or commit messages on this repo.** Internal services are downstream of this SDK; refer to them by category ("the downstream consumers" / "the CLI client") rather than by repo name.
- No AI-attribution trailers on commits (`Co-Authored-By: Claude …`, "Generated with Claude Code", etc.) — they're noise and they don't belong in project history.

## Companion repos (public)

- `polyswarm-cli` — wraps these methods in click commands. SDK changes that need a CLI surface usually ship as a pair (`polyswarm-api` PR + `polyswarm-cli` PR with the SDK PR linked under `## Requires`).
- `artifact-index` — the server-side API the SDK talks to. New endpoints land there first; the SDK PR comes after.
