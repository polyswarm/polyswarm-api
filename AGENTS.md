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
| [`specs/01-architecture.md`](./specs/01-architecture.md) | Three layers + two transports; async-canonical + unasync codegen; pure descriptors; session-as-transport |
| [`specs/02-resources.md`](./specs/02-resources.md) | `BaseJsonResource`, classmethod builder convention (returns `PolyswarmRequest` descriptors), per-domain catalogue |
| [`specs/03-endpoints.md`](./specs/03-endpoints.md) | Endpoint catalogue: `_single` vs `_paginate`, special methods (polling, uploads via session, the `engines` cached method) |
| [`specs/04-testing.md`](./specs/04-testing.md) | Three test tiers (pure unit / respx-mocked / VCR), `ClientTestCase` parametrisation, record-on-delete workflow |
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

### The e2e test image is published from `develop`, not master

`.gitlab-ci.yml` builds a **test image** (`docker/Dockerfile` — the repo + its suite) that the e2e harness runs as its `polyswarm-api` command (this SDK suite, VCR-off, against the live stack). It's a **test artifact, not a deployed service**, and its `:latest` tag is promoted from **`develop`**:

- `build` + `e2e` run on every branch **except `master`**; **`develop`** additionally promotes the freshly-built SHA image to **`:latest`** (the `release` job is overridden to `only: [develop]`).
- Every other repo's e2e pipeline resolves `polyswarm-api:latest` by default (the e2e compose service is tagless), so merging to `develop` is what updates the image all those pipelines test against — the whole point of keeping it on develop.
- **`master` builds no image** — it runs `release-pypi` only (the PyPI package). The package release (master) and the e2e test image (develop) are deliberately decoupled: master = the released package, develop = the SDK code under test. So `:latest` here means "latest integrated SDK," which is intentionally *not* the workspace-wide "`:latest` = released" convention.

## Architectural shape (the short version)

Detailed treatment is in [`specs/01-architecture.md`](./specs/01-architecture.md). The summary:

Three layers, two transports.

- **Layer 1 — pure / shared.** [`src/polyswarm_api/core.py`](./src/polyswarm_api/core.py) (hand-written) holds `PolyswarmRequest` (the dataclass descriptor), `parse_response` (the pure parse function), `_raise_for_status` (the shared non-2xx → typed-exception mapper), `BaseJsonResource`, `Hashable`, and helpers. No I/O. Imported by both transports; not unasync-processed; single class identity across modules. Resources in [`resources.py`](./src/polyswarm_api/resources.py) are also pure — their classmethods build `PolyswarmRequest` descriptors.
- **Layer 2 — transport.** Hand-written canonical async at [`aio/session.py`](./src/polyswarm_api/aio/session.py); generated sync mirror at [`session.py`](./src/polyswarm_api/session.py). One class per transport (`AsyncPolyswarmSession` / `PolyswarmSession`) owns an httpx client. Two I/O methods: `execute(request)` (the authenticated round-trip) and `upload_file(url, artifact, …)` (PUT to a pre-signed S3 URL with the session-level `Authorization` header stripped). The session is the **only** place HTTP I/O happens.
- **Layer 3 — client.** Hand-written canonical async at [`aio/api.py`](./src/polyswarm_api/aio/api.py); generated sync mirror at [`api.py`](./src/polyswarm_api/api.py). `PolySwarmAsyncAPI` / `PolyswarmAPI` own a session, expose ~80 endpoint methods, drive pagination.

Codegen: [`scripts/regenerate_sync.py`](./scripts/regenerate_sync.py) runs unasync to mirror the canonical async sources to sync. Generated files carry a `# DO NOT EDIT` header; CI rejects stale mirrors.

Customization: subclass `AsyncPolyswarmSession` (or `PolyswarmSession`), override the method you want to change, inject via `PolySwarmAsyncAPI(session=MySession(...))`. No module-level monkey-patch sites.

`httpx` is the single HTTP library — sync uses `httpx.Client`, async uses `httpx.AsyncClient`. Both produce `httpx.Response`; `parse_response` is the same logic on both sides (it's a pure function in `core.py`).

No per-symbol codegen carve-outs: every method — including `engines`, a cached listing you `await api.engines()` (async) / `api.engines()` (sync) — mirrors cleanly through unasync. Post-processing only dedupes imports and adds the `# DO NOT EDIT` header. (`engines` was a cached *property* before 4.0; properties can't `await`, so it became a method when the async client landed — a breaking change for callers; see [`specs/05-downstream-contract.md`](./specs/05-downstream-contract.md).)

## When adding a new resource

Mirror the existing patterns (`LLMPromptConfig`, `MetadataFieldProperties`, `YaraRuleset`):

1. `class FooBar(BaseJsonResource): RESOURCE_ENDPOINT = '/…'` in [`resources.py`](./src/polyswarm_api/resources.py). If the resource's identifier isn't `id`, set `RESOURCE_ID_KEYS = ['your_key']` so the base class routes it into the query string for `GET` / `DELETE` / `PUT`. Resources are transport-agnostic — only edit `resources.py`.
2. Add convenience methods on **[`PolySwarmAsyncAPI`](./src/polyswarm_api/aio/api.py)** (the canonical async source). For a single resource: `return await self._single(resources.FooBar.<builder>(self, …))`. For paginated: `async for item in self._paginate(...): yield item`.
3. Run `python scripts/regenerate_sync.py` (or rely on the pre-commit hook) to regenerate the sync mirror at `polyswarm_api/api.py`.
4. Add unit tests for the resource builder (assert the resulting `PolyswarmRequest`'s shape) and `parse_response` behaviour where relevant — no httpx fixtures needed. For end-to-end coverage, add to the parametrised `ClientTestCase` harness in `test/metadata_field_properties_test.py`. See [`specs/04-testing.md`](./specs/04-testing.md).
5. Update [`specs/03-endpoints.md`](./specs/03-endpoints.md) (and any other relevant spec) in the same PR. Commit both `aio/api.py` and the regenerated `api.py`.

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
