# AGENTS.md — polyswarm-api

Orientation document for AI agents and humans new to the repo. Update it when major workflow decisions land.

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

## Layout

- `src/polyswarm_api/_base.py` — **`PolyswarmAPIBase`** holds the shared constructor, instance state, and (incrementally) every endpoint method. Both sync and async clients subclass it.
- `src/polyswarm_api/api.py` — sync `PolyswarmAPI(PolyswarmAPIBase)`. Provides `_single` / `_paginate` / `_sleep` via `requests.Session` (and, eventually, `httpx.Client`).
- `src/polyswarm_api/aio/__init__.py` — async `PolySwarmAsyncAPI(PolyswarmAPIBase)`. Provides `_single` / `_paginate` / `_sleep` via `httpx.AsyncClient`.
- `src/polyswarm_api/core.py` — `PolyswarmRequest` (sync HTTP execution + response parsing) and the `BaseJsonResource` / `BaseResource` machinery for resource models.
- `src/polyswarm_api/aio/core.py` — `AsyncPolyswarmRequest(PolyswarmRequest)`. Inherits `parse_result` and friends from the sync request; only `execute`, `consume_results`, and `next_page` are overridden with their async bodies.
- `src/polyswarm_api/resources.py` — per-domain resource classes (mostly pure data wrappers).
- `test/` — pytest suite. Unit tests mock the HTTP boundary with `responses` (sync) and `respx` (async); the parametrisation harness in `metadata_field_properties_test.py` runs every test against both. Integration tests in `client_scan_test.py` / `async_client_test.py` use VCR cassettes — see "VCR cassette workflow" below.

## Sync + async via shared base

Every endpoint method lives **once** on `PolyswarmAPIBase`. The body is sync-shaped and ends with `return self._single(...)` or `return self._paginate(...)`. Each subclass overrides those helpers — sync returns the value (or a generator); async returns a coroutine (or an async generator). The caller picks the matching syntax:

```python
class PolyswarmAPIBase:
    def metadata_field_properties_get(self, field_path):
        return self._single(
            {'method': 'GET',
             'url': f'{self.uri}{resources.MetadataFieldProperties.RESOURCE_ENDPOINT}',
             'params': {'field_path': field_path}},
            result_parser=resources.MetadataFieldProperties,
        )

# sync caller
row = api.metadata_field_properties_get('polyunite.malware_family')

# async caller — no separate method needed
row = await async_api.metadata_field_properties_get('polyunite.malware_family')
```

For paginated endpoints, `_paginate` is a generator on sync and an async generator on async — `for x in api.foo()` vs `async for x in api.foo()`.

The trick that makes this work without metaclass magic: base methods are regular `def` (not `async def`) and just return whatever `self._single(...)` returned. Sync `_single` returns the parsed value directly; async `_single` is `async def`, so calling it returns a coroutine that the base method returns through. The caller's `await` consumes the coroutine.

This is the same pattern landed in the `akm` client (`/home/sam/repos/api-key-management`) — reference that codebase for a worked example.

### Migration status (DN-8225)

The shared base + the inheritance dedupe on `AsyncPolyswarmRequest` landed in PR `feature/httpx-shared-base`. **The metadata family is the only one currently migrated** (`metadata_mapping`, `metadata_field_properties_*`). The other ~110 endpoints still live twice — once in `api.py`, once in `aio/__init__.py`. Migrating them is mechanical (translate each pair into a single `PolyswarmAPIBase` method calling `self._single(...)`) and tracked as Phase 2 of DN-8225.

## When adding a new resource

Mirror the existing patterns (`LLMPromptConfig`, `MetadataFieldProperties`, `YaraRuleset`):

1. `class FooBar(core.BaseJsonResource): RESOURCE_ENDPOINT = '/…'`. If the resource's identifier isn't `id`, set `RESOURCE_ID_KEYS = ['your_key']` so the base class routes it into the query string for `GET`/`DELETE`/`PUT`.
2. Add convenience methods on **`PolyswarmAPIBase`** (`_base.py`). Each is a one-liner: `return self._single({'method': '…', 'url': '…', …}, result_parser=resources.FooBar)`. **Do not** add separate sync and async versions in `api.py` / `aio/__init__.py` — the base method works for both.
3. For paginated list endpoints, call `self._paginate(...)` instead. Sync callers iterate with `for`; async callers with `async for`.
4. Test with the parametrised `ClientTestCase` harness in `metadata_field_properties_test.py` — your tests run against both clients automatically.

## VCR cassette workflow

`client_scan_test.py` and `async_client_test.py` use VCR cassettes (`vcrpy`) for tests that hit real PolySwarm endpoints. Cassettes live in `test/vcr/` and use `record_mode='once'` (the default): the first run records, subsequent runs replay.

**To re-record a cassette against the live e2e stack:**

```bash
rm test/vcr/<cassette_name>.vcr
pytest test/<test_file>.py::TestClass::test_method
```

The deletion makes VCR record a fresh cassette; the test runs against whatever e2e environment your settings point at.

**`match_on=['method', 'uri']`** is set on the VCR config so the same cassette serves both sync (`requests`) and async (`httpx`) — header differences between the two HTTP libraries are ignored.

**Invariant: tests must pass against the live e2e stack with VCR off.** VCR is an efficiency cache, not a load-bearing requirement. Don't hardcode `record_mode='none'`. If a test only works against the recorded cassette, that's a bug in the test.

## Companion repos

- `polyswarm-cli` — wraps these methods in click commands. SDK changes that need a CLI surface usually ship as a pair (`polyswarm-api` PR + `polyswarm-cli` PR with the SDK PR linked under `## Requires`).
- `artifact-index` — the server-side API the SDK talks to. New endpoints land there first; the SDK PR comes after.
