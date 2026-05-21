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

- `src/polyswarm_api/` — the synchronous `PolyswarmAPI` client (`api.py`), the `core.BaseJsonResource` machinery (`core.py`), and the per-domain resource classes (`resources.py`).
- `src/polyswarm_api/aio/` — async equivalent.
- `test/` — pytest suite using `responses` to mock the HTTP boundary; no live polyswarm stack required for the unit tests.

## When adding a new resource

Mirror the existing patterns (`LLMPromptConfig`, `MetadataFieldProperties`, `YaraRuleset`):

1. `class FooBar(core.BaseJsonResource): RESOURCE_ENDPOINT = '/…'`. If the resource's identifier isn't `id`, set `RESOURCE_ID_KEYS = ['your_key']` so the base class routes it into the query string for `GET`/`DELETE`/`PUT`.
2. Add convenience methods on `PolyswarmAPI` in `api.py` (and the async equivalent in `aio/__init__.py`) — these are what CLI commands and downstream consumers call.
3. Test with `responses.activate` mocking the HTTP boundary — no need for a live stack or VCR cassettes for unit tests.

## Companion repos

- `polyswarm-cli` — wraps these methods in click commands. SDK changes that need a CLI surface usually ship as a pair (`polyswarm-api` PR + `polyswarm-cli` PR with the SDK PR linked under `## Requires`).
- `artifact-index` — the server-side API the SDK talks to. New endpoints land there first; the SDK PR comes after.
