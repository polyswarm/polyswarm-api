# Endpoints — catalogue + sync/async classification

## Scope

The full catalogue of methods on the public client surface, where each one lives (base vs subclass), and why. Use this spec to decide where a new endpoint belongs and which hook (`_single` vs `_paginate`) to call.

## Invariants

1. **New endpoints go on `PolyswarmAPIBase`** unless they fall into one of the documented carve-outs (polling, file uploads, properties, the `sandbox_providers` quirk).
2. **`_paginate` is for endpoints whose callers iterate.** If callers write `for x in api.foo()` (or `async for x in api.foo()`), the base method calls `_paginate`. If callers consume a single value (`result = api.foo()`), call `_single`.
3. **The sync subclass's `_paginate` is a generator function.** The async subclass's `_paginate` is an async generator function. Don't `return` from them — `yield from` (sync) / `async for … yield` (async).
4. **Polling helpers stay on each subclass.** They wrap a `while True:` loop around `_sleep`; the loop body is sync/async-specific even though the orchestration is the same.
5. **File uploads stay on each subclass.** Sync uploads to the pre-signed S3 URL via `httpx.put`; async uses `polyswarm_api.aio.upload.async_upload_file` (a module-level callable that downstream consumers monkey-patch — see [`05-downstream-contract.md`](./05-downstream-contract.md)).

## Files

- `src/polyswarm_api/_base.py` — every endpoint that's on the shared base.
- `src/polyswarm_api/api.py` — sync-only carve-outs.
- `src/polyswarm_api/aio/__init__.py` — async-only carve-outs.

## Classification grid

### On the base — `_single` (returns a single resource)

Search / lookup (single resource each):

| Method | Resource builder | Notes |
|---|---|---|
| `exists(hash_, hash_type=None, require_scan=False)` | `ArtifactInstance.exists_hash` | HEAD; returns `bool` derived from status code. |
| `lookup(scan)` | `ArtifactInstance.lookup_uuid` | |
| `rescan(hash_, hash_type=None, scan_config=None)` | `ArtifactInstance.rescan` | |
| `rescan_id(scan, scan_config=None)` | `ArtifactInstance.rescan_id` | |

Metadata (single):

| Method | Resource builder |
|---|---|
| `metadata_mapping()` | `MetadataMapping.get` |
| `metadata_field_properties_write(field_path, description, example=None, category=None, aliases=None)` | inline (POST) |
| `metadata_field_properties_get(field_path)` | inline (GET) |
| `metadata_field_properties_delete(field_path)` | inline (DELETE) |

Known-host CRUD (single):

| Method | Resource builder |
|---|---|
| `add_known_good_host(type, source, host)` | `IOC.create_known_good` |
| `add_known_bad_host(type, source, host)` | `IOC.create_known_bad` |
| `update_known_good_host(id, type, source, host, good)` | `IOC.update_known_good` |
| `delete_known_good_host(id)` | `IOC.delete_known_good` |

Live hunts (single):

| Method | Resource builder |
|---|---|
| `live_start(rule_id)` | `LiveYaraRuleset.create` |
| `live_stop(rule_id)` | `LiveYaraRuleset.delete` |
| `live_feed_delete(result_ids)` | `LiveHuntResultList.delete` (catches `NoResultsException`) |
| `live_result(result_id)` | `LiveHuntResult.get` |

Historical hunts (single):

| Method | Resource builder |
|---|---|
| `historical_create(rule=None, ruleset_name=None)` | `HistoricalHunt.create` |
| `historical_get(hunt=None)` | `HistoricalHunt.get` |
| `historical_update(hunt)` | `HistoricalHunt.update` |
| `historical_delete(hunt)` | `HistoricalHunt.delete` |
| `historical_result(result_id)` | `HistoricalHuntResult.get` |
| `historical_results_delete(result_ids)` | `HistoricalHuntResultList.delete` |
| `historical_delete_list(historical_ids)` | `HistoricalHuntList.delete` |

Rulesets / tags / families (single):

| Method | Resource builder |
|---|---|
| `ruleset_create(name, rules, description=None)` | `YaraRuleset.create` |
| `ruleset_get(ruleset_id=None)` | `YaraRuleset.get` |
| `ruleset_update(ruleset_id, name=None, rules=None, description=None)` | `YaraRuleset.update` |
| `ruleset_delete(ruleset_id)` | `YaraRuleset.delete` |
| `tag_link_get(sha256)` | `TagLink.get` |
| `tag_link_update(sha256, tags=None, families=None, emerging=None, remove=False)` | `TagLink.update` |
| `tag_create(name)` / `tag_get(name)` / `tag_delete(name)` | `Tag.{create,get,delete}` |
| `family_create(name)` / `family_get(name)` / `family_delete(name)` / `family_update(family_name, emerging=True)` | `MalwareFamily.{create,get,delete,update}` |

Jobs (single):

| Method | Resource builder |
|---|---|
| `assertions_create(engine_id, date_start, date_end)` | `AssertionsJob.create` |
| `assertions_get(assertions_id)` / `assertions_delete(assertions_id)` | `AssertionsJob.{get,delete}` |
| `votes_create(engine_id, date_start, date_end)` | `VotesJob.create` |
| `votes_get(votes_id)` / `votes_delete(votes_id)` | `VotesJob.{get,delete}` |

Check-known-hosts is **on the base but uses `_paginate`** because the response is a list of `IOC` resources that callers may iterate; see "On the base — `_paginate`" below.

Downloads (single):

| Method | Resource builder | Notes |
|---|---|---|
| `download(out_dir, hash_, hash_type=None)` | `LocalArtifact.download` | Opens / closes the local handle. |
| `download_id(out_dir, instance_id)` | `LocalArtifact.download_id` | Same. |
| `download_sandbox_artifact(out_dir, sandbox_task_id, instance_id)` | `LocalArtifact.download_sandbox_artifact` | Same. |
| `download_archive(out_dir, s3_path)` | `LocalArtifact.download_archive` | Same. |
| `download_to_handle(hash_, fh, hash_type=None)` | `LocalArtifact.download` | Streams to an existing file handle. |

Sandbox (single):

| Method | Resource builder |
|---|---|
| `sandbox(instance_id, provider_slug, vm_slug, network_enabled)` | `SandboxTask.create` |
| `sandbox_task_status(sandbox_task_id)` | `SandboxTask.get` |
| `sandbox_task_latest(sha256, sandbox)` | `SandboxTask.latest` |

Samples / metadata / events (single):

| Method | Resource builder |
|---|---|
| `rerun_metadata(hashes, analyses=None, skip_es=None)` | `ArtifactInstance.metadata_rerun` |
| `tool_metadata_create(instance_id, tool, tool_metadata)` | `ToolMetadata.create` |
| `sample(sha256, …)` | `Sample.create` (with `endpoint_fmt={'sha256': sha256}`) |
| `sample_bundle_task_create(instance_ids, …)` | `BundleTask.create` |
| `sample_bundle_task_get(id, **kwargs)` | `BundleTask.get` |
| `sample_bundle_download(id, folder)` | `BundleTask.get` → `task.download_zip(folder=folder)` (instance method) |

LLM / report:

| Method | Resource builder |
|---|---|
| `llm_report_create(instance_id=None, cape_sandbox_task_id=None, triage_sandbox_task_id=None)` | `ReportLLMPostProcessing.create` |
| `llm_report_get(report_task_id)` | `ReportLLMPostProcessing.get` |
| `llm_report_download(report_task_id, folder)` | `.get` → `task.download_report(folder=folder)` |
| `report_create(type, format, …)` | `ReportTask.create` |
| `report_get(id, **kwargs)` | `ReportTask.get` |
| `report_download(report_id, folder)` | `.report_get` → `report.download_report(folder=folder)` |
| `report_template_logo_download(template_id, folder)` | `ReportTemplate.get` → `report.download_logo(folder)` |
| `report_template_logo_delete(template_id)` | `ReportTemplate.get` → `report.delete_logo()` |
| `report_template_logo_upload(template_id, logo_file, content_type=…)` | `ReportTemplate.get` → `report.upload_logo(logo_file, content_type)` |
| `report_template_create(template_name, …)` | `ReportTemplate.create` |
| `report_template_update(template_id, …)` | `ReportTemplate.update` |
| `report_template_get(template_id)` | `ReportTemplate.get` |
| `report_template_delete(template_id)` | `ReportTemplate.delete` |

Account / prompt config / webhooks (single):

| Method | Resource builder |
|---|---|
| `account_whois(**kwargs)` | `WhoIs.get` |
| `account_features(**kwargs)` | `AccountFeatures.get` |
| `prompt_config_create(...)` / `prompt_config_get(...)` / `prompt_config_update(...)` | `LLMPromptConfig.{create,get,update}` |
| `notification_webhook_create(...)` / `notification_webhook_get(...)` / `notification_webhook_update(...)` / `notification_webhook_delete(...)` | `Webhook.{create,get,update,delete}` |
| `notification_webhook_test(webhook_id)` | `Webhook.test` (raises `RequestException` on non-200) |

### On the base — `_paginate` (returns iterable / async iterable)

| Method | Resource builder |
|---|---|
| `search(hash_, hash_type=None)` | `ArtifactInstance.search_hash` |
| `search_url(url)` | `ArtifactInstance.search_url` |
| `search_scans(hash_)` | `ArtifactInstance.list_scans` |
| `search_by_metadata(query, include=None, exclude=None, ips=None, urls=None, domains=None)` | `Metadata.get` |
| `iocs_by_hash(hash_type, hash_value, hide_known_good=False, beta=False)` | `IOC.iocs_by_hash` |
| `search_by_ioc(ip=None, domain=None, ttp=None, imphash=None)` | `IOC.ioc_search` |
| `check_known_hosts(ips=[], domains=[])` | `IOC.check_known_hosts` |
| `live_feed(since=None, …)` | `LiveHuntResult.list` |
| `historical_list(since=None)` | `HistoricalHunt.list` |
| `historical_results(hunt=None, …)` | `HistoricalHuntResultList.get` |
| `ruleset_list()` | `YaraRuleset.list` |
| `tag_link_list(tags=None, families=None, or_tags=None, or_families=None)` | `TagLink.list` |
| `tag_list()` | `Tag.list` |
| `family_list()` | `MalwareFamily.list` |
| `assertions_list(engine_id)` | `AssertionsJob.list` |
| `votes_list(engine_id)` | `VotesJob.list` |
| `sandbox_my_tasks_list(**kwargs)` | `SandboxTask.my_tasks` |
| `sandbox_task_list(sha256, **kwargs)` | `SandboxTask.list` |
| `stream(since=…)` | `ArtifactArchive.get` |
| `tool_metadata_list(instance_id)` | `ToolMetadata.list` |
| `event_list(**kwargs)` | `Events.list` |
| `metadata_field_properties_list()` | inline (GET `/v3/search/metadata/properties/list`) |
| `prompt_config_list(**kwargs)` | `LLMPromptConfig.list` |
| `notification_webhook_list()` | `Webhook.list` |
| `report_template_list(is_default=None, **kwargs)` | `ReportTemplate.list` |

### On each subclass — sync/async-specific

| Method | Why it's not on the base |
|---|---|
| `__init__`, `close` / `aclose`, context-manager protocol | Each constructs its own HTTP client; sync vs async context-manager. |
| `_single`, `_paginate`, `_sleep`, `_exec`, `_coerce_request` (on base) | These are the transport hooks themselves. |
| `wait_for(scan, timeout=…)` | Polling — `while True: scan = self.lookup(scan); if done: return; else: self._sleep(…)`. Sync uses `time.sleep`; async uses `asyncio.sleep`. The orchestration is identical except for `await` on the inner `lookup` call. |
| `report_wait_for(report_id, timeout=…)` | Same polling shape, different terminal condition. |
| `submit(artifact, …)` | File upload. Sync: `instance.upload_file(artifact)` via `httpx.put` to S3. Async: `polyswarm_api.aio.upload.async_upload_file(self, instance, artifact)`. |
| `sandbox_file(artifact, …)` | Same file-upload pattern for sandbox submissions. |
| `sandbox_url(url, …)` | Same. |
| `refresh_engine_cache()` | Mutates `self._engines`. Sync `@property` (`api.engines`) reads the cache and triggers refresh; async can't expose a sync `@property` that awaits, so each subclass implements its own. |
| `engines` (property) | Sync only — raises `AttributeError` on the async subclass with guidance to call `await refresh_engine_cache()` and read `_engines`. |
| `sandbox_providers()` | Returns the executed `PolyswarmRequest` itself (not the parsed list) so callers can read `.json`. Pre-existing surface quirk; sync executes immediately, async awaits. |

### Helpers (private)

| Method | Where |
|---|---|
| `_parse_rule(rule)` | On the base; pure (no I/O). Returns `(YaraRuleset, rule_id)` from a string or existing ruleset. |
| `_coerce_request(request, result_parser=None, parser_kwargs=None)` | On the base; rebuilds the subclass's `_request_cls`. |
| `_build_request_kwargs(…)` | Implicit in `_single` / `_paginate`; the dict-form path goes through `_coerce_request`. |

## Polling helpers — shape

Sync:

```python
def wait_for(self, scan, timeout=settings.DEFAULT_SCAN_TIMEOUT):
    start = time.time()
    while True:
        scan_result = self.lookup(scan)
        if scan_result.failed or scan_result.window_closed:
            return scan_result
        if -1 < timeout < time.time() - start:
            raise exceptions.TimeoutException(...)
        self._sleep(settings.POLL_FREQUENCY)
```

Async:

```python
async def wait_for(self, scan, timeout=settings.DEFAULT_SCAN_TIMEOUT):
    start = time.time()
    while True:
        scan_result = await self.lookup(scan)
        if scan_result.failed or scan_result.window_closed:
            return scan_result
        if -1 < timeout < time.time() - start:
            raise exceptions.TimeoutException(...)
        await self._sleep(settings.POLL_FREQUENCY)
```

Same body shape; the per-subclass divergence is just `await`. Don't try to fold these into the base — `wait_for` calls `self.lookup(scan)`, and that call returns a value (sync) or a coroutine (async). Threading the await through a base implementation either requires `async def` on the base method (forcing `await` for sync too) or some generator-based sans-I/O trick that's not worth the complexity.

## File-upload paths

The sync subclass:

```python
def submit(self, artifact, ...):
    instance = self._single(resources.ArtifactInstance.create(self, ...))
    instance.upload_file(artifact)            # httpx.put to instance.upload_url
    return self._single(resources.ArtifactInstance.update(self, id=instance.id, ...))
```

The async subclass:

```python
async def submit(self, artifact, ...):
    instance = await self._single(resources.ArtifactInstance.create(self, ...))
    await async_upload_file(self, instance, artifact)   # asyncio-aware S3 PUT
    return await self._single(resources.ArtifactInstance.update(self, id=instance.id, ...))
```

`async_upload_file` lives at `polyswarm_api.aio.upload.async_upload_file` and is intentionally a module-level callable — downstream consumers monkey-patch it for environments with non-standard S3 backends or auth requirements. See [`05-downstream-contract.md`](./05-downstream-contract.md) §Monkey-patch sites.

## `engines` cache

Sync:

```python
@property
def engines(self):
    if not self._engines:
        self.refresh_engine_cache()
    return self._engines

def refresh_engine_cache(self):
    engines = list(self._single(resources.Engine.list(self)))
    if not engines:
        raise exceptions.InvalidValueException(...)
    self._engines = engines
```

Async:

```python
@property
def engines(self):
    raise AttributeError(
        "Use 'await refresh_engine_cache()' then access '_engines' directly. "
        "Properties cannot be async."
    )

async def refresh_engine_cache(self):
    engine_list = []
    async for engine in self._paginate(...):
        engine_list.append(engine)
    if not engine_list:
        raise exceptions.InvalidValueException(...)
    self._engines = engine_list
```

The async surface preserves the attribute (`_engines`) so callers can manually trigger a refresh and then read it; the property raises a deliberate `AttributeError` with guidance.

## `sandbox_providers` — the executed-request quirk

Pre-existing surface that returns the **executed** `PolyswarmRequest` object (not the parsed resource list) so callers can read `.json['result']['cape']['slug']` etc. Each subclass implements it:

Sync: `resources.SandboxProvider.list(self).execute()` — note the explicit `.execute()`.
Async: `await resources.SandboxProvider.list(self).execute()` — same, awaited.

A test against this is in `client_scan_test.py::ScanTestCaseV2::test_sandbox_providers`. New code should not pattern after this — prefer `_single` / `_paginate` and return a parsed resource. The quirk persists for backward compatibility.

## Where to put a new endpoint

```
Question                                 Answer
─────────────────────────────────────    ────────────────────
Caller iterates the result?               → _paginate, on the base
Caller uses a single value?               → _single, on the base
Both sync and async return type identical?    → on the base
                                          (yes for ~95% of methods)
Polling loop?                             → both subclasses (mirror wait_for)
Pre-signed file upload?                   → both subclasses (mirror submit)
Sync-only @property?                      → sync subclass; async raises AttributeError
Quirk requiring .execute() at call site?  → both subclasses (mirror sandbox_providers)
```

If you find yourself adding a method to both `api.py` and `aio/__init__.py` and the bodies look the same modulo `await`, that's a smell — it almost certainly belongs on the base.
