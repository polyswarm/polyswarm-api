# Testing — mocking, VCR cassettes, sync+async parametrisation

## Scope

How the test suite is organised, the three mocking layers (`responses`, `respx`, `vcrpy`), the `ClientTestCase` parametrisation harness that runs each test against both clients, and the workflow for recording and re-recording cassettes against the live e2e stack.

## Invariants

1. **Tests must pass against the live e2e stack with VCR off.** VCR is an efficiency cache, not a load-bearing requirement. Don't hardcode `record_mode='none'`. If a test only works against the recorded cassette, that's a test bug.
2. **Cassette re-recording is delete-driven.** `rm test/vcr/<name>.vcr && pytest …<test>` re-records against the live e2e. `record_mode='once'` (the default) makes this work without flag-flipping.
3. **One cassette serves both transports.** Sync and async tests targeting the same scenario use the same on-the-wire request shape (because both clients now run on `httpx`). The VCR matcher is configured so cassettes survive `httpx`'s param-ordering differences from the original `requests`-recorded format — see "VCR matcher convention" below.
4. **New endpoint tests use the parametrised `ClientTestCase` harness.** It auto-emits `<Name>Sync` and `<Name>Async` siblings so the same body runs against both clients. Don't write parallel sync / async test bodies for new endpoints.
5. **The HTTP mocking library follows the transport.** Both clients now use `httpx`, so `respx` is the mocking library. `responses` (which only intercepts `requests`) is no longer in the test surface.

## Files

- `test/conftest.py` — pytest configuration.
- `test/metadata_field_properties_test.py` — the canonical example of the parametrised `ClientTestCase` harness with `respx`-backed mocking.
- `test/client_scan_test.py` — sync, VCR-backed integration tests (not yet on the parametrised harness — follow-up work).
- `test/async_client_test.py` — async, VCR-backed integration tests (not yet on the parametrised harness — follow-up work).
- `test/jmespath_test.py` — unit tests for `BaseJsonResource.jmespath`.
- `test/vcr/*.vcr` — recorded cassettes.
- `test/eicar.yara`, `test/malicious` — fixture files for upload tests.

## Three mocking layers

The SDK is tested at three levels:

| Layer | Tool | What it covers | When to use |
|---|---|---|---|
| **Unit / contract** | `respx` | Direct mocking of the `httpx` transport. Tests don't need network, e2e, or VCR. | New endpoint methods whose request shape and response parsing are independently testable. |
| **Integration / replay** | `vcrpy` | Records real HTTP exchanges; replays them on subsequent runs. | Tests that need end-to-end correctness against the platform's actual responses (search, submit, hunt). |
| **Pure** | none | Tests that don't touch HTTP at all. | `jmespath_test.py`, helper logic, model construction. |

`respx` is preferred for new tests because it's deterministic and fast. VCR is a tool for pinning the contract against the live server.

## The parametrised `ClientTestCase` harness

Implemented in `test/metadata_field_properties_test.py`. The shape:

```python
from polyswarm_api.api import PolyswarmAPI
from polyswarm_api.aio import PolySwarmAsyncAPI

class _MockBoundary:
    """Wraps respx to mock both sync and async httpx transports.
    Tests call mock.add(method, url, json=…, status=…)."""

class _AsyncToSync:
    """Drives async-client methods from sync test bodies via asyncio.run.
    Each attribute access spins up a fresh event loop per call so unittest-
    style test bodies (result = self.api.foo(...)) stay unchanged."""

class ClientTestCase(TestCase):
    """Base test case. __init_subclass__ auto-emits <Name>Sync and
    <Name>Async siblings for every concrete subclass so each test method
    runs once against PolyswarmAPI and once against PolySwarmAsyncAPI.
    The original subclass is hidden from pytest via __test__ = False."""

    _client_kind = 'sync'

    def setUp(self):
        if self._client_kind == 'sync':
            self.api = PolyswarmAPI(...)
        else:
            self.api = _AsyncToSync(PolySwarmAsyncAPI(...))
        self.mock = _MockBoundary(self._client_kind)
        self.mock.__enter__()

    def tearDown(self):
        self.mock.__exit__(None, None, None)


# A concrete test class — same body runs twice.

class MetadataFieldPropertiesTestCase(ClientTestCase):
    def test_get(self):
        row = _sample_row()
        self.mock.add('GET', _RESOURCE_URL, json={'result': row, 'status': 'OK'})
        result = self.api.metadata_field_properties_get(field_path=row['field_path'])
        assert result.field_path == row['field_path']
```

What collects:

```
$ pytest test/metadata_field_properties_test.py --collect-only
…
MetadataFieldPropertiesTestCaseSync::test_get
MetadataFieldPropertiesTestCaseSync::test_write
…
MetadataFieldPropertiesTestCaseAsync::test_get
MetadataFieldPropertiesTestCaseAsync::test_write
…
```

Each test body is written **sync-shaped** (`result = self.api.foo(...)`). The async sibling drives it through `_AsyncToSync`, which calls `asyncio.run(...)` on the async result.

When the API method returns an async generator (paginated endpoint), `_AsyncToSync` drains it via `[item async for item in result]`. The test sees a list either way.

### `_MockBoundary` contract

```python
mock.add(method: str, url: str, json: dict, status: int = 200)
    Register a matched (method, url) → json response.

mock.last_request_url -> str
    The URL of the most recent request the mocked client made. Tests use
    this to assert query-string composition.
```

The implementation uses `respx.mock(assert_all_called=False)` for both `sync` and `async` because both clients run on `httpx`. No `responses` library is involved.

### Why `_AsyncToSync` over `pytest-asyncio` here

The async tests use `pytest-asyncio` in `asyncio_mode = "auto"` (configured in `pyproject.toml`). Two reasons we use the sync-facade pattern in `ClientTestCase` instead:

1. **Unittest TestCase compatibility.** `__init_subclass__` parametrisation requires the test bodies to be sync (TestCase doesn't natively support `async def test_*`). The facade keeps the harness compatible with unittest.
2. **Per-call event loop isolation.** Each call spins up a fresh event loop via `asyncio.run`. There's no cross-call state to leak — important for VCR replay determinism.

For tests that are inherently async (concurrency, cancellation, owned-vs-injected-client lifecycle), use `async def test_*` directly with `@pytest.mark.asyncio` (or auto mode) — the parametrised harness is for endpoint-level coverage, not lifecycle coverage.

## VCR cassette workflow

`vcrpy` records each HTTP request/response pair on the first run and replays on subsequent runs. The cassette file (`test/vcr/<test_name>.vcr`) is checked in.

### Recording a new test

1. Write the test that calls the real endpoint.
2. Decorate the test method with `@vcr.use_cassette()`. The default path is `test/vcr/<test_name>.vcr`.
3. Run the test. With `record_mode='once'` (default), the cassette doesn't exist yet → VCR records the live exchange.
4. Inspect the cassette. Commit it.

### Re-recording an existing cassette

```bash
rm test/vcr/<cassette_name>.vcr
pytest test/<test_file>.py::TestClass::test_method
```

The deletion + re-run fires the live request again. **Never edit cassette YAML by hand** unless you're scrubbing sensitive header values; the recorded interactions are source-of-truth for the server's response shape.

### VCR matcher convention

For sync (recorded with `requests`-era cassettes):

```python
vcr = vcr_.VCR(
    cassette_library_dir='test/vcr',
    path_transformer=vcr_.VCR.ensure_suffix('.vcr'),
    # default matchers — includes 'query' (param-set match), not 'uri'
)
```

For async (and increasingly the canonical config):

```python
vcr = vcr_.VCR(
    cassette_library_dir='test/vcr',
    path_transformer=vcr_.VCR.ensure_suffix('.vcr'),
    match_on=['method', 'scheme', 'host', 'port', 'path', 'query'],
)
```

Why not `match_on=['method', 'uri']` (literal URI string)? `httpx` serialises query params in a slightly different order than `requests` did. With strict URI matching, cassettes recorded against `requests` mismatch on order even though the request is semantically identical. The `query` matcher compares params as a set, sidestepping the ordering issue.

### Boolean param normalisation

The HTTP session layer (`_normalise_bool_params` in `core.py`) converts Python booleans to capitalised strings (`'True'` / `'False'`) before they go on the wire. `httpx` writes them lowercase by default; the `requests` library used `str(bool)`. Existing cassettes were recorded against the capitalised form. The normalisation keeps them replaying without re-recording.

### Cassette filenames

Per-test: `<test_method_name>.vcr`. The `path_transformer=ensure_suffix('.vcr')` makes the `@vcr.use_cassette()` decorator pick the right filename automatically.

A single test method's cassette can hold multiple interactions (e.g. `test_submission` records `submit` → `upload` → `wait_for` → `lookup` chain). VCR plays them back in the order they were recorded.

### Sharing cassettes between sync and async

Where a sync test and an async test exercise the same scenario, they can share a cassette. The naming convention is to keep two files (`test_X.vcr` and `test_async_X.vcr`) but the content is identical. The parametrised `ClientTestCase` harness sidesteps this entirely — one test name, both clients use it.

For tests still split across `client_scan_test.py` / `async_client_test.py`, when both clients send the same request shape (which is increasingly true now that they share the endpoint surface), it's fine to copy the sync cassette to the async name during migration.

## VCR-off mode

A CI matrix entry should run the suite with cassettes hidden, against the live e2e:

```bash
pytest --vcr-disabled       # if vcr-pytest plugin is installed; otherwise:
mv test/vcr test/vcr.disabled
pytest
mv test/vcr.disabled test/vcr
```

This proves the SDK works without the cache. The invariant: **every test must pass in VCR-off mode against the live e2e stack**. If a test only works against a recorded cassette, it's a bug in the test.

This is also how cassettes get re-recorded en masse during major SDK changes — delete the directory, run the suite, commit the new cassettes.

## Adding a new test

Decision tree:

1. **Pure logic test?** (No HTTP, no resource side effects.) → Plain unittest / pytest function. See `jmespath_test.py`.
2. **Endpoint test with deterministic mocked response?** → Parametrised `ClientTestCase` with `_MockBoundary`. See `metadata_field_properties_test.py`. Body covers both sync and async automatically.
3. **End-to-end correctness against the live server?** → VCR-backed test. Record once against e2e, commit the cassette. The test can be sync (in `client_scan_test.py`) or async (in `async_client_test.py`) for now; long-term these migrate to the parametrised harness.

Always:

- Test method name matches the cassette filename (`@vcr.use_cassette()` auto-derives).
- Assert on resource attributes, not raw JSON, except where the test is specifically about JSON shape.
- Don't `time.sleep()` in tests — VCR replays instantly, so polling loops complete in microseconds. Live re-recording will block on real platform timing, which is expected.

## Outstanding test work

`client_scan_test.py` (sync) and `async_client_test.py` (async) still have parallel test bodies for the bulk of the endpoint surface. Rolling them onto the `ClientTestCase` parametrisation is mechanical — same shape as the metadata test — and is the next chunk of test consolidation work.

Each migration:

1. Move the test body into a `ClientTestCase` subclass.
2. Convert `async with self._api() as api: ...` to `self.api...` (the harness owns construction).
3. Convert `async for x in api.foo(...)` to `for x in api.foo(...)` — the `_AsyncToSync` proxy materialises async generators when called from sync context, and `_paginate` already returns sync generators for the sync client.
4. Delete the corresponding entry from both `client_scan_test.py` and `async_client_test.py`.
5. Run the suite. Cassettes that no longer match get re-recorded against e2e.
