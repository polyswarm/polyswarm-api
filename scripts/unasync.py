#!/usr/bin/env python
"""Regenerate the sync mirror from the canonical async source.

Reads ``src/polyswarm_api/aio/*.py`` (canonical async) and writes the
corresponding sync mirrors to ``src/polyswarm_api/*.py``. Run after any
change under ``src/polyswarm_api/aio/``; CI verifies the output is
current.

Skipped: ``aio/__init__.py`` (the public re-export shim, hand-written).
"""

import glob
import subprocess
import sys

import unasync


REPO_ROOT_SUBSTR = "/polyswarm_api/aio/"
OUTPUT_SUBSTR = "/polyswarm_api/"

# Source files under aio/ that should be unasync'd into the package root.
# __init__.py is excluded — it's a hand-written re-export.
SOURCES = sorted(
    p for p in glob.glob("src/polyswarm_api/aio/**/*.py", recursive=True)
    if not p.endswith("__init__.py")
)

# Generated files we will format with ruff after codegen.
GENERATED = [
    p.replace(REPO_ROOT_SUBSTR, OUTPUT_SUBSTR, 1) for p in SOURCES
]


REPLACEMENTS = {
    # Class-name swaps
    "PolySwarmAsyncAPI":     "PolyswarmAPI",
    "AsyncPolyswarmRequest": "PolyswarmRequest",
    "AsyncPolyswarmSession": "PolyswarmSession",
    # httpx types
    "AsyncClient":           "Client",
    "AsyncHTTPTransport":    "HTTPTransport",
    # typing helpers
    "AsyncGenerator":        "Iterator",
    "AsyncIterator":         "Iterator",
    "AsyncIterable":         "Iterable",
    # asyncio primitives mapped to their sync analogues
    "aclose":                "close",
    "async_upload_file":     "upload_file",
    # sleep is a library-level swap
    "asyncio.sleep":         "time.sleep",
    # imports inside the canonical async refer to polyswarm_api.aio.* —
    # rewrite that segment so the generated sync points at the root.
    "polyswarm_api.aio.":    "polyswarm_api.",
}


def main() -> int:
    print("running unasync...")
    unasync.unasync_files(
        SOURCES,
        rules=[
            unasync.Rule(
                fromdir=REPO_ROOT_SUBSTR,
                todir=OUTPUT_SUBSTR,
                additional_replacements=REPLACEMENTS,
            ),
        ],
    )

    print("formatting generated files with ruff...")
    cmd = ["ruff", "format", *GENERATED]
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("ruff format failed", file=sys.stderr)
        return result.returncode

    print("ok — sync mirror regenerated:")
    for path in GENERATED:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
