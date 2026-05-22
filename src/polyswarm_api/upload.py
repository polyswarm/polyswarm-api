"""Sync S3 upload for PolySwarm artifact submission.

Module-level callable so downstream consumers can monkey-patch the upload
path. See specs/05-downstream-contract.md.
"""

import io
import logging

import httpx

from polyswarm_api import exceptions

logger = logging.getLogger(__name__)


def upload_file(
    client: httpx.Client,
    upload_url: str,
    artifact,
    attempts: int = 3,
) -> httpx.Response:
    """Upload a file to a pre-signed S3 URL.

    Args:
        client: httpx.Client (typically ``PolyswarmSession._client``).
        upload_url: pre-signed S3 URL from the API response.
        artifact: file-like object to upload.
        attempts: number of retry attempts.
    """
    if not upload_url:
        raise exceptions.InvalidValueException("upload_url must be set to upload a file")
    if not artifact:
        raise exceptions.InvalidValueException("A LocalArtifact must be provided in order to upload")

    r = None
    while attempts > 0 and not r:
        attempts -= 1
        artifact.seek(0, io.SEEK_END)
        length = artifact.tell()
        artifact.seek(0)
        # Empty files use empty bytes to avoid chunked encoding.
        if not length:
            data = b""
        else:
            data = artifact.read()
        r = client.put(upload_url, content=data)
        r.raise_for_status()
    return r
