"""Async S3 upload for PolySwarm artifact submission.

Replaces the direct requests.put() calls in:
- polyswarm_api.resources.ArtifactInstance.upload_file()
- polyswarm_api.resources.SandboxTask.upload_file()
"""

import io
import logging

import httpx

from polyswarm_api import exceptions

logger = logging.getLogger(__name__)


async def async_upload_file(
    client: httpx.AsyncClient,
    upload_url: str,
    artifact,
    attempts: int = 3,
) -> httpx.Response:
    """Upload file to S3 presigned URL.

    Async equivalent of ArtifactInstance.upload_file() / SandboxTask.upload_file().

    Args:
        client: httpx.AsyncClient instance (from AsyncPolyswarmSession._client)
        upload_url: S3 presigned URL from the API response
        artifact: File-like object to upload
        attempts: Number of retry attempts
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
        # Match sync behavior: empty files use empty string to avoid chunked encoding
        if not length:
            data = b""
        else:
            data = artifact.read()
        r = await client.put(upload_url, content=data)
        r.raise_for_status()
    return r


async def async_upload_logo(
    client: httpx.AsyncClient,
    upload_url: str,
    logo_file,
    content_type: str,
) -> httpx.Response:
    """Upload a logo file for report templates.

    Async equivalent of ReportTemplate.upload_logo().
    """
    if not upload_url:
        raise exceptions.InvalidValueException("upload_url must be set")

    logo_file.seek(0, io.SEEK_END)
    length = logo_file.tell()
    logo_file.seek(0)

    if not length:
        data = b""
    else:
        data = logo_file.read()

    r = await client.put(
        upload_url,
        content=data,
        headers={"Content-Type": content_type},
    )
    r.raise_for_status()
    return r
