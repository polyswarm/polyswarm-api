import io
import logging
import time

import polyswarm_api.core

from urllib.parse import urlparse

from polyswarm_api import exceptions, resources, settings
from polyswarm_api._base import PolyswarmAPIBase

logger = logging.getLogger(__name__)


class PolyswarmAPI(PolyswarmAPIBase):
    """A synchronous interface to the public and private PolySwarm APIs."""

    def __init__(self, key, uri=None, community=None, timeout=None, verify=True, **kwargs):
        """
        :param key: PolySwarm API key
        :param uri: PolySwarm API URI
        :param community: Community to scan against.
        :param timeout: Maximum time to wait for an http response on every request.
        :param verify: Boolean, whether or not to verify TLS connections.
        :param **kwargs: Keyword args to pass to requests.Session
        """
        super().__init__(key, uri=uri, community=community, timeout=timeout, verify=verify, **kwargs)
        self.session = polyswarm_api.core.PolyswarmSession(
            key, retries=settings.DEFAULT_RETRIES, verify=verify, **kwargs,
        )

    # ── PolyswarmAPIBase hooks ──────────────────────────────────────

    _request_cls = polyswarm_api.core.PolyswarmRequest

    def _single(self, request, result_parser=None, **kwargs):
        """Execute and return parsed result.

        ``request`` may be an unexecuted ``PolyswarmRequest`` (returned by
        a resource classmethod) or a request-parameters dict.
        """
        req = self._coerce_request(request, result_parser, kwargs).execute()
        return req.result()

    def _paginate(self, request, result_parser=None, **kwargs):
        """Execute synchronously and yield items (handles pagination)."""
        req = self._coerce_request(request, result_parser, kwargs).execute()
        if req._paginated:
            yield from req.consume_results()
        else:
            result = req._result
            if isinstance(result, list):
                yield from result
            elif result is not None:
                yield result

    def _sleep(self, seconds):
        time.sleep(seconds)

    def _exec(self, request_parameters, result_parser=None, **kwargs):
        """Build and execute a ``PolyswarmRequest`` (legacy helper)."""
        return polyswarm_api.core.PolyswarmRequest(
            self, request_parameters, result_parser=result_parser, **kwargs,
        ).execute()

    @property
    def engines(self):
        if not self._engines:
            self.refresh_engine_cache()

        return self._engines

    def refresh_engine_cache(self):
        """
        Refresh the cached engine listing
        """
        engines = list(self._single(resources.Engine.list(self)))
        if not engines:
            raise exceptions.InvalidValueException("Received empty engines listing")
        self._engines = engines

    def wait_for(self, scan, timeout=settings.DEFAULT_SCAN_TIMEOUT):
        """
        Wait for a Scan to scan successfully

        :param scan: Scan id to wait for
        :param timeout: Maximum time in seconds to wait before raising a TimeoutException
        :return: The ArtifactInstance resource waited on
        """
        logger.info('Waiting for %s', int(scan))
        start = time.time()
        while True:
            scan_result = self.lookup(scan)
            if scan_result.failed or scan_result.window_closed:
                return scan_result
            elif -1 < timeout < time.time() - start:
                raise exceptions.TimeoutException(
                    f'Timed out waiting for scan {scan} to finish. Please try again.')
            else:
                time.sleep(settings.POLL_FREQUENCY)

    def submit(
            self,
            artifact,
            artifact_type=resources.ArtifactType.FILE,
            artifact_name=None,
            scan_config=None,
            preprocessing=None,
            expiration_window=None,
    ):
        """
        Submit artifacts to polyswarm

        :param artifact: A file-like, path to file, url or LocalArtifact instance
        :param artifact_type: The ArtifactType or strings containing "file" or "url"
        :param artifact_name: An appropriate filename for the Artifact
        :param scan_config: The scan configuration to be used, e.g.: "default", "more-time", "most-time"
        :param preprocessing: Preprocessing settings to be applied to the artifact, None means no preprocessing,
                              otherwise a dict with the following attributes can be passed:
                              - type (string): either "zip", "base64", "7zip", or "qrcode". "zip" means the file is a
                                zip that the server has to decompress to then scan the content (only one file inside
                                allowed). "base64" means the file content is base64-encoded and the server has to
                                decode it before scanning. "7zip" means the file is a 7zip archive that the server
                                has to decompress to then scan the content (only one file inside allowed). "qrcode"
                                means the file is a QR Code image with a URL as payload, and you want to scan the URL,
                                not the actual file (artifact_type has to be "URL").
                              - password (string, optional): will use this password to decompress the zip or 7zip file.
        :param expiration_window: The expiration window in days (7, 30, or 180). Only valid for private communities.
        :return: An ArtifactInstance resource
        """
        logger.info('Submitting artifact of type %s', artifact_type)
        artifact_type = resources.ArtifactType.parse(artifact_type)
        if isinstance(artifact, io.IOBase):
            artifact = resources.LocalArtifact.from_handle(self, artifact, artifact_name=artifact_name or '',
                                                           artifact_type=artifact_type)
        elif isinstance(artifact, str):
            if artifact_type == resources.ArtifactType.FILE:
                artifact = resources.LocalArtifact.from_path(self, artifact, artifact_type=artifact_type,
                                                             artifact_name=artifact_name)
            elif artifact_type == resources.ArtifactType.URL:
                if preprocessing and preprocessing['type'] == 'qrcode':
                    artifact = resources.LocalArtifact.from_path(self,
                                                                 artifact,
                                                                 artifact_type=artifact_type,
                                                                 artifact_name=artifact_name)
                else:
                    artifact = resources.LocalArtifact.from_content(self,
                                                                    artifact,
                                                                    artifact_name=artifact_name or artifact,
                                                                    artifact_type=artifact_type)
        if artifact_type == resources.ArtifactType.URL:
            scan_config = scan_config or 'more-time'
        if isinstance(artifact, resources.LocalArtifact):
            instance = self._single(resources.ArtifactInstance.create(
                self,
                artifact_name=artifact.artifact_name,
                artifact_type=artifact.artifact_type.name,
                scan_config=scan_config,
                community=self.community,
                preprocessing=preprocessing,
                expiration_window=expiration_window,
            ))
            instance.upload_file(artifact)
            return self._single(resources.ArtifactInstance.update(self, id=instance.id, community=self.community))
        else:
            raise exceptions.InvalidValueException('Artifacts should be a path to a file or a LocalArtifact instance')

    def sandbox_file(
            self,
            artifact,
            provider_slug,
            vm_slug,
            artifact_type=resources.ArtifactType.FILE,
            artifact_name=None,
            network_enabled=True,
            preprocessing=None,
            arguments='',
    ):
        """
        Submit artifacts to Polyswarm Sandboxing system.

        :param artifact: A file-like, path to file, url or LocalArtifact instance
        :param artifact_name: An appropriate filename for the Artifact
        :artifact_type: the type of artifact to be submitted, default FILE. Use URL type
                        with the preprocessing field to scan URLs inside QR Code images
        :param network_enabled: Whether the VM has to have Internet connection enabled or not.
        :param provider_slug: the slug of the provider that is going to execute the sandboxing, e.g.
                              'cape' or 'triage'.
                              Use `sandbox_providers()` to get the list of providers.
        :param vm_slug: The slug of the virtual machine used for the sandboxing, depending on the
                        VM chosen, is the OS and software that is going to host the sandboxing. Each
                        provider (provider_slug) supports different VMs, so check with `sandbox_providers()`
                        the list of VMs available.
        :param preprocessing: Preprocessing settings to be applied to the artifact, None means no preprocessing,
                              otherwise a dict with the following attributes can be passed:
                              - type (string): either "zip", "base64", or "qrcode". "zip" means the file is a zip that
                                the server has to decompress to then scan the content (only one file inside allowed).
                                "base64" means the file content is base64-encoded and the server has to decode it
                                before scanning. "qrcode" means the file is a QR Code image with a URL as payload,
                                and you want to scan the URL, not the actual file (artifact_type has to be "URL").
                              - password (string, optional): will use this password to decompress the zip file.
        :param arguments: The arguments to be passed to the sample being sandboxed, e.g. '--some-param="<PARAM VAL>"'
        :return: An ArtifactInstance resource
        """
        logger.info('Sandboxing %s in provider %s vm %s', artifact_type.name.lower(), provider_slug, vm_slug)
        artifact_type = resources.ArtifactType.parse(artifact_type)
        if isinstance(artifact, io.IOBase):
            artifact = resources.LocalArtifact.from_handle(self, artifact, artifact_name=artifact_name or '',
                                                           artifact_type=artifact_type)
        elif isinstance(artifact, str):
            if artifact_type == resources.ArtifactType.FILE:
                artifact = resources.LocalArtifact.from_path(self, artifact, artifact_type=artifact_type,
                                                             artifact_name=artifact_name)
            elif artifact_type == resources.ArtifactType.URL:
                artifact = resources.LocalArtifact.from_content(self, artifact,
                                                                artifact_name=artifact_name or artifact,
                                                                artifact_type=artifact_type)
        if isinstance(artifact, resources.LocalArtifact):
            task = self._single(resources.SandboxTask.create_file(
                self,
                artifact_name=artifact.artifact_name,
                artifact_type=artifact.artifact_type.name,
                community=self.community,
                provider_slug=provider_slug,
                vm_slug=vm_slug,
                network_enabled=network_enabled,
                preprocessing=preprocessing,
                arguments=arguments,
            ))
            task.upload_file(artifact)
            return self._single(resources.SandboxTask.update_file(self, id=task.id, community=self.community))
        else:
            raise exceptions.InvalidValueException(
                'Artifacts should be a path to a file or a LocalArtifact instance')

    def sandbox_url(self,
                    url,
                    provider_slug,
                    vm_slug,
                    browser=None,
                    artifact=None,
                    artifact_name=None,
                    preprocessing=None):
        """
        Submit URL to Polyswarm Sandboxing system.
        :param url: A string with the URL to be submitted. Set to `None` if the URL is provided
                    through a QR Code image in the artifact param (see artifact and preprocessing params).
        :param provider_slug: the slug of the provider that is going to execute the sandboxing, e.g.
                              'cape' or 'triage'.
                              Use `sandbox_providers()` to get the list of providers.
        :param vm_slug: The slug of the virtual machine used for the sandboxing, depending on the
                        VM chosen, is the OS and software that is going to host the sandboxing. Each
                        provider (provider_slug) supports different VMs, so check with `sandbox_providers()`
                        the list of VMs available.
        :param browser: browser name, e.g. 'edge' or 'firefox'.
        :param artifact: A file-like, path to file, or LocalArtifact instance (default None). The url
                         param has to be None to use this param. For now QR Code image files
                         are supported
        :param artifact_name: name of the artifact, if None (default) the URL string is used as a name,
                              or the file name if artifact is provided (QR Code image file).
        :param preprocessing: Preprocessing settings to be applied to the artifact, None means no preprocessing,
                              otherwise a dict with the following attributes can be passed:
                              - type (string): only "qrcode" is supported for URL sandboxing:
                                the file is a QR Code image with a URL as payload, and you want
                                to scan the URL, not the actual file. This argument has to be used with the
                                `artifact` param and `url` set to `None`.
        """
        logger.info('Sandboxing url in provider %s vm %s', provider_slug, vm_slug)
        if artifact and url:
            raise exceptions.InvalidValueException("Cannot use artifact with url param")
        if artifact:
            if not preprocessing or preprocessing.get('type') != 'qrcode':
                raise exceptions.InvalidValueException("Only artifact of type qrcode is supported")
            if isinstance(artifact, str):
                artifact = resources.LocalArtifact.from_path(self,
                                                             artifact,
                                                             artifact_type='URL',
                                                             artifact_name=artifact_name)
            else:
                artifact = resources.LocalArtifact.from_handle(self,
                                                               artifact,
                                                               artifact_name=artifact_name or '',
                                                               artifact_type='URL')
        else:
            artifact_name = url
            artifact = resources.LocalArtifact.from_content(self,
                                                            url,
                                                            artifact_name=artifact_name,
                                                            artifact_type='URL')
        task = self._single(resources.SandboxTask.create_file(self,
                                                 artifact_name=artifact_name,
                                                 artifact_type="URL",
                                                 community=self.community,
                                                 provider_slug=provider_slug,
                                                 vm_slug=vm_slug,
                                                 browser=browser,
                                                 preprocessing=preprocessing,
                                                 network_enabled=True))
        task.upload_file(artifact)
        return self._single(resources.SandboxTask.update_file(self, id=task.id, community=self.community))

    def sandbox_providers(self):
        """
        List sandboxes available in polyswarm.
        """
        logger.info('Listing sandbox names')
        # Returns the executed ``PolyswarmRequest`` itself so callers can
        # read ``.json`` on it (rather than the parsed resource list).
        return resources.SandboxProvider.list(self).execute()

    # ── Multi-statement endpoint carve-outs ─────────────────────────
    #
    # Methods below read the result of a ``_single`` call and act on
    # it (read an attribute, branch on state, feed it into a second
    # request). The shared-base pass-through trick only works for
    # single-statement ``return self._single(...)`` bodies, so these
    # methods live on the subclasses as sync+async pairs. The async
    # twins are in [aio/api.py](aio/api.py).

    def report_template_logo_download(self, template_id, folder):
        report = self._single(resources.ReportTemplate.get(self, id=template_id))
        result = self._single(report.download_logo(folder))
        result.handle.close()
        return result

    def report_template_logo_delete(self, template_id):
        report = self._single(resources.ReportTemplate.get(self, id=template_id))
        result = self._single(report.delete_logo())
        return result

    def report_template_logo_upload(self, template_id, logo_file, content_type=None, content_tpe=None):
        if content_tpe is not None and content_type is None:
            content_type = content_tpe
        if content_type is None:
            raise exceptions.InvalidValueException("missing required argument: 'content_type'")
        report = self._single(resources.ReportTemplate.get(self, id=template_id))
        result = self._single(report.upload_logo(logo_file, content_type))
        return result

    def report_download(self, report_id, folder):
        report = self.report_get(id=report_id)
        if report.state == 'PENDING':
            raise exceptions.InvalidValueException('Report is in PENDING state, wait for completion first')
        if report.state == 'FAILED':
            raise exceptions.InvalidValueException("Report is in FAILED state, won't be generated")
        result = self._single(report.download_report(folder=folder))
        result.handle.close()
        return result

    def sample_bundle_download(self, id, folder):
        task = self._single(resources.BundleTask.get(self, id=id, community=self.community))
        if task.state == 'PENDING':
            raise exceptions.InvalidValueException('Bundle is in PENDING state, wait for completion first')
        if task.state == 'FAILED':
            raise exceptions.InvalidValueException("Bundle is in FAILED state, won't be generated")
        result = self._single(task.download_zip(folder=folder))
        result.handle.close()
        return result

    def llm_report_download(self, report_task_id, folder):
        task = self._single(resources.ReportLLMPostProcessing.get(self, id=report_task_id, community=self.community))
        result = self._single(task.download_report(folder=folder))
        result.handle.close()
        return result

    def download(self, out_dir, hash_, hash_type=None):
        """
        Grab the data of an artifact identified by hash and write the data to a file in the provided directory
        under a file named after the hash_.
        :param out_dir: Destination directory to download the file.
        :param hash_: The hash we should use to lookup the artifact to download.
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading %s into %s', hash_, out_dir)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        artifact = self._single(resources.LocalArtifact.download(self, hash_.hash, hash_.hash_type, folder=out_dir))
        artifact.handle.close()
        return artifact

    def download_id(self, out_dir, instance_id):
        """
        Grab the data of an artifact identified by hash and write the data to a file in the provided directory
        under a file named after the hash_.
        :param out_dir: Destination directory to download the file.
        :param instance_id: The instance id we should use to lookup the artifact to download.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading %s into %s', instance_id, out_dir)
        artifact = self._single(resources.LocalArtifact.download_id(self, instance_id, folder=out_dir))
        artifact.handle.close()
        return artifact

    def download_sandbox_artifact(self, out_dir, sandbox_task_id, instance_id):
        """
        Grab the data of a sandbox artifact identified by sandbox task id and instance id,
        and write the data to a file in the provided directory under a file named after the sandbox artifact.
        :param out_dir: Destination directory to download the file.
        :param sandbox_task_id: The sandbox task id we should use to lookup the artifact to download.
        :param instance_id: The instance id we should use to lookup the artifact to download.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading sandbox artifact %s %s', sandbox_task_id, instance_id)
        sandbox_artifact = self._single(resources.LocalArtifact.download_sandbox_artifact(
            self, sandbox_task_id, instance_id, folder=out_dir))
        sandbox_artifact.handle.close()
        return sandbox_artifact

    def download_archive(self, out_dir, s3_path):
        """
        Grab the data in the s3 path provided in the stream() method, and write the contents
        in the provided directory.
        :param out_dir: Destination directory to download the file.
        :param s3_path: Target S3 object to download.
        :return: A LocalArtifact resource
        """
        logger.info('Downloading %s into %s', s3_path, out_dir)
        artifact = self._single(resources.LocalArtifact.download_archive(self, s3_path, folder=out_dir))
        artifact.handle.close()
        return artifact

    def exists(self, hash_, hash_type=None, require_scan=False):
        """
        Search for the latest scans matching the given hash and hash_type.

        :param hash_: A Hashable object (Artifact, local.LocalArtifact, Hash) or hex-encoded SHA256/SHA1/MD5
        :param hash_type: Hash type of the provided hash_. Will attempt to auto-detect if not explicitly provided.
        :param require_scan: If True, only return True if the artifact has been scanned. Default is False.
        :return: A boolean if the instance exists for search.
        """
        logger.info('Exists for hash %s', hash_)
        hash_ = resources.Hash.from_hashable(hash_, hash_type=hash_type)
        result = self._single(resources.ArtifactInstance.exists_hash(self, hash_.hash, hash_.hash_type, require_scan=require_scan))
        return str(result) == '200'

    def report_wait_for(self, report_id, timeout=settings.DEFAULT_REPORT_TIMEOUT):
        """
        Wait for a Report to finish successfully.

        :param report_id: Report id to wait for
        :param timeout: Maximum time in seconds to wait before raising a TimeoutException
        :return: The ReportTask resource waited on, either in 'SUCCEEDED' or 'FAILED' state
        """
        logger.info('Waiting for report %s', report_id)
        start = time.time()
        while True:
            report_result = self.report_get(id=report_id)
            if report_result.state != 'PENDING':
                return report_result
            elif -1 < timeout < time.time() - start:
                raise exceptions.TimeoutException(
                    f'Timed out waiting for report {report_id} to finish. Please try again.')
            else:
                time.sleep(settings.POLL_FREQUENCY)
