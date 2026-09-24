"""A QR-code ``sandbox_file`` submission uploads the IMAGE, respx-mocked on BOTH
clients (``ClientTestCase`` — specs/04-testing.md invariant 5).

The respx tier because the e2e stack's sandbox providers cannot reasonably
process a QR image. What is pinned is the wire: the S3 PUT body must be the
file's bytes. A client that hands the path string to ``from_content`` uploads
the text of the path instead, and the server then fails the task as an
unrecognised image — that is the bug this guards. Refanging is switched on so
the same test also proves the path (``qr[.]png``, shaped like a domain once
refanged) is never rewritten.
"""
import json
import os
import tempfile

from polyswarm_api.aio import PolySwarmAsyncAPI
from polyswarm_api.api import PolyswarmAPI

from test._client_harness import API_KEY, BASE_URL, COMMUNITY, ClientTestCase, _AsyncToSync

_TASK_URL = f'{BASE_URL}/sandbox/sandboxtask/instance'
_UPLOAD_URL = 'https://s3.example.test/upload?signature=abc'
_IMAGE_BYTES = b'\x89PNG\r\n\x1a\n not really a png, but bytes all the same'
_TASK = {
    'id': '7', 'community': COMMUNITY, 'sandbox': 'provider', 'created': None,
    'expiration': None, 'status': 'PENDING', 'account_number': None,
    'team_account_number': None, 'instance_id': None, 'sha256': None,
    'report': None, 'upload_url': _UPLOAD_URL, 'config': {}, 'artifact': None,
}


class SandboxFileQrCodeTestCase(ClientTestCase):
    def setUp(self):
        super().setUp()
        if self._client_kind == 'sync':
            self.api = PolyswarmAPI(API_KEY, uri=BASE_URL, community=COMMUNITY, refang_iocs=True)
        else:
            self.api = _AsyncToSync(
                PolySwarmAsyncAPI(API_KEY, uri=BASE_URL, community=COMMUNITY, refang_iocs=True),
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'qr[.]png')
        with open(self.path, 'wb') as f:
            f.write(_IMAGE_BYTES)

    def test_uploads_the_image_bytes_under_its_unrefanged_basename(self):
        self.mock.add('POST', _TASK_URL, json={'status': 'OK', 'result': _TASK})
        self.mock.add('PUT', _UPLOAD_URL, json={})
        self.mock.add('PUT', f'{_TASK_URL}?id=7', json={'status': 'OK', 'result': _TASK})

        self.api.sandbox_file(self.path, 'provider', 'vm', artifact_type='URL',
                              preprocessing={'type': 'qrcode'})

        create, upload, _finalize = self.mock.requests
        assert upload.url == _UPLOAD_URL
        assert upload.content == _IMAGE_BYTES
        assert json.loads(create.content)['artifact_name'] == 'qr[.]png'
