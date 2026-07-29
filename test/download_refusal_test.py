"""Refusal handling on the streaming-download arm, both transports.

respx rather than the live e2e stack (specs/04-testing.md, invariant 1): the
scenario under test is the SDK's *transport arm*, not the endpoint. A download
refusal never reaches ``parse_response`` — ``_execute_download`` reads the small
error body itself and hands it to the shared ``_raise_for_status`` — so neither a
pure-unit parse test nor a cassette-backed endpoint test that asserts only the
caller-visible outcome exercises that code path. Endpoint behaviour against the
real server stays with the live-e2e VCR tests.

On the ``ClientTestCase`` harness (invariant 5) so the one body runs against
``PolyswarmAPI`` **and** ``PolySwarmAsyncAPI``: ``_execute_download`` exists twice
(the canonical async source and its generated sync mirror), and the sync arm is
exactly the one a hand-written async-only respx body leaves uncovered.
"""
import os
import tempfile

from polyswarm_api import exceptions

from test._client_harness import BASE_URL, ClientTestCase


SHA256 = 'a' * 64
_DOWNLOAD_URL = f'{BASE_URL}/consumer/download/sha256/{SHA256}'

# The server's refusal envelope: a 404 whose machine-readable ``errors`` code says
# the bytes are withheld because the artifact is a known-good binary.
_REFUSAL_BODY = {
    'status': 'error',
    'result': 'Unable to download the provided artifact, it is a known-good '
              'binary; its bytes are withheld by design.',
    'errors': {'code': 'KNOWN_GOOD', 'known_good': True, 'sources': ['nsrl']},
}


class DownloadRefusalTestCase(ClientTestCase):
    def test_download_known_good_refusal_raises_withheld(self):
        # Regression: the refusal arrives on the streaming arm, which bypasses
        # ``parse_response`` entirely. Without the shared ``_raise_for_status``
        # mapping being reached there, a refused download surfaces as a bare
        # ``NotFoundException`` (no ``.sources``, indistinguishable from a plain
        # miss) — or, worse, gets written out as an artifact file holding the
        # error JSON. Pin both: the typed exception with its payload, and an
        # untouched destination folder.
        self.mock.add('GET', _DOWNLOAD_URL, json=_REFUSAL_BODY, status=404)
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(exceptions.KnownGoodWithheldException) as caught:
                self.api.download(tmp_dir, SHA256)
            exc = caught.exception
            assert exc.sources == ['nsrl']
            # Still a NotFoundException, so existing handlers keep catching it.
            assert isinstance(exc, exceptions.NotFoundException)
            # The raw envelope stays reachable for callers that want the rest.
            assert exc.request.errors == _REFUSAL_BODY['errors']
            # A refusal must leave nothing behind — no empty file, no error JSON
            # written out as if it were the artifact.
            assert os.listdir(tmp_dir) == []
