"""``iocs_by_hash`` by md5/sha1, respx-mocked on BOTH clients (``ClientTestCase`` —
specs/04-testing.md invariant 5).

The ``AMBIGUOUS_HASH`` refusal (artifact-index specs/20-ioc-by-hash.md) lives here
because the e2e stack cannot produce it: it needs two artifacts sharing one md5.
"""
import re

import pytest

from polyswarm_api import exceptions

from test._client_harness import BASE_URL, ClientTestCase

MD5 = 'c' * 32
CANDIDATES = ['d' * 64, 'e' * 64]


class IocsByHashTestCase(ClientTestCase):
    def test_ambiguous_md5_refusal_is_machine_readable_on_both_routes(self):
        # No typed exception (specs/05): the contract is the raw envelope at
        # ``exc.request.errors``, whose candidates let the caller retry by sha256.
        envelope = {
            'status': 'error',
            'result': 'The md5 matches several artifacts; query by sha256.',
            'errors': {'code': 'AMBIGUOUS_HASH', 'hash_type': 'md5',
                       'sha256s': CANDIDATES, 'truncated': False},
        }
        for path, beta in (('ioc', False), ('ioc-beta', True)):
            self.mock.add('GET', re.compile(re.escape(f'{BASE_URL}/{path}/md5/{MD5}') + r'(\?.*)?$'),
                          json=envelope, status=400)
            with pytest.raises(exceptions.RequestException) as excinfo:
                list(self.api.iocs_by_hash('md5', MD5, beta=beta))
            errors = excinfo.value.request.errors
            assert errors['code'] == 'AMBIGUOUS_HASH', path
            assert errors['sha256s'] == CANDIDATES, path
            assert 'code=AMBIGUOUS_HASH' in str(excinfo.value), path
