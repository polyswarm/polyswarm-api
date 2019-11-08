import os
import shutil
import tempfile
from contextlib import contextmanager

import pytest
import responses
from polyswarm_api.api import PolyswarmAPI

try:
    from unittest import TestCase, mock
except ImportError:
    import mock


@contextmanager
def TemporaryDirectory():
    """The day we drop python 2.7 support we can use python 3 version of this"""
    name = tempfile.mkdtemp()
    try:
        yield name
    finally:
        shutil.rmtree(name)


@contextmanager
def temp_dir(files_dict):
    with TemporaryDirectory() as tmp_dir:
        files = []
        for file_name, file_content in files_dict.items():
            mode = 'w' if isinstance(file_content, str) else 'wb'
            file_path = os.path.join(tmp_dir, file_name)
            open(file_path, mode=mode).write(file_content)
            files.append(file_path)
        yield tmp_dir, files


class ScanTestCaseV2(TestCase):
    def __init__(self, *args, **kwargs):
        super(ScanTestCaseV2, self).__init__(*args, **kwargs)
        self.test_api_key = '11111111111111111111111111111111'
        self.api_version = 'v2'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_submission(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.scan('test/malicious'))
        assert result[0].status == 'Bounty Awaiting Arbitration'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_rescan(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.rescan('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].status == 'Bounty Awaiting Arbitration'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_download(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}/consumer', community='gamma')
        with temp_dir({}) as (path, _):
            result = list(api.download(path, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
            with result[0].file_handle as f:
                assert f.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_stream(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with temp_dir({}) as (path, _):
            result = list(api.stream(path))
            with result[0].file_handle as f:
                assert f.read() == b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_hash_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.search('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].sha256 == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_metadata_search(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.search_by_metadata('hash.sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'))
        assert result[0].sha256 == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_resolve_engine_name(self):
        # This still does not have a v2 path
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:3000/api/v1', community='gamma')
        result = api._resolve_engine_name('0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8')
        assert result == 'eicar'

    @pytest.mark.skip(reason="only for local testing for now")
    def test_live(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            live_hunt = api.live_create(yara.read())
        assert live_hunt.active
        assert live_hunt.status == 'SUCCESS'
        api.live_update(live_hunt.id)
        updated_live_hunt = api.live_get(live_hunt.id)
        assert not updated_live_hunt.active
        deleted_live_hunt = api.live_delete(live_hunt.id)
        assert live_hunt.id == deleted_live_hunt.id

    @pytest.mark.skip(reason="only for local testing for now")
    def test_live_results(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.live_results(hunt_id='63433636835291189'))
        assert len(result) == 86

    @pytest.mark.skip(reason="only for local testing for now")
    def test_list_live(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            yara = yara.read()
            for _ in range(100):
                api.live_create(yara)
        result = list(api.live_list())
        assert len(result) >= 100

    @pytest.mark.skip(reason="only for local testing for now")
    def test_historical(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            historical_hunt = api.historical_create(yara.read())
        assert historical_hunt.status == 'PENDING'
        get_historical_hunt = api.historical_get(historical_hunt.id)
        assert historical_hunt.id == get_historical_hunt.id
        deleted_historical_hunt = api.historical_delete(get_historical_hunt.id)
        assert historical_hunt.id == deleted_historical_hunt.id

    @pytest.mark.skip(reason="only for local testing for now")
    def test_list_historical(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        with open('test/eicar.yara') as yara:
            yara = yara.read()
            for _ in range(100):
                api.historical_create(yara)
        result = list(api.historical_list())
        assert len(result) >= 100

    @pytest.mark.skip(reason="only for local testing for now")
    def test_historical_results(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.historical_results(hunt_id='47190397989086018'))
        assert len(result) == 34

    @pytest.mark.skip(reason="only for local testing for now")
    def test_polyscore(self):
        api = PolyswarmAPI(self.test_api_key, uri=f'http://localhost:9696/{self.api_version}', community='gamma')
        result = list(api.score('6eadcabe-9f9e-4301-8e60-c9e58504c325'))
        assert result[0].scores['77090327141458166'] == 0.9999682631387563
