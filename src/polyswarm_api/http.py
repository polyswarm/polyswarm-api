import logging
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from . import const

logger = logging.getLogger(__name__)


class PolyswarmHTTP(requests.Session):
    def __init__(self, key, retries, user_agent=const.DEFAULT_USER_AGENT):
        super(PolyswarmHTTP, self).__init__()
        logger.debug('Creating PolyswarmHTTP instance')
        self.requests_retry_session(retries=retries)

        if key:
            self.set_auth(key)

        if user_agent:
            self.set_user_agent(user_agent)

    def requests_retry_session(self, retries=const.DEFAULT_RETRIES, backoff_factor=const.DEFAULT_BACKOFF,
                               status_forcelist=const.DEFAULT_RETRY_CODES):
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.mount('http://', adapter)
        self.mount('https://', adapter)

    def set_auth(self, key):
        if key:
            self.headers.update({'Authorization': key})
        else:
            self.headers.pop('Authorization', None)

    def set_user_agent(self, ua):
        if ua:
            self.headers.update({'User-Agent': ua})
        else:
            self.headers.pop('User-Agent', None)
