import os
import platform
from . import _version

# API constants
DEFAULT_GLOBAL_API = 'https://api.polyswarm.network/v1'
DEFAULT_PERMALINK_BASE = os.getenv('POLYSWARM_PORTAL_URI', 'https://polyswarm.network/scan/results')
DEFAULT_COMMUNITY = 'lima'
DEFAULT_SCAN_TIMEOUT = 60*15
RESULT_CHUNK_SIZE = 100

# HTTP settings
DEFAULT_HTTP_TIMEOUT = 30
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 1
DEFAULT_RETRY_CODES = (500, 502, 504)
DEFAULT_USER_AGENT = 'polyswarm-api/{} ({}-{}-{}-{})'.format(_version.__version__, platform.machine(), platform.system(),
                                                       platform.python_implementation(), platform.python_version())

# concurrent HTTP workers
DEFAULT_WORKER_COUNT = 8

# API maximums
MAX_HUNT_RESULTS = 20000
MAX_ARTIFACT_BATCH_SIZE = 256

# Filesystem constants
FILE_CHUNK_SIZE = 8192
MAX_OPEN_FDS = 256
# this results in worst case 32MB memory usage during downloads
DOWNLOAD_CHUNK_SIZE = 1024*1024*4

MAX_SINCE_TIME_STREAM = 60*24*2

USAGE_EXCEEDED_MESSAGE = 'Usage limits were exceeded. This may mean you need to purchase a ' \
                         'larger package, or that you have exceeded rate limits.\n' \
                         'If you continue to have issues, please contact us at info@polyswarm.io.'

