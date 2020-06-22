import os
import platform
import polyswarm_api

# API constants
DEFAULT_GLOBAL_API = 'https://api.polyswarm.network/v2'
DEFAULT_PERMALINK_BASE = os.getenv('POLYSWARM_PORTAL_URI', 'https://polyswarm.network/scan/results/file')
DEFAULT_COMMUNITY = 'default'
DEFAULT_SCAN_TIMEOUT = 60*15
RESULT_CHUNK_SIZE = 100
POLL_FREQUENCY = 1

# HTTP settings
DEFAULT_HTTP_TIMEOUT = 30
DEFAULT_RETRIES = 0
DEFAULT_BACKOFF = 1
DEFAULT_RETRY_CODES = (502, 504)
DEFAULT_USER_AGENT = 'polyswarm-api/{} ({}-{}-{}-{})'.format(
    polyswarm_api.__version__, platform.machine(), platform.system(),
    platform.python_implementation(), platform.python_version(),
)

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

MAX_SINCE_TIME_STREAM = 2 * 60 * 24
