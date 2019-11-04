import subprocess
import json

from .base import Analyzer
from ..log import logger


class ExiftoolAnalyzer(Analyzer):
    MODULE = 'exiftool'
    CACHE = {}

    def __init__(self):
        super(ExiftoolAnalyzer, self).__init__()

    def is_supported(self, fh):
        return True

    def analyze(self, fh):
        raise NotImplementedError

    def _get_data(self, fh):
        try:
            p = subprocess.Popen(['exiftool', '-j', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        except OSError as e:
            logger.warning('Could not find exiftool. Please install it to use this feature.')
            raise e

        results, errors = p.communicate(fh.read())

        return json.loads(results.decode('utf-8', errors='ignore'))[0]
