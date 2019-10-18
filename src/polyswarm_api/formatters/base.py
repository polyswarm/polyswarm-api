from ..const import USAGE_EXCEEDED_MESSAGE


class BaseOutput(object):
    name = 'base'

    def __init__(self, output, **kwargs):
        self.out = output

    def search_result(self, result):
        raise NotImplementedError

    def hunt_result(self, result):
        raise NotImplementedError

    def scan_result(self, result):
        raise NotImplementedError

    def hunt_submission(self, result):
        raise NotImplementedError

    def download_result(self, result):
        raise NotImplementedError

    def usage_exceeded(self):
        print(USAGE_EXCEEDED_MESSAGE)
