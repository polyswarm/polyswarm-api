

class BaseFormatter(object):
    def __init__(self, **kwargs):
        pass

    def format_search_result(self, result):
        raise NotImplemented

    def format_hunt_result(self, result):
        raise NotImplemented

    def format_scan_result(self, result):
        raise NotImplemented

    def format_hunt_creation(self, result):
        raise NotImplemented