import json

from . import base


class JSONFormatter(base.BaseFormatter):
    @staticmethod
    def _to_json(result):
        return json.dumps(result.json['result'])

    def format_search_result(self, result):
        return self._to_json(result)

    def format_scan_result(self, result):
        return self._to_json(result)

    def format_hunt_result(self, result):
        return self._to_json(result)
