import json

from . import base


class JSONOutput(base.BaseOutput):
    name = 'json'
    @staticmethod
    def _to_json(result):
        return json.dumps(result.json['result'])

    def search_result(self, result):
        self.out.write(self._to_json(result))

    def scan_result(self, result):
        self.out.write(self._to_json(result))

    def hunt_result(self, result):
        # here, we output just the match results
        for match in result:
            self.out.write(json.dumps(match.json))

    def hunt_submission(self, result):
        self.out.write(self._to_json(result))
