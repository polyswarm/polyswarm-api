import json

from . import base
from ..const import USAGE_EXCEEDED_MESSAGE


class JSONOutput(base.BaseOutput):
    name = 'json'
    @staticmethod
    def _to_json(result):
        return json.dumps(result.json['result'], sort_keys=True)

    def search_result(self, result):
        self.out.write(self._to_json(result)+'\n')

    def scan_result(self, result):
        self.out.write(self._to_json(result)+'\n')

    def hunt_result(self, result):
        # here, we output just the match results
        for match in result:
            self.out.write(json.dumps(match.json, sort_keys=True)+'\n')

    def hunt_submission(self, result):
        self.out.write(self._to_json(result)+'\n')

    def hunt_deletion(self, result):
        self.out.write(self._to_json(result)+'\n')

    def hunt_list(self, result):
        for hunt in result:
            self.out.write(json.dumps(hunt.json, sort_keys=True)+'\n')

    def download_result(self, result):
        artifact = result.result
        self.out.write(json.dumps({'hash': artifact.artifact_name, 'path': artifact.path}, sort_keys=True)+'\n')

    def invalid_rule(self, e):
        self.out.write(json.dumps('Malformed yara file: {}'.format(e.args[0])))

    @staticmethod
    def usage_exceeded():
        return json.dumps(USAGE_EXCEEDED_MESSAGE)
