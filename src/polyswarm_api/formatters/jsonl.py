import json

from . import base


class JSONOutput(base.BaseOutput):
    name = 'json'
    @staticmethod
    def _to_json(result):
        return json.dumps(result.json['result'])

    def search_result(self, result):
        self.out.write(self._to_json(result)+'\n')

    def scan_result(self, result):
        self.out.write(self._to_json(result)+'\n')

    def hunt_result(self, result):
        # here, we output just the match results
        for match in result:
            self.out.write(json.dumps(match.json)+'\n')

    def hunt_submission(self, result):
        self.out.write(self._to_json(result)+'\n')

    def download_result(self, result):
        artifact = result.result
        self.out.write(json.dumps({'hash': artifact.artifact_name, 'path': artifact.path})+'\n')