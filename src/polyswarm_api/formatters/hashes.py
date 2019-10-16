import json

from . import base


class SHA256Output(base.BaseOutput):
    """ Formatter that simply outputs SHA256s separated by newlines, only supports search/scan results """
    name = 'sha256'
    @staticmethod
    def _to_json(result):
        return json.dumps(result.json['result'])

    def search_result(self, result):
        self.out.write('\n'.join([artifact.sha256.hash for artifact in result])+'\n')
    
    def scan_result(self, result):
        """ Only returns sha256s of malicious results """
        if result.status_code == 404:
            return

        bounty = result.result
        artifact = result.artifact

        f = bounty.get_file_by_hash(artifact.hash)

        if f and len(f.detections) > 0:
            self.out.write('{}\n'.format(artifact.hash.hash))

    def hunt_result(self, result):
        for match in result:
            self.out.write(match.artifact.sha256.hash+'\n')


class SHA1Output(base.BaseOutput):
    """ Formatter that simply outputs SHA1s separated by newlines, only supports search/scan results """
    name = 'sha1'
    @staticmethod
    def _to_json(result):
        return json.dumps(result.json['result'])

    def search_result(self, result):
        self.out.write('\n'.join([artifact.sha1.hash for artifact in result])+'\n')

    def scan_result(self, result):
        """ Only returns sha1s of malicious results """
        self.out.write('\n'.join([artifact.sha1.hash for artifact in result if len(artifact.detections) > 0])+'\n')

    def hunt_result(self, result):
        self.out.write('\n'.join([match.artifact.sha1.hash for match in result])+'\n')


class MD5Output(base.BaseOutput):
    """ Formatter that simply outputs MD5s separated by newlines, only supports search/scan results """
    name = 'md5'
    @staticmethod
    def _to_json(result):
        return json.dumps(result.json['result'])

    def search_result(self, result):
        self.out.write('\n'.join([artifact.md5.hash for artifact in result])+'\n')

    def scan_result(self, result):
        """ Only returns md5s of malicious results """
        self.out.write('\n'.join([artifact.md5.hash for artifact in result if len(artifact.detections) > 0])+'\n')

    def hunt_result(self, result):
        self.out.write('\n'.join([match.artifact.md5.hash for match in result])+'\n')
