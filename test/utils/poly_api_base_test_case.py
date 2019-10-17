from pkg_resources import resource_string
import json


class PolyApiBaseTestCase(object):

    def __init__(self, *args, **kwargs):
        super(PolyApiBaseTestCase, self).__init__(*args, **kwargs)
        self.test_query = {
            'query': {
                'exists': {
                    'field': 'lief.libraries'
                }
            }
        }
        self.test_api_key = '317b21cb093263b701043cb0831a53b9'

    @staticmethod
    def _get_test_text_resource(resource):
        return resource_string('test.resources', resource).decode('utf-8')

    def _get_test_json_resource(self, resource):
        return json.loads(self._get_test_text_resource(resource))
