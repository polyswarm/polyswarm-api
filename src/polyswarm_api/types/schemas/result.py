api_response_schema = {
    'type': 'object',
    'properties': {
        'status': {'type': 'string'},
        'result': {'type': ['array', 'object', 'string']},
        'errors': {'type': 'string'},
        'total': {'type': 'integer'},
        'limit': {'type': 'integer'},
        'page': {'type': 'integer'},
        'orderBy': {'type': 'string'},
        'direction': {'type': 'string'}
    },
    'required': ['status', 'result'],
}