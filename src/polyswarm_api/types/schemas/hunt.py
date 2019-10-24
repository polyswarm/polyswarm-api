hunt_submission = {
    'type': 'object',
    'properties': {
        'hunt_id': {'type': 'string'},
    },
    'required': ['hunt_id'],
}

hunt_status = {
    'type': 'object',
    'properties': {
        'active': {'type': 'boolean'},
        'created': {'type': 'string'},
        'id': {'type': 'string'},
        'results': {'type': 'array'},
        'total': {'type': 'integer'},
        'status': {'type': 'string'},
    },
    'required': ['created', 'id', 'results', 'status']
}

hunt_result = {
    'type': 'object',
    'properties': {
        'artifact': {'type': 'object'},
        'rule_name': {'type': 'string'},
        'tags': {'type': 'string'},
    }
}

