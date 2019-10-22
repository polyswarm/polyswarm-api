
# TODO change API so that metadata isn't a string when empty...and also not a list
# TODO much of this could be taken from polyswarm-artifact
assertion_schema = {
    'type': 'object',
    'properties': {
        'author': {'type': 'string'},
        'bid': {'type': ['string', 'integer']},
        'mask': {'type': 'boolean'},
        'metadata': {
            'oneOf': [
                {'type': 'string'},
                {'type': 'array'},
                {
                    'type': 'object',
                    'properties': {
                        'malware_family': {'type': 'string'},
                        'scanner': {
                            'type': 'object',
                            'properties': {
                                'environment': {'type': 'object'},
                            }
                        }
                    },
                    'required': ['malware_family']
                },
            ]
        },
        'verdict': {'type': ['boolean', 'null']},
    },
    'required': ['author', 'bid', 'mask', 'metadata', 'verdict']
}

vote_schema = {
    'type': 'object',
    'properties': {
        'arbiter': {'type': 'string'},
        'vote': {'type': 'boolean'},
    },
    'required': ['arbiter', 'vote']
}

bounty_file_schema = {
    'type': 'object',
    'properties': {
        'assertions': {
            'type': 'array',
            'items': {
                'type': 'object'
            }
        },
        'bounty_guid': {'type': ['string', 'null']},
        'bounty_status': {'type': ['string', 'null']},
        'failed': {'type': 'boolean'},
        'filename': {'type': 'string'},
        'hash': {'type': 'string'},
        'result': {'type': ['boolean', 'null']},
        'size': {'type': 'integer'},
        'votes': {
            'type': 'array',
            'items': {
                'type': 'object'
            }
        },
        'window_closed': {'type': 'boolean'},
        'id': {'type': 'string'},
    },
    'required': ['assertions', 'bounty_guid', 'bounty_status', 'failed', 'filename', 'hash', 'result',
                 'size', 'votes', 'window_closed']
}

bounty_schema = {
    'type': 'object',
    'properties': {
        'artifact_type': {'type': 'string'},
        'files': {
            'type': 'array',
            'items': {
                'type': 'object'
            },
        },  # has custom validation, we should flatten this in AI
        'permalink': {'type': 'string'},
        'status': {'type': 'string'},
        'uuid': {'type': 'string'},
    },
    'required': ['files', 'status', 'uuid'],
}

polyscore_schema = {
    'type': 'object',
    'properties': {
        'scores': {'type': 'object'},
    },
    'required': ['scores']
}
