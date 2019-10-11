
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

artifact_instance_schema = {
    'type': 'object',
    'properties': {
        'artifact_id': {'type': 'string'},
        'bounty_id': {'type': ['null', 'string']},
        'bounty_result': {
            'oneOf': [
                {'type': 'null'},
                {
                    'type': 'object',
                    'properties': {
                        'artifact_type': {'type': 'string'},
                        'files': {'type': 'array'}, # has custom validation, we should flatten this in AI
                        'permalink': {'type': 'string'},
                        'status': {'type': 'string'},
                        'uuid': {'type': 'string'},
                    },
                },
            ],
        },
        'community': {'type': 'string'},
        'consumer_guid': {'type': ['string', 'null']},
        'country': {'type': ['string', 'null']},
        'id': {'type': 'string'},
        'name': {'type': ['string', 'null']},
        'submitted': {'type': 'string'},
    },
    'required': ['artifact_id', 'bounty_id', 'bounty_result', 'community', 'country', 'id', 'name', 'submitted']
}


artifact_schema = {
    'type': 'object',
    'properties': {
        'artifact_instances': {'type': 'array'},
        'artifact_metadata': {'type': 'object'},
        'extended_type': {'type': 'string', 'minLength': 1},
        'first_seen': {'type': 'string'},
        'id': {'type': 'string'},
        'sha256': {
            'type': 'string',
            'minLength': 64,
            'maxLength': 64,
        },
        'sha1': {
            'type': 'string',
            'minLength': 40,
            'maxLength': 40,
        },
        'md5': {
            'type': 'string',
            'minLength': 32,
            'maxLength': 32,
        },
        'mimetype': {
            'type': 'string',
            'minLength': 1,
        },
    },
    'required': ['extended_type', 'first_seen', 'id', 'sha256', 'sha1', 'md5', 'mimetype'],
}

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