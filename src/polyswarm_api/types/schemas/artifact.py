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

artifact_archive_schema = {
    'type': 'object',
    'properties': {
        'id': {'type': 'string'},
        's3_path': {
            'type': 'string',
        },
        'community': {
            'type': 'string',
        },
        'created': {'type': 'string'},

    },
    'required': ['s3_path'],
}

# TODO fill out more
artifact_metadata = {
    'type': 'object',
}
