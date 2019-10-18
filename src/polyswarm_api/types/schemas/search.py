# This is duplicated from AI. Sharing these somewhere would be helpful...

simple_query_string_schema = {
    'properties': {
        'query': {
            'type': 'object',
            'properties': {
                'simple_query_string': {
                    'type': 'object',
                    'properties': {
                        'query': {
                            'type': 'string'
                        },
                        'fields': {
                            'type': 'array',
                            'items': {
                                'type': 'string'
                            }
                        },
                        'default_operator': {
                            'type': 'string'
                        }
                    },
                    'additionalProperties': False,
                    'required': ['query', 'fields'],
                }
            },
            'additionalProperties': False,
            'required': ['simple_query_string'],
        }
    },
    'additionalProperties': False,
    'required': ['query']
}

query_string_schema = {
    'properties': {
        'query': {
            'type': 'object',
            'properties': {
                'query_string': {
                    'type': 'object',
                    'properties': {
                        'default_field': {
                            'type': 'string'
                        },
                        'query': {
                            'type': 'string'
                        }
                    },
                    'additionalProperties': False,
                    'required': ['query']
                }
            },
            'additionalProperties': False,
            'required': ['query_string']
        }
    },
    'additionalProperties': False,
    'required': ['query']
}

exists_schema = {
    'properties': {
        'query': {
            'type': 'object',
            'properties': {
                'exists': {
                    'type': 'object',
                    'properties': {
                        'field': {
                            'type': 'string'
                        }
                    },
                    'additionalProperties': False,
                    'required': ['field']
                },
            },
            'additionalProperties': False,
            'required': ['exists']
        }
    },
    'additionalProperties': False,
    'required': ['query']
}

range_schema = {
    'properties': {
        'query': {
            'type': 'object',
            'properties': {
                'range': {
                    'type': 'object',
                    'patternProperties': {
                        '^.*$': {
                            'type': 'object',
                            'patternProperties': {
                                'gte?': {
                                    "anyOf": [
                                        {"type": "string"},
                                        {"type": "number"}
                                    ]
                                },
                                'lte?': {
                                    'anyOf': [
                                        {"type": "string"},
                                        {"type": "number"}
                                    ]
                                },
                                'boost': {
                                    'type': 'number'
                                }

                            },
                            'additionalProperties': False
                        }
                    },
                    'additionalProperties': False
                },
            },
            'additionalProperties': False,
            'required': ['range']
        }
    },
    'additionalProperties': False,
    'required': ['query']
}

terms_query = {
    'properties': {
        'query': {
            'type': 'object',
            'properties': {
                'terms': {
                    'type': 'object',
                    'patternProperties': {
                        '^.*$': {
                            'type': 'array',
                            'items': {
                                'anyOf': [
                                    {"type": "string"},
                                    {"type": "number"},
                                    {"type": "integer"}
                                ]
                            }
                        }
                    },
                    'additionalProperties': False
                }
            },
            'additionalProperties': False,
            'required': ['terms']

        }
    },
    'additionalProperties': False,
    'required': ['query']

}

search_schema = {
    'type': 'object',
    'oneOf': [
        simple_query_string_schema,
        query_string_schema,
        exists_schema,
        range_schema,
        terms_query
    ]
}
