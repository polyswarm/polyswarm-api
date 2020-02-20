from dateutil import parser


def parse_isoformat(date_string):
    """ Parses the current date format version """
    if date_string:
        return parser.isoparse(date_string)
    else:
        return None
