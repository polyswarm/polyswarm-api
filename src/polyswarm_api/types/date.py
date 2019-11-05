import datetime
from dateutil import parser


def parse_isoformat(date_string):
    """ Parses the current date format version """
    return parser.isoparse(date_string)


def parse_date(date_string):
    """ Parses the current date format version """
    return datetime.datetime.strptime(date_string, '%a, %d %b %Y %H:%M:%S %Z')


def parse_timestamp(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp)