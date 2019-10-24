import datetime


def parse_date(date_string):
    """ Parses the current date format version """
    return datetime.datetime.strptime(date_string, '%a, %d %b %Y %H:%M:%S %Z')


def parse_timestamp(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp)