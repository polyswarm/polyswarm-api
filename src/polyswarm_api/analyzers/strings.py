import re

from .base import Analyzer
from .. import utils


def strings(file_data, n=4, encoding='utf-8'):
    regexp = '[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ]{' + str(n) + ',}'
    pattern = re.compile(regexp)
    data = file_data.decode(encoding, errors='replace')
    result = [i for i in pattern.findall(data)]
    return result


def get_all_strings(file_data, n=4, filter=None):
    encodings = ['ascii', 'utf-8']

    for encoding in encodings:
        res = strings(file_data, n, encoding)

        for s in res:
            if filter is None:
                yield res
            else:
                r = filter(s)
                if r:
                    for i in r:
                        yield i


class StringsAnalyzer(Analyzer):
    MODULE = 'strings'

    def __init__(self):
        super(StringsAnalyzer, self).__init__()

    def is_supported(self, fh):
        return True

    def analyze(self, fh):
        ioc = utils.try_import('iocextract')
        tld = utils.try_import('tldextract')

        fh.seek(0)
        data = fh.read()

        urls = list(set(get_all_strings(data, filter=lambda s: ioc.extract_urls(s, refang=True))))
        domains = list(set([tld.extract(u).fqdn for u in urls]))
        ipv4 = list(set(get_all_strings(data, filter=lambda s: ioc.extract_ipv4s(s, refang=True))))
        ipv6 = list(set(get_all_strings(data, filter=lambda s: ioc.extract_ipv6s(s))))

        return [
            self._make_feature(*args) for args in [
                (urls, 'urls'),
                (domains, 'domains'),
                (ipv4, 'ipv4'),
                (ipv6, 'ipv6'),
            ]
        ]

