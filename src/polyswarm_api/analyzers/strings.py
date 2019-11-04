import re

from .base import BaseAnalyzer
from .. import utils


def strings(fh, n=4, encoding='utf-8'):
    regexp = '[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ]{' + str(n) + ',}'
    pattern = re.compile(regexp)
    data = fh.read().decode(encoding, errors='replace')
    result = [i for i in pattern.findall(data)]
    return result


def get_all_strings(fh, n=4, filter=None):
    encodings = ['ascii', 'utf-8']

    for encoding in encodings:
        fh.seek(0)
        res = strings(fh, n, encoding)

        for s in res:
            if filter is None:
                yield res
            else:
                r = filter(s)
                if r:
                    for i in r:
                        yield i


class StringsAnalyzer(BaseAnalyzer):
    MODULE = 'strings'

    def __init__(self):
        super(StringsAnalyzer, self).__init__()

    def is_supported(self, fh):
        return True

    def analyze(self, fh):
        raise NotImplementedError


class URLAnalyzer(StringsAnalyzer):
    NAME = 'urls'

    def analyze(self, fh):
        fh.seek(0)
        ioc = utils.try_import('iocextract')

        def filter_func(s):
            return ioc.extract_urls(s, refang=True)

        return self._make_analysis_object(list(set(get_all_strings(fh, filter=filter_func))))


class DomainsAnalyzer(StringsAnalyzer):
    NAME = 'domains'

    def analyze(self, fh):
        fh.seek(0)
        ioc = utils.try_import('iocextract')
        tld = utils.try_import('tldextract')

        def filter_func(s):
            for url in ioc.extract_urls(s, refang=True):
                yield tld.extract(url).fqdn

        return self._make_analysis_object(list(set(get_all_strings(fh, filter=filter_func))))


class IPV4Analyzer(StringsAnalyzer):
    NAME = 'ipv4'

    def analyze(self, fh):
        fh.seek(0)
        ioc = utils.try_import('iocextract')

        def filter_func(s):
            return ioc.extract_ipv4s(s, refang=True)

        return self._make_analysis_object(list(set(get_all_strings(fh, filter=filter_func))))


class IPV6Analyzer(StringsAnalyzer):
    NAME = 'ipv6'

    def analyze(self, fh):
        fh.seek(0)
        ioc = utils.try_import('iocextract')

        def filter_func(s):
            return ioc.extract_ipv6s(s)

        return self._make_analysis_object(list(set(get_all_strings(fh, filter=filter_func))))
