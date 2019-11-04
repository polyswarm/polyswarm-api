import json


class BaseFeature(object):
    def __init__(self, features, module='base', name='base'):
        self.features = features
        self.module = module
        self.name = name

    @staticmethod
    def _escape(s):
        # TODO use re for performance. Also, make this function.
        reserved = ['+','-','=', '&&', '||', '!', '(', ')', '{', '}', '[', ']',
                   '^', '"', '~', '*', '?', ':', '\\', '/']

        for r in reserved:
            s = s.replace(r, '\\'+r)

        # per https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html
        # these *cannot* be escaped. we can only wildcard them.
        wild = ['<', '>']

        for r in wild:
            s = s.replace(r, '*')

        return s

    def as_search(self):
        """ Returns a representation of this object as a PolySwarm metadata query """
        if isinstance(self.features, list):
            return '{}.{}:({})'.format(self.module, self.name,
                                       ' AND '.join('"{}"'.format(str(s)) for s in self.features if s))
        elif isinstance(self.features, str):
            return '{}.{}:{}'.format(self.module, self.name, '"{}"'.format(self.features))
        else:
            raise NotImplementedError

    def as_json(self):
        """ Returns a representation of this analysis as JSON """
        return json.dumps(self.features)

    def __str__(self):
        return 'Feature: {}'.format(str(self.features))

    def __repr__(self):
        return self.as_json()


class BaseAnalyzer(object):
    MODULE = 'base'
    NAME = 'base'
    FEATURE = BaseFeature

    def is_supported(self, fh):
        """
        Check whether or not the data pointed to by fh is supported by this analyzer.

        :param fh: A seekable file-handle.
        :return: True if the content is supported, False if not.
        """
        raise NotImplementedError

    def analyze(self, fh):
        """
        Run this analyzer's analysis and return a BaseFeature object (or subclassed object)
        :param fh: A seekable file-handle
        :return: BaseFeature object
        """
        raise NotImplementedError

    def _make_analysis_object(self, features):
        return self.FEATURE(features, self.MODULE, self.NAME)

