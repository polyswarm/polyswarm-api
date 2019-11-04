from . import DEFAULT_ANALYZERS
from ..log import logger


class ArtifactFeatures(object):
    def __init__(self, artifact, analyzers=None):
        """
        An aggregator of BaseAnalyzer objects

        :param analyzers: list of BaseAnalyzer objects
        :param artifact: A LocalArtifact object
        """
        if not analyzers:
            analyzers = DEFAULT_ANALYZERS

        self.analyzers = analyzers
        self.features = []

        fh = artifact.file_handle

        for analyzer in analyzers:
            if not analyzer.is_supported(fh):
                logger.info('Attempted to use an incompatible analyzer {} for Artifact'.format(analyzer.NAME))
                continue

            try:
                self.features.append(analyzer.analyze(fh))
            except NameError:
                # handle missing deps
                continue
            except ImportError:
                continue

    def as_search(self):
        return ' AND '.join(f.as_search() for f in self.features if f.features)

