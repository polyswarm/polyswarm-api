from . import DEFAULT_ANALYZERS, DEFAULT_FEATURES
from ..log import logger


class ArtifactFeatures(object):
    def __init__(self, artifact, analyzers=None, desired_features=None):
        """
        An aggregator of BaseAnalyzer objects

        :param analyzers: list of BaseAnalyzer objects
        :param artifact: A LocalArtifact object
        """

        if not analyzers:
            analyzers = DEFAULT_ANALYZERS

        if not desired_features:
            desired_features = DEFAULT_FEATURES

        self.analyzers = analyzers
        self.features = []

        fh = artifact.file_handle

        for analyzer in analyzers:
            if not analyzer.is_supported(fh):
                logger.info('Attempted to use an incompatible analyzer {} for Artifact'.format(analyzer.MODULE))
                continue

            try:
                self.features.extend([f for f in analyzer.analyze(fh)
                                      if '{}.{}'.format(f.module, f.name) in desired_features])
            except NameError:
                # handle missing deps
                continue
            except ImportError:
                continue
            except OSError:
                # handle missing exiftool
                # TODO will anything else throw this? unfortunately, we need to be
                # this general because of python 2.7
                continue

    def as_search(self):
        return ' AND '.join(f.as_search() for f in self.features if f.features)

