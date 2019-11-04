from .base import BaseAnalyzer
from .. import utils


class ELFAnalyzer(BaseAnalyzer):
    MODULE = 'lief'
    CACHE = {}

    def __init__(self):
        super(ELFAnalyzer, self).__init__()

    def is_supported(self, fh):
        fh.seek(0)
        return fh.read(4) == b'\x7fELF'

    def analyze(self, fh):
        raise NotImplementedError

    def _get_elf(self, file_data):
        # we do this to avoid storing the actual content as a key
        h = hash(file_data)
        if h in self.CACHE:
            return self.CACHE[h]

        lief = utils.try_import('lief')

        self.CACHE[h] = lief.parse(bytearray(file_data))
        return self.CACHE[h]


class ImportedFunctionAnalyzer(ELFAnalyzer):
    NAME = 'imported_functions'

    def analyze(self, fh):
        fh.seek(0)
        elf = self._get_elf(fh.read())
        return self._make_analysis_object(elf.imported_functions)


class ExportedFunctionAnalyzer(ELFAnalyzer):
    NAME = 'exported_functions'

    def analyze(self, fh):
        fh.seek(0)
        elf = self._get_elf(fh.read())
        return self._make_analysis_object(elf.exported_functions)


class ImportedLibrariesAnalyzer(ELFAnalyzer):
    NAME = 'libraries'

    def analyze(self, fh):
        fh.seek(0)
        elf = self._get_elf(fh.read())
        return self._make_analysis_object(elf.libraries)



