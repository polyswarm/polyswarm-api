from .base import BaseAnalyzer
from .. import utils

class PEAnalyzer(BaseAnalyzer):
    MODULE = 'pefile'
    CACHE = {}

    def __init__(self):
        super(PEAnalyzer, self).__init__()

    def is_supported(self, fh):
        fh.seek(0)
        return fh.read(2) == b'MZ'

    def analyze(self, fh):
        raise NotImplementedError

    def _get_pefile(self, file_data):
        # we do this to avoid storing the actual content as a key
        h = hash(file_data)
        if h in self.CACHE:
            return self.CACHE[h]

        pefile = utils.try_import('pefile')

        self.CACHE[h] = pefile.PE(data=file_data)
        return self.CACHE[h]


class ImportedFunctionAnalyzer(PEAnalyzer):
    NAME = 'imported_functions'

    def analyze(self, fh):
        fh.seek(0)
        pe = self._get_pefile(fh.read())
        imported_functions = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is not None:
                        imported_functions.append(imp.name.decode("utf-8", "ignore"))
        return self._make_analysis_object(imported_functions)


class ImportedLibrariesAnalyzer(PEAnalyzer):
    NAME = 'libraries'

    def analyze(self, fh):
        fh.seek(0)
        pe = self._get_pefile(fh.read())
        libraries = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", "ignore")
                libraries.append(dll_name)
        return self._make_analysis_object(libraries)


class ImportHashAnalyzer(PEAnalyzer):
    NAME = 'imphash'

    def analyze(self, fh):
        # unfortunately, pefile module requires either file data or file path
        # as the least-worst option, we do not write the Artifact to disk and make sure
        # it's loaded into memory
        fh.seek(0)
        pe = self._get_pefile(fh.read())
        return self._make_analysis_object(pe.get_imphash())

