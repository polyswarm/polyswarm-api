from .base import Analyzer
from .. import utils


class PEAnalyzer(Analyzer):
    MODULE = 'pefile'

    def __init__(self):
        super(PEAnalyzer, self).__init__()

    def is_supported(self, fh):
        fh.seek(0)
        return fh.read(2) == b'MZ'

    def analyze(self, fh):
        fh.seek(0)
        pe = self._get_pefile(fh.read())
        imphash = pe.get_imphash()

        imported_functions, libraries = [], []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", "ignore")
                libraries.append(dll_name)

                for imp in entry.imports:
                    if imp.name is not None:
                        imported_functions.append(imp.name.decode("utf-8", "ignore"))

        return [
            self._make_feature(*args) for args in [
                (imphash, 'imphash'),
                (libraries, 'libraries'),
                (imported_functions, 'imported_functions')
            ]
        ]

    def _get_pefile(self, file_data):
        pefile = utils.try_import('pefile')

        return pefile.PE(data=file_data)
