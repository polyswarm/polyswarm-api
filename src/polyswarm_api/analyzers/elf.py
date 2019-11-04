from .base import Analyzer
from .. import utils


class ELFAnalyzer(Analyzer):
    MODULE = 'lief'

    def __init__(self):
        super(ELFAnalyzer, self).__init__()

    def is_supported(self, fh):
        fh.seek(0)
        return fh.read(4) == b'\x7fELF'

    def analyze(self, fh):
        fh.seek(0)
        elf = self._get_elf(fh.read())

        return [
            self._make_feature(*args) for args in [
                (elf.imported_functions, 'imported_functions'),
                (elf.exported_functions, 'exported_functions'),
                (elf.libraries, 'libraries')
            ]
        ]

    def _get_elf(self, file_data):
        lief = utils.try_import('lief')
        return lief.parse(bytearray(file_data))



