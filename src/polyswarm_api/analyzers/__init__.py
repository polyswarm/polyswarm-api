from . import base
from . import elf
from . import pe
from . import strings

DEFAULT_ANALYZERS = [pe.ImportedLibrariesAnalyzer(), pe.ImportHashAnalyzer(),
                     strings.DomainsAnalyzer(), strings.IPV4Analyzer(),
                     elf.ImportedLibrariesAnalyzer()]
