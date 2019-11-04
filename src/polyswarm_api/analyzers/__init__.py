from . import base
from . import pe

DEFAULT_ANALYZERS = [pe.ImportedLibrariesAnalyzer(), pe.ImportHashAnalyzer()]
