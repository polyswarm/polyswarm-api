from . import base
from . import elf
from . import pe
from . import strings

DEFAULT_ANALYZERS = [pe.PEAnalyzer(), elf.ELFAnalyzer(),
                     strings.StringsAnalyzer()]

DEFAULT_FEATURES = ['pefile.libraries', 'pefile.imphash', 'strings.domains', 'strings.ipv4', 'lief.libraries']
