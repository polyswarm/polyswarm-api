from . import base
from . import elf
from . import pe
from . import strings
from . import pdf

DEFAULT_ANALYZERS = [pe.PEAnalyzer(), elf.ELFAnalyzer(),
                     strings.StringsAnalyzer(), pdf.PDFAnalyzer()]

DEFAULT_FEATURES = ['pefile.libraries', 'pefile.imphash', 'strings.domains', 'strings.ipv4', 'lief.libraries',
                    'exiftool.author', 'exiftool.language', 'exiftool.mimetype', 'exiftool.producer',
                    'exiftool.pdfversion']
