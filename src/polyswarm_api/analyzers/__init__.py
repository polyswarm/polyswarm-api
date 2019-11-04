from . import base
from . import elf
from . import pe
from . import strings
from . import pdf
from . import doc

DEFAULT_ANALYZERS = [pe.PEAnalyzer(), elf.ELFAnalyzer(),
                     strings.StringsAnalyzer(), pdf.PDFAnalyzer(), doc.DocAnalyzer()]

DEFAULT_FEATURES = ['pefile.libraries', 'pefile.imphash', 'strings.domains', 'strings.ipv4', 'lief.libraries',
                    'exiftool.author', 'exiftool.language', 'exiftool.mimetype', 'exiftool.producer',
                    'exiftool.pdfversion', 'exiftool.title', 'exiftool.company', 'exiftool.codepage',
                    'exiftool.software', 'exiftool.subject']
