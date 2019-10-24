from .text import TextOutput
from .jsonl import JSONOutput
from .hashes import SHA256Output, MD5Output, SHA1Output

formatter_list = [TextOutput, JSONOutput, SHA256Output, SHA1Output, MD5Output]

formatters = {cls.name: cls for cls in formatter_list}
