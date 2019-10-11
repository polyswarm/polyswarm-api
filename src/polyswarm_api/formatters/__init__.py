from .text import TextFormatter
from .jsonl import JSONFormatter

formatters = {
    "text": TextFormatter,
    "json": JSONFormatter,
}