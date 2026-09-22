"""Refang defanged indicators of compromise (IoCs).

Threat-intel reports print every indicator defanged — ``hxxps[:]//evil[.]com``,
``127[.]0[.]0[.]1`` — so that nobody clicks it by accident. Pasted as-is into a
search or a URL submission it never matches anything: the server looks URLs up
by an exact hash of the string and stores a submitted URL verbatim, so a
defanged value silently misses (search) or becomes a new, broken URL artifact
(submission). The server deliberately does not guess, so clients refang at their
own edge, before the request is built.

This module is the SDK's implementation of a contract other PolySwarm clients
implement too: same rules, same order, same gate, same case table
(``test/fixtures/refang_cases.json``, kept byte-identical across clients).

Portability is part of that contract, because the same pattern can match
different characters in different regex engines. So: no case-insensitive
flag (Python's folds Unicode, e.g. U+212A KELVIN SIGN matches ``k``) — letters
are spelled as explicit ``[aA]`` classes; no ``\\b``, ``\\d``, ``\\w``, ``\\s``
or ``\\S`` (their Unicode sets differ between engines) — whitespace is the
explicit ASCII set ``[ \\t\\n\\r\\f\\v]``, and trimming strips only that set;
and full matches use ``fullmatch`` (Python's ``$`` also matches before a
trailing newline).

Out of scope, everywhere: email ``[at]``, a bare-word `` dot ``, ``http__host``
and ``http:\\\\host`` variants, stripping bare brackets (they are IPv6 literal
syntax), and non-ASCII (IDN) hosts.
"""

import re

__all__ = ['is_network_ioc', 'refang_ioc', 'refang_text']

# ASCII whitespace only — see the module docstring on portability.
_WS_CHARS = ' \t\n\r\f\v'
_WS = r'[ \t\n\r\f\v]'

# Applied in order. The bracket rules run first so that ``hxxps[:]//`` has
# become ``hxxps://`` by the time the (anchored) scheme rules look for ``://``.
# ``hxxps`` is matched before ``hxxp``: the shorter rule would otherwise leave
# a stray ``s`` behind. Each scheme rule is a literal replacement — a capture
# group would carry the input's case (``HXXPS`` -> ``httpS``).
_RULES = (
    (re.compile(rf'[\[({{]{_WS}*:{_WS}*/{_WS}*/{_WS}*[\])}}]'), '://'),
    (re.compile(rf'[\[({{]{_WS}*:{_WS}*[\])}}]'), ':'),
    (re.compile(rf'[\[({{]{_WS}*/{_WS}*[\])}}]'), '/'),
    (re.compile(rf'[\[({{]{_WS}*\.{_WS}*[\])}}]'), '.'),
    (re.compile(rf'[\[({{]{_WS}*[dD][oO][tT]{_WS}*[\])}}]'), '.'),
    (re.compile(r'^[hH][xX*]{2}[pP][sS](?=://)'), 'https'),
    (re.compile(r'^[hH][xX*]{2}[pP](?=://)'), 'http'),
    (re.compile(r'^[fF][xX][pP][sS](?=://)'), 'ftps'),
    (re.compile(r'^[fF][xX][pP](?=://)'), 'ftp'),
)

_OCTET = r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
_IPV4 = rf'{_OCTET}(?:\.{_OCTET}){{3}}'
_LABEL = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
_TLD = r'(?:[a-zA-Z]{2,63}|[xX][nN]--[a-zA-Z0-9-]{1,59})'
_DOMAIN = rf'(?:{_LABEL}\.)+{_TLD}'
_IPV6 = r'\[[0-9a-fA-F:.]+\]'
_HOST = rf'(?:{_DOMAIN}|{_IPV4}|{_IPV6})'
_SCHEME = r'(?:[hH][tT][tT][pP][sS]?|[fF][tT][pP][sS]?)'
# Used with ``fullmatch`` — never ``^…$``, whose ``$`` accepts a trailing ``\n``.
_NETWORK_IOC = re.compile(
    rf'(?:{_SCHEME}://)?(?:[^ \t\n\r\f\v/?#@]+@)?{_HOST}(?::[0-9]{{1,5}})?(?:[/?#][^ \t\n\r\f\v]*)?'
)
# An optional scheme-like token (live or defanged, e.g. ``hxxps``) plus the
# host: everything before the first ``/``, ``?`` or ``#``.
_SCHEME_AND_HOST = re.compile(r'^(?:[a-zA-Z*]+://)?[^/?#]*')
_QUERY_SYNTAX = re.compile(r'[ \t\n\r\f\v"]')


def refang_text(text):
    """Apply every refang rewrite to ``text``, with no trimming and no gate.

    Ungated: it rewrites anything that contains a defang token, IoC or not.
    Callers that take user input want :func:`refang_ioc` instead.
    """
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def is_network_ioc(candidate):
    """Whether ``candidate`` is a URL, a domain, or an IP address.

    A URL may carry an http(s)/ftp(s) scheme, userinfo, a port and a path; an
    IPv6 host is accepted only in its bracketed URL form.
    """
    return bool(_NETWORK_IOC.fullmatch(candidate))


def refang_ioc(value, accept=None):
    """Return the refanged form of ``value`` if it is a defanged network IoC.

    Anything else comes back exactly as given (untrimmed), so this is safe to
    run on every IoC-shaped input. The gate, in order:

    * nothing was defanged -> unchanged;
    * the rewrite contains ASCII whitespace or a double quote -> unchanged: that is
      a query or quoted data, never a single indicator;
    * the rewrite keeps the input's scheme and host intact (with or without
      a scheme) -> unchanged: only a path, query or fragment would change,
      so a legitimate ``[.]`` in ``example.com/a[.]b`` survives;
    * the rewrite is not a URL, domain or IP -> unchanged;
    * ``accept`` (optional) rejects the rewrite -> unchanged. Callers use it
      to require their own routing to agree, e.g. "this would be searched as
      a URL".

    A refanged value is returned trimmed of ASCII whitespace.
    """
    if not isinstance(value, str):
        return value
    trimmed = value.strip(_WS_CHARS)
    candidate = refang_text(trimmed)
    if candidate == trimmed:
        return value
    if _QUERY_SYNTAX.search(candidate):
        return value
    if candidate.startswith(_SCHEME_AND_HOST.match(trimmed).group(0)):
        return value
    if not is_network_ioc(candidate):
        return value
    if accept is not None and not accept(candidate):
        return value
    return candidate
