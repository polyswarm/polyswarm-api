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
(``test/fixtures/refang_cases.json``, kept byte-identical across clients). The
regexes avoid ``\\b``, ``\\d`` and ``\\w`` on purpose so every implementation
matches the same characters.

Out of scope, everywhere: email ``[at]``, a bare-word `` dot ``, ``http__host``
and ``http:\\\\host`` variants, stripping bare brackets (they are IPv6 literal
syntax), and non-ASCII (IDN) hosts.
"""

import re

__all__ = ['is_network_ioc', 'refang_ioc', 'refang_text']

# Applied in order. The bracket rules run first so that ``hxxps[:]//`` has
# become ``hxxps://`` by the time the (anchored) scheme rules look for ``://``.
# ``hxxps`` is matched before ``hxxp``: the shorter rule would otherwise leave
# a stray ``s`` behind. Each scheme rule is a literal replacement — a capture
# group would carry the input's case (``HXXPS`` -> ``httpS``).
_RULES = (
    (re.compile(r'[\[({]\s*:\s*/\s*/\s*[\])}]'), '://'),
    (re.compile(r'[\[({]\s*:\s*[\])}]'), ':'),
    (re.compile(r'[\[({]\s*/\s*[\])}]'), '/'),
    (re.compile(r'[\[({]\s*\.\s*[\])}]'), '.'),
    (re.compile(r'[\[({]\s*dot\s*[\])}]', re.IGNORECASE), '.'),
    (re.compile(r'^h[x*]{2}ps(?=://)', re.IGNORECASE), 'https'),
    (re.compile(r'^h[x*]{2}p(?=://)', re.IGNORECASE), 'http'),
    (re.compile(r'^fxps(?=://)', re.IGNORECASE), 'ftps'),
    (re.compile(r'^fxp(?=://)', re.IGNORECASE), 'ftp'),
)

_OCTET = r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
_IPV4 = rf'{_OCTET}(?:\.{_OCTET}){{3}}'
_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
_TLD = r'(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})'
_DOMAIN = rf'(?:{_LABEL}\.)+{_TLD}'
_IPV6 = r'\[[0-9a-f:.]+\]'
_HOST = rf'(?:{_DOMAIN}|{_IPV4}|{_IPV6})'
_NETWORK_IOC = re.compile(
    rf'^(?:(?:https?|ftps?)://)?(?:[^\s/?#@]+@)?{_HOST}(?::[0-9]{{1,5}})?(?:[/?#]\S*)?$',
    re.IGNORECASE,
)
_LIVE_URL_HOST = re.compile(r'^(?:https?|ftps?)://([^/?#]*)', re.IGNORECASE)
_QUERY_SYNTAX = re.compile(r'[\s"]')


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
    return bool(_NETWORK_IOC.match(candidate))


def refang_ioc(value, accept=None):
    """Return the refanged form of ``value`` if it is a defanged network IoC.

    Anything else comes back exactly as given (untrimmed), so this is safe to
    run on every IoC-shaped input. The gate, in order:

    * nothing was defanged -> unchanged;
    * the rewrite contains whitespace or a double quote -> unchanged: that is
      a query or quoted data, never a single indicator;
    * the input is already a live http(s)/ftp(s) URL whose host has no defang
      token -> unchanged, so a legitimate ``[.]`` in a path survives;
    * the rewrite is not a URL, domain or IP -> unchanged;
    * ``accept`` (optional) rejects the rewrite -> unchanged. Callers use it
      to require their own routing to agree, e.g. "this would be searched as
      a URL".

    A refanged value is returned trimmed.
    """
    if not isinstance(value, str):
        return value
    trimmed = value.strip()
    candidate = refang_text(trimmed)
    if candidate == trimmed:
        return value
    if _QUERY_SYNTAX.search(candidate):
        return value
    live = _LIVE_URL_HOST.match(trimmed)
    if live and refang_text(live.group(1)) == live.group(1):
        return value
    if not is_network_ioc(candidate):
        return value
    if accept is not None and not accept(candidate):
        return value
    return candidate
