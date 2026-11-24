"""URL extraction from invitation fields, and structural URL analysis.

Invitation bodies arrive in four shapes that all matter:

  1. plain URLs in DESCRIPTION / LOCATION / COMMENT
  2. HTML with ``<a href>`` -- the anchor text is attacker-controlled and is
     the single most reliable phishing signal we get for free
  3. vendor properties: URL, ATTACH, CONFERENCE, X-*-URL
  4. redirect wrappers and shorteners, including URLs nested inside query
     parameters

This module does not judge.  It produces normalised facts for the risk engine.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from . import domains

# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------

# TLD alternation for bare (scheme-less) hosts.  Longest first so that
# "co.uk" wins over "uk" when the engine backtracks.
_BARE_TLDS = sorted(
    {t for t in domains.SUFFIXES if "." in t}
    | {
        "com", "net", "org", "cn", "io", "co", "us", "uk", "de", "fr", "jp",
        "info", "biz", "ru", "br", "in", "au", "ca", "nl", "se", "ch", "it",
        "es", "pl", "kr", "tw", "hk", "sg", "me", "tv", "cc", "xyz", "top",
        "app", "dev", "cloud", "online", "site", "store", "tech", "live",
    },
    key=len,
    reverse=True,
)
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

# Deliberately conservative: stop at whitespace, angle brackets and quotes.
_URL_RE = re.compile(
    r"""(?ix)
    (?:
        (?:https?|ftp)://[^\s<>"'`\\]+          # explicit scheme
      | www\.[^\s<>"'`\\]+                      # bare www.
      | (?<![\w@.-])                              # not mid-token
        (?:%(label)s\.)+                          # host labels
        (?:%(tlds)s)\b                            # known TLD
        (?:/[^\s<>"'`\\]*)?                      # optional path
    )
    """ % {"label": _LABEL, "tlds": "|".join(_BARE_TLDS)}
)

_HREF_RE = re.compile(r"""(?is)<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a>""")
_ANY_URL_ATTR_RE = re.compile(
    r"""(?is)\b(?:href|src|action|data-url|data-href|formaction)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"""
)
_TAG_RE = re.compile(r"(?is)<\s*(?:br|/p|/div|/tr|/li|/h[1-6])\s*/?>")
_SCRIPT_RE = re.compile(r"(?is)<\s*(script|style)\b.*?<\s*/\s*\1\s*>")
_HTML_HINT_RE = re.compile(r"(?is)<\s*(?:html|body|div|p|a|table|center|font|span)\b")

# URL shorteners: destination unknowable at delivery time -> never auto-trust.
SHORTENERS: frozenset[str] = frozenset("""
    bit.ly bitly.com t.co tinyurl.com tiny.cc goo.gl g.co ow.ly is.gd v.gd
    buff.ly rebrand.ly cutt.ly rb.gy shorturl.at s.id lnkd.in t.ly cutt.us
    tiny.pl urlz.fr clck.ru u.to adf.ly shrtco.de 1url.com bl.ink tinu.be
    chilp.it qps.ru x.co me2.do dlvr.it ift.tt trib.al snip.ly
    su.pr tr.im twurl.nl href.li linktr.ee
""".split())

# Redirectors that carry the real destination in a query parameter.  The
# wrapper domain is trusted mail infrastructure; the payload is not.
REDIRECT_PARAM_HINTS: tuple[str, ...] = (
    "url", "u", "q", "target", "dest", "destination", "redirect", "redirect_uri",
    "redirect_url", "return", "returnurl", "continue", "next", "out", "link",
    "to", "goto", "r", "surl", "jump", "forward",
)

# Hosts whose wrapper behaviour we decode: corporate link protection and the
# well-known consumer wrappers.
KNOWN_REDIRECT_HOSTS: frozenset[str] = frozenset({
    "safelinks.protection.outlook.com",
    "nam12.safelinks.protection.outlook.com",
    "eur01.safelinks.protection.outlook.com",
    "apac01.safelinks.protection.outlook.com",
    "statics.teams.cdn.office.net",
    "outlook.office.com",
    "google.com",
    "www.google.com",
    "l.google.com",
    "l.instagram.com",
    "l.facebook.com",
    "lm.facebook.com",
})


@dataclass
class FoundUrl:
    raw: str
    normalized: str = ""
    source: str = ""            # description | location | attr | html_href | ...
    anchor_text: str = ""       # visible text for <a> tags
    context: str = ""           # surrounding prose, for evidence

    @property
    def has_scheme(self) -> bool:
        return bool(re.match(r"(?i)^[a-z][a-z0-9+.-]*:", self.raw))


@dataclass
class ParsedUrl:
    raw: str
    scheme: str = ""
    userinfo: str = ""
    host: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    error: str = ""

    @property
    def is_http(self) -> bool:
        return self.scheme in {"http", "https"}

    @property
    def registrable(self) -> str:
        return domains.registrable_domain(self.host)

    @property
    def decoded_path(self) -> str:
        return unquote(self.path or "")


def _trim(raw: str) -> str:
    """Strip trailing punctuation that prose attaches to URLs."""
    raw = raw.strip().strip("​﻿")
    while raw:
        last = raw[-1]
        if last in ".,;:!?'\"":
            raw = raw[:-1]
        elif last == ")" and raw.count("(") < raw.count(")"):
            raw = raw[:-1]
        elif last == "]" and raw.count("[") < raw.count("]"):
            raw = raw[:-1]
        elif last == "}" and raw.count("{") < raw.count("}"):
            raw = raw[:-1]
        else:
            break
    return raw


def normalize(raw: str) -> str:
    """Add a scheme when a URL was written bare, and unescape HTML entities."""
    url = html.unescape(_trim(raw))
    if url.startswith("//"):
        url = "https:" + url
    elif url and not re.match(r"(?i)^[a-z][a-z0-9+.-]*:", url):
        url = "http://" + url
    # Drop default ports so comparisons are stable.
    url = re.sub(r"(?i)^(https?)://([^/?#]+):(80|443)(?=[/?#]|$)", lambda m: (
        f"{m.group(1)}://{m.group(2)}" if (m.group(1).lower(), m.group(3)) in
        {("http", "80"), ("https", "443")} else m.group(0)), url)
    return url


def parse(raw: str) -> ParsedUrl:
    url = normalize(raw)
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        userinfo = ""
        if "@" in (parts.netloc or ""):
            userinfo = parts.netloc.rsplit("@", 1)[0]
        return ParsedUrl(
            raw=raw,
            scheme=parts.scheme.lower(),
            userinfo=userinfo,
            host=domains.clean_host(host),
            port=parts.port,
            path=parts.path or "",
            query=parts.query or "",
            fragment=parts.fragment or "",
        )
    except ValueError as exc:  # malformed port, bad IPv6, etc.
        return ParsedUrl(raw=raw, error=str(exc))


def html_to_text_and_hrefs(markup: str) -> tuple[str, list[FoundUrl]]:
    """Convert an HTML invitation body into plain text plus its anchors.

    Script/style content is dropped entirely -- it is never rendered by the
    calendar client and it is a favourite place to hide payloads from naive
    text scanners while keeping them in the raw part.
    """
    stripped = _SCRIPT_RE.sub(" ", markup)
    hrefs: list[FoundUrl] = []
    for match in _HREF_RE.finditer(stripped):
        target = match.group(1) or match.group(2) or match.group(3) or ""
        anchor = re.sub(r"(?is)<[^>]+>", " ", match.group(4) or "")
        anchor = html.unescape(re.sub(r"\s+", " ", anchor)).strip()
        hrefs.append(FoundUrl(
            raw=target.strip(),
            source="html_href",
            anchor_text=anchor,
            context="",
        ))
    # Any href-like attribute we did not already capture by the <a> matcher.
    for match in _ANY_URL_ATTR_RE.finditer(stripped):
        target = (match.group(1) or match.group(2) or match.group(3) or "").strip()
        if target and not any(h.raw == target for h in hrefs):
            hrefs.append(FoundUrl(raw=target, source="attr"))
    text = _TAG_RE.sub("\n", stripped)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t ]+", " ", text)
    return text.strip(), hrefs


def extract(text: str, *, source: str, include_html_attrs: bool = True) -> list[FoundUrl]:
    """Find every URL-like token in *text*."""
    if not text:
        return []
    found: list[FoundUrl] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text):
        raw = _trim(match.group(0))
        if len(raw) < 4:
            continue
        key = raw.lower()
        if key in seen:
            continue
        seen.add(key)
        start = max(0, match.start() - 60)
        end = min(len(text), match.end() + 60)
        found.append(FoundUrl(
            raw=raw,
            source=source,
            context=re.sub(r"\s+", " ", text[start:end]).strip(),
        ))
    return found


def collect(fields: dict[str, str]) -> list[FoundUrl]:
    """Extract URLs from a mapping of field name -> text, HTML included."""
    results: list[FoundUrl] = []
    for name, value in fields.items():
        if not value:
            continue
        if _HTML_HINT_RE.search(value):
            text, hrefs = html_to_text_and_hrefs(value)
            for item in hrefs:
                if item.raw:
                    item.source = f"{name}.html_href" if name else "html_href"
                    results.append(item)
            results.extend(extract(text, source=name))
        else:
            results.extend(extract(value, source=name))
    return results


# ---------------------------------------------------------------------------
# structural analysis
# ---------------------------------------------------------------------------

def is_shortener(host: str) -> bool:
    host = domains.clean_host(host)
    return host in SHORTENERS or domains.registrable_domain(host) in SHORTENERS


def unwrap_redirects(parsed: ParsedUrl, depth: int = 0) -> list[ParsedUrl]:
    """Follow obviously-encoded destinations inside query parameters.

    Only unwraps one level per parameter and only for well-known wrappers or
    parameters that plainly contain a URL; returns the original first so callers
    always see what the client would actually open.
    """
    chain: list[ParsedUrl] = [parsed]
    if depth >= 3 or not parsed.query:
        return chain
    host = parsed.host
    trusted_wrapper = host in KNOWN_REDIRECT_HOSTS or host.endswith(".safelinks.protection.outlook.com")
    for key, value in _query_pairs(parsed.query):
        if not value:
            continue
        candidate = unquote(value)
        looks_like_url = bool(re.match(r"(?i)^(?:https?:)?//", candidate))
        if not looks_like_url and not (trusted_wrapper and key.lower() in REDIRECT_PARAM_HINTS):
            continue
        if not looks_like_url:
            continue
        nested = parse(candidate)
        if nested.error or not nested.host:
            continue
        if nested.host == host and nested.path == parsed.path:
            continue
        chain.extend(unwrap_redirects(nested, depth + 1))
        break
    return chain


def _query_pairs(query: str):
    for chunk in (query or "").split("&"):
        if not chunk:
            continue
        key, _, value = chunk.partition("=")
        yield unquote(key), value


def anchor_mismatch(anchor_text: str, parsed: ParsedUrl) -> str | None:
    """Return a human description when visible link text contradicts the host.

    This is the highest-precision signal in HTML invitations: attackers write
    ``https://teams.microsoft.com/...`` as anchor text over a href to their own
    domain.
    """
    text = (anchor_text or "").strip()
    if not text:
        return None
    candidates = extract(text, source="anchor")
    for candidate in candidates:
        target = parse(candidate.raw)
        if target.error or not target.host:
            continue
        if domains.registrable_domain(target.host) != parsed.registrable:
            return (
                f"link text points at {domains.display_host(target.host)} "
                f"but the actual destination is {domains.display_host(parsed.host)}"
            )
    # Bare-domain anchor text without a scheme, e.g. "zoom.us" over evil host.
    bare = re.fullmatch(r"(?i)([a-z0-9.-]+\.[a-z]{2,})/?", text)
    if bare:
        claimed = domains.clean_host(bare.group(1))
        if domains.registrable_domain(claimed) != parsed.registrable:
            return (
                f"link shows {claimed!r} but the actual destination is "
                f"{domains.display_host(parsed.host)}"
            )
    return None


def userinfo_deception(parsed: ParsedUrl) -> str | None:
    """``https://teams.microsoft.com@evil.cn/`` reads as Microsoft to humans."""
    if not parsed.userinfo:
        return None
    fake = parsed.userinfo.split(":", 1)[0]
    if "." not in fake:
        return None
    fake_host = domains.clean_host(fake)
    if domains.registrable_domain(fake_host) == parsed.registrable:
        return None
    return (
        f"URL contains credentials-like prefix {fake!r} but actually connects to "
        f"{domains.display_host(parsed.host)}"
    )


_SAFE_DATA_RE = re.compile(r"(?i)^data:image/(?:png|jpe?g|gif|webp|bmp);")


def dangerous_scheme(parsed: ParsedUrl) -> str | None:
    """Classify schemes a calendar client may treat as actionable.

    ``data:`` has to be judged on its media type: an inline image is harmless
    and common in signatures, while ``data:text/html`` is a self-contained
    phishing page.
    """
    scheme = parsed.scheme.lower()
    if scheme in {"javascript", "vbscript", "ms-msdt"}:
        return f"{scheme}: URI executes script in some calendar clients"
    if scheme == "file":
        return "file: URI references a local path"
    if scheme == "data":
        if _SAFE_DATA_RE.match(parsed.raw):
            return None
        return "data: URI can embed script or a fake page"
    if scheme in {"jar", "blob", "intent"}:
        return f"unusual scheme {scheme!r}"
    return None


def ip_literal_hint(parsed: ParsedUrl) -> str | None:
    if not domains.is_ip(parsed.host):
        return None
    if domains.is_private_ip(parsed.host):
        return f"link points at a private/loopback address {parsed.host!r}"
    return f"link points at a raw IP address {parsed.host!r} instead of a hostname"


def punycode_hint(parsed: ParsedUrl) -> str | None:
    if not parsed.host:
        return None
    for label in parsed.host.split("."):
        if label.lower().startswith("xn--"):
            decoded = domains.punycode_label(label)
            return (
                f"host uses punycode {label!r} which displays as {decoded!r}"
                if decoded else f"host uses punycode label {label!r}"
            )
    return None


def tld_risky(host: str, policy) -> bool:
    """True when the host's TLD is on the high-abuse list and not whitelisted."""
    from .policy import tld_of

    tld = tld_of(host)
    if not tld:
        return False
    if tld in policy.benign_tlds:
        return False
    return tld in policy.high_risk_tlds
