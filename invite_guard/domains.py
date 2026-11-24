"""Domain mechanics: registrable domains, IDN, and lookalike detection.

No network calls and no third-party PSL library.  The embedded suffix list
below covers the corporate-relevant cases we need to answer one question
reliably: *which registrable domain does this host actually belong to?*  That
question decides whether ``teams.microsoft.com`` and ``zoom.us`` really are the
vendors they claim, or whether ``teams.microsoft.com.secure-join.cn`` is a
stranger wearing the brand as a subdomain.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

# Multi-label public suffixes that matter for corporate mail security.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    """
    co.uk org.uk ac.uk gov.uk me.uk net.uk sch.uk ltd.uk plc.uk
    com.cn net.cn org.cn gov.cn edu.cn ac.cn
    com.hk org.hk net.hk edu.hk gov.hk
    com.tw org.tw net.tw edu.tw gov.tw idv.tw
    com.sg org.sg net.sg edu.sg gov.sg
    com.my org.my net.my edu.my gov.my
    co.jp ne.jp or.jp ac.jp go.jp ad.jp ed.jp gr.jp lg.jp
    co.kr or.kr ne.kr re.kr go.kr ac.kr
    com.au net.au org.au edu.au gov.au asn.au id.au
    co.nz net.nz org.nz govt.nz ac.nz
    com.br net.br org.br gov.br edu.br art.br blog.br
    com.mx org.mx net.mx gob.mx edu.mx
    com.ar org.ar net.ar gob.ar edu.ar
    co.za org.za net.za gov.za ac.za
    com.tr org.tr net.tr gov.tr edu.tr
    com.sa org.sa net.sa gov.sa edu.sa
    com.ae org.ae net.ae gov.ae ac.ae
    co.in org.in net.in gen.in firm.in ind.in ac.in edu.in gov.in
    com.ph org.ph net.ph gov.ph edu.ph
    com.vn org.vn net.vn gov.vn edu.vn
    co.th or.th ac.th go.th in.th
    com.id co.id or.id web.id ac.id go.id
    com.pl net.pl org.pl gov.pl edu.pl
    com.ua net.ua org.ua gov.ua edu.ua
    co.il org.il net.il ac.il gov.il
    com.es org.es nom.es gob.es edu.es
    co.it
    com.ru net.ru org.ru
    co.at or.at ac.at gv.at
    com.pt org.pt gov.pt edu.pt
    com.gr org.gr net.gr gov.gr edu.gr
    com.co net.co org.co gov.co edu.co
    com.pe org.pe net.pe gob.pe edu.pe
    com.ve com.uy com.ec com.bo com.py com.do com.gt com.sv com.hn com.ni com.pa com.cr
    co.ke co.ug co.tz co.zw co.bw co.mz co.zm
    com.ng org.ng gov.ng edu.ng
    com.eg com.ma com.dz com.tn
    co.jp com.kw com.qa com.om com.bh com.jo com.lb com.iq com.ir
    com.pk com.bd com.lk com.np
    """.split()
)

# Hosting platforms where every tenant gets its own subdomain.  Treating these
# as suffix boundaries means ``contoso.sharepoint.com`` and ``evil-login.sharepoint.com``
# are correctly seen as two different registrable domains.
PRIVATE_SUFFIXES: frozenset[str] = frozenset(
    """
    github.io gitlab.io bitbucket.io
    herokuapp.com appspot.com azurewebsites.net cloudapp.net
    cloudapp.azure.com blob.core.windows.net web.core.windows.net
    sharepoint.com sharepoint.cn onmicrosoft.com
    googleusercontent.com firebaseapp.com web.app
    vercel.app netlify.app pages.dev workers.dev r2.dev
    trycloudflare.com ngrok.io ngrok-free.app ngrok.app
    duckdns.org hopto.org no-ip.org ddns.net myftp.org zapto.org
    s3.amazonaws.com notion.site wixsite.com blogspot.com myshopify.com
    readthedocs.io surge.sh glitch.me repl.co deno.dev fly.dev
    onrender.com railway.app up.railway.app localtunnel.me serveo.net
    lhr.life telebit.io dweb.link ipfs.dweb.link
    """.split()
)

SUFFIXES: frozenset[str] = MULTI_LABEL_SUFFIXES | PRIVATE_SUFFIXES

_WS_RE = re.compile(r"[\s​-‏‪-‮⁠﻿]+")

# Cyrillic / Greek letters that render almost identically to Latin ones.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i",
    "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "г": "r",
    "п": "n", "и": "u", "л": "n", "д": "d", "ф": "f", "ц": "u", "ч": "y",
    "ш": "w", "ь": "b", "э": "e", "ю": "io", "я": "r",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "σ": "o", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
    "μ": "u", "γ": "y", "ζ": "z",
    # Latin lookalikes and fullwidth forms
    "ı": "i", "ȷ": "j", "ℓ": "l", "ɑ": "a", "ɡ": "g", "ʟ": "l", "ᴏ": "o",
    "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "０": "0", "１": "1", "３": "3", "５": "5",
}

_LEET: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "l",
}


def clean_host(host: str) -> str:
    """Lowercase, strip brackets/ports/whitespace and normalise Unicode."""
    host = _WS_RE.sub("", host or "")
    host = host.strip("[]").strip(".")
    host = unicodedata.normalize("NFKC", host)
    # A trailing dot is a legal FQDN marker; drop it.
    return host.rstrip(".").lower()


def is_ip(host: str) -> bool:
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate.split("%")[0])
        return True
    except ValueError:
        return False


def is_private_ip(host: str) -> bool:
    candidate = host.strip("[]").split("%")[0]
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified
    ) and not ip.is_global


def registrable_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1) for *host*.

    For hosts we cannot classify (single label, raw IP, unknown IDN) the whole
    host is returned, which is the safe answer: it never merges two hosts that
    are in fact different.
    """
    host = clean_host(host)
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 1:
        return host
    for width in (3, 2):
        if len(labels) > width:
            suffix = ".".join(labels[-width:])
            if suffix in SUFFIXES:
                return ".".join(labels[-(width + 1):])
    return ".".join(labels[-2:])


def subdomain_labels(host: str) -> list[str]:
    host = clean_host(host)
    registrable = registrable_domain(host)
    if not registrable or host == registrable:
        return []
    return host[: -(len(registrable) + 1)].split(".")


def apex_label(domain: str) -> str:
    domain = clean_host(domain)
    labels = domain.split(".")
    return labels[0] if labels else ""


def punycode_label(label: str) -> str | None:
    """Decode an xn-- label; return None when it is not punycode."""
    if not label.lower().startswith("xn--"):
        return None
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return None


def display_host(host: str) -> str:
    """Human-readable host with punycode labels decoded (for logs and banners)."""
    out = []
    for label in clean_host(host).split("."):
        decoded = punycode_label(label)
        out.append(decoded if decoded else label)
    return ".".join(out)


def has_non_ascii(host: str) -> bool:
    return any(ord(c) > 127 for c in display_host(host))


def fold_confusables(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "").lower()
    return "".join(_CONFUSABLES.get(c, c) for c in text)


def _all_token_forms(tokens: set[str]) -> set[str]:
    forms: set[str] = set()
    for token in tokens:
        forms |= _brand_forms(token)
    return forms


def _brand_forms(token: str) -> set[str]:
    """Brand-token spellings, normalised *exactly like a host label*.

    Using the same ``skeleton`` on both sides is what keeps the comparison
    symmetric: ``office365`` must normalise to the same string whether it is a
    token or a label being tested against that token.
    """
    return {f for f in (skeleton(token),) if len(f) >= 3}


def skeleton(label: str) -> str:
    """Normalise a label for lookalike comparison.

    Folds homoglyphs and leetspeak and drops punctuation.  Used only to
    *compare against brand tokens*, never to decide reachability.  Deliberately
    does **not** collapse repeated characters: run-collapsing makes ``zoom``
    equal ``zom``, which both breaks self-comparison and produces false
    "homograph" hits on legitimate hosts.
    """
    folded = fold_confusables(label)
    return "".join(c for c in folded if c.isalnum())


def leet_folded(label: str) -> str:
    """Skeleton with digit/character substitutions mapped to letters.

    Kept separate from :func:`skeleton` because folding leet unconditionally
    turns legitimate digit-bearing brands (``office365``) into apparent
    look-alikes.  A leet match is only interesting when the raw label actually
    contains a substitution character.
    """
    return "".join(_LEET.get(c, c) for c in skeleton(label))


_LEET_CHARS = frozenset(_LEET)


def levenshtein(a: str, b: str, limit: int = 3) -> int:
    """Edit distance with an early exit above *limit*."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.append(value)
            best = min(best, value)
        if best > limit:
            return limit + 1
        previous = current
    return previous[-1]


@dataclass(frozen=True)
class Lookalike:
    brand: str           # brand key, e.g. "microsoft"
    kind: str            # homograph | typosquat | combosquat | brand_subdomain | brand_in_path
    detail: str
    strong: bool         # True when we are confident enough to act automatically

    @property
    def code(self) -> str:
        return f"link.lookalike.{self.kind}"


def visible_text(label: str) -> str:
    """The characters a human actually sees for one host label."""
    decoded = punycode_label(label)
    return decoded if decoded else label


def _homoglyph_edit(shown: str, brand_form: str) -> bool:
    """True when the only difference is a non-ASCII character standing in."""
    if shown.isascii():
        return False
    if len(shown) != len(brand_form):
        return False
    return sum(1 for a, b in zip(shown.lower(), brand_form) if a != b) == 1


def _suspicious_affix(label: str) -> bool:
    """Labels like ``teams-login``/``zoom-join`` are classic combosquats."""
    for word in (
        "login", "signin", "logon", "verify", "secure", "account", "update",
        "join", "meeting", "meet", "invite", "calendar", "auth", "portal",
        "support", "help", "service", "webmail", "owa", "sso", "mfa", "2fa",
        "confirm", "billing", "password", "reset", "download", "app", "cloud",
        "docs", "file", "share", "drive", "mail", "video", "call", "conference",
    ):
        if word in label:
            return True
    return False


def find_lookalikes(
    host: str,
    *,
    brand_tokens: dict[str, set[str]],
    official: "object",
    claimed: set[str] | None = None,
    path: str = "",
    always_claim: set[str] | None = None,
) -> list[Lookalike]:
    """Compare *host* against known brand tokens.

    ``claimed`` is the set of brands the invite text actually names; a brand
    that is both claimed in the text and imitated in the host is a much
    stronger signal than a coincidental string match.  ``always_claim`` forces
    strength (used for the organisation's own name).
    """
    host = clean_host(host)
    if not host or is_ip(host):
        return []
    if official.match(host):  # type: ignore[attr-defined]
        return []

    claimed = claimed or set()
    always_claim = always_claim or set()
    found: dict[tuple[str, str], Lookalike] = {}
    form_cache: dict[str, set[str]] = {}

    def _forms(tokens: set[str]) -> set[str]:
        cached = form_cache.get(id(tokens))
        if cached is None:
            cached = _all_token_forms(tokens)
            form_cache[id(tokens)] = cached
        return cached

    def add(brand: str, kind: str, detail: str, strong: bool) -> None:
        key = (brand, kind)
        previous = found.get(key)
        if previous is None or (strong and not previous.strong):
            found[key] = Lookalike(brand, kind, detail, strong)

    labels = host.split(".")
    reg = registrable_domain(host)
    reg_labels = set(reg.split(".")[:-1]) if reg else set()
    apex = apex_label(reg)

    # 1. Homoglyph / punycode in any label.
    for label in labels:
        decoded = punycode_label(label)
        visible = decoded if decoded else label
        if decoded is not None:
            folded = skeleton(visible)
            for brand, tokens in brand_tokens.items():
                if folded in {skeleton(t) for t in tokens} and folded != visible:
                    add(brand, "homograph", f"punycode label {label!r} renders as {visible!r}",
                        True)
        if has_non_ascii(visible):
            folded = skeleton(visible)
            if folded != skeleton(unicodedata.normalize("NFKD", visible).encode(
                    "ascii", "ignore").decode("ascii").lower()):
                for brand, tokens in brand_tokens.items():
                    if folded in _forms(tokens):
                        add(brand, "homograph",
                            f"label {visible!r} uses look-alike characters for {brand!r}", True)

    for label in labels:
        decoded = punycode_label(label)
        plain = skeleton(decoded if decoded else label)
        leet = leet_folded(label)
        if not plain:
            continue
        for brand, tokens in brand_tokens.items():
            is_claimed = brand in claimed or brand in always_claim
            forms = _forms(tokens)
            for tok in forms:
                if len(tok) < 3:
                    continue
                shown = visible_text(label)
                if plain == tok:
                    # Same string after normalisation.  Only a *finding* when the
                    # normalisation actually did something (a homoglyph); a
                    # directly spelled brand label is simply the brand.
                    if skeleton(shown) != shown.lower():
                        add(brand, "homograph", f"label {shown!r} normalises to {tok!r}",
                            is_claimed or brand in always_claim)
                    continue
                if leet == tok and _LEET_CHARS & set(shown):
                    add(brand, "homograph",
                        f"label {shown!r} substitutes characters for {tok!r}",
                        is_claimed or brand in always_claim)
                    continue
                elif len(tok) >= 6 and levenshtein(plain, tok, 1) == 1:
                    kind = "homograph" if _homoglyph_edit(shown, tok) else "typosquat"
                    add(brand, kind, f"label {shown!r} is one character from {tok!r}",
                        is_claimed)
                elif len(tok) >= 9 and levenshtein(plain, tok, 2) == 2:
                    add(brand, "typosquat", f"label {shown!r} is close to {tok!r}", is_claimed)
                elif tok in plain and plain != tok:
                    if _suspicious_affix(plain) or "-" in label:
                        add(brand, "combosquat", f"label {label!r} embeds {tok!r}",
                            is_claimed)
                elif len(tok) >= 6 and tok in leet and leet != tok:
                    # Leet-speak combo: "micros0ft-login".
                    if _suspicious_affix(leet) or "-" in label:
                        add(brand, "combosquat",
                            f"label {label!r} embeds {tok!r} with substituted characters",
                            is_claimed)

    # 2. Brand present as a subdomain while the real domain is somebody else's.
    for label in subdomain_labels(host):
        plain = skeleton(visible_text(label))
        for brand, tokens in brand_tokens.items():
            if plain in _forms(tokens):
                add(brand, "brand_subdomain",
                    f"{brand!r} appears as a subdomain of {reg!r}", True)

    # 3. Brand only in the path (e.g. /microsoft/login).
    if path:
        segments = [s for s in re.split(r"[/?&#=_]+", path) if s]
        for segment in segments:
            plain = skeleton(segment)
            for brand, tokens in brand_tokens.items():
                forms = _forms(tokens)
                if plain in forms or any(levenshtein(plain, f, 1) == 0 for f in forms if len(f) >= 6):
                    add(brand, "brand_in_path",
                        f"{brand!r} appears in the URL path of {reg!r}",
                        brand in claimed or brand in always_claim)

    return sorted(found.values(), key=lambda l: (not l.strong, l.kind))
