"""Signals, scoring, and the final disposition.

Design rules that make this usable rather than a nuisance:

1. **Hard signals decide alone.**  A look-alike domain, a javascript: link, or
   a link whose anchor text lies about its destination is enough to hold the
   invite no matter how many benign features are present.
2. **Soft signals accumulate.**  An unknown external organiser is not evidence
   of anything; it is one point among many.
3. **Known customers get slack, not immunity.**  A domain the organisation has
   approved repeatedly raises the threshold for soft holds but never suppresses
   a hard signal.
4. **Every decision is explainable.**  Each signal carries a code, a weight and
   a human sentence, so a held meeting can be reviewed in seconds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum

from . import domains, urls
from .auth import AuthResult, header_from_mismatch
from .model import Invite, ParsedCalendar
from .policy import Policy, Vendor
from .trust import TrustStore, UidRecord


class Disposition(IntEnum):
    """How the invite is handled after screening.

    ALLOW      content is clean; deliver unchanged
    PENDING    plausible but unverified external meeting; deliver *degraded*,
               marked TENTATIVE / needs-confirmation, with reminders and
               unverified links disabled
    QUARANTINE a hard impersonation signal is present; do not put it on anyone's
               calendar, route it to the security review queue with a warning
    REJECT     a confirmed hostile payload (e.g. executable attachment) or a
               DMARC-failing impersonation; drop entirely
    """
    ALLOW = 0
    PENDING = 1
    QUARANTINE = 2
    REJECT = 3


SEVERITY_BY_DISPOSITION = {
    Disposition.ALLOW: "info",
    Disposition.PENDING: "warning",
    Disposition.QUARANTINE: "serious",
    Disposition.REJECT: "critical",
}


@dataclass
class Signal:
    code: str
    weight: int
    detail: str
    hard: bool = False
    category: str = "content"

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "weight": self.weight,
            "detail": self.detail,
            "hard": self.hard,
            "category": self.category,
        }


@dataclass
class LinkVerdict:
    raw: str
    source: str
    host: str = ""
    registrable: str = ""
    displayed: str = ""
    trusted_vendor: str = ""
    shortener: bool = False
    signals: list[Signal] = field(default_factory=list)
    anchor_text: str = ""

    @property
    def trusted(self) -> bool:
        return bool(self.trusted_vendor) and not any(s.hard for s in self.signals)

    @property
    def risk(self) -> int:
        return sum(s.weight for s in self.signals)

    @property
    def is_hard(self) -> bool:
        return any(s.hard for s in self.signals)

    def as_dict(self) -> dict:
        return {
            "raw": self.raw,
            "source": self.source,
            "host": self.host,
            "registrable": self.registrable,
            "displayed": self.displayed,
            "trusted_vendor": self.trusted_vendor,
            "shortener": self.shortener,
            "anchor_text": self.anchor_text,
            "risk": self.risk,
            "signals": [s.as_dict() for s in self.signals],
        }


@dataclass
class Assessment:
    disposition: Disposition
    score: int = 0
    signals: list[Signal] = field(default_factory=list)
    links: list[LinkVerdict] = field(default_factory=list)
    summary: str = ""
    reasons: list[str] = field(default_factory=list)
    claimed_vendors: list[str] = field(default_factory=list)
    trusted_vendors: list[str] = field(default_factory=list)
    sender_domain: str = ""
    organizer_domain: str = ""
    uid_known: bool = False
    known_customer: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return SEVERITY_BY_DISPOSITION[self.disposition]

    @property
    def hard_signals(self) -> list[Signal]:
        return [s for s in self.signals if s.hard]

    @property
    def status(self) -> str:
        """The value written into the calendar as ``X-INVITE-GUARD-STATUS``."""
        return {
            Disposition.ALLOW: "CONFIRMED",
            Disposition.PENDING: "PENDING-CONFIRMATION",
            Disposition.QUARANTINE: "HELD-FOR-REVIEW",
            Disposition.REJECT: "BLOCKED",
        }[self.disposition]

    def as_dict(self) -> dict:
        return {
            "disposition": self.disposition.name.lower(),
            "status": self.status,
            "severity": self.severity,
            "score": self.score,
            "summary": self.summary,
            "reasons": self.reasons,
            "signals": [s.as_dict() for s in self.signals],
            "links": [l.as_dict() for l in self.links],
            "claimed_vendors": self.claimed_vendors,
            "trusted_vendors": self.trusted_vendors,
            "sender_domain": self.sender_domain,
            "organizer_domain": self.organizer_domain,
            "uid_known": self.uid_known,
            "known_customer": self.known_customer,
            "notes": self.notes,
        }


@dataclass
class MailContext:
    """Everything the MTA/MDA knows that the calendar body does not."""

    from_address: str = ""
    from_display_name: str = ""
    return_path: str = ""
    reply_to: str = ""
    sender: str = ""
    subject: str = ""
    auth: AuthResult = field(default_factory=AuthResult)
    declared_method: str = ""      # from Content-Type: method=...
    content_type_mismatch: bool = False
    recipient_domains: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# weights
# ---------------------------------------------------------------------------

HARD_WEIGHT = 100

WEIGHTS = {
    "link.lookalike.homograph": HARD_WEIGHT,
    "link.lookalike.typosquat": HARD_WEIGHT,
    "link.lookalike.combosquat": HARD_WEIGHT,
    "link.lookalike.brand_subdomain": HARD_WEIGHT,
    "link.lookalike.brand_in_path": 40,
    "link.anchor_mismatch": HARD_WEIGHT,
    "link.userinfo_deception": HARD_WEIGHT,
    "link.dangerous_scheme": HARD_WEIGHT,
    "link.malformed": 15,
    "link.ip_literal": 35,
    "link.punycode": 45,
    "link.shortener": 45,
    "link.high_risk_tld": 20,
    "link.credential_lookalike": 30,
    "link.no_https": 8,
    "link.mismatched_vendor": 45,
    "link.brand_impersonation_in_copy": 35,
    "link.hidden_script_redirect": HARD_WEIGHT,
    "link.vendor_host_in_prose": 10,
    "link.many_suspicious_hosts": 30,
    "link.unverified_external": 18,
    "mail.dmarc_fail": HARD_WEIGHT,
    "mail.dkim_domain_mismatch": 25,
    "mail.reply_to_mismatch": 20,
    "mail.envelope_mismatch": 25,
    "mail.sender_header_mismatch": 25,
    "mail.unauthenticated": 15,
    "mail.from_name_claims_brand": 30,
    "org.external_organizer": 10,
    "org.unknown_organizer": 8,
    "org.free_mail_organizer": 25,
    "org.disposable_organizer": HARD_WEIGHT,
    "org.lookalike_organizer": HARD_WEIGHT,
    "org.internal_claim_spoofed": HARD_WEIGHT,
    "org.sent_by_mismatch": 30,
    "org.organizer_sender_mismatch": 20,
    "invite.method_mismatch": 30,
    "invite.uid_reused": HARD_WEIGHT,
    "invite.sequence_regression": 40,
    "invite.cancel_no_history": 35,
    "invite.unsolicited_cancel": 30,
    "invite.high_risk_attachment": HARD_WEIGHT,
    "invite.attachment_type_spoof": HARD_WEIGHT,
    "invite.attachment_external_uri": 30,
    "invite.alarm_with_link": 25,
    "invite.alarm_attach": 55,
    "invite.bulk_invites": 15,
    "invite.no_organizer": 20,
    "invite.recurring_seed": 10,
    "invite.description_link_no_vendor_prop": 25,
    "invite.vendor_brand_in_copy_only": 20,
    "invite.phone_conference_confusion": 20,
    "invite.obfuscated_text": 20,
    "invite.single_invite_multi_vendor": 20,
}

# Words that turn a benign redirect into a credential lure.
CREDENTIAL_WORDS = (
    "login", "signin", "sign-in", "logon", "password", "passwd", "verify",
    "verification", "authenticate", "auth", "sso", "mfa", "2fa", "otp",
    "unlock", "identity", "session", "token", "reset", "onmicrosoft",
    "webmail", "owa",
)

_INVISIBLE_RE = re.compile(r"[​-‏‪-‮⁠-⁤﻿­]")

# Thresholds.  A hard signal bypasses them entirely.
THRESHOLD_PENDING = 40
THRESHOLD_QUARANTINE = 70
THRESHOLD_REJECT = 140

# Known-customer domains get this much slack before a *soft* hold.
KNOWN_CUSTOMER_SLACK = 20


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# Properties that hold structured data rather than a link, even though they sit
# in VENDOR_URL_PROPS (used for their presence, not their value).
_STRUCTURED_PROPS = {
    "X-MICROSOFT-SKYPETEAMSPROPERTIES",
    "X-MOZ-GENERATION",
    "X-MICROSOFT-SKYPETEAMSMEETINGURL",  # still scanned, but see below
}

# Schemes a calendar client can actually be tricked into opening.
_WEB_SCHEMES = {"http", "https", "ftp"}


def _is_web_link(parsed: urls.ParsedUrl) -> bool:
    """Only web-scheme URLs are evaluated as clickable links.

    ``geo:`` (Apple's structured location), ``tel:``, ``mailto:``, ``urn:`` and
    JSON blobs are not join links, and scoring them produces noise that erodes
    trust in the warning banner.
    """
    if parsed.error:
        return bool(parsed.raw) and "://" in parsed.raw
    return parsed.scheme in _WEB_SCHEMES


def _credential_lure(parsed: urls.ParsedUrl) -> str | None:
    haystack = " ".join([
        parsed.host, parsed.decoded_path, urls.unquote(parsed.query), parsed.fragment,
    ]).lower()
    for word in CREDENTIAL_WORDS:
        if re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", haystack):
            return word
    return None


def _mentioned_brands(text: str, policy: Policy) -> set[str]:
    lowered = (text or "").lower()
    found: set[str] = set()
    for brand, tokens in policy.brand_tokens.items():
        if any(len(t) >= 3 and t in lowered for t in tokens):
            found.add(brand)
    return found


class _OfficialMatcher:
    """Adapter so domains.find_lookalikes can ask 'is this host official?'."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def match(self, host: str) -> bool:
        if self.policy.org.is_internal_domain(host, registrable_domain=domains.registrable_domain):
            return True
        return self.policy.vendor_for_host(host, registrable_domain=domains.registrable_domain) is not None


def _brand_in_anchor(anchor: str, policy: Policy, parsed: urls.ParsedUrl) -> str | None:
    anchor_lower = anchor.lower()
    reg = domains.registrable_domain(parsed.host)
    for brand, tokens in policy.brand_tokens.items():
        for token in tokens:
            if len(token) >= 4 and token in anchor_lower:
                vendor = policy.vendor_by_key(brand)
                if vendor is not None and reg in vendor.domains:
                    continue
                if policy.org.is_internal_domain(parsed.host, registrable_domain=domains.registrable_domain):
                    continue
                return f"link text names {token!r} but links to {parsed.host!r}"
    return None


def _worst_in_chain(chain: list[urls.ParsedUrl], policy: Policy) -> urls.ParsedUrl:
    """Wrapper URLs hide the real destination; judge the payload, not the wrapper."""
    effective = chain[0]
    for candidate in chain[1:]:
        if not candidate.host or candidate.host == effective.host:
            continue
        if policy.vendor_for_host(candidate.host, registrable_domain=domains.registrable_domain):
            continue
        official = _OfficialMatcher(policy)
        bad = bool(domains.find_lookalikes(
            candidate.host,
            brand_tokens=policy.brand_tokens,
            official=official,
            path=candidate.decoded_path,
        )) or urls.tld_risky(candidate.host, policy)
        if bad:
            effective = candidate
    return effective


# ---------------------------------------------------------------------------
# link analysis
# ---------------------------------------------------------------------------

def analyze_link(found: urls.FoundUrl, *, policy: Policy, prose: str) -> LinkVerdict:
    parsed = urls.parse(found.raw)
    verdict = LinkVerdict(
        raw=found.raw,
        source=found.source,
        host=parsed.host,
        registrable=parsed.registrable,
        displayed=domains.display_host(parsed.host) if parsed.host else "",
        anchor_text=found.anchor_text,
    )
    if not _is_web_link(parsed):
        return verdict
    if parsed.error:
        verdict.signals.append(Signal("link.malformed", WEIGHTS["link.malformed"],
                                      f"URL could not be parsed: {parsed.error}"))
        return verdict

    effective = _worst_in_chain(urls.unwrap_redirects(parsed), policy)
    if effective is not parsed:
        verdict.host = effective.host
        verdict.registrable = effective.registrable
        verdict.displayed = domains.display_host(effective.host)
    if not effective.host:
        verdict.signals.append(Signal("link.malformed", WEIGHTS["link.malformed"], "URL has no host"))
        return verdict

    if found.source.endswith("X-HIDDEN-SCRIPT") or "X-HIDDEN-SCRIPT" in found.source:
        verdict.signals.append(Signal(
            "link.hidden_script_redirect", WEIGHTS["link.hidden_script_redirect"],
            f"an embedded <script> redirects to {effective.host!r}; the visible text does "
            "not show this destination", hard=True,
        ))
    verdict.shortener = urls.is_shortener(effective.host)
    official = _OfficialMatcher(policy)
    is_official = official.match(effective.host)
    claimed = _mentioned_brands(prose, policy)

    # --- structural deceptions (work even on "official-looking" strings) ---
    scheme_reason = urls.dangerous_scheme(parsed)
    if scheme_reason:
        verdict.signals.append(Signal("link.dangerous_scheme", WEIGHTS["link.dangerous_scheme"],
                                      scheme_reason, hard=True))
    userinfo_reason = urls.userinfo_deception(parsed)
    if userinfo_reason:
        verdict.signals.append(Signal("link.userinfo_deception", WEIGHTS["link.userinfo_deception"],
                                      userinfo_reason, hard=True))
    if found.anchor_text:
        mismatch = urls.anchor_mismatch(found.anchor_text, effective)
        if mismatch:
            verdict.signals.append(Signal("link.anchor_mismatch", WEIGHTS["link.anchor_mismatch"],
                                          mismatch, hard=True))

    # --- host properties ---
    ip_reason = urls.ip_literal_hint(effective)
    if ip_reason:
        verdict.signals.append(Signal("link.ip_literal", WEIGHTS["link.ip_literal"], ip_reason))
    puny_reason = urls.punycode_hint(effective)
    if puny_reason:
        verdict.signals.append(Signal("link.punycode", WEIGHTS["link.punycode"], puny_reason))
    if effective.scheme == "http" and not urls.is_shortener(effective.host):
        verdict.signals.append(Signal("link.no_https", WEIGHTS["link.no_https"],
                                      "link is plain http:// and can be altered in transit"))
    if urls.tld_risky(effective.host, policy):
        verdict.signals.append(Signal("link.high_risk_tld", WEIGHTS["link.high_risk_tld"],
                                      f"host {effective.host!r} uses a high-abuse TLD"))
    if verdict.shortener:
        verdict.signals.append(Signal("link.shortener", WEIGHTS["link.shortener"],
                                      f"link goes through URL shortener {effective.host!r}; the "
                                      "real destination is hidden until clicked"))

    # --- brand imitation ---
    # Group by kind so one host imitating three brands is one finding, not three.
    grouped: dict[str, list[domains.Lookalike]] = {}
    for item in domains.find_lookalikes(
        effective.host,
        brand_tokens=policy.brand_tokens,
        official=official,
        claimed=claimed | set(policy.org.own_brands),
        path=effective.decoded_path,
        always_claim=set(policy.org.own_brands),
    ):
        grouped.setdefault(item.code, []).append(item)
    for code, items in grouped.items():
        strong = any(
            i.strong or i.brand in claimed or i.brand in policy.org.own_brands for i in items
        )
        hard = code != "link.lookalike.brand_in_path" and strong
        brand_list = ", ".join(sorted({i.brand for i in items}))
        detail = items[0].detail
        if len(items) > 1:
            detail = f"host {effective.host!r} imitates {brand_list} ({items[0].kind})"
        verdict.signals.append(Signal(code, WEIGHTS.get(code, 30), detail, hard=hard))

    if not is_official:
        credential = _credential_lure(effective)
        if credential:
            verdict.signals.append(Signal(
                "link.credential_lookalike", WEIGHTS["link.credential_lookalike"],
                f"URL looks like a login/password-capture page (matched {credential!r}) "
                f"yet is hosted on {effective.host!r}",
            ))
        mention = _vendor_mention_mismatch(effective, prose, policy)
        if mention:
            verdict.signals.append(mention)

    if found.anchor_text and not is_official:
        misdescribed = _brand_in_anchor(found.anchor_text, policy, effective)
        if misdescribed:
            verdict.signals.append(Signal("link.brand_impersonation_in_copy",
                                          WEIGHTS["link.brand_impersonation_in_copy"], misdescribed))

    # A link that is neither internal nor a recognised vendor is, by definition,
    # unverifiable.  It should count for something even when it looks bland --
    # otherwise a throwaway domain with descriptive anchor text sails through.
    is_internal = policy.org.is_internal_domain(
        effective.host, registrable_domain=domains.registrable_domain)
    is_vendor = policy.vendor_for_host(
        effective.host, registrable_domain=domains.registrable_domain) is not None
    clickable = bool(effective.host) and (
        found.source.endswith("html_href") or found.source.startswith("prop:"))
    if (clickable and not is_internal and not is_vendor and not verdict.shortener
            and not any(s.hard for s in verdict.signals)):
        verdict.signals.append(Signal(
            "link.unverified_external", WEIGHTS["link.unverified_external"],
            f"link points at {effective.host!r}, which is neither an internal host "
            "nor a recognised conferencing vendor; it cannot be verified",
        ))

    vendor = policy.vendor_for_host(effective.host, registrable_domain=domains.registrable_domain)
    if vendor is not None and not any(s.hard for s in verdict.signals):
        if _source_is_authoritative(found.source):
            verdict.trusted_vendor = vendor.key
        else:
            # A vendor-owned URL that only exists as visible *prose* is exactly
            # what an attacker types as anchor text.  It is not evidence of a
            # real meeting, so it must not earn the verified-link treatment.
            verdict.signals.append(Signal(
                "link.vendor_host_in_prose", 10,
                f"a {vendor.display} address appears in free text but the invite "
                "has no structured conferencing property pointing at it",
            ))
    return verdict


def _source_is_authoritative(source: str) -> bool:
    """Trust a link only when it came from a structured property or a real href.

    Plain-text occurrences are attacker-typed strings, not evidence.
    """
    source = source or ""
    if source.startswith("prop:"):
        return True
    if source.endswith("html_href"):
        return True
    return False


def _vendor_mention_mismatch(parsed: urls.ParsedUrl, prose: str, policy: Policy) -> Signal | None:
    for candidate in policy.vendor_mentioned(prose):
        if _host_claims_vendor(parsed, candidate) and not candidate.owns(
            parsed.host, registrable_domain=domains.registrable_domain
        ):
            return Signal(
                "link.mismatched_vendor", WEIGHTS["link.mismatched_vendor"],
                f"invite describes a {candidate.display} meeting but the link is at "
                f"{parsed.host!r}, which {candidate.display} does not control",
            )
    return None


def _host_claims_vendor(parsed: urls.ParsedUrl, vendor: Vendor) -> bool:
    haystack = f"{parsed.host} {parsed.decoded_path}".lower()
    return any(token in haystack for token in vendor.tokens if len(token) >= 4)


# ---------------------------------------------------------------------------
# invite-level signals
# ---------------------------------------------------------------------------

def _organizer_signal(invite: Invite, mail: MailContext, policy: Policy,
                      store: TrustStore) -> list[Signal]:
    signals: list[Signal] = []
    org_domain = _domain_of(invite.organizer_email)
    if not org_domain:
        return [Signal("invite.no_organizer", WEIGHTS["invite.no_organizer"],
                       "invitation has no ORGANIZER property")]
    rd = domains.registrable_domain

    if policy.org.is_internal_domain(org_domain, registrable_domain=rd):
        # Organizer claims to be one of ours.  Is it actually from our mail system?
        sender_reg = rd(_domain_of(mail.from_address)) if mail.from_address else ""
        if not mail.from_address or not policy.org.is_internal_domain(mail.from_address,
                                                                      registrable_domain=rd):
            signals.append(Signal(
                "org.internal_claim_spoofed", WEIGHTS["org.internal_claim_spoofed"],
                f"ORGANIZER claims internal address {invite.organizer_email!r} but the "
                f"message was sent from {mail.from_address or 'an unknown sender'!r}",
                hard=True, category="identity",
            ))
        return signals

    # External organiser.
    if org_domain in policy.free_mail_domains or rd(org_domain) in policy.free_mail_domains:
        signals.append(Signal("org.free_mail_organizer", WEIGHTS["org.free_mail_organizer"],
                              f"organiser uses a free consumer mailbox ({org_domain!r})",
                              category="identity"))
    if rd(org_domain) in policy.disposable_suffixes:
        signals.append(Signal("org.disposable_organizer", WEIGHTS["org.disposable_organizer"],
                              f"organiser domain {org_domain!r} is a disposable-mail provider",
                              hard=True, category="identity"))

    # Compare the organiser domain against vendor/org brands only.  A person's
    # display name is not a brand and must not raise the strength of a match.
    lookalikes = domains.find_lookalikes(
        org_domain, brand_tokens=policy.brand_tokens, official=_OfficialMatcher(policy),
        claimed=set(),
        always_claim=set(policy.org.own_brands),
    )
    for item in lookalikes:
        if item.strong or item.kind in {"typosquat", "homograph", "combosquat"}:
            signals.append(Signal("org.lookalike_organizer",
                                  WEIGHTS["org.lookalike_organizer"], item.detail,
                                  hard=True, category="identity"))

    if invite.organizer_sent_by:
        sent_by_domain = _domain_of(invite.organizer_sent_by)
        if rd(sent_by_domain) != rd(org_domain):
            signals.append(Signal("org.sent_by_mismatch", WEIGHTS["org.sent_by_mismatch"],
                                  f"ORGANIZER SENT-BY is {sent_by_domain!r} but organizer is "
                                  f"{org_domain!r}", category="identity"))

    sender_domain = _domain_of(mail.from_address)
    if sender_domain and rd(sender_domain) != rd(org_domain):
        # Very common for real invites (calendar bridges), so this is only a
        # signal when mail auth is also weak; scored accordingly.
        if mail.auth.weak or mail.auth.dmarc_failed:
            signals.append(Signal(
                "org.organizer_sender_mismatch", WEIGHTS["org.organizer_sender_mismatch"],
                f"ORGANIZER is {org_domain!r} but the message came from {sender_domain!r} "
                "with no strong authentication", category="identity",
            ))

    rep = store.domain(rd(org_domain))
    if rep is not None and rep.is_bad:
        signals.append(Signal("org.unknown_organizer", WEIGHTS["org.unknown_organizer"],
                              f"{org_domain!r} has previously produced blocked invitations",
                              category="identity"))
    elif rep is None or rep.invites == 0:
        signals.append(Signal("org.unknown_organizer", WEIGHTS["org.unknown_organizer"],
                              f"first invitation from external organiser {org_domain!r}",
                              category="identity"))
    return signals


def _domain_of(address: str) -> str:
    address = (address or "").strip().lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def _attachment_signals(invite: Invite) -> list[Signal]:
    signals: list[Signal] = []
    for attachment in invite.attachments:
        name = (attachment.filename or "").strip()
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if attachment.error and "declared as" in attachment.error:
            signals.append(Signal("invite.attachment_type_spoof",
                                  WEIGHTS["invite.attachment_type_spoof"],
                                  f"attachment {name or '(unnamed)'}: {attachment.error}", hard=True))
        if ext in {"exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js",
                   "jse", "wsf", "wsh", "ps1", "msi", "cpl", "hta", "jar", "lnk",
                   "url", "reg", "iso", "img", "vhd", "dmg", "apk", "xll"}:
            signals.append(Signal("invite.high_risk_attachment",
                                  WEIGHTS["invite.high_risk_attachment"],
                                  f"invitation carries executable attachment {name!r}", hard=True))
        elif ext in {"html", "htm", "xhtml", "svg", "xsl", "xslt"}:
            signals.append(Signal("invite.high_risk_attachment",
                                  WEIGHTS["invite.high_risk_attachment"],
                                  f"invitation carries renderable-markup attachment {name!r} "
                                  "(often a credential-harvest page)", hard=True))
        elif attachment.value_type == "URI" and attachment.uri and not attachment.uri.lower().startswith("cid:"):
            target = urls.parse(attachment.uri)
            if target.host:
                signals.append(Signal("invite.attachment_external_uri",
                                      WEIGHTS["invite.attachment_external_uri"],
                                      f"attachment {name or '(unnamed)'} is a remote URL "
                                      f"({target.host!r}) rather than attached content"))
    return signals


def _alarm_signals(invite: Invite) -> list[Signal]:
    signals: list[Signal] = []
    for alarm in invite.alarms:
        blob = " ".join(str(v or "") for v in alarm.values())
        if alarm.get("attach"):
            signals.append(Signal("invite.alarm_attach", WEIGHTS["invite.alarm_attach"],
                                  "VALARM carries an ATTACH property (fires at reminder time)"))
        elif urls.extract(blob, source="alarm"):
            signals.append(Signal("invite.alarm_with_link", WEIGHTS["invite.alarm_with_link"],
                                  "VALARM reminder text contains a link"))
    return signals


def _history_signals(invite: Invite, store: TrustStore, policy: Policy) -> tuple[list[Signal], UidRecord | None]:
    signals: list[Signal] = []
    previous = store.uid(invite.uid)
    if previous is None:
        if invite.method == "CANCEL" or invite.status == "CANCELLED":
            signals.append(Signal("invite.cancel_no_history",
                                  WEIGHTS["invite.cancel_no_history"],
                                  "cancel/decline for a meeting UID this organisation has never seen",
                                  category="history"))
        return signals, None

    rd = domains.registrable_domain
    if previous.organizer and invite.organizer_email:
        if rd(_domain_of(previous.organizer)) != rd(_domain_of(invite.organizer_email)):
            signals.append(Signal(
                "invite.uid_reused", WEIGHTS["invite.uid_reused"],
                f"UID {invite.uid!r} was previously owned by "
                f"{previous.organizer!r} but now claims {invite.organizer_email!r}",
                hard=True, category="history",
            ))

    if previous.sequence is not None and invite.sequence is not None:
        if invite.sequence < previous.sequence:
            signals.append(Signal(
                "invite.sequence_regression", WEIGHTS["invite.sequence_regression"],
                f"SEQUENCE went backwards ({previous.sequence} -> {invite.sequence}) for "
                "an existing meeting; clients may ignore or mis-apply it",
                category="history",
            ))
    return signals, previous


def _content_signals(invite: Invite, verdicts: list[LinkVerdict], policy: Policy) -> list[Signal]:
    signals: list[Signal] = []
    prose = invite.prose()

    invisible = _INVISIBLE_RE.findall(prose)
    if invisible:
        signals.append(Signal("invite.obfuscated_text", WEIGHTS["invite.obfuscated_text"],
                              f"description contains {len(invisible)} invisible/formatting "
                              "control characters used to hide text from scanners"))

    # A clickable link in prose while the structured vendor properties are absent
    # is the signature of a hand-crafted fake meet-up.
    has_vendor_prop = any(slot.is_vendor_prop and slot.value for slot in invite.links)
    prose_links = [v for v in verdicts if v.source in {"description", "location", "summary",
                                                       "prop:X-ALT-DESC"}]
    if prose_links and not has_vendor_prop:
        risky = [v for v in prose_links if v.host and not v.trusted_vendor]
        if risky:
            signals.append(Signal(
                "invite.description_link_no_vendor_prop",
                WEIGHTS["invite.description_link_no_vendor_prop"],
                "join link appears only in free text; the invite carries no machine-readable "
                "conferencing property, so the link cannot be verified against a vendor",
            ))

    # "Dial-in" numbers that are actually links, or links labelled as phone numbers.
    if re.search(r"(?i)(?:tel|phone|dial[- ]?in|call[- ]?in|音频|电话)", prose):
        untrusted = [v for v in verdicts if v.host and not v.trusted_vendor and v.risk >= 20]
        if untrusted:
            signals.append(Signal(
                "invite.phone_conference_confusion", WEIGHTS["invite.phone_conference_confusion"],
                "invite mentions dial-in numbers while also carrying unverified links; users "
                "may click the wrong entry",
            ))

    # Multiple different vendors in one invite is a common lure.
    claimed = {c.key for c in policy.vendor_mentioned(prose)}
    if len(claimed) > 1:
        signals.append(Signal("invite.single_invite_multi_vendor",
                              WEIGHTS["invite.single_invite_multi_vendor"],
                              f"invite names several conferencing vendors "
                              f"({', '.join(sorted(claimed))}); genuine invites use one"))
    return signals


def _vendor_claim_signals(invite: Invite, verdicts: list[LinkVerdict], policy: Policy
                          ) -> tuple[list[Signal], list[str], list[str]]:
    """Brand the invite names vs brand the links actually belong to."""
    prose = invite.prose()
    named = [v.key for v in policy.vendor_mentioned(prose)]
    for slot in invite.links:
        if slot.prop != "CONFERENCE":
            continue
        for vendor in policy.vendors:
            if slot.label and any(t in slot.label.lower() for t in vendor.tokens):
                if vendor.key not in named:
                    named.append(vendor.key)
    trusted = [v.trusted_vendor for v in verdicts if v.trusted_vendor]
    if not trusted and not named:
        # Fall back to the org's own brand, which is always "claimed".
        return [], named, trusted
    if named:
        if not trusted and any(v.host for v in verdicts):
            return [Signal(
                "invite.vendor_brand_in_copy_only", WEIGHTS["invite.vendor_brand_in_copy_only"],
                f"invite names {', '.join(sorted(set(named)))} but no link belongs to that vendor",
            )], named, trusted
        foreign = [v for v in trusted if v not in named]
        if foreign and not (set(trusted) & set(named)):
            return [Signal(
                "invite.vendor_brand_in_copy_only", WEIGHTS["invite.vendor_brand_in_copy_only"],
                f"invite names {', '.join(sorted(set(named)))} but its only verifiable link "
                f"is to {', '.join(sorted(set(foreign)))}",
            )], named, trusted
    return [], named, trusted


def analyze(
    calendar: ParsedCalendar,
    *,
    mail: MailContext | None = None,
    policy: Policy | None = None,
    store: TrustStore | None = None,
) -> Assessment:
    """Assess a parsed calendar and decide how to deliver it."""
    mail = mail or MailContext()
    policy = policy or Policy()
    store = store or TrustStore()
    primary = calendar.primary

    assessment = Assessment(disposition=Disposition.ALLOW)
    if primary is None:
        assessment.disposition = Disposition.PENDING
        assessment.summary = "calendar body contained no meeting invitation"
        assessment.reasons.append("no VEVENT to evaluate; held for manual review")
        return assessment

    invite = primary
    signals: list[Signal] = list(assessment.signals)

    sender_domain = _domain_of(mail.from_address)
    organizer_domain = _domain_of(invite.organizer_email)
    assessment.sender_domain = sender_domain
    assessment.organizer_domain = organizer_domain

    # --- 1. identity: who says they invited us -----------------------------
    signals.extend(_organizer_signal(invite, mail, policy, store))
    for code, detail in header_from_mismatch(
        from_address=mail.from_address,
        return_path=mail.return_path,
        sender=mail.sender,
        reply_to=mail.reply_to,
        auth=mail.auth,
        registrable_domain=domains.registrable_domain,
    ):
        category = "identity"
        hard = code == "mail.dmarc_fail"
        weight = WEIGHTS.get(code, 20)
        signals.append(Signal(code, weight, detail, hard=hard, category=category))

    # Display-name brand claims: "Microsoft Teams" from a non-Microsoft sender.
    if mail.from_display_name:
        for brand, tokens in policy.brand_tokens.items():
            vendor = policy.vendor_by_key(brand)
            if vendor is None:
                continue
            if any(t in mail.from_display_name.lower() for t in tokens):
                if not vendor.owns(sender_domain, registrable_domain=domains.registrable_domain):
                    signals.append(Signal(
                        "mail.from_name_claims_brand", WEIGHTS["mail.from_name_claims_brand"],
                        f"From display name {mail.from_display_name!r} claims {vendor.display} "
                        f"but the message is from {sender_domain or 'unknown'!r}",
                        category="identity",
                    ))
                break

    # --- 2. links ----------------------------------------------------------
    prose = invite.prose()
    # Structured properties and real hrefs come first so that, when the same URL
    # also appears as free text, the authoritative occurrence wins the dedupe.
    found: list[urls.FoundUrl] = []
    for slot in invite.links:
        if slot.value_type in {"PHONE", "BINARY"} or slot.prop in _STRUCTURED_PROPS:
            continue
        if slot.value.lower().startswith(("cid:", "mailto:", "tel:")):
            continue
        found.append(urls.FoundUrl(raw=slot.value.strip(), source=f"prop:{slot.prop}"))
    found.extend(urls.collect(invite.text_fields()))
    for attachment in invite.attachments:
        if attachment.value_type == "URI" and attachment.uri:
            found.append(urls.FoundUrl(raw=attachment.uri, source="attach"))

    seen_urls: dict[str, int] = {}
    verdicts: list[LinkVerdict] = []
    for item in found:
        key = (item.raw or "").strip().lower()
        if not key:
            continue
        if key in seen_urls:
            # Prefer the authoritative occurrence: the same URL that appears in
            # free text may also be a structured property (or a real href), and
            # only that occurrence can earn verified-link treatment.
            index = seen_urls[key]
            if (_source_is_authoritative(item.source)
                    and not _source_is_authoritative(verdicts[index].source)):
                verdicts[index] = analyze_link(item, policy=policy, prose=prose)
            continue
        seen_urls[key] = len(verdicts)
        verdicts.append(analyze_link(item, policy=policy, prose=prose))
    assessment.links = verdicts
    for verdict in verdicts:
        signals.extend(verdict.signals)

    # Volume is itself evidence: an invite that sprays many distinct untrusted
    # hosts is not a normal meeting, even when each host looks unremarkable.
    untrusted_hosts = {
        v.registrable for v in verdicts
        if v.host and not v.trusted and any(s.category != "identity" for s in v.signals)
    }
    if len(untrusted_hosts) >= 4:
        signals.append(Signal(
            "link.many_suspicious_hosts", WEIGHTS["link.many_suspicious_hosts"],
            f"invitation references {len(untrusted_hosts)} distinct unverified hosts, "
            "which is not how a genuine meeting invite is built",
        ))

    # --- 3. invite structure ----------------------------------------------
    signals.extend(_attachment_signals(invite))
    signals.extend(_alarm_signals(invite))
    signals.extend(_content_signals(invite, verdicts, policy))
    content_signals, named_vendors, trusted_vendors = _vendor_claim_signals(invite, verdicts, policy)
    signals.extend(content_signals)
    assessment.claimed_vendors = sorted(set(named_vendors))
    assessment.trusted_vendors = sorted(set(trusted_vendors))

    if mail.declared_method and calendar.method and mail.declared_method.upper() != calendar.method:
        signals.append(Signal("invite.method_mismatch", WEIGHTS["invite.method_mismatch"],
                              f"declared {mail.declared_method!r} but body METHOD is "
                              f"{calendar.method!r}", category="structure"))
    if len(calendar.invites) > 1:
        signals.append(Signal("invite.bulk_invites", WEIGHTS["invite.bulk_invites"],
                              f"single message carries {len(calendar.invites)} invitations",
                              category="structure"))
    if invite.rrule and not invite.recurrence_id:
        signals.append(Signal("invite.recurring_seed", WEIGHTS["invite.recurring_seed"],
                              "invitation seeds a recurring series, so a reminder will recur "
                              "long after the mail is forgotten", category="structure"))

    # --- 4. history --------------------------------------------------------
    history_signals, previous = _history_signals(invite, store, policy)
    signals.extend(history_signals)
    assessment.uid_known = previous is not None

    if invite.is_cancel and previous is None and not any(
        s.code == "invite.cancel_no_history" for s in signals
    ):
        signals.append(Signal("invite.unsolicited_cancel", WEIGHTS["invite.unsolicited_cancel"],
                              "cancellation refers to a meeting not present in the calendar "
                              "store", category="history"))
    # A CANCEL that carries a link or attachment is being used as a lure.
    if invite.is_cancel:
        for verdict in verdicts:
            if verdict.host and not verdict.trusted_vendor:
                signals.append(Signal(
                    "invite.unsolicited_cancel", WEIGHTS["invite.unsolicited_cancel"],
                    f"cancellation notice contains an active link to {verdict.host!r}",
                    category="history",
                ))
                break

    # --- 5. customer standing ---------------------------------------------
    org_reg = domains.registrable_domain(organizer_domain) if organizer_domain else ""
    known_customer = bool(org_reg) and (
        store.is_allowed_domain(org_reg)
        or (store.domain(org_reg) is not None and store.domain(org_reg).is_known)  # type: ignore[union-attr]
    )
    assessment.known_customer = known_customer
    if known_customer:
        signals = [s for s in signals if s.code != "org.unknown_organizer"]

    # --- 6. decide ---------------------------------------------------------
    hard = [s for s in signals if s.hard]
    score = sum(s.weight for s in signals)
    threshold_pending = THRESHOLD_PENDING + (KNOWN_CUSTOMER_SLACK if known_customer else 0)
    threshold_quarantine = THRESHOLD_QUARANTINE + (KNOWN_CUSTOMER_SLACK if known_customer else 0)
    threshold_reject = THRESHOLD_REJECT + (KNOWN_CUSTOMER_SLACK if known_customer else 0)

    if invite.method == "REPLY":
        # Replies carry no join link and no scheduling authority; only hard
        # identity signals should hold them.
        if hard:
            disposition = Disposition.QUARANTINE
        elif score >= threshold_quarantine:
            disposition = Disposition.PENDING
        else:
            disposition = Disposition.ALLOW
    elif hard:
        # A hard signal means the invite impersonates something.  The org's own
        # identity being spoofed, or a payload, is dropped; a look-alike vendor
        # link is quarantined so a reviewer can still see and release it.
        if any(s.code in {"org.internal_claim_spoofed", "mail.dmarc_fail",
                          "invite.high_risk_attachment", "invite.attachment_type_spoof",
                          "org.disposable_organizer"} for s in hard):
            disposition = Disposition.REJECT
        else:
            disposition = Disposition.QUARANTINE
    elif score >= threshold_quarantine:
        disposition = Disposition.QUARANTINE
    elif score >= threshold_pending:
        disposition = Disposition.PENDING
    else:
        disposition = Disposition.ALLOW

    # Collapse repeats of the same code (a 500-link spray is one phenomenon,
    # not 500 findings) and cap the contribution so score stays readable.
    grouped: dict[str, list[Signal]] = {}
    for signal in signals:
        grouped.setdefault(signal.code, []).append(signal)
    collapsed: list[Signal] = []
    for code, group in grouped.items():
        if len(group) == 1:
            collapsed.append(group[0])
            continue
        representative = group[0]
        # Weight grows sub-linearly with repeats, capped at 3x a single hit.
        extra = min(len(group) - 1, 2) * max(1, representative.weight // 2)
        collapsed.append(Signal(
            code,
            representative.weight + extra,
            f"{representative.detail} (and {len(group) - 1} more like it)",
            hard=any(s.hard for s in group),
            category=representative.category,
        ))
    signals = collapsed
    score = sum(s.weight for s in signals)

    # Sort: hard first, then by weight.
    signals.sort(key=lambda s: (not s.hard, -s.weight, s.code))
    deduped: list[Signal] = []
    for signal in signals:
        if any(s.code == signal.code and s.detail == signal.detail for s in deduped):
            continue
        deduped.append(signal)

    assessment.signals = deduped
    assessment.score = score
    assessment.disposition = disposition
    assessment.summary = _summarise(disposition, invite, deduped)
    assessment.reasons = [f"{s.code}: {s.detail}" for s in deduped if s.hard or s.weight >= 20]
    return assessment


def _summarise(disposition: Disposition, invite: Invite, signals: list[Signal]) -> str:
    org = invite.organizer_email or "an unknown organiser"
    title = invite.summary or "(no title)"
    if disposition == Disposition.ALLOW:
        return f"Invitation from {org} '{title}' passed screening."
    top = "; ".join(s.detail for s in signals if s.hard)[:300]
    if not top:
        top = "; ".join(s.detail for s in signals[:3])[:300]
    verb = {
        Disposition.PENDING: "held as needs-confirmation",
        Disposition.QUARANTINE: "held for review",
        Disposition.REJECT: "blocked",
    }[disposition]
    return f"Invitation from {org} '{title}' {verb}: {top}"


def record_outcome(
    invite: Invite,
    assessment: Assessment,
    *,
    store: TrustStore,
    policy: Policy | None = None,
) -> None:
    """Persist what we learned so updates and cancels can be judged next time."""
    policy = policy or Policy()
    if not invite.uid:
        return
    link_hosts = sorted({v.registrable for v in assessment.links if v.registrable})
    record = UidRecord(
        uid=invite.uid,
        organizer=invite.organizer_email,
        sender=assessment.sender_domain,
        sequence=invite.sequence,
        dtstamp=invite.dtstamp,
        method=invite.method,
        summary_fingerprint=_fingerprint(invite.summary),
        link_hosts=link_hosts,
        recurrence_ids=[invite.recurrence_id] if invite.recurrence_id else [],
        decision=assessment.disposition.name.lower(),
    )
    existing = store.uid(invite.uid)
    if existing is not None:
        record.first_seen = existing.first_seen
        record.seen_count = existing.seen_count
        record.recurrence_ids = sorted(set(existing.recurrence_ids) | set(record.recurrence_ids))
    store.remember_uid(record, decision=assessment.disposition.name.lower())

    domain = domains.registrable_domain(assessment.organizer_domain) if assessment.organizer_domain else ""
    if domain:
        store.observe_domain(
            domain,
            decision=assessment.disposition.name.lower(),
            organizer_name=invite.organizer_name,
        )


def _fingerprint(text: str) -> str:
    import hashlib

    normalized = re.sub(r"\s+", " ", (text or "").strip().lower())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
