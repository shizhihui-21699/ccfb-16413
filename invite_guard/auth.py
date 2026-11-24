"""Mail authentication context: SPF, DKIM, DMARC and header alignment.

Calendar phishing routinely spoofs the organizer address while the envelope is
someone else entirely.  The receiving MTA already computed the answer; we only
have to read it instead of re-deriving it.  When no Authentication-Results
header is present (e.g. a forwarded message) we say "unknown" rather than
guessing, and the risk engine compensates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class AuthResult:
    spf: str = "none"          # pass | fail | softfail | neutral | none | unknown
    dkim: str = "none"
    dmarc: str = "none"
    dkim_domains: list[str] = field(default_factory=list)
    dmarc_from: str = ""
    evidence: list[str] = field(default_factory=list)

    @property
    def any_pass(self) -> bool:
        return "pass" in {self.spf, self.dkim}

    @property
    def dmarc_failed(self) -> bool:
        return self.dmarc in {"fail", "quarantine", "reject"}

    @property
    def weak(self) -> bool:
        """No usable authentication at all."""
        return self.spf in {"none", "unknown"} and self.dkim in {"none", "unknown"}


def _first(header_value: str, mechanism: str) -> str | None:
    match = re.search(rf"(?i)\b{mechanism}\s*=\s*([a-z]+)", header_value)
    return match.group(1).lower() if match else None


def parse_authentication_results(headers: list[str]) -> AuthResult:
    """Parse every ``Authentication-Results`` header present."""
    result = AuthResult()
    if not headers:
        result.evidence.append("no Authentication-Results header")
        return result
    joined = "\n".join(headers)
    spf = _first(joined, "spf")
    dkim = _first(joined, "dkim")
    dmarc = _first(joined, "dmarc")
    if spf:
        result.spf = spf
        result.evidence.append(f"SPF={spf}")
    if dkim:
        result.dkim = dkim
        result.evidence.append(f"DKIM={dkim}")
    if dmarc:
        result.dmarc = dmarc
        result.evidence.append(f"DMARC={dmarc}")
    result.dkim_domains = sorted({d.lower() for d in re.findall(r"(?i)header\.d\s*=\s*([a-z0-9.-]+)", joined)})
    dmarc_from = re.search(r"(?i)header\.from\s*=\s*([a-z0-9._-]+@[a-z0-9.-]+)", joined)
    if dmarc_from:
        result.dmarc_from = dmarc_from.group(1).lower()
    if result.spf == "fail" or result.dkim == "fail" or result.dmarc_failed:
        result.evidence.append("authentication explicitly failed")
    return result


def parse_received_spf(header_value: str) -> str:
    match = re.search(r"(?i)\b(pass|fail|softfail|neutral|none|permerror|temperror)\b", header_value or "")
    return match.group(1).lower() if match else "unknown"


def _domain_of(address: str) -> str:
    address = (address or "").strip().lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def header_from_mismatch(
    *,
    from_address: str,
    return_path: str,
    sender: str,
    reply_to: str,
    auth: AuthResult,
    registrable_domain,
) -> list[tuple[str, str]]:
    """Return (code, detail) pairs for envelope/header inconsistencies."""
    findings: list[tuple[str, str]] = []
    from_domain = _domain_of(from_address)

    if reply_to:
        reply_domain = _domain_of(reply_to)
        if reply_domain and from_domain and registrable_domain(reply_domain) != registrable_domain(from_domain):
            findings.append((
                "mail.reply_to_mismatch",
                f"Reply-To {reply_to!r} does not share a domain with From {from_address!r}",
            ))
    if return_path:
        rp_domain = _domain_of(return_path)
        if rp_domain and from_domain and registrable_domain(rp_domain) != registrable_domain(from_domain):
            findings.append((
                "mail.envelope_mismatch",
                f"envelope sender {rp_domain!r} differs from header From {from_domain!r}",
            ))
    if sender and from_address and sender.lower() != from_address.lower():
        findings.append((
            "mail.sender_header_mismatch",
            f"Sender: {sender!r} differs from From: {from_address!r}",
        ))
    if auth.dmarc_failed:
        findings.append((
            "mail.dmarc_fail",
            f"DMARC result for {from_domain!r} is {auth.dmarc}",
        ))
    elif auth.weak and from_domain:
        findings.append((
            "mail.unauthenticated",
            f"no SPF/DKIM result available for {from_domain!r}",
        ))
    # From address the human sees vs the domain that actually authenticated.
    if auth.dkim_domains and from_domain:
        from_reg = registrable_domain(from_domain)
        if not any(registrable_domain(d) == from_reg for d in auth.dkim_domains):
            findings.append((
                "mail.dkim_domain_mismatch",
                f"DKIM signed by {', '.join(auth.dkim_domains)} but From is {from_domain}",
            ))
    return findings
