"""MIME integration: find the calendar parts of a real message and rewrite them.

A gateway does not receive a naked .ics file.  It receives a MIME tree where the
invitation may be an ``application/ics`` part, a ``text/calendar`` part inside
``multipart/alternative``, or the same calendar repeated in several alternative
representations (that repetition is itself worth knowing about -- attackers
sometimes give the text/plain part a benign body and the HTML part the lure).

This module is deliberately conservative:

* it never touches non-calendar parts;
* it preserves the original Content-Type parameters (``method=``, ``charset=``);
* it recomputes ``Content-Transfer-Encoding`` correctly for rewritten bodies;
* it refuses to rewrite a part it cannot parse, and reports why.
"""

from __future__ import annotations

import email
import email.policy
from dataclasses import dataclass, field
from email.message import Message

from . import ical
from .model import interpret
from .risk import Assessment, Disposition, MailContext, analyze
from .sanitize import render

CALENDAR_MIME_TYPES = {"text/calendar", "application/ics", "application/calendar+xml"}


@dataclass
class PartInfo:
    index: int
    content_type: str
    method: str = ""
    filename: str = ""
    charset: str = "utf-8"
    cte: str = ""
    bytes: int = 0
    assessment: Assessment | None = None
    error: str = ""


@dataclass
class MimeResult:
    message: Message
    parts: list[PartInfo] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    # Original bytes, kept so a clean message can be forwarded verbatim.
    original: bytes | None = None

    @property
    def worst(self) -> Disposition:
        return max((p.assessment.disposition for p in self.parts if p.assessment),
                   default=Disposition.ALLOW)

    @property
    def has_calendar(self) -> bool:
        return bool(self.parts)

    @property
    def passed_through(self) -> bool:
        return all(p.assessment is None or p.assessment.disposition == Disposition.ALLOW
                   for p in self.parts)

    def summary(self) -> dict:
        return {
            "has_calendar": self.has_calendar,
            "worst_disposition": self.worst.name.lower(),
            "passed_through": self.passed_through,
            "findings": self.findings,
            "parts": [
                {
                    "index": p.index,
                    "content_type": p.content_type,
                    "method": p.method,
                    "decision": p.assessment.disposition.name.lower() if p.assessment else "skipped",
                    "score": p.assessment.score if p.assessment else None,
                    "error": p.error,
                }
                for p in self.parts
            ],
        }


def _method_from_content_type(content_type: str) -> str:
    params = dict(
        part.split("=", 1) for part in content_type.split(";")[1:] if "=" in part
    )
    return params.get("method", "").strip().strip('"')


def _iter_parts(message: Message):
    if message.is_multipart():
        for index, part in enumerate(message.walk()):
            if part.is_multipart():
                continue
            yield index, part
    else:
        yield 0, message


def _decode(part: Message) -> bytes:
    payload = part.get_payload(decode=True)
    if payload is not None:
        return payload
    raw = part.get_payload()
    if isinstance(raw, str):
        charset = part.get_content_charset() or "utf-8"
        try:
            return raw.encode(charset)
        except LookupError:
            return raw.encode("utf-8", "replace")
    return b""


def process_message(
    raw: bytes | str,
    *,
    mail: MailContext | None = None,
    policy=None,
    store=None,
) -> MimeResult:
    """Screen and rewrite every calendar part of a MIME message."""
    original = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    message = email.message_from_bytes(original, policy=email.policy.default)
    base = mail or MailContext()
    result = MimeResult(message=message, original=original)

    header_from = message.get("From", "")
    result_mail = MailContext(
        from_address=base.from_address or _address_of(header_from),
        from_display_name=base.from_display_name or _display_name_of(header_from),
        return_path=base.return_path or message.get("Return-Path", ""),
        reply_to=base.reply_to or message.get("Reply-To", ""),
        sender=base.sender or message.get("Sender", ""),
        subject=base.subject or message.get("Subject", ""),
        auth=base.auth,
        declared_method=base.declared_method,
        content_type_mismatch=base.content_type_mismatch,
        recipient_domains=base.recipient_domains,
    )

    seen_bodies: dict[int, tuple[str, str]] = {}
    for index, part in _iter_parts(message):
        content_type = (part.get_content_type() or "").lower()
        if content_type not in CALENDAR_MIME_TYPES:
            continue
        info = PartInfo(
            index=index,
            content_type=content_type,
            method=_method_from_content_type(part.get("Content-Type", "")),
            filename=part.get_filename() or "",
            charset=part.get_content_charset() or "utf-8",
            cte=part.get("Content-Transfer-Encoding", ""),
            bytes=len(part.get_payload() or ""),
        )
        try:
            body = _decode(part)
            calendars = ical.load(body)
            calendar = interpret(calendars, declared_method=info.method)
            assessment = analyze(calendar, mail=result_mail, policy=policy, store=store)
        except ical.IcalError as exc:
            info.error = f"unparseable calendar: {exc}"
            info.assessment = _unparseable(calendar_report=str(exc))
            result.parts.append(info)
            continue

        info.assessment = assessment
        if store is not None and calendar.primary is not None:
            from .risk import record_outcome
            record_outcome(calendar.primary, assessment, store=store, policy=policy)
        info.method = info.method or calendar.method
        info.bytes = len(body)
        _record_duplicate(seen_bodies, assessment, result.findings)
        result.parts.append(info)

        if assessment.disposition != Disposition.ALLOW:
            rewritten = render(calendar, assessment)
            if rewritten is None:
                # REJECT: replace the part with a harmless explanatory text part.
                _replace_with_notice(part, assessment)
            else:
                _set_calendar_body(part, rewritten)

    if result.parts and result.passed_through:
        pass
    return result


def _record_duplicate(seen: dict[int, tuple[str, str]], assessment: Assessment,
                      findings: list[str]) -> None:
    signature = (assessment.organizer_domain, assessment.sender_domain)
    seen[id(assessment)] = signature


def _unparseable(*, calendar_report: str) -> Assessment:
    assessment = Assessment(disposition=Disposition.PENDING)
    assessment.summary = "calendar part could not be parsed"
    assessment.reasons.append(calendar_report)
    assessment.notes.append("delivered as-is but flagged for review")
    return assessment


def _replace_with_notice(part: Message, assessment: Assessment) -> None:
    """Turn a rejected calendar part into a plain-text warning.

    Keeping the part (rather than deleting it) means the recipient learns why the
    meeting is missing, which cuts the "I'll just click the one in my other
    mailbox" follow-up that makes these campaigns profitable.
    """
    lines = [
        "⚠ A calendar invitation was removed because it impersonated a trusted sender.",
        "",
        f"Organiser claimed: {assessment.organizer_email}" if hasattr(assessment, "organizer_email")
        else f"Organiser domain: {assessment.organizer_domain}",
        f"Reason: {assessment.summary}",
        "",
    ]
    lines.extend(f"- {s.detail}" for s in assessment.signals[:6])
    lines.append("")
    lines.append("If this meeting is real, ask the organiser to send it again from "
                 "their normal account.")
    body = "\n".join(lines)
    part.set_payload(body, charset="utf-8")
    if part.get("Content-Type"):
        part.replace_header("Content-Type", 'text/plain; charset="utf-8"')
    else:
        part["Content-Type"] = 'text/plain; charset="utf-8"'
    if part.get("Content-Transfer-Encoding"):
        part.replace_header("Content-Transfer-Encoding", "8bit")
    else:
        part["Content-Transfer-Encoding"] = "8bit"


def _set_calendar_body(part: Message, body: bytes) -> None:
    """Write a new calendar body, keeping the part's declared parameters.

    UTF-8 with 8bit CTE is what every calendar client we care about accepts, and
    it avoids the line-length and charset bugs that base64 re-encoding
    introduces when folding is done after encoding.
    """
    content_type = part.get("Content-Type", "text/calendar")
    if "charset" not in content_type.lower():
        content_type += '; charset="utf-8"'
    if part.get("Content-Type"):
        part.replace_header("Content-Type", content_type)
    else:
        part["Content-Type"] = content_type
    part.set_payload(body.decode("utf-8", "replace"), charset="utf-8")
    if part.get("Content-Transfer-Encoding"):
        part.replace_header("Content-Transfer-Encoding", "8bit")
    else:
        part["Content-Transfer-Encoding"] = "8bit"


def _address_of(header: str) -> str:
    from .model import _email_address

    return _email_address(header)[0]


def _display_name_of(header: str) -> str:
    from .model import _email_address

    return _email_address(header)[1]


def flatten(result: MimeResult) -> bytes:
    """Serialise the message, or return it untouched when nothing changed.

    Re-serialising is lossy: it rewrites line endings, re-encodes headers and
    can reorder multipart structure.  For a message we did not need to change,
    the only correct output is the input.
    """
    if result.passed_through and result.original is not None:
        return result.original
    return result.message.as_bytes(policy=email.policy.SMTP)
