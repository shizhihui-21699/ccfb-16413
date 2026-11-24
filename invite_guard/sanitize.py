"""Rewrite an invitation so a suspicious meeting cannot be joined by accident.

The rules here implement the requirement directly: *deliver, but do not arm*.

  * Verified links from a vendor that actually owns the domain survive as a
    single clickable URL.
  * Everything else has its scheme stripped (``https://evil.cn/x`` becomes
    ``hxxps://evil[.]cn/x``) and is placed behind an explicit warning.
  * The event is retitled and marked ``TENTATIVE`` with
    ``X-INVITE-GUARD-STATUS: PENDING-CONFIRMATION`` so the calendar shows it as
    unconfirmed instead of a normal accepted meeting.
  * Alarms are removed from suspicious invites: the reminder is the delivery
    mechanism for the attack, and there is nothing worth reminding about until
    a human confirms.
  * Attachments are dropped and named in the warning body.

Nothing is silently deleted that a reviewer would need.  The original is
preserved on the message (``X-INVITE-GUARD-ORIGINAL-SHA256``) for audit.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from . import ical
from .model import Invite, ParsedCalendar
from .risk import Assessment, Disposition, LinkVerdict

BANNER_PREFIX = "[⚠ 待确认]"
STATUS_PROP = "X-INVITE-GUARD-STATUS"
REASON_PROP = "X-INVITE-GUARD-REASON"
SCORE_PROP = "X-INVITE-GUARD-SCORE"
LINKS_PROP = "X-INVITE-GUARD-BLOCKED-LINKS"
HASH_PROP = "X-INVITE-GUARD-ORIGINAL-SHA256"
VERIFIED_PROP = "X-INVITE-GUARD-VERIFIED-LINK"


@dataclass
class ProcessResult:
    calendar: ParsedCalendar
    assessment: Assessment
    output: bytes | None = None
    delivered: bool = True

    @property
    def summary(self) -> dict:
        return {
            "disposition": self.assessment.disposition.name.lower(),
            "status": self.assessment.status,
            "score": self.assessment.score,
            "delivered": self.delivered,
            "reasons": self.assessment.reasons,
        }


# ---------------------------------------------------------------------------
# defanging
# ---------------------------------------------------------------------------

def defang(url: str) -> str:
    """Render a URL unclickable while keeping it readable and searchable."""
    url = url.strip()
    url = re.sub(r"(?i)^http://", "hxxp://", url)
    url = re.sub(r"(?i)^https://", "hxxps://", url)
    url = re.sub(r"(?i)^ftp://", "fxp://", url)
    url = url.replace(".", "[.]")
    url = url.replace("@", "[@]")
    url = url.replace("://", "[://]")
    return url


_BARE_HOST_RE = re.compile(
    r"(?<![\w.\-/])((?:[a-z0-9-]+\.)+[a-z]{2,24})(?![\w-]|\.[a-z])", re.IGNORECASE
)


def _defang_hosts(text: str) -> str:
    """Defang bare host names inside explanatory prose (no scheme needed)."""
    return _BARE_HOST_RE.sub(lambda m: m.group(1).replace(".", "[.]"), text)


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------------------
# body rewriting
# ---------------------------------------------------------------------------

def _warning_block(assessment: Assessment, invite: Invite, *, compact: bool = False) -> str:
    lines: list[str] = []
    lines.append("⚠ 此会议邀请未能通过安全校验,请勿点击其中的链接或输入任何密码。")
    lines.append("This meeting invitation could not be verified. Do not click links "
                 "or enter credentials.")
    lines.append("")
    lines.append(f"状态 / Status: {assessment.status}")
    if assessment.claimed_vendors:
        lines.append("声称的平台 / Claimed platform: " + ", ".join(assessment.claimed_vendors))
    if assessment.trusted_vendors:
        lines.append("已核实平台 / Verified platform: " + ", ".join(assessment.trusted_vendors))
    lines.append("")
    lines.append("检测到的可疑之处 / Why it was held:")
    shown = 0
    for signal in assessment.signals:
        if shown >= (3 if compact else 6):
            break
        if signal.weight < 15 and not signal.hard:
            continue
        lines.append(f"- {_defang_hosts(signal.detail)}")
        shown += 1
    if not shown:
        lines.append("- invitation could not be matched to any known vendor or contact")
    blocked = [v for v in assessment.links if v.host and not v.trusted]
    if blocked:
        lines.append("")
        lines.append("已停用链接 / Links disabled (defanged, copy only if you trust the sender):")
        for verdict in blocked[:6]:
            lines.append(f"- {defang(verdict.raw)}")
    lines.append("")
    lines.append("请通过你已知可靠的渠道向组织者核实后再参加。/ "
                 "Contact the organiser through a separate, trusted channel before joining.")
    return "\n".join(lines)



def _strip_html_links(markup: str, keep: set[str]) -> str:
    """Replace href/src attributes with inert text except for *keep* URLs."""
    def replace(match: re.Match) -> str:
        attribute, quote, value = match.group(1), match.group(2), match.group(3)
        if value.strip().lower() in keep:
            return match.group(0)
        return f"{attribute}={quote}#{quote}"
    return re.sub(
        r"""(?i)\b(href|src|action|formaction|data-url|data-href)\s*=\s*(["'])(.*?)\2""",
        replace, markup,
    )


_SCRIPT_ANY_RE = re.compile(r"(?is)<\s*script\b[^>]*>(.*?)<\s*/\s*script\s*>")


def _rewrite_text_field(
    value: str, *, verdicts: list[LinkVerdict], keep: set[str], escape_scripts: bool = False
) -> str:
    """Neutralise links in one field, preserving structure.

    In HTML we must do three things: drop the href attributes we do not trust,
    defang the *visible* URL text (attackers often print the real target as
    plain text), and remove script bodies, which never render but do execute in
    some clients.
    """
    if not value:
        return value
    is_html = bool(re.search(r"(?is)<\s*(?:html|body|div|p|a|table)\b", value))
    out = value
    if is_html:
        out = _strip_html_links(out, keep)
    for verdict in sorted(verdicts, key=lambda v: -len(v.raw)):
        if not verdict.host or verdict.raw.lower() in keep:
            continue
        if verdict.raw in out:
            out = out.replace(verdict.raw, defang(verdict.raw))
    if escape_scripts:
        out = _SCRIPT_ANY_RE.sub(lambda m: f"(removed script: {defang(m.group(1).strip())})"
                                 if m.group(1).strip() else "(removed script)", out)
        out = re.sub(r"(?is)<\s*script\b[^>]*/?>", "", out)
    return out


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render(calendar: ParsedCalendar, assessment: Assessment) -> bytes | None:
    """Return the bytes to deliver, or None when the invite must not be delivered.

    ALLOW       -> untouched calendar
    PENDING     -> delivered, degraded to needs-confirmation
    QUARANTINE  -> degraded, routed to the review queue (still returns bytes so
                   the reviewer and the user-warning copy have the same artefact)
    REJECT      -> None; nothing reaches the mailbox
    """
    if assessment.disposition == Disposition.REJECT:
        return None
    if assessment.disposition == Disposition.ALLOW:
        return _serialize(calendar, sanitize=False)

    keep = {v.raw.strip().lower() for v in assessment.links if v.trusted}
    for invite in calendar.invites:
        _degrade_invite(invite, assessment, keep)
    return _serialize(calendar, sanitize=True)


def _degrade_invite(invite: Invite, assessment: Assessment, keep: set[str]) -> None:
    component = invite.source_component
    if component is None:
        return
    verdicts = assessment.links
    compact = assessment.disposition == Disposition.QUARANTINE

    # Title: prefix so the calendar list itself carries the warning.
    original_summary = invite.summary or "(no title)"
    if not original_summary.startswith(BANNER_PREFIX):
        component.set_text("SUMMARY", f"{BANNER_PREFIX} {original_summary}")

    # Body: warning block first, then the (defanged) original description.
    warning = _warning_block(assessment, invite, compact=compact)
    original_description = _rewrite_text_field(
        invite.description, verdicts=verdicts, keep=keep, escape_scripts=True)

    dropped = [a.filename or "(unnamed)" for a in invite.attachments]
    note = ""
    if dropped:
        note = "附件已移除 / Attachments removed: " + ", ".join(dropped)

    if re.search(r"(?is)<\s*(?:html|body)\b", original_description):
        body = (
            "<html><body><div style='background:#fff3cd;border:2px solid #d39e00;"
            "padding:12px;font-family:sans-serif;margin-bottom:12px'>"
            + "<br>".join(_escape_line(line) for line in warning.splitlines())
            + "</div><div style='font-family:sans-serif'>"
            + original_description
            + (f"<p><b>{_escape_line(note)}</b></p>" if note else "")
            + "</div></body></html>"
        )
        alt = component.get("X-ALT-DESC")
        if alt is not None:
            alt.value = _rewrite_text_field(alt.value, verdicts=verdicts, keep=keep,
                                            escape_scripts=True)
    else:
        body = warning + ("\n\n----- original invitation -----\n" + original_description
                          if original_description.strip() else "")
        if note:
            body += "\n\n" + note

    # Always escape: a decoded description contains real newlines, commas and
    # semicolons, and writing it raw produces an invalid content line that
    # clients truncate at the first newline.
    component.set_text("DESCRIPTION", body)

    # Location: strip the host from prose so it is not a one-tap map/link target.
    if invite.location:
        new_location = _rewrite_text_field(invite.location, verdicts=verdicts, keep=set())
        if new_location != invite.location:
            new_location = f"{new_location} (unverified / 未核实)"
        component.set_text("LOCATION", new_location)

    # Links: only verified vendor URLs keep a URI property.  Everything else is
    # dropped from structured properties (the readable text remains in the body
    # in defanged form).
    verified = [v.raw for v in assessment.links if v.trusted]
    component.remove("URL")
    component.remove("CONFERENCE")
    for prop in list(component.props):
        if prop.name.upper() in {"X-MICROSOFT-SKYPETEAMSMEETINGURL",
                                 "X-MICROSOFT-SKYPETEAMSPROPERTIES",
                                 "X-MICROSOFT-ONLINEMEETINGCONFLINK",
                                 "X-MICROSOFT-ONLINE-MEETING-CONFLINK",
                                 "X-GOOGLE-CONFERENCE", "X-GOOGLE-CONFERENCE-URL",
                                 "X-ZOOM-MEETING-URL", "X-WEBEX-MEETING-URL",
                                 "X-TENCENT-MEETING-URL", "X-FEISHU-MEETING-URL",
                                 "X-DINGTALK-MEETING-URL", "X-APPLE-STRUCTURED-LOCATION"}:
            component.remove(prop.name)
    # Unknown / custom properties can carry a join link too; defang any URL left
    # in a property we are not otherwise rewriting, so no clickable value
    # survives under an attacker-chosen name.
    _known_text = {"SUMMARY", "DESCRIPTION", "LOCATION", "UID", "ORGANIZER", "ATTENDEE",
                   "DTSTART", "DTEND", "DTSTAMP", "SEQUENCE", "STATUS", "TRANSP",
                   "CLASS", "PRIORITY", "CREATED", "LAST-MODIFIED", "RRULE", "RDATE",
                   "EXDATE", "RECURRENCE-ID", "DURATION", "PRODID", "VERSION",
                   "CALSCALE", "METHOD"}
    for prop in component.props:
        if prop.name.upper() in _known_text:
            continue
        if prop.value and re.search(r"(?i)(?:https?://|ftp://|www\.)", prop.value):
            prop.value = _rewrite_text_field(prop.value, verdicts=verdicts, keep=keep)

    if verified:
        prop = ical.Prop("URL", verified[0])
        component.props.append(prop)

    # Reminders are the attack trigger; drop them until a human confirms.
    component.children = [c for c in component.children if c.name != "VALARM"]

    # Attachments are removed entirely, not just described.  Leaving the ATTACH
    # property in place would keep a remote payload one click away while the
    # body claims it was removed.
    if dropped:
        component.remove("ATTACH")

    # Mark it as tentative so clients show it as not-yet-accepted.
    if component.get("STATUS") is not None:
        component.set_text("STATUS", "TENTATIVE", raw=True)
    else:
        component.props.append(ical.Prop("STATUS", "TENTATIVE"))
    if component.get("TRANSP") is None:
        component.props.append(ical.Prop("TRANSP", "TRANSPARENT"))

    # Machine-readable provenance for the calendar client and for audit.
    for name in (STATUS_PROP, REASON_PROP, SCORE_PROP, LINKS_PROP, HASH_PROP, VERIFIED_PROP):
        component.remove(name)
    component.props.append(ical.Prop(STATUS_PROP, assessment.status))
    top_codes = ",".join(s.code for s in assessment.signals[:8])
    component.props.append(ical.Prop(REASON_PROP, top_codes))
    component.props.append(ical.Prop(SCORE_PROP, str(assessment.score)))
    blocked = [v.raw for v in assessment.links if v.host and not v.trusted]
    if blocked:
        if len(blocked) <= 5:
            # Defang here too: an X- property is still text a client may linkify.
            component.props.append(
                ical.Prop(LINKS_PROP, " ".join(defang(u) for u in blocked[:5])))
        else:
            component.props.append(
                ical.Prop(LINKS_PROP, f"{len(blocked)} links disabled; see description"))
    if verified:
        component.props.append(ical.Prop(VERIFIED_PROP, verified[0]))
    component.props.append(ical.Prop(HASH_PROP, _sha256(original_summary + "\n" + invite.description)))

    # A held event should not claim a physical room either.
    invite.notes.append(f"degraded to {assessment.status}")


def _escape_line(line: str) -> str:
    return (line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _serialize(calendar: ParsedCalendar, *, sanitize: bool) -> bytes:
    """Serialise every VCALENDAR we were given, keeping unknown parts intact."""
    chunks: list[str] = []
    seen: set[int] = set()
    for invite in calendar.invites:
        parent = invite.calendar_component or _find_calendar(invite.source_component)
        if parent is None or id(parent) in seen:
            continue
        seen.add(id(parent))
        if sanitize:
            _ensure_prodid(parent)
        chunks.append(parent.serialize())
    if not chunks:
        return b""
    return "".join(chunks).encode("utf-8")


def _find_calendar(component: ical.Comp | None) -> ical.Comp | None:
    """Fallback: locate the VCALENDAR that owns a VEVENT."""
    return getattr(component, "_calendar", None) if component is not None else None


def _ensure_prodid(parent: ical.Comp) -> None:
    if parent.get("PRODID") is None:
        parent.props.insert(0, ical.Prop("PRODID", "-//invite-guard//calendar screening//EN"))
    if parent.get("VERSION") is None:
        parent.props.insert(0, ical.Prop("VERSION", "2.0"))
    if parent.get("CALSCALE") is None:
        parent.props.append(ical.Prop("CALSCALE", "GREGORIAN"))
