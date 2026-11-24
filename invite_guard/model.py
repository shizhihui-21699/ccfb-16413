"""Normalise an iCalendar invitation into the facts the risk engine needs.

Calendar clients disagree wildly about where the join link lives.  The same
Zoom meeting may appear as::

    LOCATION:https://zoom.us/j/912345
    X-MICROSOFT-SKYPETEAMSMEETINGURL:https://teams.microsoft.com/l/meetup-join/...
    CONFERENCE;VALUE=URI;FEATURE=VIDEO;LABEL=Zoom:https://zoom.us/j/912345
    X-GOOGLE-CONFERENCE:https://meet.google.com/abc-defg-hij
    DESCRIPTION:Join Zoom Meeting\\nhttps://zoom.us/j/912345?pwd=...

and Apple adds ``X-APPLE-STRUCTURED-LOCATION`` alongside a plain ``LOCATION``.
Instead of special-casing clients in the detector, we flatten everything into
one list of *link slots* with provenance, and let the URL layer judge them.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from . import ical

# Properties that carry a link the user is meant to click.
VENDOR_URL_PROPS = (
    "URL",
    "CONFERENCE",
    "X-MICROSOFT-SKYPETEAMSMEETINGURL",
    "X-MICROSOFT-SKYPETEAMSPROPERTIES",
    "X-MICROSOFT-ONLINEMEETINGCONFLINK",
    "X-MICROSOFT-ONLINE-MEETING-CONFLINK",
    "X-GOOGLE-CONFERENCE",
    "X-GOOGLE-CONFERENCE-URL",
    "X-ZOOM-MEETING-URL",
    "X-WEBEX-MEETING-URL",
    "X-TENCENT-MEETING-URL",
    "X-FEISHU-MEETING-URL",
    "X-DINGTALK-MEETING-URL",
    "X-APPLE-STRUCTURED-LOCATION",
    "X-ALT-DESC",
    "X-ALT-DESC-URL",
    "X-MOZ-GENERATION",
    "IMAGE",
)

# Properties whose text may contain prose with links.
TEXT_PROPS = ("SUMMARY", "DESCRIPTION", "LOCATION", "COMMENT", "CONTACT")

# Values that answer "is this invite claiming to be a real meeting?".
METHODS_OF_INTEREST = {"REQUEST", "REPLY", "CANCEL", "ADD", "PUBLISH", "DECLINECOUNTER", "REFRESH"}

# Extensions a calendar client will happily offer to open.
RISKY_ATTACHMENT_EXT = frozenset("""
    exe scr bat cmd com pif vbs vbe js jse wsf wsh ps1 psm1 msi msp cpl hta
    jar class dll lnk url reg inf iso img vhd vhdx dmg pkg app deb rpm apk
    msix appx xll ocx svg html htm xhtml xsl xslt
""".split())

# Anything that looks like a scheme-prefixed or www URL inside a property value.
_URL_IN_VALUE_RE = re.compile(r"(?i)(?:https?://|ftp://|www\.)|\b[a-z0-9-]+\.[a-z]{2,}/")

_SCRIPT_BODY_RE = re.compile(r"(?is)<\s*script\b[^>]*>(.*?)<\s*/\s*script\s*>")
_SCRIPT_URL_RE = re.compile(
    r"""(?ix)
    (?:
        location(?:\.href)?\s*=
      | window\.open\s*\(\s*['"]?
      | (?:href|src)\s*=\s*['"]?
    )
    (?P<url>(?:https?://|//)[^\s'">)]+)
    """
)

_ZIP_MAGIC = b"PK\x03\x04"
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


@dataclass
class LinkSlot:
    """One place a clickable link appeared, with where it came from."""
    prop: str
    value: str
    index: int = 0
    value_type: str = "URI"
    label: str = ""

    @property
    def is_vendor_prop(self) -> bool:
        return self.prop in VENDOR_URL_PROPS

    @property
    def location_hint(self) -> str:
        if self.prop == "CONFERENCE":
            label = self.label or "conference"
            return f"CONFERENCE ({label})"
        return self.prop


@dataclass
class Attachment:
    filename: str
    fmttype: str = ""
    value_type: str = "URI"
    uri: str = ""
    data_prefix: bytes = b""
    size: int = 0
    error: str = ""


@dataclass
class Attendee:
    email: str
    common_name: str = ""
    role: str = "REQ-PARTICIPANT"
    partstat: str = "NEEDS-ACTION"
    rsvp: bool = False
    cutype: str = "INDIVIDUAL"
    is_organiser_copy: bool = False


@dataclass
class Invite:
    """A single interpreted VEVENT with everything the detector needs."""

    uid: str = ""
    method: str = ""
    prodid: str = ""
    calendar_scale: str = ""

    sequence: int | None = None
    revision: int | None = None
    dtstamp: str = ""
    dtstart: str = ""
    dtend: str = ""
    duration: str = ""
    rrule: str = ""
    recurrence_id: str = ""
    is_recurring: bool = False

    status: str = ""
    transp: str = ""
    class_: str = ""
    priority: str = ""
    summary: str = ""
    description: str = ""
    location: str = ""

    organizer_email: str = ""
    organizer_name: str = ""
    organizer_sent_by: str = ""

    attendees: list[Attendee] = field(default_factory=list)
    links: list[LinkSlot] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    alarms: list[dict] = field(default_factory=list)

    # Provenance of the interpretation itself.
    source_component: ical.Comp | None = None
    calendar_component: ical.Comp | None = None
    notes: list[str] = field(default_factory=list)

    # ---- derived views --------------------------------------------------
    @property
    def is_cancel(self) -> bool:
        return self.method == "CANCEL" or self.status.upper() == "CANCELLED"

    @property
    def is_update(self) -> bool:
        return bool(self.recurrence_id) or (self.sequence or 0) > 0

    @property
    def is_reply(self) -> bool:
        return self.method == "REPLY"

    @property
    def external_attendees(self) -> list[Attendee]:
        return self.attendees

    def prose(self) -> str:
        """All free text an attacker could have written, concatenated."""
        parts = [self.summary, self.description, self.location]
        for slot in self.links:
            if slot.prop in {"X-ALT-DESC", "X-ALT-DESC-URL"}:
                parts.append(slot.value)
        return "\n".join(p for p in parts if p)

    # Properties whose value is a URI by definition; scanned elsewhere as slots.
    _SLOT_PROPS = frozenset(VENDOR_URL_PROPS) | {"ATTACH"}

    def text_fields(self) -> dict[str, str]:
        """Every field an attacker could put a link into.

        This deliberately includes *unknown* properties.  Restricting the scan
        to a known-property allowlist hands attackers a trivial bypass: rename
        ``URL`` to ``X-CUSTOM-JOIN-URL`` and the link becomes invisible.  Values
        of properties already represented as link slots are skipped here so
        they are not scanned twice.
        """
        fields = {
            "summary": self.summary,
            "description": self.description,
            "location": self.location,
        }
        component = self.source_component
        if component is not None:
            # Properties can repeat (COMMENT, ATTENDEE, custom X- props).  Key by
            # occurrence, never by name: storing by name would let an attacker
            # hide links behind duplicates that overwrite each other.
            for index, prop in enumerate(component.props):
                name = prop.name.upper()
                if name in self._SLOT_PROPS or name in {"SUMMARY", "DESCRIPTION", "LOCATION"}:
                    continue
                if prop.value and len(prop.value) <= 8192:
                    fields[f"prop:{name}#{index}"] = prop.value
        for slot in self.links:
            if slot.prop in {"X-ALT-DESC", "X-ALT-DESC-URL", "X-HIDDEN-SCRIPT"}:
                fields[f"slot:{slot.prop}"] = slot.value
        return fields

    def link_bearing_properties(self) -> set[str]:
        """Property names whose value carries a URL, for rewrite decisions."""
        names = {slot.prop for slot in self.links if slot.value}
        component = self.source_component
        if component is not None:
            for prop in component.props:
                if prop.value and _URL_IN_VALUE_RE.search(prop.value):
                    names.add(prop.name.upper())
        return names


def _email_address(value: str) -> tuple[str, str]:
    """Split ``Name <addr>`` / ``mailto:addr`` into (address, name)."""
    raw = (value or "").strip()
    if raw.lower().startswith("mailto:"):
        raw = raw[7:]
    match = re.match(r'^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$', raw)
    if match:
        return match.group(2).strip().lower(), match.group(1).strip()
    return raw.strip().lower(), ""


def _int_or_none(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _read_attendee(prop: ical.Prop) -> Attendee:
    address, name = _email_address(prop.text())
    common = prop.param("CN") or name
    return Attendee(
        email=address,
        common_name=ical.unescape_param(common or ""),
        role=(prop.param("ROLE") or "REQ-PARTICIPANT").upper(),
        partstat=(prop.param("PARTSTAT") or "NEEDS-ACTION").upper(),
        rsvp=(prop.param("RSVP") or "").upper() == "TRUE",
        cutype=(prop.param("CUTYPE") or "INDIVIDUAL").upper(),
    )


_BASE64_BODY_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def _looks_like_base64(value: str) -> bool:
    compact = re.sub(r"\s+", "", value or "")
    if len(compact) < 24 or len(compact) % 4:
        return False
    if not _BASE64_BODY_RE.match(compact):
        return False
    # Real base64 payloads contain mixed case or +/; a plain word does not.
    return bool(re.search(r"[A-Z]", compact) and re.search(r"[a-z]", compact))


def _decode_attachment(prop: ical.Prop) -> Attachment:
    fmttype = (prop.param("FMTTYPE") or prop.param("FMT-TYPE") or "").lower()
    value_type = (prop.param("VALUE") or "").upper()
    filename = ical.unescape_param(prop.param("FILENAME") or prop.param("X-FILENAME") or "")
    if not value_type:
        # Some clients omit VALUE=BINARY.  An inline base64 blob is unambiguously
        # binary, and treating it as a URI would hide an executable attachment.
        value_type = "BINARY" if (fmttype and _looks_like_base64(prop.value)) else "URI"
    uri = prop.value if value_type == "URI" else ""
    attachment = Attachment(filename=filename, fmttype=fmttype, value_type=value_type, uri=uri)
    if value_type == "BINARY":
        try:
            raw = base64.b64decode(re.sub(r"\s+", "", prop.value), validate=False)
        except (binascii.Error, ValueError) as exc:
            attachment.error = f"invalid base64: {exc}"
            return attachment
        attachment.size = len(raw)
        attachment.data_prefix = raw[:16]
        # A "PDF" that is really a ZIP or an OLE compound file is a payload.
        actual = _sniff_type(raw)
        if actual and fmttype and actual not in fmttype and not _compatible(actual, fmttype):
            attachment.error = f"content is {actual} but declared as {fmttype}"
        elif actual and not fmttype:
            attachment.fmttype = actual
    return attachment


def _sniff_type(raw: bytes) -> str:
    if raw.startswith(_ZIP_MAGIC):
        return "application/zip"
    if raw.startswith(_OLE_MAGIC):
        return "application/msword"
    if raw.startswith(b"%PDF"):
        return "application/pdf"
    if raw.startswith(b"MZ"):
        return "application/x-msdownload"
    if raw.startswith(b"\x7fELF"):
        return "application/x-elf"
    return ""


def _compatible(actual: str, declared: str) -> bool:
    families = {
        "application/zip": {"application/zip", "application/x-zip-compressed",
                            "application/vnd.openxmlformats", "application/epub"},
        "application/msword": {"application/msword", "application/vnd.ms-", "application/vnd.openxmlformats"},
        "application/x-msdownload": {"application/x-msdownload", "application/octet-stream", "application/x-dosexec"},
    }
    for family, allowed in families.items():
        if actual == family:
            return any(declared.startswith(a) for a in allowed)
    return False


def from_vevent(
    vevent: ical.Comp,
    *,
    method: str = "",
    prodid: str = "",
    calendar_scale: str = "",
    calendar: ical.Comp | None = None,
) -> Invite:
    """Interpret one VEVENT component."""
    invite = Invite(
        method=(method or "").upper(),
        prodid=prodid,
        calendar_scale=calendar_scale,
        source_component=vevent,
        calendar_component=calendar,
    )
    invite.uid = vevent.text("UID").strip()
    invite.sequence = _int_or_none(vevent.text("SEQUENCE", ""))
    invite.revision = _int_or_none(vevent.text("REV", ""))
    invite.dtstamp = vevent.text("DTSTAMP").strip()
    invite.dtstart = vevent.text("DTSTART").strip()
    invite.dtend = vevent.text("DTEND").strip()
    invite.duration = vevent.text("DURATION").strip()
    invite.rrule = vevent.text("RRULE").strip()
    invite.recurrence_id = vevent.text("RECURRENCE-ID").strip()
    invite.is_recurring = bool(invite.rrule or invite.recurrence_id)
    invite.status = vevent.text("STATUS").strip().upper()
    invite.transp = vevent.text("TRANSP").strip().upper()
    invite.class_ = vevent.text("CLASS").strip().upper()
    invite.priority = vevent.text("PRIORITY").strip()
    invite.summary = vevent.text("SUMMARY").strip()
    invite.description = vevent.text("DESCRIPTION")
    invite.location = vevent.text("LOCATION").strip()

    organizer = vevent.get("ORGANIZER")
    if organizer is not None:
        invite.organizer_email, invite.organizer_name = _email_address(organizer.text())
        sent_by = organizer.param("SENT-BY")
        if sent_by:
            invite.organizer_sent_by = _email_address(sent_by)[0]

    for prop in vevent.all("ATTENDEE"):
        invite.attendees.append(_read_attendee(prop))

    # Link slots: every vendor URL property, plus prose, plus structured location.
    # Script bodies are never rendered, so they are a favourite hiding place for
    # redirects.  Surface them as link slots so the URL layer can judge them.
    for prop in vevent.all("DESCRIPTION") + vevent.all("X-ALT-DESC"):
        for script_body in _SCRIPT_BODY_RE.findall(prop.value):
            for match in _SCRIPT_URL_RE.finditer(script_body):
                target = match.group("url")
                invite.links.append(LinkSlot(prop="X-HIDDEN-SCRIPT", value=target.strip()))

    for prop in vevent.props:
        upper = prop.name.upper()
        if upper in VENDOR_URL_PROPS:
            slot = LinkSlot(
                prop=upper,
                value=prop.value.strip(),
                value_type=(prop.param("VALUE") or "URI").upper(),
                label=prop.param("LABEL") or prop.param("X-LABEL") or "",
            )
            if upper == "CONFERENCE":
                # FEATURE=PHONE entries are dial-in numbers, not clickable pages.
                features = {f.upper() for f in prop.param_list("FEATURE")}
                if features and "VIDEO" not in features and "WEB" not in features:
                    slot.value_type = "PHONE"
            if slot.value:
                invite.links.append(slot)

    for prop in vevent.all("ATTACH"):
        invite.attachments.append(_decode_attachment(prop))

    for alarm in vevent.descendants("VALARM"):
        invite.alarms.append({
            "action": alarm.text("ACTION").upper(),
            "trigger": alarm.text("TRIGGER").strip(),
            "description": alarm.text("DESCRIPTION"),
            "summary": alarm.text("SUMMARY"),
            "attendee": alarm.text("ATTENDEE"),
            "attach": alarm.text("ATTACH"),
        })

    if not invite.uid:
        invite.notes.append("missing UID")
    if not invite.organizer_email:
        invite.notes.append("missing ORGANIZER")
    if not invite.dtstart:
        invite.notes.append("missing DTSTART")
    return invite


@dataclass
class ParsedCalendar:
    """A whole MIME calendar body: method plus every VEVENT it carries."""

    method: str = ""
    prodid: str = ""
    calendar_scale: str = ""
    invites: list[Invite] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    component_counts: dict[str, int] = field(default_factory=dict)

    @property
    def primary(self) -> Invite | None:
        return self.invites[0] if self.invites else None

    @property
    def unique_uids(self) -> set[str]:
        return {i.uid for i in self.invites if i.uid}


def interpret(calendars: list[ical.Comp], *, declared_method: str = "") -> ParsedCalendar:
    """Turn parsed components into interpreted invites.

    ``declared_method`` comes from the MIME layer (``method=REQUEST`` on the
    Content-Type), which some clients set while omitting the in-body METHOD.
    A disagreement between the two is itself a signal.
    """
    result = ParsedCalendar()
    body_methods: set[str] = set()
    for calendar in calendars:
        if calendar.name != "VCALENDAR":
            result.warnings.extend(calendar.warnings)
            continue
        result.warnings.extend(calendar.warnings)
        result.prodid = result.prodid or calendar.text("PRODID").strip()
        result.calendar_scale = result.calendar_scale or calendar.text("CALSCALE").strip()
        method = calendar.text("METHOD").strip().upper()
        if method:
            body_methods.add(method)
        for component in calendar.children:
            result.component_counts[component.name] = result.component_counts.get(component.name, 0) + 1
            if component.name != "VEVENT":
                continue
            result.invites.append(from_vevent(
                component,
                method=method or declared_method,
                prodid=calendar.text("PRODID").strip(),
                calendar_scale=calendar.text("CALSCALE").strip(),
                calendar=calendar,
            ))
    if declared_method:
        result.method = declared_method.upper()
    elif body_methods:
        result.method = sorted(body_methods)[0]
    if declared_method and body_methods and declared_method.upper() not in body_methods:
        result.warnings.append(
            f"Content-Type method={declared_method!r} but body METHOD={sorted(body_methods)!r}"
        )
    if len(body_methods) > 1:
        result.warnings.append(f"multiple METHOD values in one body: {sorted(body_methods)!r}")
    if not result.invites:
        result.warnings.append("calendar contains no VEVENT")
    return result
