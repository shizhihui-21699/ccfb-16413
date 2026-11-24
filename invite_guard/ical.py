"""A defensive, dependency-free RFC 5545 reader/writer.

This is intentionally *not* a full iCalendar implementation.  It exists to
answer one question safely: what exactly does this invitation claim, and what
does it contain?  Therefore it is tolerant (real-world clients are sloppy) and
bounded (attacker-controlled input must not be able to exhaust the process).

Supported on purpose:
  * line unfolding (CRLF + LWSP, bare LF tolerated)
  * quoted parameters, RFC 6868 caret escaping
  * TEXT value escaping, BASE64 attachments
  * nested components (VCALENDAR / VEVENT / VALARM / VTIMEZONE)
  * serialisation with 75-octet folding, so a rewritten invite is valid

Not supported: RRULE expansion, timezone database lookups, VALARM semantics.
Nothing in the risk engine needs them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_LINE_CHARS = 200_000
MAX_LOGICAL_LINES = 50_000
MAX_DEPTH = 12
MAX_COMPONENTS = 5_000
MAX_NAME_LEN = 64

_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
_ESCAPE_RE = re.compile(r"\\([\\;,nN])")


class IcalError(ValueError):
    """Raised for fatal structural problems (size, depth, empty input)."""


# --------------------------------------------------------------------------
# text helpers
# --------------------------------------------------------------------------

def decode_bytes(data: bytes) -> str:
    """Decode an iCalendar byte string without trusting the charset header."""
    if len(data) > MAX_INPUT_BYTES:
        raise IcalError(f"calendar too large: {len(data)} bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or (b"\x00" in data[:256] and len(data) > 4):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    for encoding in ("utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def unescape_text(value: str) -> str:
    """Decode RFC 5545 TEXT escapes (\\n, \\, \\; \\\\)."""
    return _ESCAPE_RE.sub(lambda m: "\n" if m.group(1) in "nN" else m.group(1), value)


def escape_text(value: str) -> str:
    """Encode a plain string as an RFC 5545 TEXT value."""
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace(";", "\\;")
        .replace(",", "\\,")
    )


def unescape_param(value: str) -> str:
    """Decode RFC 6868 parameter escaping."""
    value = value.replace("^^", "\x00").replace("^'", '"').replace("^n", "\n").replace("^N", "\n")
    return value.replace("\x00", "^")


def escape_param(value: str) -> str:
    return value.replace("^", "^^").replace('"', "^'").replace("\n", "^n")


def fold_line(line: str, limit: int = 75) -> str:
    """Fold a content line to <= *limit* octets per physical line."""
    out: list[str] = []
    current = ""
    used = 0
    for char in line:
        width = len(char.encode("utf-8"))
        # Continuation lines start with a single space, counted in the limit.
        if used + width > limit and current:
            out.append(current)
            current = " "
            used = 1
        current += char
        used += width
    out.append(current)
    return "\r\n".join(out)


def _split_unquoted(text: str, sep: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    quoted = False
    for char in text:
        if char == '"':
            quoted = not quoted
            buf.append(char)
        elif char == sep and not quoted:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return parts


def _find_separator(line: str, needle: str) -> int:
    quoted = False
    for index, char in enumerate(line):
        if char == '"':
            quoted = not quoted
        elif char == needle and not quoted:
            return index
    return -1


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return unescape_param(value)


# --------------------------------------------------------------------------
# properties and components
# --------------------------------------------------------------------------

@dataclass
class Prop:
    name: str
    value: str
    params: list[tuple[str, list[str]]] = field(default_factory=list)

    def param(self, key: str, default: str | None = None) -> str | None:
        key = key.upper()
        for name, values in self.params:
            if name.upper() == key:
                return values[0] if values else ""
        return default

    def param_list(self, key: str) -> list[str]:
        key = key.upper()
        for name, values in self.params:
            if name.upper() == key:
                return list(values)
        return []

    def set_param(self, key: str, value: str) -> None:
        key = key.upper()
        for index, (name, _values) in enumerate(self.params):
            if name.upper() == key:
                self.params[index] = (name, [value])
                return
        self.params.append((key, [value]))

    def delete_param(self, key: str) -> None:
        key = key.upper()
        self.params = [(n, v) for (n, v) in self.params if n.upper() != key]

    def text(self) -> str:
        value_type = (self.param("VALUE") or "TEXT").upper()
        if value_type in {"URI", "BINARY", "DATE", "DATE-TIME", "DURATION", "PERIOD"}:
            return self.value
        return unescape_text(self.value)

    def serialize(self) -> str:
        head = self.name
        for name, values in self.params:
            rendered = []
            for value in values:
                needs_quote = any(c in value for c in ';:,"') or value != value.strip()
                escaped = escape_param(value)
                rendered.append(f'"{escaped}"' if needs_quote else escaped)
            head += f";{name}={','.join(rendered)}"
        return fold_line(f"{head}:{self.value}")


@dataclass
class Comp:
    name: str
    props: list[Prop] = field(default_factory=list)
    children: list["Comp"] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # -- lookup ----------------------------------------------------------
    def get(self, name: str) -> Prop | None:
        upper = name.upper()
        for prop in self.props:
            if prop.name.upper() == upper:
                return prop
        return None

    def all(self, name: str) -> list[Prop]:
        upper = name.upper()
        return [p for p in self.props if p.name.upper() == upper]

    def text(self, name: str, default: str = "") -> str:
        prop = self.get(name)
        return prop.text() if prop is not None else default

    def set_text(self, name: str, value: str, *, raw: bool = False) -> Prop:
        prop = self.get(name)
        if prop is None:
            prop = Prop(name.upper(), "")
            self.props.append(prop)
        prop.value = value if raw else escape_text(value)
        return prop

    def remove(self, name: str) -> None:
        upper = name.upper()
        self.props = [p for p in self.props if p.name.upper() != upper]

    def descendants(self, name: str | None = None) -> Iterator["Comp"]:
        for child in self.children:
            if name is None or child.name.upper() == name.upper():
                yield child
            yield from child.descendants(name)

    # -- output ----------------------------------------------------------
    def serialize(self) -> str:
        lines: list[str] = [f"BEGIN:{self.name}"]
        for prop in self.props:
            lines.append(prop.serialize())
        for child in self.children:
            lines.append(child.serialize().rstrip("\r\n"))
        lines.append(f"END:{self.name}")
        return "\r\n".join(lines) + "\r\n"


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def _logical_lines(text: str) -> list[str]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    physical = text.split("\n")
    if len(physical) > MAX_LOGICAL_LINES:
        raise IcalError("too many lines")
    logical: list[str] = []
    for line in physical:
        if len(line) > MAX_LINE_CHARS:
            raise IcalError("line too long")
        if line[:1] in (" ", "\t") and logical:
            logical[-1] += line[1:]
        else:
            logical.append(line)
    return logical


def parse_prop(line: str) -> Prop | None:
    colon = _find_separator(line, ":")
    if colon <= 0:
        return None
    head, value = line[:colon], line[colon + 1:]
    segments = _split_unquoted(head, ";")
    name = segments[0].strip()
    if not name or len(name) > MAX_NAME_LEN or not _NAME_RE.match(name):
        return None
    params: list[tuple[str, list[str]]] = []
    for segment in segments[1:]:
        key, sep, raw = segment.partition("=")
        if not sep:
            continue
        key = key.strip().upper()
        if not key or len(key) > MAX_NAME_LEN:
            continue
        values = [_strip_quotes(v) for v in _split_unquoted(raw, ",")]
        params.append((key, values))
    return Prop(name.upper(), value, params)


def parse_calendars(text: str) -> list[Comp]:
    """Parse one or more VCALENDAR blocks (or a bare VEVENT) from *text*."""
    if not text or not text.strip():
        raise IcalError("empty calendar")

    roots: list[Comp] = []
    stack: list[Comp] = []
    total = 0

    for line in _logical_lines(text):
        if not line.strip():
            continue
        marker = re.match(r"(?i)^\s*(BEGIN|END)\s*:\s*([A-Za-z0-9-]+)\s*$", line)
        if marker:
            kind, name = marker.group(1).upper(), marker.group(2).upper()
            if len(name) > MAX_NAME_LEN:
                continue
            if kind == "BEGIN":
                if len(stack) >= MAX_DEPTH:
                    raise IcalError("component nesting too deep")
                component = Comp(name)
                if stack:
                    stack[-1].children.append(component)
                else:
                    roots.append(component)
                stack.append(component)
                total += 1
                if total > MAX_COMPONENTS:
                    raise IcalError("too many components")
            else:
                for depth in range(len(stack) - 1, -1, -1):
                    if stack[depth].name == name:
                        del stack[depth:]
                        break
            continue

        if not stack:
            continue  # stray property outside any component: ignore
        prop = parse_prop(line)
        if prop is not None:
            stack[-1].props.append(prop)

    if not roots:
        raise IcalError("no component found")

    # A few clients emit a bare VEVENT/VTODO without the VCALENDAR wrapper.
    wrapped: list[Comp] = []
    for root in roots:
        if root.name == "VCALENDAR":
            wrapped.append(root)
        elif root.name in {"VEVENT", "VTODO", "VFREEBUSY"}:
            calendar = Comp("VCALENDAR")
            calendar.warnings.append("missing VCALENDAR wrapper")
            calendar.children.append(root)
            wrapped.append(calendar)
        else:
            wrapped.append(root)

    for calendar in wrapped:
        if calendar.name != "VCALENDAR":
            continue
        if calendar.get("VERSION") is None:
            calendar.warnings.append("missing VERSION")
        if calendar.get("PRODID") is None:
            calendar.warnings.append("missing PRODID")
        if not calendar.children:
            calendar.warnings.append("VCALENDAR without components")
    return wrapped


def _walk_roots(roots: list[Comp]) -> Iterator[Comp]:
    for root in roots:
        yield root
        yield from root.descendants()


def load(data: bytes | str) -> list[Comp]:
    text = decode_bytes(data) if isinstance(data, bytes) else data
    return parse_calendars(text)
