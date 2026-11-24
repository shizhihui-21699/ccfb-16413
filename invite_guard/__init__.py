"""invite_guard -- calendar-invitation phishing defence for mail gateways.

Pipeline:  bytes -> ical.parse -> model.interpret -> risk.analyze -> sanitize.render

    from invite_guard import process, MailContext
    result = process(raw_ics, MailContext(from_address="a@b.com"))
    result.assessment.disposition   # ALLOW / PENDING / QUARANTINE / REJECT
    result.output                   # rewritten .ics, or None when not delivered
"""

from .auth import AuthResult, parse_authentication_results
from .model import Invite, ParsedCalendar, interpret
from .policy import Organisation, Policy, Vendor
from .risk import Assessment, Disposition, MailContext, Signal, analyze, record_outcome
from .trust import TrustStore
from . import ical

__all__ = [
    "AuthResult", "Assessment", "Disposition", "Invite", "MailContext",
    "Organisation", "ParsedCalendar", "Policy", "Signal", "TrustStore",
    "Vendor", "analyze", "interpret", "parse_authentication_results",
    "process", "record_outcome", "ical",
]

__version__ = "1.0.0"


def process(raw, *, mail=None, policy=None, store=None, rewrite=True, remember=False):
    """Full pipeline: parse, assess, optionally rewrite.

    Returns an object with ``assessment``, ``calendar``, ``formatted`` and
    ``output`` (bytes, or None when nothing should be delivered).
    """
    from .sanitize import ProcessResult, render

    original = raw.encode("utf-8", "replace") if isinstance(raw, str) else raw
    calendars = ical.load(raw) if isinstance(raw, (bytes, str)) else raw
    calendar = interpret(calendars, declared_method=(mail.declared_method if mail else ""))
    assessment = analyze(calendar, mail=mail, policy=policy, store=store)
    if not rewrite:
        output = None
    elif assessment.disposition is Disposition.ALLOW:
        # A clean invite is forwarded byte-for-byte.  Re-serialising it would
        # discard vendor- or client-specific formatting for no benefit.
        output = original
    else:
        output = render(calendar, assessment)
    if remember and store is not None and calendar.primary is not None:
        # Persist the UID so a later update/cancel can be tied to this delivery.
        record_outcome(calendar.primary, assessment, store=store, policy=policy)
    return ProcessResult(calendar=calendar, assessment=assessment, output=output)
