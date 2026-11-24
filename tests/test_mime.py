"""MIME integration: the shape a gateway actually receives."""

from __future__ import annotations

import email
import unittest
from email.message import EmailMessage

from invite_guard import ical, mime
from invite_guard.auth import AuthResult
from invite_guard.risk import Disposition

from .test_detection import SAMPLES


def build(calendar: bytes, *, from_addr='"Contoso Finance" <cfo@contoso-finance.com>',
          subject="Q4 Financial Review") -> bytes:
    message = EmailMessage()
    message["From"] = from_addr
    message["To"] = "victim@example.com"
    message["Subject"] = subject
    message.set_content("Please see the invitation below.")
    message.add_alternative(calendar.decode("utf-8"), subtype="calendar; method=REQUEST")
    return message.as_bytes()


def run(raw: bytes) -> mime.MimeResult:
    return mime.process_message(
        raw,
        mail=mime.MailContext(from_address="cfo@contoso-finance.com",
                              auth=AuthResult(spf="pass", dkim="pass", dmarc="pass")),
    )


class MimeHandling(unittest.TestCase):
    def test_finds_calendar_inside_alternative(self):
        raw = build((SAMPLES / "benign" / "teams_external_customer.ics").read_bytes())
        result = run(raw)
        self.assertTrue(result.has_calendar)
        self.assertEqual(len(result.parts), 1)
        self.assertEqual(result.parts[0].content_type, "text/calendar")
        self.assertEqual(result.parts[0].method, "REQUEST")

    def test_benign_message_passes_through(self):
        raw = build((SAMPLES / "benign" / "zoom_external_client.ics").read_bytes())
        result = run(raw)
        self.assertTrue(result.passed_through)
        self.assertEqual(result.worst, Disposition.ALLOW)

    def test_suspicious_chroneme_rewritten_in_place(self):
        raw = build((SAMPLES / "attack" / "brand_subdomain_teams.ics").read_bytes())
        result = run(raw)
        self.assertEqual(result.worst, Disposition.QUARANTINE)
        flattened = mime.flatten(result)
        message = email.message_from_bytes(flattened)
        calendar_part = [p for p in message.walk()
                         if p.get_content_type() == "text/calendar"][0]
        event = ical.load(calendar_part.get_payload(decode=True))[0].children[0]
        self.assertEqual(event.text("STATUS"), "TENTATIVE")
        self.assertEqual(event.text("X-INVITE-GUARD-STATUS"), "HELD-FOR-REVIEW")
        self.assertEqual(calendar_part.get_content_charset(), "utf-8")

    def test_rejected_part_becomes_explanatory_text(self):
        raw = build((SAMPLES / "attack" / "internal_spoof.ics").read_bytes())
        result = mime.process_message(raw, mail=mime.MailContext(
            from_address="it-security@example.com",
            auth=AuthResult(spf="fail", dkim="fail", dmarc="fail"),
        ))
        self.assertEqual(result.worst, Disposition.REJECT)
        flattened = mime.flatten(result)
        message = email.message_from_bytes(flattened)
        types = [p.get_content_type() for p in message.walk()]
        self.assertNotIn("text/calendar", types)
        self.assertIn("text/plain", types)
        body = "\n".join(p.get_payload() for p in message.walk()
                         if p.get_content_type() == "text/plain")
        self.assertIn("removed", body.lower())

    def test_non_calendar_message_untouched(self):
        message = EmailMessage()
        message["From"] = "a@b.com"
        message["Subject"] = "hello"
        message.set_content("no calendar here")
        raw = message.as_bytes()
        result = mime.process_message(raw)
        self.assertFalse(result.has_calendar)
        self.assertEqual(mime.flatten(result), raw)

    def test_unparseable_calendar_is_flagged_not_crashed(self):
        message = EmailMessage()
        message["From"] = "a@b.com"
        message["Subject"] = "invite"
        message.set_content("x")
        message.add_alternative("NOT A CALENDAR AT ALL", subtype="calendar")
        result = mime.process_message(message.as_bytes())
        self.assertTrue(result.has_calendar)
        self.assertTrue(result.parts[0].error)

    def test_flatten_preserves_other_parts(self):
        raw = build((SAMPLES / "attack" / "brand_subdomain_teams.ics").read_bytes())
        result = run(raw)
        message = email.message_from_bytes(mime.flatten(result))
        texts = [p.get_payload() for p in message.walk()
                 if p.get_content_type() == "text/plain"]
        self.assertTrue(any("Please see the invitation" in str(t) for t in texts))

    def test_two_calendar_parts_worst_wins(self):
        message = EmailMessage()
        message["From"] = "a@b.com"
        message["Subject"] = "two"
        message.set_content("x")
        message.add_alternative(
            (SAMPLES / "benign" / "zoom_external_client.ics").read_bytes().decode(),
            subtype="calendar",
        )
        message.add_alternative(
            (SAMPLES / "attack" / "brand_subdomain_teams.ics").read_bytes().decode(),
            subtype="calendar",
        )
        result = mime.process_message(message.as_bytes())
        self.assertEqual(len(result.parts), 2)
        self.assertEqual(result.worst, Disposition.QUARANTINE)


if __name__ == "__main__":
    unittest.main()
