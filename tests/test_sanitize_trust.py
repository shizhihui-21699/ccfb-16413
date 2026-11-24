"""How a held invite is rewritten, and what cross-message state catches."""

from __future__ import annotations

import unittest

from invite_guard import ical, process
from invite_guard.sanitize import (
    BANNER_PREFIX, HASH_PROP, LINKS_PROP, STATUS_PROP, defang, render,
)

from .test_detection import SAMPLES, assess_file, mail_for


class Defang(unittest.TestCase):
    def test_schemes_and_dots(self):
        self.assertEqual(
            defang("https://teams.microsoft.com.secure-join.cn/meet/1"),
            "hxxps[://]teams[.]microsoft[.]com[.]secure-join[.]cn/meet/1",
        )

    def test_http_and_at(self):
        self.assertEqual(defang("http://a@b.cn/x"), "hxxp[://]a[@]b[.]cn/x")

    def test_results_are_not_linkified(self):
        # Nothing in the output should parse back as a URL.
        from invite_guard import urls
        self.assertEqual(urls.extract(defang("https://evil.cn/x"), source="t"), [])


class DegradedRender(unittest.TestCase):
    def setUp(self):
        path = SAMPLES / "attack" / "brand_subdomain_teams.ics"
        raw = path.read_bytes()
        self.result = process(raw, mail=mail_for(path.name, raw))
        self.assessment = self.result.assessment
        self.event = ical.load(self.result.output)[0].children[0]

    def test_status_and_marker_properties(self):
        self.assertEqual(self.event.text(STATUS_PROP), "HELD-FOR-REVIEW")
        self.assertEqual(self.event.text("STATUS"), "TENTATIVE")
        self.assertEqual(self.event.text("TRANSP"), "TRANSPARENT")

    def test_summary_is_bannered(self):
        self.assertTrue(self.event.text("SUMMARY").startswith(BANNER_PREFIX))

    def test_alarms_are_removed(self):
        self.assertEqual(list(self.event.descendants("VALARM")), [])

    def test_bad_properties_dropped(self):
        for name in ("URL", "CONFERENCE", "X-MICROSOFT-SKYPETEAMSMEETINGURL"):
            self.assertIsNone(self.event.get(name), name)

    def test_location_is_defanged(self):
        location = self.event.text("LOCATION")
        self.assertNotIn("https://", location)
        self.assertIn("[.]", location)

    def test_description_warns_in_both_languages(self):
        description = self.event.text("DESCRIPTION")
        self.assertIn("未能通过安全校验", description)
        self.assertIn("could not be verified", description)
        self.assertIn("hxxps[://]", description)

    def test_blocked_links_are_recorded(self):
        self.assertIn("secure-join", self.event.text(LINKS_PROP))
        self.assertNotIn("https://", self.event.text(LINKS_PROP))

    def test_original_hash_present(self):
        self.assertEqual(len(self.event.text(HASH_PROP)), 64)

    def test_output_is_valid_icalendar(self):
        reparsed = ical.load(self.result.output)[0]
        self.assertEqual(reparsed.name, "VCALENDAR")
        self.assertEqual(reparsed.text("VERSION"), "2.0")
        self.assertEqual(reparsed.children[0].text("UID"),
                         "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d")

    def test_no_executable_url_survives(self):
        from invite_guard import urls
        text = self.result.output.decode("utf-8")
        for found in urls.extract(text.replace("hxxps", "https"), source="out"):
            self.fail(f"output still contains a live URL: {found.raw}")


class VerifiedLinkSurvives(unittest.TestCase):
    """A genuine vendor link inside a held invite stays usable."""

    def test_real_zoom_link_is_kept(self):
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nMETHOD:REQUEST\r\n"
            "BEGIN:VEVENT\r\nUID:u-1\r\nDTSTAMP:20251125T000000Z\r\n"
            "DTSTART:20251126T100000Z\r\n"
            "SUMMARY:Sync\r\n"
            "ORGANIZER;CN=Partner:mailto:pm@acme-corp.com\r\n"
            "ATTENDEE:mailto:victim@example.com\r\n"
            "URL:https://us02web.zoom.us/j/84719263501?pwd=x\r\n"
            "LOCATION:https://us02web.zoom.us/j/84719263501?pwd=x\r\n"
            "DESCRIPTION:Join: https://us02web.zoom.us/j/84719263501?pwd=x\r\n"
            "  Backup: https://bit.ly/xyz\r\n"
            "SEQUENCE:0\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        from invite_guard import MailContext
        from invite_guard.auth import AuthResult
        result = process(raw, mail=MailContext(
            from_address="pm@acme-corp.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        ))
        self.assertNotEqual(result.assessment.disposition.name, "ALLOW")
        event = ical.load(result.output)[0].children[0]
        self.assertEqual(event.text("URL"), "https://us02web.zoom.us/j/84719263501?pwd=x")


class HtmlBody(unittest.TestCase):
    def test_html_description_is_sanitised_not_deleted(self):
        path = SAMPLES / "attack" / "html_script_hidden_payload.ics"
        raw = path.read_bytes()
        output = process(raw, mail=mail_for(path.name, raw)).output
        text = output.decode("utf-8").replace("\r\n ", "")
        self.assertIn("harvest-credentials", text)   # evidence is kept...
        self.assertIn("hxxp", text.lower())          # ...but defanged
        self.assertNotIn('href="https://', text)

    def test_script_removed_from_delivered_body(self):
        path = SAMPLES / "attack" / "html_script_hidden_payload.ics"
        raw = path.read_bytes()
        output = process(raw, mail=mail_for(path.name, raw)).output.decode("utf-8")
        self.assertNotIn("<script", output.lower())


class History(unittest.TestCase):
    def setUp(self):
        self.raw = (SAMPLES / "benign" / "zoom_external_client.ics").read_bytes()
        self.mail = mail_for("zoom_external_client.ics", self.raw)

    def test_sequence_regression_flagged(self):
        from invite_guard import TrustStore
        from invite_guard.risk import record_outcome
        store = TrustStore()
        newer = self.raw.replace(b"SEQUENCE:0", b"SEQUENCE:5")
        first = process(newer, mail=self.mail, store=store)
        record_outcome(first.calendar.primary, first.assessment, store=store)

        # An attacker replays the same UID with a *lower* SEQUENCE, which many
        # clients will still apply.
        older = self.raw.replace(b"SEQUENCE:0", b"SEQUENCE:1")
        assessment = process(older, mail=self.mail, store=store).assessment
        self.assertIn("invite.sequence_regression",
                      [s.code for s in assessment.signals])

    def test_unknown_uid_update_is_flagged(self):
        from invite_guard import TrustStore
        store = TrustStore()
        updated = self.raw.replace(b"SEQUENCE:0", b"SEQUENCE:5")
        assessment = process(updated, mail=self.mail, store=store).assessment
        self.assertIn("org.unknown_organizer", [s.code for s in assessment.signals])

    def test_cancel_for_known_meeting_is_not_flagged(self):
        from invite_guard import TrustStore
        from invite_guard.risk import record_outcome
        store = TrustStore()
        first = process(self.raw, mail=self.mail, store=store)
        record_outcome(first.calendar.primary, first.assessment, store=store)

        cancel = (self.raw
                  .replace(b"METHOD:REQUEST", b"METHOD:CANCEL")
                  .replace(b"STATUS:CONFIRMED", b"STATUS:CANCELLED")
                  .replace(b"SEQUENCE:1", b"SEQUENCE:2")
                  .replace(b"https://us02web.zoom.us/j/84719263501?pwd=aBcDeF123", b"Zoom"))
        assessment = process(cancel, mail=self.mail, store=store).assessment
        self.assertNotIn("invite.cancel_no_history",
                         [s.code for s in assessment.signals])

    def test_store_roundtrip_on_disk(self):
        import tempfile
        from invite_guard import TrustStore
        from invite_guard.risk import record_outcome
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/trust.json"
            store = TrustStore.load(path)
            result = process(self.raw, mail=self.mail, store=store)
            record_outcome(result.calendar.primary, result.assessment, store=store)
            store.save()
            reloaded = TrustStore.load(path)
            self.assertIn("zoom-meeting-84719263501@zoom.us", reloaded.uids)
            self.assertIn("acme-corp.com", reloaded.domains)

    def test_corrupt_store_degrades_to_empty(self):
        import tempfile
        from invite_guard import TrustStore
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write("{not json")
            path = handle.name
        store = TrustStore.load(path)
        self.assertEqual(store.uids, {})
        self.assertEqual(store.domains, {})


if __name__ == "__main__":
    unittest.main()


class RegressionFixes(unittest.TestCase):
    """Bugs found in review; each test fails against the buggy version."""

    def _degrade(self, body: str):
        from invite_guard import MailContext, process
        from invite_guard.auth import AuthResult
        ics = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nMETHOD:REQUEST\r\n"
            "BEGIN:VEVENT\r\nUID:rg@x\r\nDTSTAMP:20251125T000000Z\r\n"
            "DTSTART:20251126T000000Z\r\nSUMMARY:Q4 review\r\n"
            "ORGANIZER:mailto:pm@acme-corp.com\r\n"
            "LOCATION:https://teams.microsoft.com.secure-join.cn/m/1\r\n"
            + body + "\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        return process(ics, mail=MailContext(
            from_address="pm@acme-corp.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        ))

    def test_attachments_are_actually_removed(self):
        result = self._degrade(
            "DESCRIPTION:see attached\r\n"
            "ATTACH;FMTTYPE=application/pdf:https://evil.cn/a.pdf"
        )
        event = ical.load(result.output)[0].children[0]
        self.assertIsNone(event.get("ATTACH"))

    def test_decoded_description_is_re_escaped(self):
        # A decoded description has real newlines; writing it raw produced an
        # invalid content line and truncated the body at the first newline.
        result = self._degrade(
            r"DESCRIPTION:Agenda: a\, b\; c\ndetails here\nmore"
        )
        output = result.output.decode("utf-8")
        self.assertNotIn("\n", output.replace("\r\n", ""))  # no bare LF
        event = ical.load(result.output)[0].children[0]
        description = event.text("DESCRIPTION")
        self.assertIn("details here", description)
        self.assertIn("more", description)

    def test_attachment_note_survives_roundtrip(self):
        result = self._degrade(
            "DESCRIPTION:x\r\nATTACH;FMTTYPE=application/pdf:https://evil.cn/a.pdf"
        )
        event = ical.load(result.output)[0].children[0]
        self.assertIn("Attachments removed", event.text("DESCRIPTION"))


class SanitisedOutputIsInert(unittest.TestCase):
    """The rewritten artefact must carry no live threat, even if rescanned."""

    def test_degraded_output_has_no_live_links(self):
        from invite_guard import MailContext, process, urls
        from invite_guard.auth import AuthResult
        for name in ("brand_subdomain_teams.ics", "anchor_text_lie.ics",
                     "userinfo_deception.ics", "outlook_props_fake_domain.ics"):
            with self.subTest(sample=name):
                raw = (SAMPLES / "attack" / name).read_bytes()
                result = process(raw, mail=MailContext(
                    from_address="o@example.net",
                    auth=AuthResult(spf="pass", dkim="pass", dmarc="pass")))
                self.assertIsNotNone(result.output)
                self.assertEqual(urls.extract(result.output.decode("utf-8"), source="o"), [])

    def test_rescanning_a_degraded_invite_finds_nothing_dangerous(self):
        # Idempotency: sanitising twice is stable, because the first pass already
        # removed every actionable element.
        from invite_guard import MailContext, process
        from invite_guard.auth import AuthResult
        raw = (SAMPLES / "attack" / "brand_subdomain_teams.ics").read_bytes()
        mail = MailContext(from_address="o@contoso-finance.com",
                           auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"))
        first = process(raw, mail=mail)
        second = process(first.output, mail=mail)
        self.assertEqual(second.assessment.disposition.name, "ALLOW")
        self.assertEqual(second.assessment.hard_signals, [])
