"""Detection-quality tests: every attack sample must be caught, every real
customer invitation must pass untouched.

The samples double as regression fixtures: adding a real-world invite that gets
a false positive is the cheapest way to keep the tool usable.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from invite_guard import MailContext, Policy, TrustStore, process
from invite_guard.auth import AuthResult
from invite_guard.risk import Disposition

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# These messages are assumed to arrive with failing authentication unless the
# sample is specifically about a *passing* spoof (which is the hard case).
SPOOF_SAMPLES = {
    "internal_spoof.ics", "punycode_organizer.ics", "uid_reuse_different_organizer.ics",
}


def _organizer_domain(raw: bytes) -> str:
    match = re.search(rb"ORGANIZER[^:]*:mailto:[^@\r\n]+@([^\r\n]+)", raw)
    return match.group(1).decode().strip() if match else "unknown.example"


def mail_for(name: str, raw: bytes, *, authenticated: bool | None = None) -> MailContext:
    if authenticated is None:
        authenticated = name not in SPOOF_SAMPLES
    verdict = "pass" if authenticated else "fail"
    return MailContext(
        from_address=f"organiser@{_organizer_domain(raw)}",
        from_display_name="Meeting Organiser",
        auth=AuthResult(spf=verdict, dkim=verdict, dmarc=verdict),
    )


def assess_file(path: Path, **kwargs):
    raw = path.read_bytes()
    return process(raw, mail=mail_for(path.name, raw, **kwargs))


class BenignSamples(unittest.TestCase):
    """The false-positive budget. Keep this list growing."""

    def test_every_benign_sample_is_allowed(self):
        for path in sorted((SAMPLES / "benign").glob("*.ics")):
            with self.subTest(sample=path.name):
                result = assess_file(path)
                self.assertEqual(
                    result.assessment.disposition, Disposition.ALLOW,
                    f"{path.name} was held: "
                    + "; ".join(f"{s.code}({s.weight})" for s in result.assessment.signals),
                )
                self.assertEqual(result.assessment.hard_signals, [])

    def test_benign_invite_is_delivered_unmodified(self):
        path = SAMPLES / "benign" / "zoom_external_client.ics"
        raw = path.read_bytes()
        result = process(raw, mail=mail_for(path.name, raw))
        self.assertEqual(result.output, raw)

    def test_benign_score_stays_low(self):
        for path in sorted((SAMPLES / "benign").glob("*.ics")):
            with self.subTest(sample=path.name):
                self.assertLess(assess_file(path).assessment.score, 40)

    def test_known_customer_lowers_noise(self):
        path = SAMPLES / "benign" / "zoom_external_client.ics"
        raw = path.read_bytes()
        store = TrustStore()
        store.allow_domains.add("acme-corp.com")
        result = process(raw, mail=mail_for(path.name, raw), store=store)
        self.assertNotIn("org.unknown_organizer",
                         [s.code for s in result.assessment.signals])
        self.assertTrue(result.assessment.known_customer)


class AttackSamples(unittest.TestCase):
    def test_no_attack_sample_is_allowed(self):
        for path in sorted((SAMPLES / "attack").glob("*.ics")):
            with self.subTest(sample=path.name):
                assessment = assess_file(path).assessment
                self.assertNotEqual(assessment.disposition, Disposition.ALLOW,
                                    f"{path.name} slipped through with "
                                    f"{[s.code for s in assessment.signals]}")

    def test_expected_hard_signal_present(self):
        expectations = {
            "brand_subdomain_teams.ics": "link.lookalike.brand_subdomain",
            "anchor_text_lie.ics": "link.anchor_mismatch",
            "userinfo_deception.ics": "link.userinfo_deception",
            "internal_spoof.ics": "org.internal_claim_spoofed",
            "executable_attachment.ics": "invite.attachment_type_spoof",
            "html_script_hidden_payload.ics": "link.hidden_script_redirect",
            "punycode_organizer.ics": "org.lookalike_organizer",
        }
        for name, code in expectations.items():
            with self.subTest(sample=name):
                assessment = assess_file(SAMPLES / "attack" / name).assessment
                self.assertIn(code, [s.code for s in assessment.hard_signals])

    def test_internal_impersonation_is_rejected(self):
        assessment = assess_file(SAMPLES / "attack" / "internal_spoof.ics").assessment
        self.assertEqual(assessment.disposition, Disposition.REJECT)

    def test_executable_attachment_is_rejected(self):
        assessment = assess_file(SAMPLES / "attack" / "executable_attachment.ics").assessment
        self.assertEqual(assessment.disposition, Disposition.REJECT)

    def test_rejected_invite_produces_no_output(self):
        result = assess_file(SAMPLES / "attack" / "internal_spoof.ics")
        self.assertIsNone(result.output)

    def test_shortener_is_degraded_not_delivered_clean(self):
        assessment = assess_file(SAMPLES / "attack" / "shortener_link.ics").assessment
        self.assertEqual(assessment.disposition, Disposition.PENDING)
        self.assertIn("link.shortener", [s.code for s in assessment.signals])

    def test_cancel_without_history_is_held(self):
        assessment = assess_file(SAMPLES / "attack" / "cancel_no_history.ics").assessment
        self.assertIn("invite.cancel_no_history", [s.code for s in assessment.signals])

    def test_script_redirect_found_even_though_hidden(self):
        assessment = assess_file(SAMPLES / "attack" / "html_script_hidden_payload.ics").assessment
        hosts = {link.host for link in assessment.links}
        self.assertIn("harvest-credentials.cyou", hosts)

    def test_alarm_payload_held(self):
        assessment = assess_file(SAMPLES / "attack" / "alarm_only_payload.ics").assessment
        self.assertIn("invite.alarm_attach", [s.code for s in assessment.signals])
        self.assertNotEqual(assessment.disposition, Disposition.ALLOW)


class ScoringInvariants(unittest.TestCase):
    """Properties of the scoring model itself, independent of any sample."""

    def test_hard_signal_overrides_benign_surroundings(self):
        raw = (SAMPLES / "attack" / "brand_subdomain_teams.ics").read_bytes()
        # Present it as an established, allowlisted customer with perfect auth:
        # the hard signal must still hold it.
        store = TrustStore()
        store.allow_domains.add("contoso-finance.com")
        result = process(raw, mail=MailContext(
            from_address="cfo@contoso-finance.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        ), store=store)
        self.assertNotEqual(result.assessment.disposition, Disposition.ALLOW)

    def test_known_customer_does_not_suppress_hard_signal(self):
        raw = (SAMPLES / "attack" / "userinfo_deception.ics").read_bytes()
        store = TrustStore()
        store.allow_domains.add("zoom.us")
        assessment = process(raw, mail=mail_from_zoom(), store=store).assessment
        self.assertNotEqual(assessment.disposition, Disposition.ALLOW)

    def test_score_is_sum_of_weights(self):
        assessment = assess_file(SAMPLES / "attack" / "cancel_no_history.ics").assessment
        self.assertEqual(assessment.score, sum(s.weight for s in assessment.signals))

    def test_every_signal_is_explainable(self):
        for path in sorted((SAMPLES / "attack").glob("*.ics")):
            with self.subTest(sample=path.name):
                for signal in assess_file(path).assessment.signals:
                    self.assertTrue(signal.detail.strip())
                    self.assertTrue(signal.code)


def mail_from_zoom() -> MailContext:
    return MailContext(from_address="no-reply@zoom.us",
                       auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"))


if __name__ == "__main__":
    unittest.main()


class HiddenPropertyBypasses(unittest.TestCase):
    """A link must not become invisible just by moving it to a different property."""

    TEMPLATE = (
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nMETHOD:REQUEST\r\n"
        "BEGIN:VEVENT\r\nUID:{uid}@x\r\nDTSTAMP:20251125T000000Z\r\n"
        "DTSTART:20251126T000000Z\r\nSUMMARY:Sync\r\n"
        "ORGANIZER:mailto:pm@acme-corp.com\r\n{body}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )

    def _assess(self, body, uid="hidden"):
        from invite_guard import MailContext, process
        from invite_guard.auth import AuthResult
        raw = self.TEMPLATE.format(uid=uid, body=body)
        return process(raw, mail=MailContext(
            from_address="pm@acme-corp.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        )).assessment

    def test_unknown_x_property_is_scanned(self):
        for prop in ("X-CUSTOM-JOIN-URL", "X-JOIN", "X-MEETING-LINK"):
            with self.subTest(prop=prop):
                assessment = self._assess(
                    f"{prop}:https://teams.microsoft.com.secure-join.cn/m/1")
                self.assertNotEqual(assessment.disposition, Disposition.ALLOW)
                self.assertIn("link.lookalike.brand_subdomain",
                              [s.code for s in assessment.signals])

    def test_geo_and_comment_are_scanned(self):
        for prop in ("GEO", "COMMENT", "CONTACT"):
            with self.subTest(prop=prop):
                assessment = self._assess(
                    f"{prop}:https://teams.microsoft.com.secure-join.cn/m/1")
                self.assertNotEqual(assessment.disposition, Disposition.ALLOW)

    def test_benign_unknown_property_not_flagged(self):
        assessment = self._assess("X-NOTE:please bring the slides")
        self.assertEqual(assessment.disposition, Disposition.ALLOW)

    def test_hidden_property_defanged_on_degrade(self):
        from invite_guard import MailContext, process, urls
        from invite_guard.auth import AuthResult
        raw = self.TEMPLATE.format(
            uid="hd2", body="X-CUSTOM-JOIN-URL:https://teams.microsoft.com.secure-join.cn/m/1")
        result = process(raw, mail=MailContext(
            from_address="pm@acme-corp.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass")))
        text = result.output.decode("utf-8").replace("hxxps", "https")
        self.assertEqual(urls.extract(text, source="out"), [])


class VerifiedLinkProvenance(unittest.TestCase):
    """A vendor URL typed as prose must not be treated as a real meeting link."""

    def test_anchor_text_vendor_url_is_not_verified(self):
        assessment = assess_file(SAMPLES / "attack" / "anchor_text_lie.ics").assessment
        trusted = [l for l in assessment.links if l.trusted_vendor]
        self.assertEqual(trusted, [])
        for link in assessment.links:
            if link.host == "teams.microsoft.com":
                self.assertIn("link.vendor_host_in_prose",
                              [s.code for s in link.signals])

    def test_structured_property_still_verifies(self):
        from invite_guard import MailContext, process
        from invite_guard.auth import AuthResult
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nMETHOD:REQUEST\r\n"
            "BEGIN:VEVENT\r\nUID:v@x\r\nDTSTAMP:20251125T000000Z\r\n"
            "DTSTART:20251126T100000Z\r\nSUMMARY:Sync\r\n"
            "ORGANIZER:mailto:pm@acme-corp.com\r\n"
            "URL:https://us02web.zoom.us/j/84719263501?pwd=x\r\n"
            "LOCATION:https://us02web.zoom.us/j/84719263501?pwd=x\r\n"
            "DESCRIPTION:Join: https://us02web.zoom.us/j/84719263501?pwd=x\r\n"
            "SEQUENCE:0\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        assessment = process(raw, mail=MailContext(
            from_address="pm@acme-corp.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        )).assessment
        # The structured URL earns vendor trust even though the same string
        # also appears as prose.
        self.assertIn("zoom", assessment.trusted_vendors)

    def test_same_url_prefers_authoritative_source(self):
        from invite_guard import MailContext, process
        from invite_guard.auth import AuthResult
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nMETHOD:REQUEST\r\n"
            "BEGIN:VEVENT\r\nUID:w@x\r\nDTSTAMP:20251125T000000Z\r\n"
            "DTSTART:20251126T100000Z\r\nSUMMARY:Sync\r\n"
            "ORGANIZER:mailto:pm@acme-corp.com\r\n"
            "DESCRIPTION:https://us02web.zoom.us/j/1\r\n"
            "URL:https://us02web.zoom.us/j/1\r\n"
            "SEQUENCE:0\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        assessment = process(raw, mail=MailContext(
            from_address="pm@acme-corp.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        )).assessment
        zoom_links = [l for l in assessment.links if l.host == "us02web.zoom.us"]
        self.assertEqual(len(zoom_links), 1)
        self.assertTrue(zoom_links[0].source.startswith("prop:"))


class DuplicatePropertyAndVolume(unittest.TestCase):
    """Duplicate properties and link sprays were both bypasses in review."""

    TEMPLATE = (
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nMETHOD:REQUEST\r\n"
        "BEGIN:VEVENT\r\nUID:{uid}@x\r\nDTSTAMP:20251125T000000Z\r\n"
        "DTSTART:20251126T000000Z\r\nSUMMARY:Sync\r\n"
        "ORGANIZER:mailto:pm@acme-corp.com\r\n{body}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )

    def _assess(self, body, uid="v"):
        from invite_guard import MailContext, process
        from invite_guard.auth import AuthResult
        return process(self.TEMPLATE.format(uid=uid, body=body), mail=MailContext(
            from_address="pm@acme-corp.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        )).assessment

    def test_duplicate_properties_are_all_scanned(self):
        body = "\r\n".join(
            f"COMMENT:join https://teams.microsoft.com.secure-join.cn/m/{i}"
            for i in range(5)
        )
        assessment = self._assess(body)
        suspicious = [l for l in assessment.links if l.host == "teams.microsoft.com.secure-join.cn"]
        self.assertEqual(len(suspicious), 5)

    def test_link_spray_is_caught(self):
        body = "\r\n".join(f"COMMENT:https://host{i}.evil-{i}.top/x" for i in range(10))
        assessment = self._assess(body)
        self.assertNotEqual(assessment.disposition, Disposition.ALLOW)
        self.assertIn("link.many_suspicious_hosts", [s.code for s in assessment.signals])

    def test_signal_and_score_stay_bounded(self):
        body = "\r\n".join(f"COMMENT:https://host{i}.evil-{i}.top/x" for i in range(500))
        assessment = self._assess(body)
        self.assertLessEqual(len(assessment.signals), 20)
        self.assertLess(assessment.score, 500)
        self.assertEqual(assessment.score, sum(s.weight for s in assessment.signals))


class UnverifiableClickableLink(unittest.TestCase):
    """A clickable link to an unknown host is evidence even when it looks bland."""

    def test_html_anchor_to_unknown_host_scores(self):
        from invite_guard import MailContext, process
        from invite_guard.auth import AuthResult
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nMETHOD:REQUEST\r\n"
            "BEGIN:VEVENT\r\nUID:ue@x\r\nDTSTAMP:20251125T000000Z\r\n"
            "DTSTART:20251126T100000Z\r\nSUMMARY:Meeting\r\n"
            "ORGANIZER:mailto:pm@acme-corp.com\r\n"
            'DESCRIPTION;FMTTYPE=text/html:<html><body><a href="https://join-portal.example.cn/x">'
            "Click here to join</a></body></html>\r\n"
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        assessment = process(raw, mail=MailContext(
            from_address="pm@acme-corp.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        )).assessment
        self.assertIn("link.unverified_external", [s.code for s in assessment.signals])

    def test_prose_text_link_is_not_scored_as_clickable(self):
        from invite_guard import MailContext, process
        from invite_guard.auth import AuthResult
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\nMETHOD:REQUEST\r\n"
            "BEGIN:VEVENT\r\nUID:upp@x\r\nDTSTAMP:20251125T000000Z\r\n"
            "DTSTART:20251126T100000Z\r\nSUMMARY:Meeting\r\n"
            "ORGANIZER:mailto:pm@acme-corp.com\r\n"
            "DESCRIPTION:notes at https://fabrikam.co.uk/notes/ms-sync\r\n"
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        assessment = process(raw, mail=MailContext(
            from_address="pm@acme-corp.com",
            auth=AuthResult(spf="pass", dkim="pass", dmarc="pass"),
        )).assessment
        self.assertNotIn("link.unverified_external", [s.code for s in assessment.signals])
