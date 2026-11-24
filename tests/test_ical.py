"""Parsing-level tests: the invariants everything else depends on."""

from __future__ import annotations

import unittest

from invite_guard import ical


class ParseBasics(unittest.TestCase):
    def test_unfolds_and_decodes_text(self):
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\n"
            "BEGIN:VEVENT\r\nUID:1\r\n"
            "DESCRIPTION:line one\\nline two\\, with comma\\; semicolon\r\n"
            " and a folded tail\r\n"
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        cal = ical.load(raw)[0]
        event = cal.children[0]
        self.assertEqual(
            event.text("DESCRIPTION"),
            "line one\nline two, with comma; semicolonand a folded tail",
        )

    def test_bare_lf_and_cr_only(self):
        for newline in ("\n", "\r", "\r\n"):
            raw = newline.join([
                "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//t//EN",
                "BEGIN:VEVENT", "UID:u1", "SUMMARY:x", "END:VEVENT", "END:VCALENDAR", "",
            ])
            cal = ical.load(raw)[0]
            self.assertEqual(cal.children[0].text("SUMMARY"), "x")

    def test_quoted_params_may_contain_colons_and_semicolons(self):
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\n"
            "BEGIN:VEVENT\r\nUID:1\r\n"
            'ATTENDEE;CN="Doe; John: Jr.";ROLE=REQ-PARTICIPANT:mailto:j@x.com\r\n'
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        prop = ical.load(raw)[0].children[0].get("ATTENDEE")
        self.assertEqual(prop.param("CN"), "Doe; John: Jr.")
        self.assertEqual(prop.text(), "mailto:j@x.com")  # callee strips mailto:

    def test_rfc6868_caret_escaping(self):
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\n"
            "BEGIN:VEVENT\r\nUID:1\r\n"
            'SUMMARY;X-NOTE="a^nb^^c^\'d":title\r\n'
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        prop = ical.load(raw)[0].children[0].get("SUMMARY")
        self.assertEqual(prop.param("X-NOTE"), 'a\nb^c"d')

    def test_nested_components(self):
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\n"
            "BEGIN:VEVENT\r\nUID:1\r\n"
            "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\n"
            "BEGIN:VALARM\r\nACTION:EMAIL\r\nTRIGGER:-PT1H\r\nEND:VALARM\r\n"
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        event = ical.load(raw)[0].children[0]
        self.assertEqual(len(list(event.descendants("VALARM"))), 2)

    def test_bare_vevent_is_wrapped(self):
        raw = "BEGIN:VEVENT\r\nUID:1\r\nSUMMARY:s\r\nEND:VEVENT\r\n"
        cal = ical.load(raw)[0]
        self.assertEqual(cal.name, "VCALENDAR")
        self.assertIn("missing VCALENDAR wrapper", cal.warnings)

    def test_utf16_input(self):
        text = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\n"
                "BEGIN:VEVENT\r\nUID:1\r\nSUMMARY:会议\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
        cal = ical.load(text.encode("utf-16"))[0]
        self.assertEqual(cal.children[0].text("SUMMARY"), "会议")

    def test_empty_input_rejected(self):
        with self.assertRaises(ical.IcalError):
            ical.load("   ")

    def test_oversized_input_rejected(self):
        with self.assertRaises(ical.IcalError):
            ical.load(b"x" * (ical.MAX_INPUT_BYTES + 1))

    def test_deep_nesting_rejected(self):
        raw = "BEGIN:VCALENDAR\r\n"
        raw += "BEGIN:X\r\n" * (ical.MAX_DEPTH + 5)
        raw += "END:VCALENDAR\r\n"
        with self.assertRaises(ical.IcalError):
            ical.load(raw)

    def test_preamble_junk_ignored(self):
        raw = (
            "This is a MIME preamble, not iCalendar.\r\n"
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\n"
            "BEGIN:VEVENT\r\nUID:1\r\nSUMMARY:s\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        cal = ical.load(raw)[0]
        self.assertEqual(cal.children[0].text("SUMMARY"), "s")


class SerialiseBasics(unittest.TestCase):
    def test_folding_roundtrip(self):
        long_value = "x" * 400
        prop = ical.Prop("DESCRIPTION", long_value)
        line = prop.serialize()
        for physical in line.split("\r\n"):
            self.assertLessEqual(len(physical.encode()), 75)
        reparsed = ical.parse_prop(line.replace("\r\n ", ""))
        self.assertEqual(reparsed.value, long_value)

    def test_folding_counts_utf8_octets(self):
        prop = ical.Prop("SUMMARY", "会议" * 80)
        for physical in prop.serialize().split("\r\n"):
            self.assertLessEqual(len(physical.encode("utf-8")), 75)

    def test_escape_roundtrip(self):
        original = "a,b;c\\d\nnewline"
        encoded = ical.escape_text(original)
        self.assertEqual(ical.unescape_text(encoded), original)

    def test_param_with_specials_is_quoted(self):
        prop = ical.Prop("ATTENDEE", "mailto:a@b.com", [("CN", ["Doe, John; Jr."])])
        line = prop.serialize()
        self.assertIn('CN="Doe, John; Jr."', line)
        reparsed = ical.parse_prop(line.replace("\r\n ", ""))
        self.assertEqual(reparsed.param("CN"), "Doe, John; Jr.")

    def test_instance_roundtrip(self):
        raw = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//EN\r\n"
            "BEGIN:VEVENT\r\nUID:1\r\nSUMMARY:会议 & things\r\n"
            "DESCRIPTION:a\\, b\\; c\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
        cal = ical.load(raw)[0]
        again = ical.load(cal.serialize())[0]
        self.assertEqual(again.children[0].text("SUMMARY"), "会议 & things")
        self.assertEqual(again.children[0].text("DESCRIPTION"), "a, b; c")

    def test_stray_end_does_not_crash(self):
        raw = "END:VEVENT\r\nBEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"
        self.assertEqual(ical.load(raw)[0].name, "VCALENDAR")


if __name__ == "__main__":
    unittest.main()
