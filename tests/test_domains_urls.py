"""Domain and URL mechanics -- the highest-leverage part of the detector."""

from __future__ import annotations

import unittest

from invite_guard import domains, urls


class RegistrableDomain(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(domains.registrable_domain("teams.microsoft.com"), "microsoft.com")
        self.assertEqual(domains.registrable_domain("a.b.c.example.com"), "example.com")

    def test_multi_label_suffixes(self):
        cases = {
            "www.bbc.co.uk": "bbc.co.uk",
            "mail.corp.com.cn": "corp.com.cn",
            "a.b.com.au": "b.com.au",
            "shop.example.co.jp": "example.co.jp",
        }
        for host, expected in cases.items():
            self.assertEqual(domains.registrable_domain(host), expected, host)

    def test_private_suffix_keeps_tenants_separate(self):
        # Two tenants of the same platform are different registrable domains.
        self.assertEqual(domains.registrable_domain("contoso.sharepoint.com"), "contoso.sharepoint.com")
        self.assertEqual(domains.registrable_domain("evil.sharepoint.com"), "evil.sharepoint.com")
        self.assertNotEqual(
            domains.registrable_domain("contoso.sharepoint.com"),
            domains.registrable_domain("evil.sharepoint.com"),
        )
        self.assertEqual(domains.registrable_domain("x.github.io"), "x.github.io")

    def test_ip_and_single_label(self):
        self.assertEqual(domains.registrable_domain("192.168.1.1"), "192.168.1.1")
        self.assertEqual(domains.registrable_domain("localhost"), "localhost")

    def test_clean_host(self):
        self.assertEqual(domains.clean_host("  TEAMS.Microsoft.COM.  "), "teams.microsoft.com")
        self.assertEqual(domains.clean_host("[::1]"), "::1")
        self.assertEqual(domains.clean_host("evil​.cn"), "evil.cn")

    def test_ip_detection(self):
        self.assertTrue(domains.is_ip("10.0.0.1"))
        self.assertTrue(domains.is_ip("::1"))
        self.assertFalse(domains.is_ip("example.com"))
        self.assertTrue(domains.is_private_ip("127.0.0.1"))
        self.assertTrue(domains.is_private_ip("169.254.1.1"))
        self.assertFalse(domains.is_private_ip("8.8.8.8"))


class Lookalikes(unittest.TestCase):
    BRANDS = {
        "microsoft": {"microsoft", "office365"},
        "zoom": {"zoom"},
        "teams": {"teams", "ms teams"},
        "examplecorp": {"examplecorp"},
    }

    class _None:
        def match(self, host):
            return False

    class _Microsoft:
        def match(self, host):
            return domains.registrable_domain(host) in {
                "microsoft.com", "zoom.us", "examplecorp.com",
            }

    def kinds(self, host, *, path=""):
        return {(l.brand, l.kind) for l in domains.find_lookalikes(
            host, brand_tokens=self.BRANDS, official=self._None(), path=path)}

    def test_brand_as_subdomain(self):
        found = self.kinds("teams.microsoft.com.secure-join.cn")
        self.assertIn(("teams", "brand_subdomain"), found)
        self.assertIn(("microsoft", "brand_subdomain"), found)

    def test_typosquat(self):
        self.assertIn(("microsoft", "typosquat"), self.kinds("microsooft.com"))
        self.assertIn(("microsoft", "typosquat"), self.kinds("rnicrosoft.com"))

    def test_combosquat(self):
        self.assertIn(("zoom", "combosquat"), self.kinds("zoom-login.top"))
        self.assertIn(("microsoft", "combosquat"), self.kinds("microsoft-verify.cn"))

    def test_legit_domains_not_flagged(self):
        # With an official matcher that knows these vendors, nothing fires.
        for host in ("microsoft.com", "zoom.us", "us02web.zoom.us",
                     "teams.microsoft.com", "office365.com", "examplecorp.com"):
            self.assertEqual(
                domains.find_lookalikes(host, brand_tokens=self.BRANDS,
                                        official=self._Microsoft()), [],
                host,
            )
        # Without it, only the structural "brand is a subdomain of a different
        # registrable domain" rule could fire -- and microsoft.com is itself a
        # brand domain, so the caller suppresses it.
        self.assertEqual(self.kinds("acme-corp.com"), set())

    def test_unrelated_domain_not_flagged(self):
        self.assertEqual(self.kinds("acme-corp.com"), set())
        self.assertEqual(self.kinds("northwind-traders.com"), set())

    def test_punycode_homograph(self):
        host = "mіcrosoft.com"  # Cyrillic i
        encoded = host.encode("idna").decode()
        self.assertIn(("microsoft", "homograph"), self.kinds(encoded))

    def test_brand_in_path_only_when_asked(self):
        self.assertIn(("microsoft", "brand_in_path"), self.kinds("evil.cn", path="/microsoft/login"))

    def test_official_matcher_suppresses(self):
        class Allow:
            def match(self, host):
                return True
        self.assertEqual(
            domains.find_lookalikes("teams.microsoft.com", brand_tokens=self.BRANDS,
                                    official=Allow()),
            [],
        )

    def test_claimed_raises_strength(self):
        weak = domains.find_lookalikes("zoom-meet.click", brand_tokens=self.BRANDS,
                                       official=self._None())
        strong = domains.find_lookalikes("zoom-meet.click", brand_tokens=self.BRANDS,
                                         official=self._None(), claimed={"zoom"})
        self.assertFalse(any(l.strong for l in weak))
        self.assertTrue(any(l.strong for l in strong))

    def test_skeleton_does_not_mutate_legit_brand(self):
        self.assertEqual(domains.skeleton("zoom"), "zoom")
        self.assertEqual(domains.skeleton("microsoft"), "microsoft")

    def test_edit_distance_early_exit(self):
        self.assertEqual(domains.levenshtein("abc", "abc"), 0)
        self.assertEqual(domains.levenshtein("abc", "abd"), 1)
        self.assertGreater(domains.levenshtein("a" * 10, "b" * 10, 2), 2)


class UrlExtraction(unittest.TestCase):
    def test_scheme_and_path(self):
        found = urls.extract("see https://teams.microsoft.com/l/meetup-join/x now", source="t")
        self.assertEqual(found[0].raw, "https://teams.microsoft.com/l/meetup-join/x")

    def test_bare_host_and_bare_www(self):
        raw = [f.raw for f in urls.extract("zoom.us/j/1 and www.example.com/a", source="t")]
        self.assertIn("zoom.us/j/1", raw)
        self.assertIn("www.example.com/a", raw)

    def test_email_is_not_a_url(self):
        self.assertEqual(urls.extract("write to cfo@contoso.com", source="t"), [])

    def test_trailing_punctuation_stripped(self):
        found = urls.extract("(see https://a.b.com/x).", source="t")
        self.assertEqual(found[0].raw, "https://a.b.com/x")

    def test_balanced_parens_kept(self):
        found = urls.extract("https://en.wikipedia.org/wiki/Foo_(bar)", source="t")
        self.assertEqual(found[0].raw, "https://en.wikipedia.org/wiki/Foo_(bar)")

    def test_html_anchors(self):
        html = ('<p>Join <a href="https://evil.cn/x">https://teams.microsoft.com/y</a></p>')
        text, hrefs = urls.html_to_text_and_hrefs(html)
        self.assertEqual(len(hrefs), 1)
        self.assertEqual(hrefs[0].raw, "https://evil.cn/x")
        self.assertIn("teams.microsoft.com", hrefs[0].anchor_text)
        self.assertIn("Join", text)

    def test_script_content_dropped_from_text(self):
        html = '<p>hi</p><script>location="https://evil.cn/x"</script>'
        text, _ = urls.html_to_text_and_hrefs(html)
        self.assertNotIn("evil", text)


class UrlAnalysis(unittest.TestCase):
    def test_userinfo_deception(self):
        parsed = urls.parse("https://teams.microsoft.com@evil.cn/x")
        self.assertEqual(parsed.host, "evil.cn")
        self.assertIsNotNone(urls.userinfo_deception(parsed))

    def test_no_userinfo_when_same_domain(self):
        parsed = urls.parse("https://a@example.com/x")
        self.assertIsNone(urls.userinfo_deception(parsed))

    def test_anchor_mismatch(self):
        target = urls.parse("https://evil.cn/x")
        reason = urls.anchor_mismatch("https://teams.microsoft.com/l/meetup-join", target)
        self.assertIsNotNone(reason)

    def test_anchor_match_is_silent(self):
        target = urls.parse("https://teams.microsoft.com/l/x")
        self.assertIsNone(urls.anchor_mismatch("https://teams.microsoft.com/l/x", target))

    def test_bare_domain_anchor_mismatch(self):
        target = urls.parse("https://evil.cn/x")
        self.assertIsNotNone(urls.anchor_mismatch("zoom.us", target))

    def test_dangerous_schemes(self):
        self.assertIsNotNone(urls.dangerous_scheme(urls.parse("javascript:alert(1)")))
        self.assertIsNotNone(urls.dangerous_scheme(urls.parse("data:text/html,<script>x</script>")))
        self.assertIsNone(urls.dangerous_scheme(urls.parse("data:image/png;base64,AAAA")))

    def test_safelinks_unwrap(self):
        wrapper = (
            "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.cn%2Fx"
            "&data=04&reserved=0"
        )
        chain = urls.unwrap_redirects(urls.parse(wrapper))
        self.assertEqual(chain[0].host, "nam12.safelinks.protection.outlook.com")
        self.assertEqual(chain[-1].host, "evil.cn")

    def test_nested_wrapper_depth_limited(self):
        inner = "https://evil.cn/x"
        for _ in range(5):
            from urllib.parse import quote
            inner = "https://nam12.safelinks.protection.outlook.com/?url=" + quote(inner, safe="")
        chain = urls.unwrap_redirects(urls.parse(inner))
        self.assertLessEqual(len(chain), 4)  # original + at most 3 unwraps

    def test_normalize_default_port(self):
        self.assertEqual(urls.normalize("https://a.com:443/x"), "https://a.com/x")
        self.assertEqual(urls.normalize("http://a.com:8080/x"), "http://a.com:8080/x")

    def test_private_ip_hint(self):
        self.assertIsNotNone(urls.ip_literal_hint(urls.parse("http://192.168.1.1/x")))
        self.assertIsNone(urls.ip_literal_hint(urls.parse("https://example.com/x")))

    def test_shortener(self):
        self.assertTrue(urls.is_shortener("bit.ly"))
        self.assertTrue(urls.is_shortener("t.co"))
        self.assertFalse(urls.is_shortener("microsoft.com"))


if __name__ == "__main__":
    unittest.main()
