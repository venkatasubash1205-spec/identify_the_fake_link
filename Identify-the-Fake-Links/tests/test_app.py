"""Run:  python -m unittest discover -s tests -v   (from the project root)"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import app as app_module  # noqa: E402
from url_analyzer import analyze_url  # noqa: E402

FAKE_INFO = {"ip": "93.184.216.34", "location": "X", "organization": "Y",
             "domain_age": "10 years", "domain_age_days": 3650,
             "ssl": "Valid certificate", "tls_valid": True}


class AnalyzerTests(unittest.TestCase):
    def flagged(self, url, **kw):
        return {c["label"] for c in analyze_url(url, **kw)["checks"] if c["flagged"]}

    def test_clean_url_scores_zero(self):
        self.assertEqual(analyze_url("https://www.wikipedia.org")["score"], 0)

    def test_http_flagged(self):
        self.assertIn("HTTPS", self.flagged("http://example.com"))

    def test_missing_scheme_not_penalised(self):
        self.assertNotIn("HTTPS", self.flagged("https://example.com", scheme_given=False))

    def test_ip_host(self):
        self.assertIn("IP address", self.flagged("http://192.168.1.10/login"))
        self.assertIn("IP address", self.flagged("http://3232235777/"))

    def test_at_symbol(self):
        self.assertIn("@ symbol", self.flagged("https://google.com@evil.com/"))

    def test_at_symbol_fake_domain_is_high(self):
        self.assertGreaterEqual(analyze_url("https://google.com@evil.tk/")["score"], 45)

    def test_keywords_hyphens_encoding(self):
        f = self.flagged("http://secure-login-bank.example.xyz/verify?x=%20")
        self.assertTrue({"Suspicious keywords", "Hyphens", "Encoded characters",
                         "Top-level domain"} <= f)

    def test_subdomains(self):
        self.assertIn("Subdomains", self.flagged("https://a.b.c.d.example.com"))
        self.assertNotIn("Subdomains", self.flagged("https://www.example.co.in"))

    def test_punycode(self):
        self.assertIn("Look-alike characters", self.flagged("https://xn--pypal-4ve.com"))

    def test_long_url(self):
        self.assertIn("URL length", self.flagged("https://example.com/" + "a" * 150))


@mock.patch.object(app_module, "get_domain_info", return_value=dict(FAKE_INFO))
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    def post(self, url):
        return self.client.post("/analyze", json={"url": url})

    def test_low_risk(self, _):
        r = self.post("https://www.wikipedia.org").get_json()
        self.assertEqual(r["level"], "Low")
        self.assertLess(r["score"], 30)

    def test_high_risk_phishing(self, _):
        r = self.post("http://paypa1-secure-login.verify-account.xyz/update?id=%20").get_json()
        self.assertEqual(r["level"], "High")
        self.assertGreaterEqual(r["score"], 60)
        self.assertTrue(any("impersonation" in x.lower() for x in r["reasons"]))

    def test_brand_in_subdomain(self, _):
        r = self.post("https://paypal.com.account-check.net").get_json()
        self.assertTrue(any(c["label"] == "Brand impersonation" and c["flagged"] for c in r["checks"]))

    def test_real_brand_not_flagged(self, _):
        r = self.post("https://accounts.google.com/signin").get_json()
        self.assertFalse(any(c["label"] == "Brand impersonation" and c["flagged"] for c in r["checks"]))
        self.assertEqual(r["level"], "Low")

    def test_blacklist(self, _):
        r = self.post("https://login.phishing-test.example/").get_json()
        self.assertTrue(any(c["label"] == "Blacklist" and c["flagged"] for c in r["checks"]))

    def test_medium_risk(self, _):
        r = self.post("http://192.168.1.10/login").get_json()
        self.assertEqual(r["level"], "Medium")

    def test_domain_age_penalty(self, mock_info):
        info = dict(FAKE_INFO, domain_age_days=5, domain_age="5 days")
        mock_info.return_value = info
        r = self.post("https://brand-new-site.com").get_json()
        self.assertTrue(any(c["label"] == "Domain age" and c["flagged"] for c in r["checks"]))

    def test_invalid_inputs(self, _):
        for bad in ["", "   ", "hello", "http://", "https://exa mple.com", "http://a.com:99999"]:
            self.assertEqual(self.post(bad).status_code, 400, bad)

    def test_score_capped(self, _):
        r = self.post("http://user@192.168.1.1/login-verify-secure-bank-account-update").get_json()
        self.assertLessEqual(r["score"], 100)

    def test_static_frontend_served(self, _):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/script.js").status_code, 200)
        self.assertEqual(self.client.get("/health").get_json(), {"status": "ok"})


class NetworkFailureTests(unittest.TestCase):
    def test_real_domain_info_fails_soft(self):
        from domain_info import get_domain_info
        info = get_domain_info("this-domain-does-not-exist-xyz123.invalid", "https")
        self.assertEqual(info["ip"], "Unavailable")

    def test_private_ip_not_contacted(self):
        from domain_info import get_domain_info
        with mock.patch("domain_info._tls_check") as tls:
            info = get_domain_info("127.0.0.1", "http")
            tls.assert_not_called()
        self.assertIn("Private", info["location"])


if __name__ == "__main__":
    unittest.main()
