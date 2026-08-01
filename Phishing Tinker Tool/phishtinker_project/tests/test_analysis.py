import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phishtinker.analyzers import EmailAnalysis, analyze_attachment, ScoreEngine
from phishtinker.utils.ioc import valid_ip, is_reserved_ip, defang_ip, defang_url

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "sample_phish.eml")


class TestIocUtils(unittest.TestCase):
    def test_valid_ip(self):
        self.assertTrue(valid_ip("8.8.8.8"))
        self.assertFalse(valid_ip("999.999.999.999"))

    def test_reserved_ip(self):
        self.assertTrue(is_reserved_ip("192.168.1.1"))
        self.assertFalse(is_reserved_ip("8.8.8.8"))

    def test_defang(self):
        self.assertEqual(defang_ip("1.2.3.4"), "1[.]2[.]3[.]4")
        self.assertIn("hxxp", defang_url("http://evil.com"))


class TestEmailAnalysis(unittest.TestCase):
    def setUp(self):
        self.analysis = EmailAnalysis(SAMPLE)

    def test_headers_parsed(self):
        self.assertIn("Subject", self.analysis.headers)
        self.assertEqual(self.analysis.from_domain, "paypal-secure-login.xyz")
        self.assertEqual(self.analysis.reply_to_domain, "totallynotphish.top")

    def test_auth_results(self):
        self.assertEqual(self.analysis.auth_results["spf"], "fail")
        self.assertEqual(self.analysis.auth_results["dmarc"], "fail")

    def test_ips_extracted(self):
        self.assertTrue(any(ip.startswith("192.0.2") or ip.startswith("203.0.113") for ip in self.analysis.ips))

    def test_urls_extracted(self):
        self.assertTrue(any("verify-login.php" in u for u in self.analysis.urls))


class TestScoring(unittest.TestCase):
    def test_high_risk_score(self):
        analysis = EmailAnalysis(SAMPLE)
        att_results = [analyze_attachment(a) for a in analysis.attachments]
        engine = ScoreEngine(analysis, att_results)
        # Reply-To mismatch + SPF/DMARC fail + urgency + raw IP URL should push this well into risk territory
        self.assertGreaterEqual(engine.score, 50)
        verdict, _ = engine.verdict()
        self.assertEqual(verdict, "MALICIOUS / HIGH RISK")


if __name__ == "__main__":
    unittest.main()
