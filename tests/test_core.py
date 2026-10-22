"""Offline unit tests for atarus-phishcheck.

DNS lookups are patched out and no reputation services are called, so the
suite runs without network access. Standard library only.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from atarus_phishcheck.analyzers import parser, auth, indicators, content, scoring, brands, homoglyph, reputation
from atarus_phishcheck.analyzers.sanitize import sanitize_html_for_preview
from atarus_phishcheck.models import AnalysisResult
from atarus_phishcheck.reports import html_report, json_export
from atarus_phishcheck import batch

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "..", "examples", "sample-phish.eml")


def no_dns(*args, **kwargs):
    raise Exception("DNS disabled in tests")


def analyze(raw):
    headers, body = parser.parse_email(raw)
    auth_result, auth_findings = auth.check_authentication(headers)
    iocs, ioc_findings = indicators.extract_indicators(headers, body)
    findings = (auth_findings + ioc_findings + content.analyze_content(headers, body)
                + brands.check_brand_impersonation(headers, body) + homoglyph.check_homoglyphs(headers, body))
    result = AnalysisResult(source_file="sample", headers=headers, body=body, auth=auth_result)
    result.indicators = iocs
    for f in findings:
        result.add_finding(f)
    scoring.score_result(result)
    return result


@mock.patch("atarus_phishcheck.analyzers.auth.dns.resolver.resolve", side_effect=no_dns)
class SampleTests(unittest.TestCase):
    def setUp(self):
        with open(SAMPLE, errors="replace") as f:
            self.raw = f.read()

    def test_offline_sample_verdict(self, _dns):
        r = analyze(self.raw)
        self.assertEqual(r.headers.from_domain, "paypa1-verify.xyz")
        self.assertEqual((r.auth.spf_result, r.auth.dkim_result, r.auth.dmarc_result), ("fail", "fail", "fail"))
        self.assertEqual(r.verdict, "likely_phishing")
        self.assertEqual(r.phish_score, 100)
        titles = " | ".join(f.title for f in r.findings)
        self.assertIn("Brand impersonation", titles)
        self.assertIn("ASCII lookalike", titles)
        self.assertIn("raw IP address", titles)

    def test_reports(self, _dns):
        r = analyze(self.raw)
        with tempfile.TemporaryDirectory() as d:
            h = html_report.generate(r, os.path.join(d, "r.html"))
            with open(h) as f:
                self.assertIn("paypa1-verify.xyz", f.read())
            j = json_export.generate(r, os.path.join(d, "r.json"))
            with open(j) as f:
                self.assertEqual(json.load(f)["verdict"], "likely_phishing")

    def test_batch_directory_offline(self, _dns):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
            shutil.copy(SAMPLE, os.path.join(src, "a.eml"))
            results = batch.analyze_batch(src, out, "all", offline=True)
            self.assertEqual(len(results), 1)
            self.assertTrue(os.path.exists(os.path.join(out, "batch-summary.html")))


class OfflineTests(unittest.TestCase):
    def test_offline_skips_reputation_calls(self):
        with mock.patch("requests.post") as post:
            self.assertEqual(reputation.check_urls([], offline=True), [])
            self.assertEqual(reputation.check_hashes_malwarebazaar([], offline=True), [])
            post.assert_not_called()


class SanitizeTests(unittest.TestCase):
    def test_strips_active_content(self):
        out = sanitize_html_for_preview(
            '<p onclick="x()">hi</p><script>alert(1)</script>'
            '<a href="javascript:alert(1)">j</a><a href="https://evil.example/login">l</a>'
            '<img src="https://evil.example/pixel.gif">')
        self.assertNotIn("<script", out)
        self.assertNotIn("onclick", out)
        self.assertNotIn("javascript:", out)
        self.assertIn('data-original-href="https://evil.example/login"', out)
        self.assertIn("#blocked-image", out)
        self.assertNotIn('src="https://evil.example/pixel.gif"', out)


class PackagingTests(unittest.TestCase):
    def test_template_ships_inside_package(self):
        import atarus_phishcheck
        pkg = os.path.dirname(atarus_phishcheck.__file__)
        self.assertTrue(os.path.exists(os.path.join(pkg, "templates", "phishcheck_report.html")))


if __name__ == "__main__":
    unittest.main()
