"""Tests for the offline default, the network guard, input limits and wording.

Every test class that must not touch the network inherits SocketGuard, which
replaces the socket layer with functions that raise. A lookup that is not
mocked therefore fails loudly instead of quietly reaching the internet.
Standard library only.
"""
import http.server
import json
import os
import re
import shutil
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from click.testing import CliRunner

from atarus_phishcheck import __version__, cli, network, pipeline
from atarus_phishcheck.analyzers import auth, content, geoip, parser, reputation, scoring, urlexpand
from atarus_phishcheck.analyzers.sanitize import sanitize_html_for_preview
from atarus_phishcheck.models import Indicator, EmailHeaders
from atarus_phishcheck.network import Policy
from atarus_phishcheck.reports import html_report, json_export
from atarus_phishcheck.safe_output import safe_text

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
SAMPLE = os.path.join(ROOT, "examples", "sample-phish.eml")


def _blocked(*args, **kwargs):
    raise AssertionError("network use during an offline test: " + repr(args[:2]))


class SocketGuard(unittest.TestCase):
    """Any socket creation, resolution or connection fails the test."""

    def setUp(self):
        super().setUp()
        self._patches = [
            mock.patch.object(socket, "socket", side_effect=_blocked),
            mock.patch.object(socket, "create_connection", side_effect=_blocked),
            mock.patch.object(socket, "getaddrinfo", side_effect=_blocked),
            mock.patch.object(socket, "gethostbyname", side_effect=_blocked),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)


def sample_raw():
    with open(SAMPLE, errors="replace") as f:
        return f.read()


def email_with(html_body="", text_body="", extra_headers=""):
    if html_body:
        return f"From: a@example.test\nTo: b@example.test\nSubject: t\n{extra_headers}Content-Type: text/html; charset=utf-8\n\n{html_body}"
    return f"From: a@example.test\nTo: b@example.test\nSubject: t\n{extra_headers}Content-Type: text/plain; charset=utf-8\n\n{text_body}"


class AddressGuardTests(unittest.TestCase):
    def test_non_public_addresses_are_refused(self):
        for ip in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.0.9", "100.64.0.1",
                   "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1",
                   "::", "2002:0a00:0001::", "not-an-ip", ""):
            self.assertFalse(network.is_public_address(ip), ip)

    def test_public_addresses_are_accepted(self):
        for ip in ("93.184.216.34", "8.8.8.8", "2606:4700::1111", "[203.0.114.1]"):
            self.assertTrue(network.is_public_address(ip), ip)

    def test_resolution_to_private_is_refused_without_connecting(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
                 (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 80))]
        with mock.patch.object(socket, "getaddrinfo", return_value=infos), mock.patch.object(socket, "create_connection", side_effect=_blocked):
            with self.assertRaises(ValueError) as ctx:
                network.public_addresses("short.example", 80)
        self.assertIn("non-public", str(ctx.exception))

    def test_literal_private_host_refused_without_resolving(self):
        with mock.patch.object(socket, "getaddrinfo", side_effect=_blocked):
            with self.assertRaises(ValueError):
                network.public_addresses("169.254.169.254", 80)
            self.assertEqual(network.public_addresses("93.184.216.34", 80), ["93.184.216.34"])

    def test_split_url(self):
        self.assertEqual(network.split_url("https://bit.ly/abc?x=1"), ("https", "bit.ly", 443, "/abc?x=1"))
        self.assertEqual(network.split_url("http://T.CO:8080"), ("http", "t.co", 8080, "/"))
        with self.assertRaises(ValueError):
            network.split_url("ftp://example.test/x")


class OfflineDefaultTests(SocketGuard):
    """A default run sends nothing. The socket guard proves it."""

    def test_default_policy_is_offline(self):
        self.assertFalse(network.OFFLINE.online)
        self.assertFalse(network.OFFLINE.expand_links)
        self.assertEqual(Policy().mode, "offline")
        self.assertEqual(Policy().destinations(), [])

    def test_sample_analysis_makes_no_network_calls(self):
        result = pipeline.analyze_raw(sample_raw(), "sample")
        self.assertEqual(result.mode, "offline")
        self.assertEqual(result.verdict, "likely_phishing")
        self.assertEqual(result.phish_score, 100)
        checks = " | ".join(c.check for c in result.checks_not_run)
        self.assertIn("SPF and DMARC record lookup", checks)
        self.assertIn("URL shortener expansion", checks)
        self.assertIn("URLhaus reputation", checks)
        self.assertIn("IP geolocation", checks)
        self.assertIn("DKIM signature verification", checks)
        for c in result.checks_not_run:
            if "DKIM signature" in c.check:
                continue
            self.assertIn("offline", c.reason, c)
        self.assertEqual(result.auth.spf_record, "")
        self.assertFalse(result.auth.records_looked_up)

    def test_offline_run_emits_no_dns_dependent_findings(self):
        result = pipeline.analyze_raw(email_with(text_body="hello"), "x")
        titles = [f.title for f in result.findings]
        self.assertNotIn("Sender domain has no DMARC record", titles)
        self.assertEqual(result.verdict, "no_strong_indicators")

    def test_reports_list_checks_not_run_and_mode(self):
        result = pipeline.analyze_raw(sample_raw(), "sample")
        with tempfile.TemporaryDirectory() as d:
            j = json_export.generate(result, os.path.join(d, "r.json"))
            with open(j) as f:
                data = json.load(f)
            self.assertEqual(data["mode"], "offline")
            self.assertEqual(data["version"], __version__)
            self.assertTrue(any("URLhaus" in c["check"] for c in data["checks_not_run"]))
            self.assertIn("checks_not_run", data)
            h = html_report.generate(result, os.path.join(d, "r.html"))
            with open(h) as f:
                page = f.read()
            self.assertIn("Checks Not Run", page)
            self.assertIn("Mode: offline", page)
            self.assertIn("URLhaus", page)

    def test_old_signature_calls_stay_offline(self):
        headers, body = parser.parse_email(sample_raw())
        auth_result, _ = auth.check_authentication(headers)
        self.assertEqual(auth_result.spf_record, "")
        iocs = [Indicator(type="url", value="https://bit.ly/abc"), Indicator(type="ip", value="93.184.216.34")]
        self.assertEqual(urlexpand.expand_urls(iocs), ([], []))
        self.assertEqual(reputation.check_urls(iocs), [])
        self.assertEqual(geoip.lookup_ips(iocs, headers), [])

    def test_expand_links_without_online_sends_nothing(self):
        notes = []
        iocs = [Indicator(type="url", value="https://bit.ly/abc")]
        self.assertEqual(urlexpand.expand_urls(iocs, policy=Policy(online=False, expand_links=True), notes=notes), ([], []))
        self.assertEqual(len(notes), 1)
        notes = []
        self.assertEqual(urlexpand.expand_urls(iocs, policy=Policy(online=True, expand_links=False), notes=notes), ([], []))
        self.assertIn("--expand-links", notes[0][1])


class OnlineLookupTests(SocketGuard):
    """With --online the declared sinks are used (mocked here) and failures are recorded."""

    def _resolve(self, name, rdtype, lifetime=None):
        rec = mock.Mock()
        rec.strings = [b"v=spf1 -all"] if not name.startswith("_dmarc") else [b"v=DMARC1; p=none"]
        return [rec]

    def test_dns_runs_only_online_and_records_policy(self):
        headers, _ = parser.parse_email(sample_raw())
        notes = []
        with mock.patch("atarus_phishcheck.analyzers.auth.dns.resolver.resolve", side_effect=self._resolve) as resolve:
            result, findings = auth.check_authentication(headers, policy=Policy(online=True), notes=notes)
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(result.spf_record, "v=spf1 -all")
        self.assertEqual(result.dmarc_policy, "none")
        self.assertTrue(result.records_looked_up)

    def test_dns_failure_is_a_check_not_run(self):
        headers, _ = parser.parse_email(sample_raw())
        notes = []
        with mock.patch("atarus_phishcheck.analyzers.auth.dns.resolver.resolve", side_effect=TimeoutError("boom")):
            result, _ = auth.check_authentication(headers, policy=Policy(online=True), notes=notes)
        self.assertFalse(result.records_looked_up)
        self.assertTrue(any("DNS query failed" in reason for _, reason in notes))

    def test_urlhaus_failure_is_recorded_and_absence_is_not_clean(self):
        iocs = [Indicator(type="url", value="http://a.example.test/x"), Indicator(type="url", value="http://b.example.test/y")]
        answers = [mock.Mock(status_code=401, json=lambda: {}), mock.Mock(status_code=200, json=lambda: {"query_status": "no_results"})]
        notes = []
        with mock.patch("atarus_phishcheck.analyzers.reputation.requests.post", side_effect=answers) as post:
            findings = reputation.check_urls(iocs, policy=Policy(online=True), notes=notes)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(findings, [])
        self.assertEqual(iocs[0].reputation, "unknown")
        self.assertEqual(iocs[1].reputation, "not_listed")
        self.assertTrue(any("HTTP 401" in reason for _, reason in notes))
        self.assertNotIn("clean", (iocs[0].reputation, iocs[1].reputation))

    def test_malwarebazaar_online(self):
        iocs = [Indicator(type="hash", value="a" * 64)]
        answer = mock.Mock(status_code=200, json=lambda: {"query_status": "ok", "data": [{"signature": "Test", "file_type": "exe", "first_seen": "2026"}]})
        notes = []
        with mock.patch("atarus_phishcheck.analyzers.reputation.requests.post", return_value=answer):
            findings = reputation.check_hashes_malwarebazaar(iocs, policy=Policy(online=True), notes=notes)
        self.assertEqual(len(findings), 1)
        self.assertEqual(iocs[0].reputation, "malicious")

    def test_geoip_skips_private_ips_and_records_failures(self):
        headers = EmailHeaders(received_chain=["from x [10.0.0.5]", "from y [93.184.216.34]"])
        iocs = [Indicator(type="ip", value="10.0.0.5"), Indicator(type="ip", value="93.184.216.34")]
        notes = []
        answer = mock.Mock(status_code=429, json=lambda: {})
        with mock.patch("atarus_phishcheck.analyzers.geoip.requests.get", return_value=answer) as get:
            geoip.lookup_ips(iocs, headers, policy=Policy(online=True), notes=notes)
        self.assertEqual(get.call_count, 1)
        self.assertIn("93.184.216.34", get.call_args[0][0])
        self.assertTrue(any("non-public" in reason for _, reason in notes))
        self.assertTrue(any("HTTP 429" in reason for _, reason in notes))

    def test_unmocked_lookup_fails_loudly(self):
        iocs = [Indicator(type="ip", value="93.184.216.34")]
        with self.assertRaises(AssertionError):
            geoip.lookup_ips(iocs, EmailHeaders(), policy=Policy(online=True), notes=[])


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    seen = None
    location = None
    status = 302

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.seen.append((self.command, self.path, self.headers.get("Host")))
        self.send_response(self.status)
        if self.location:
            self.send_header("Location", self.location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_HEAD


class _LabServer:
    def __init__(self, location, status=302):
        self.seen = []
        handler = type("H", (_RedirectHandler,), {"seen": self.seen, "location": location, "status": status})
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class LinkExpansionTests(unittest.TestCase):
    """One HEAD to the shortener, redirect read, never followed. Uses a local server."""

    def _expand(self, location, status=302):
        server = _LabServer(location, status)
        self.addCleanup(server.close)
        iocs = [Indicator(type="url", value=f"http://bit.ly:{server.port}/short")]
        notes = []
        with mock.patch("atarus_phishcheck.analyzers.urlexpand.public_addresses", return_value=["127.0.0.1"]):
            new, findings = urlexpand.expand_urls(iocs, policy=Policy(online=True, expand_links=True), notes=notes)
        return server, new, findings, notes

    def test_one_hop_only(self):
        server, new, findings, notes = self._expand("http://second-hop.example.test/landing?token=abc")
        self.assertEqual(len(server.seen), 1)
        self.assertEqual(server.seen[0][0], "HEAD")
        self.assertEqual(server.seen[0][1], "/short")
        self.assertTrue(server.seen[0][2].startswith("bit.ly"))
        self.assertEqual([i.value for i in new if i.type == "url"], ["http://second-hop.example.test/landing?token=abc"])
        self.assertEqual(len(findings), 1)
        self.assertIn("Hops followed: 0", findings[0].evidence)
        self.assertIn("not contacted", findings[0].description)

    def test_redirect_to_metadata_address_is_flagged_and_not_contacted(self):
        with mock.patch.object(socket, "create_connection", wraps=socket.create_connection) as cc:
            server, new, findings, notes = self._expand("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(len(server.seen), 1)
        self.assertEqual(cc.call_count, 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("non-public address", findings[0].title)

    def test_relative_location_is_resolved_against_the_shortener(self):
        server, new, findings, notes = self._expand("/elsewhere")
        self.assertEqual(new[0].value, f"http://bit.ly:{server.port}/elsewhere")

    def test_no_redirect_is_reported(self):
        server, new, findings, notes = self._expand(None, status=200)
        self.assertEqual(new, [])
        self.assertIn("did not redirect", findings[0].title)

    def test_shortener_resolving_to_private_is_refused_before_any_request(self):
        iocs = [Indicator(type="url", value="https://tinyurl.com/abc")]
        notes = []
        with mock.patch("atarus_phishcheck.analyzers.urlexpand.public_addresses", side_effect=ValueError("tinyurl.com resolves to a non-public address (10.0.0.1)")), \
                mock.patch.object(socket, "create_connection", side_effect=_blocked):
            new, findings = urlexpand.expand_urls(iocs, policy=Policy(online=True, expand_links=True), notes=notes)
        self.assertEqual(new, [])
        self.assertIn("could not be expanded", findings[0].title)
        self.assertTrue(any("refused before any request" in reason for _, reason in notes))

    def test_non_shortener_urls_are_never_requested(self):
        iocs = [Indicator(type="url", value="http://phisher.example.test/login")]
        with mock.patch.object(socket, "create_connection", side_effect=_blocked), mock.patch.object(socket, "getaddrinfo", side_effect=_blocked):
            self.assertEqual(urlexpand.expand_urls(iocs, policy=Policy(online=True, expand_links=True), notes=[]), ([], []))


class CliTests(SocketGuard):
    def setUp(self):
        super().setUp()
        self.runner = CliRunner()
        self.out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.out, True)

    def test_default_is_offline_and_lists_checks_not_run(self):
        res = self.runner.invoke(cli.main, ["-i", SAMPLE, "--format", "terminal"])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertIn("Offline mode (default)", res.output)
        self.assertIn("Checks not run", res.output)
        self.assertIn("LIKELY PHISHING", res.output)
        self.assertNotIn("legitimate", res.output.lower())

    def test_offline_flag_still_accepted(self):
        res = self.runner.invoke(cli.main, ["-i", SAMPLE, "--format", "terminal", "--offline"])
        self.assertEqual(res.exit_code, 0, res.output)

    def test_expand_links_requires_online(self):
        res = self.runner.invoke(cli.main, ["-i", SAMPLE, "--format", "terminal", "--expand-links"])
        self.assertEqual(res.exit_code, 2)
        self.assertIn("--expand-links needs --online", res.output)

    def test_offline_and_online_conflict(self):
        res = self.runner.invoke(cli.main, ["-i", SAMPLE, "--format", "terminal", "--offline", "--online"])
        self.assertEqual(res.exit_code, 2)

    def test_online_prints_destinations_before_lookups(self):
        with mock.patch("atarus_phishcheck.analyzers.auth.dns.resolver.resolve", side_effect=TimeoutError("x")), \
                mock.patch("atarus_phishcheck.analyzers.reputation.requests.post", return_value=mock.Mock(status_code=503, json=lambda: {})), \
                mock.patch("atarus_phishcheck.analyzers.geoip.requests.get", return_value=mock.Mock(status_code=503, json=lambda: {})), \
                mock.patch("atarus_phishcheck.analyzers.urlexpand.public_addresses", side_effect=ValueError("no resolver in tests")):
            res = self.runner.invoke(cli.main, ["-i", SAMPLE, "--format", "json", "-o", self.out, "--online", "--expand-links"])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertIn("Online mode", res.output)
        self.assertIn("urlhaus-api.abuse.ch", res.output)
        self.assertIn("ip-api.com", res.output)
        self.assertIn("DNS resolver", res.output)
        self.assertIn("shortener", res.output)
        self.assertLess(res.output.index("Online mode"), res.output.index("Analyzing"))
        with open(os.path.join(self.out, "phishcheck-sample-phish.json")) as f:
            data = json.load(f)
        self.assertEqual(data["mode"], "online")
        self.assertIn("shortener-expansion", data["lookups_enabled"])
        reasons = " ".join(c["reason"] for c in data["checks_not_run"])
        self.assertIn("HTTP 503", reasons)
        self.assertIn("DNS query failed", reasons)
        self.assertIn("no resolver in tests", reasons)

    def test_terminal_output_neutralises_markup_and_control_characters(self):
        raw = email_with(text_body="hi", extra_headers="X-Dummy: 1\n").replace("Subject: t", "Subject: [bold red]ALERT[/] \x1b[31mred\x1b[0m ‮evil")
        path = os.path.join(self.out, "m.eml")
        with open(path, "w") as f:
            f.write(raw)
        res = self.runner.invoke(cli.main, ["-i", path, "--format", "terminal"])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertIn("[bold red]ALERT[/]", res.output)
        self.assertNotIn("\x1b[31m", res.output)
        self.assertNotIn("‮", res.output)

    def test_oversized_input_is_refused(self):
        path = os.path.join(self.out, "big.eml")
        with open(path, "wb") as f:
            f.truncate(parser.MAX_INPUT_BYTES + 1)
        res = self.runner.invoke(cli.main, ["-i", path, "--format", "terminal"])
        self.assertEqual(res.exit_code, 2)
        self.assertIn("Refused", res.output)


class InputLimitTests(SocketGuard):
    def test_body_parts_are_capped_and_recorded(self):
        big = "x" * (parser.MAX_PART_CHARS + 10)
        headers, body = parser.parse_email(email_with(text_body=big))
        self.assertEqual(len(body.text), parser.MAX_PART_CHARS)
        self.assertEqual(len(body.truncated), 1)
        result = pipeline.analyze_raw(email_with(text_body=big), "x")
        self.assertTrue(any("Full body analysis" == c.check for c in result.checks_not_run))

    def test_header_values_are_capped(self):
        headers, _ = parser.parse_email(email_with(text_body="hi", extra_headers="Reply-To: " + "a" * 10000 + "\n"))
        self.assertLessEqual(len(headers.reply_to), parser.MAX_HEADER_CHARS)

    def test_overlong_hostnames_are_skipped(self):
        raw = email_with(text_body="see http://" + "a" * 400 + ".example.test/x")
        result = pipeline.analyze_raw(raw, "x")
        self.assertFalse(any(i.type == "domain" and len(i.value) > 253 for i in result.indicators))

    def test_pathological_inputs_finish_in_bounded_time(self):
        """Inputs built to make the old regexes backtrack. The old mismatched-link
        regex took 8.9 s at 24 KB; these are 300 to 500 KB each."""
        cases = [
            "<a href='x' " * 40000,
            ("<a href='http://1.2.3.4/'>https://www.paypal.com</a>" + "<a href='x' ") * 8000,
            "<" * 300000,
            'style="' * 60000,
            "<script>" * 60000,
            '<p onx="' * 60000,
            "<img " * 60000,
            '<a href="' * 60000,
            "http://" + "a" * 300000,
        ]
        start = time.perf_counter()
        for body in cases:
            result = pipeline.analyze_raw(email_with(html_body=body), "x")
            sanitize_html_for_preview(body)
            with tempfile.TemporaryDirectory() as d:
                html_report.generate(result, os.path.join(d, "r.html"))
        text_case = email_with(text_body="a" * 300000, extra_headers="Reply-To: " + "b" * 4000 + "\n")
        pipeline.analyze_raw(text_case, "x")
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 5.0, f"pathological inputs took {elapsed:.1f}s")

    def test_detections_still_work_on_normal_html(self):
        html = ('<p style="display:none">hidden filter bait</p>'
                '<a href="http://185.234.219.45/login">https://www.paypal.com/signin</a>')
        self.assertTrue(content._hidden_text_in_html(html))
        self.assertTrue(content._mismatched_link_text(html))
        self.assertFalse(content._mismatched_link_text('<a href="https://www.paypal.com/x">https://paypal.com/x</a>'))
        self.assertFalse(content._hidden_text_in_html('<p style="color:#333">visible</p>'))
        self.assertTrue(content._hidden_text_in_html('<span style="color:#fff">' + "w" * 30 + '</span>'))


class WordingTests(unittest.TestCase):
    FORBIDDEN = ("legitimate", "safe", "clean")

    def test_verdict_text_never_says_legitimate_safe_or_clean(self):
        for verdict, text in scoring.VERDICT_TEXT.items():
            low = text.lower()
            for word in self.FORBIDDEN:
                self.assertNotIn(word, low, (verdict, word))
        for verdict in scoring.VERDICTS:
            for word in self.FORBIDDEN:
                self.assertNotIn(word, verdict)

    def test_template_has_no_legitimate_or_clean_verdict(self):
        import atarus_phishcheck
        path = os.path.join(os.path.dirname(atarus_phishcheck.__file__), "templates", "phishcheck_report.html")
        with open(path) as f:
            page = f.read().lower()
        self.assertNotIn("legitimate", page)
        self.assertNotIn("clean", page)
        self.assertIn("checks not run", page)

    def test_lowest_verdict_name(self):
        self.assertEqual(scoring.VERDICTS[0], "no_strong_indicators")
        self.assertEqual(scoring.verdict_label("no_strong_indicators"), "NO STRONG INDICATORS")

    def test_no_source_sets_a_clean_reputation(self):
        src = os.path.join(ROOT, "src", "atarus_phishcheck")
        for dirpath, _, files in os.walk(src):
            for name in files:
                if name.endswith(".py"):
                    with open(os.path.join(dirpath, name)) as f:
                        self.assertNotIn('reputation = "clean"', f.read(), name)


class NetworkTableTests(unittest.TestCase):
    def test_every_network_module_declares_its_sinks_and_the_readme_lists_them(self):
        with open(os.path.join(ROOT, "README.md")) as f:
            readme = f.read()
        self.assertIn("What this tool sends over the network", readme)
        for module in (auth, reputation, geoip, urlexpand):
            self.assertTrue(module.NETWORK, module.__name__)
            for entry in module.NETWORK:
                self.assertIn("--online", entry["when"])
        for host in ("urlhaus-api.abuse.ch", "mb-api.abuse.ch", "ip-api.com", "DNS resolver", "shortener"):
            self.assertIn(host, readme)
        for line in Policy(online=True, expand_links=True).destinations("example.test"):
            self.assertTrue(line)

    def test_user_agents_follow_the_version(self):
        for module in (reputation, geoip, urlexpand):
            self.assertEqual(module.USER_AGENT, f"atarus-phishcheck/{__version__}")


class SafeOutputTests(unittest.TestCase):
    def test_safe_text_strips_controls_and_format_characters(self):
        self.assertEqual(safe_text("a\x1b[31mb\x07c‮d​e"), "abcde")
        self.assertEqual(safe_text("keep\ttabs\nand lines"), "keep\ttabs\nand lines")
        self.assertEqual(safe_text("x" * 400, limit=10), "x" * 10 + "...")
        self.assertEqual(safe_text(None), "")


class SanitizerTests(unittest.TestCase):
    def test_allowlist_rebuild(self):
        out = sanitize_html_for_preview(
            '<base href="https://evil.example/"><form action="https://evil.example/post"><input name=p></form>'
            '<p style="background:url(https://evil.example/t.gif)">x</p><p style="color:red">y</p>'
            '<img srcset="https://evil.example/a.png 1x" src=https://evil.example/b.png>'
            '<style>body{background:url(https://evil.example/c.png)}</style>'
            '<svg><script>alert(1)</script></svg><div onmouseover="x()" title="t">z</div>'
            '<a href=" java\nscript:alert(1)">j</a><a href="https://evil.example/login?t=1">l</a>'
            'a < b <script src="https://evil.example/x.js">')
        self.assertIn("Content-Security-Policy", out)
        self.assertIn("default-src 'none'", out)
        for bad in ("<base", "<form", "<input", "<style", "<svg", "<script", "srcset", "url(", "onmouseover", "javascript:", "evil.example/c.png", "evil.example/x.js", "evil.example/t.gif"):
            self.assertNotIn(bad, out, bad)
        self.assertIn('<p style="color:red">y</p>', out)
        self.assertIn('<div title="t">z</div>', out)
        self.assertIn('data-original-href="https://evil.example/login?t=1"', out)
        self.assertIn('data-original-href="(blocked: javascript scheme)"', out)
        self.assertIn('src="#blocked-image"', out)
        self.assertIn("a &lt; b", out)

    def test_report_embeds_preview_once_escaped(self):
        result = pipeline.analyze_raw(sample_raw(), "sample")
        with tempfile.TemporaryDirectory() as d:
            h = html_report.generate(result, os.path.join(d, "r.html"))
            with open(h) as f:
                page = f.read()
        self.assertIn('sandbox=""', page)
        self.assertIn("srcdoc=\"&lt;!DOCTYPE html&gt;", page)
        self.assertNotIn("&amp;lt;!DOCTYPE", page)


class BatchTests(SocketGuard):
    def test_mbox_split_lives_under_output_and_is_removed(self):
        from atarus_phishcheck import batch
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
            mbox_path = os.path.join(src, "in.mbox")
            with open(mbox_path, "w") as f:
                for i in range(2):
                    f.write(f"From a@example.test Mon Oct 27 10:00:00 2026\n" + email_with(text_body=f"msg {i}") + "\n\n")
            results = batch.analyze_batch(mbox_path, out, "json")
            self.assertEqual(len(results), 2)
            self.assertEqual(os.listdir(src), ["in.mbox"])
            self.assertFalse([n for n in os.listdir(out) if n.startswith("mbox-split-")])
            with open(os.path.join(out, "batch-summary.html")) as f:
                page = f.read()
            self.assertIn("Offline mode", page)
            self.assertIn("NO STRONG INDICATORS", page)


if __name__ == "__main__":
    unittest.main()
