"""A parse that fails or is uncertain never produces
"nothing" (lenient reads plus a malformed finding), the Authentication-
Results grammar, limited analysis past the structure limits, detection
gaps in part decoding and file names, and linear cost for every reader.
Benign payloads and reserved names only."""
import base64
import json
import os
import shutil
import socket
import tempfile
import time
import tracemalloc
import unittest

from click.testing import CliRunner

from atarus_phishcheck import cli, pipeline
from atarus_phishcheck.analyzers import auth, parser

AR_FAIL = "Authentication-Results: mx.example.test; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail header.from=paypal.com\n"
LOOKALIKE = "http://paypa1-login.example/verify"


class SocketGuard(unittest.TestCase):
    def setUp(self):
        def refuse(*a, **k):
            raise AssertionError("network use in an offline test")
        for name in ("connect",):
            orig = getattr(socket.socket, name)
            setattr(socket.socket, name, refuse)
            self.addCleanup(setattr, socket.socket, name, orig)
        orig = socket.getaddrinfo
        socket.getaddrinfo = refuse
        self.addCleanup(setattr, socket, "getaddrinfo", orig)


def titles(result):
    return [f.title for f in result.findings]


def analyze(raw):
    return pipeline.analyze_raw(raw, "x.eml")


class SenderFallbackTests(SocketGuard):
    """From headers that main read correctly lost the sender, and with it
    every SPF, DKIM and DMARC failure. Scores are main's for each shape."""

    def score(self, from_value, body="hello"):
        return analyze(f"{AR_FAIL}From: {from_value}\nTo: a@example.test\nSubject: hi\n\n{body}\n")

    def test_valid_and_near_valid_from_headers_keep_the_sender(self):
        cases = [
            ("service@paypal.com (PayPal, Inc.)", "hello", 58, "service@paypal.com"),
            ("PayPal <service@paypal.com> (Support, Team)", "hello", 58, "service@paypal.com"),
            ("PayPal <service@paypal.com>,", LOOKALIKE, 100, "service@paypal.com"),
            ("PayPal <service@paypal.com>;", LOOKALIKE, 100, "service@paypal.com"),
            ("<service@paypal.com>,", "hello", 58, "service@paypal.com"),
            ("support@paypal.com <service@evil.example>", LOOKALIKE, 100, "service@evil.example"),
        ]
        for from_value, body, main_score, sender in cases:
            with self.subTest(from_value=from_value):
                result = self.score(from_value, body)
                self.assertEqual(result.headers.from_email, sender)
                self.assertEqual((result.auth.spf_result, result.auth.dmarc_result), ("fail", "fail"))
                self.assertGreaterEqual(result.phish_score, main_score)

    def test_an_address_written_as_the_display_name_is_flagged_and_checked(self):
        result = self.score("support@paypal.com <service@evil.example>", LOOKALIKE)
        self.assertIn(("Address headers are malformed", "medium"), [(f.title, f.severity) for f in result.findings])
        self.assertIn("paypal.com", result.headers.sender_candidates)
        self.assertTrue(any(t.startswith("Brand impersonation") for t in titles(result)))

    def test_reply_to_with_a_trailing_comma(self):
        result = analyze("From: a@corp.example.test\nReply-To: Support <collect@evil.example>,\nSubject: x\n\nhi\n")
        self.assertEqual(result.headers.reply_to_email, "collect@evil.example")
        self.assertIn("Reply-To address differs from From address", titles(result))
        self.assertGreaterEqual(result.phish_score, 25)  # main 25

    def test_white_space_before_the_colon(self):
        result = analyze(f"{AR_FAIL}From : PayPal <service@paypal.com>\nSubject : x\n\nhi\n")
        self.assertEqual(result.headers.from_email, "service@paypal.com")
        self.assertEqual(result.headers.subject, "x")
        self.assertIn(("Header names are malformed", "medium"), [(f.title, f.severity) for f in result.findings])
        self.assertIn("DMARC alignment failed", titles(result))

    def test_a_comment_two_thousand_levels_deep(self):
        result = self.score("PayPal <service@paypal.com> " + "(" * 2000 + ")" * 2000)
        self.assertEqual(result.headers.from_email, "service@paypal.com")
        self.assertGreaterEqual(result.phish_score, 58)

    def test_no_readable_sender_still_reads_the_recorded_failures(self):
        """Empty sender with a recorded auth failure must never score lower than main (58 here)."""
        for from_value in ("PayPal", "PayPal <>", '""@'):
            with self.subTest(from_value=from_value):
                result = self.score(from_value)
                self.assertEqual(result.headers.from_email, "")
                self.assertEqual((result.auth.spf_result, result.auth.dmarc_result), ("fail", "fail"))
                found = titles(result)
                self.assertIn("DMARC alignment failed", found)
                self.assertTrue({"Address headers are malformed", "No sender address could be read"} & set(found))
                self.assertIn("paypal.com", result.headers.sender_candidates)
                self.assertGreaterEqual(result.phish_score, 58)

    def test_missing_from_header(self):
        result = analyze(AR_FAIL + "Subject: Your PayPal account\n\nhello\n")
        self.assertIn("Message has no From header", titles(result))
        self.assertIn("DMARC alignment failed", titles(result))

    def test_brand_claim_with_no_readable_sender_is_reported(self):
        result = analyze("From: PayPal Security\nSubject: Your PayPal account\n\nverify now\n")
        self.assertTrue(any(t.startswith("Brand impersonation") for t in titles(result)))

    def test_lenient_read_finds_an_address_in_broken_syntax(self):
        result = analyze('From: "PayPal <service@evil.example>\nSubject: x\n\nhi\n')
        self.assertEqual(result.headers.from_email, "service@evil.example")
        self.assertIn(("Address headers are malformed", "medium"), [(f.title, f.severity) for f in result.findings])

    def test_ordinary_from_headers_raise_nothing(self):
        for from_value in ("Billing <billing@example.test>", '"Smith, John" <j@example.test>', "j@example.test",
                           "=?utf-8?q?Zo=C3=AB?= <z@example.test>", "J. Smith <j@example.test>"):
            with self.subTest(from_value=from_value):
                result = analyze(f"From: {from_value}\nSubject: x\n\nhi\n")
                self.assertEqual(result.headers.malformed, [])

    def test_more_mailboxes_than_are_kept(self):
        raw = "From: " + ", ".join(f"u{i}@d{i}.example.test" for i in range(1000)) + "\nSubject: x\n\nhi\n"
        result = analyze(raw)
        self.assertEqual(len(result.headers.from_addresses), parser.MAX_MAILBOXES)
        self.assertIn(f"From header names more than {parser.MAX_MAILBOXES} mailboxes", titles(result))


class AuthGrammarTests(SocketGuard):
    """A backslash outside quoted strings and comments is not an escape."""

    def test_backslash_outside_quotes_does_not_hide_a_later_result(self):
        details = auth.read_authentication_details("mx.example; spf=pass smtp.mailfrom=a\\; dmarc=fail header.from=paypal.com")
        self.assertEqual(details["results"].get("dmarc"), "fail")
        self.assertEqual(details["results"].get("spf"), "unknown")
        self.assertIsNotNone(details["malformed"])
        self.assertEqual(details["header_from"], "paypal.com")

    def test_backslash_inside_quotes_and_comments_still_escapes(self):
        details = auth.read_authentication_details('mx; spf=pass smtp.mailfrom="a\\";b"@x.test (c\\) d); dmarc=fail')
        self.assertEqual(details["results"], {"spf": "pass", "dmarc": "fail"})
        self.assertIsNone(details["malformed"])

    def test_stray_close_paren_is_malformed_for_its_segment_only(self):
        details = auth.read_authentication_details("mx; spf=pass smtp.mailfrom=a); dkim=pass; dmarc=fail")
        self.assertEqual(details["results"], {"spf": "unknown", "dkim": "pass", "dmarc": "fail"})

    def test_cascading_unclosed_openers_never_drop_a_later_segment(self):
        for value in ('mx; spf=pass smtp.mailfrom="(x; dkim=pass; dmarc=fail', '("(; spf=pass; dmarc=fail',
                      'mx; spf=pass x=' + '"(' * 5 + '; dmarc=fail'):
            with self.subTest(value=value):
                self.assertEqual(auth.read_authentication_details(value)["results"].get("dmarc"), "fail")

    def test_backslash_finding_reaches_the_report(self):
        result = analyze("From: Billing <billing@paypal.com>\nAuthentication-Results: mx.example; spf=pass smtp.mailfrom=a\\; dmarc=fail header.from=paypal.com\nSubject: x\n\nhi\n")
        self.assertIn("Authentication-Results header is malformed", titles(result))
        self.assertIn("DMARC alignment failed", titles(result))


class LimitedAnalysisTests(SocketGuard):
    """A message over the part or nesting limits still gets a report and
    a verdict; exit code 2 is kept for inputs that cannot be analysed at all."""

    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def message(self):
        return (AR_FAIL + "From: x@evil.example\nSubject: invoice\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n"
                "--b\nContent-Disposition: attachment; filename=invoice.exe\n\nMZ\n" + "--b\n\n" * (parser.MAX_PARTS + 1) + "--b--\n")

    def test_part_limit_gives_a_scored_report(self):
        result = analyze(self.message())
        self.assertIn("more than 10,000 MIME parts", result.analysis_limited)
        found = titles(result)
        for title in ("MIME structure exceeds the analysis limits", "Dangerous attachment type: invoice.exe", "DMARC alignment failed"):
            self.assertIn(title, found)
        self.assertIn(result.verdict, ("suspicious", "likely_phishing"))
        self.assertTrue(any(c.check == "Rest of the message" for c in result.checks_not_run))

    def test_limited_message_scores_at_least_75(self):
        raw = "From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n" + "--b\n\n" * (parser.MAX_PARTS + 1)
        result = analyze(raw)
        self.assertGreaterEqual(result.phish_score, 75)
        self.assertEqual(result.verdict, "likely_phishing")

    def test_cli_writes_reports_and_exits_0(self):
        path = os.path.join(self.dir, "parts.eml")
        with open(path, "w") as f:
            f.write(self.message())
        out_dir = os.path.join(self.dir, "out")
        res = CliRunner().invoke(cli.main, ["-i", path, "-o", out_dir, "--format", "all"])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertIn("Limited analysis", res.output)
        with open(os.path.join(out_dir, "phishcheck-parts.json")) as f:
            data = json.load(f)
        self.assertIn("more than 10,000 MIME parts", data["analysis_limited"])
        with open(os.path.join(out_dir, "phishcheck-parts.html")) as f:
            self.assertIn("Limited analysis", f.read())

    def test_batch_lists_it_as_analyzed_with_limits(self):
        with open(os.path.join(self.dir, "parts.eml"), "w") as f:
            f.write(self.message())
        out_dir = os.path.join(self.dir, "out")
        res = CliRunner().invoke(cli.main, ["-i", self.dir, "--batch", "-o", out_dir, "--format", "json"])
        self.assertEqual(res.exit_code, 0, res.output)
        with open(os.path.join(out_dir, "batch-summary.html")) as f:
            summary = f.read()
        self.assertIn("analyzed with limits", summary)
        self.assertNotIn("Not analyzed", summary)

    def test_nesting_limit(self):
        raw = "From: a@example.test\nSubject: x\nMIME-Version: 1.0\n"
        for i in range(parser.MAX_DEPTH + 20):
            raw += f'Content-Type: multipart/mixed; boundary="b{i}"\n\n--b{i}\n'
        raw += "Content-Type: text/plain\n\nhello\n"
        result = analyze(raw)
        self.assertIn(f"more than {parser.MAX_DEPTH} levels deep", result.analysis_limited)
        self.assertGreaterEqual(result.phish_score, 75)

    def test_empty_input_is_still_exit_2(self):
        path = os.path.join(self.dir, "empty.eml")
        open(path, "w").close()
        res = CliRunner().invoke(cli.main, ["-i", path, "--format", "terminal"])
        self.assertEqual(res.exit_code, 2)


class ParameterTests(SocketGuard):
    """Comments inside MIME parameters, and the tolerant parameter scan."""

    def attachment(self, disposition, ctype="application/octet-stream"):
        raw = f"From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: {ctype}\nContent-Disposition: {disposition}\n\nAAAA\n"
        result = analyze(raw)
        return result, result.body.attachments[0] if result.body.attachments else None

    def test_comment_before_a_filename(self):
        result, att = self.attachment('attachment; (c) filename="invoice.exe"')
        self.assertEqual(att["filename"], "invoice.exe")
        self.assertIn("Dangerous attachment type: invoice.exe", titles(result))

    def test_comment_in_a_charset(self):
        body = base64.b64encode("<a href='http://192.0.2.7/x'>x</a>".encode("utf-16")).decode()
        result = analyze(f"From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: text/html; charset=(c)utf-16\nContent-Transfer-Encoding: base64\n\n{body}\n")
        self.assertIn("http://192.0.2.7/x", result.body.urls)

    def test_tolerant_scan_finds_names_the_grammar_does_not(self):
        for disposition in ('attachment filename="invoice.exe"', 'attachment; foo=(bar; filename="invoice.exe"',
                            "attachment; filename==?utf-8?q?invoice.exe?=", 'Attac"hment; filename="invoice.exe"',
                            "attachment; filename*0=\"inv\"; filename*2=\"oice.exe\"", "attachment; filename=invoice .exe"):
            with self.subTest(disposition=disposition):
                result, att = self.attachment(disposition)
                self.assertIsNotNone(att)
                self.assertTrue(att["malformed"])
                found = titles(result)
                self.assertTrue(any(t.startswith("Attachment headers are malformed") for t in found))

    def test_hidden_name_inside_a_comment_like_run(self):
        result, att = self.attachment("a(tt=achment; filename*=utf-8''invoice.exe)")
        self.assertIsNotNone(att)
        self.assertTrue(att["malformed"])

    def test_junk_in_a_base64_encoded_word(self):
        result, att = self.attachment('attachment; filename="=?utf-8?b?aW52b2lj@ZS5leGU=?="')
        self.assertIn("invoice.exe", [att["filename"]] + att["other_names"])
        self.assertIn("Dangerous attachment type: invoice.exe", titles(result))

    def test_ordinary_parameters_raise_nothing(self):
        for disposition in ('attachment; filename="report.pdf"', "attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf",
                            'attachment; filename="report.pdf"; filename*=utf-8\'\'report.pdf', "inline",
                            'attachment;\r\n filename="=?utf-8?b?cmVwb3J0LnBkZg==?="'):
            with self.subTest(disposition=disposition):
                result, att = self.attachment(disposition)
                self.assertEqual(att["malformed"] if att else [], [])
                self.assertFalse(any("malformed" in t for t in titles(result)))


class PartDecodingTests(SocketGuard):
    """Pre-existing: a Content-Transfer-Encoding with a trailing space, a
    comment, quotes or a fold left base64 HTML undecoded, so its link was
    never seen. Second text parts and HTML attachments were never scanned."""

    LINK = "http://192.0.2.7/x"

    def html_part(self, cte):
        body = base64.b64encode(f"<a href='{self.LINK}'>x</a>".encode()).decode()
        return f"From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: text/html\nContent-Transfer-Encoding:{cte}\n\n{body}\n"

    def test_transfer_encoding_variants_are_decoded(self):
        for cte in (" base64 ", " base64 (x)", ' "base64"', "\n base64", " BASE64"):
            with self.subTest(cte=cte):
                result = analyze(self.html_part(cte))
                self.assertIn(self.LINK, result.body.urls)
                self.assertTrue(any(t.startswith("URL uses raw IP address") for t in titles(result)))

    def test_quoted_transfer_encoding_is_also_a_finding(self):
        self.assertIn("MIME part header is malformed", titles(analyze(self.html_part(' "base64"'))))

    def multipart(self, *parts):
        return ("From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n"
                + "".join(f"--b\n{p}\n" for p in parts) + "--b--\n")

    def test_second_html_part_is_scanned(self):
        result = analyze(self.multipart("Content-Type: text/html\n\n<p>hi</p>", f"Content-Type: text/html\n\n<a href='{self.LINK}'>x</a>"))
        self.assertIn(self.LINK, result.body.urls)

    def test_second_text_part_is_scanned(self):
        result = analyze(self.multipart("Content-Type: text/plain\n\nhi", f"Content-Type: text/plain\n\nsee {self.LINK}"))
        self.assertIn(self.LINK, result.body.urls)

    def test_html_attachment_is_scanned(self):
        html = (f"<form action='{self.LINK}'><input type=password></form>"
                "<a href='http://paypa1-login.example/'>https://www.paypal.com/</a> verify your account")
        result = analyze(self.multipart("Content-Type: text/plain\n\nsee attached",
                                        f"Content-Type: text/html\nContent-Disposition: attachment; filename=invoice.html\n\n{html}"))
        self.assertIn("http://paypa1-login.example/", result.body.urls)
        self.assertIn("Link text does not match URL destination", titles(result))
        self.assertEqual(result.body.html, "")  # the attachment is not shown as the message body


class FileNameTests(SocketGuard):
    """Pre-existing: an RLO, a trailing dot or a missing name hid an executable."""

    def attachment(self, disposition, ctype="application/octet-stream", payload="QUFBQQ=="):
        raw = (f"From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: {ctype}\n{disposition}"
               f"Content-Transfer-Encoding: base64\n\n{payload}\n")
        return titles(analyze(raw))

    def test_direction_override_in_a_name(self):
        found = self.attachment('Content-Disposition: attachment; filename="photo‮gpj.exe"\n')
        self.assertTrue(any(t.startswith("Attachment name holds hidden or direction-changing characters") for t in found))
        self.assertTrue(any(t.startswith("Dangerous attachment type") for t in found))
        found = self.attachment('Content-Disposition: attachment; filename="photo‮exe.jpg"\n')
        self.assertTrue(any(t.startswith("Attachment name holds hidden or direction-changing characters") for t in found))

    def test_trailing_dot_and_quotes(self):
        for name in ("invoice.exe.", "invoice.exe. . ", "'invoice.exe'"):
            with self.subTest(name=name):
                found = self.attachment(f'Content-Disposition: attachment; filename="{name}"\n')
                self.assertIn(f"Dangerous attachment type: {name.strip()}", found)

    def test_nameless_executable_by_type_or_content(self):
        self.assertTrue(any(t.startswith("Executable attachment content") for t in self.attachment("Content-Disposition: attachment\n", "application/x-msdownload")))
        self.assertTrue(any(t.startswith("Executable attachment content") for t in self.attachment("Content-Disposition: attachment\n", payload="TVqQAAMAAAAEAAAA")))

    def test_ordinary_attachment_is_quiet(self):
        found = self.attachment('Content-Disposition: attachment; filename="report.pdf"\n', "application/pdf", "JVBERi0xLjQK")
        self.assertEqual([t for t in found if "ttachment" in t], [])


def best_of(fn, runs=3):
    best = None
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        elapsed = time.perf_counter() - start
        best = elapsed if best is None else min(best, elapsed)
    return best


def peak_bytes(fn):
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class ScalingTests(SocketGuard):
    """Every reader in the parse and analysis path is timed at n and at 4n.
    Linear cost gives about 4x; a quadratic one gives 16x. The bound is 8x
    plus 50 ms, so noise does not fail it and a quadratic path does. Peak
    memory (tracemalloc) is held to 6x plus 1 MB the same way."""

    SHAPES = {
        "headers": (2000, lambda n: "".join(f"X-H{i}: v{i}\n" for i in range(n)) + "From: a@example.test\n\nhi\n"),
        "parameters": (3000, lambda n: "From: a@example.test\nMIME-Version: 1.0\nContent-Type: application/pdf\nContent-Disposition: attachment"
                       + "".join(f'; filename="f{i:07d}.pdf"' for i in range(n)) + "\n\nAAAA\n"),
        "parameters past the token cap": (20000, lambda n: "From: a@example.test\nMIME-Version: 1.0\nContent-Type: application/pdf\nContent-Disposition: attachment"
                                          + "".join(f'; filename="f{i:07d}.pdf"' for i in range(n)) + "\n\nAAAA\n"),
        "addresses": (20000, lambda n: "From: " + ", ".join(f"u{i}@d{i}.example.test" for i in range(n)) + "\n\nhi\n"),
        "display name words": (20000, lambda n: "From: " + "w " * n + "<a@example.test>\n\nhi\n"),
        "address comment depth": (20000, lambda n: "From: a@example.test " + "(" * n + ")" * n + "\n\nhi\n"),
        "parts": (500, lambda n: "From: a@example.test\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n"
                  + "--b\nContent-Type: text/plain\n\nhi\n" * n + "--b--\n"),
        "attachments": (500, lambda n: "From: a@example.test\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n"
                        + "".join(f'--b\nContent-Disposition: attachment; filename="f{i}.exe"\n\nMZ\n' for i in range(n)) + "--b--\n"),
        "links": (500, lambda n: "From: a@example.test\nSubject: x\n\n" + " ".join(f"http://h{i}.example.test/p" for i in range(n)) + "\n"),
        "unclosed anchors": (5000, lambda n: "From: a@example.test\nMIME-Version: 1.0\nContent-Type: text/html\n\n" + "<a href=http://x.example.test/>" * n + "</a>\n"),
        "received literals": (20000, lambda n: "Received: from x " + " ".join(f"[192.0.2.{i % 250}] [2001:db8::{i:x}]" for i in range(n)) + "\nFrom: a@example.test\n\nhi\n"),
        "authentication segments": (20000, lambda n: "From: a@example.test\nAuthentication-Results: mx" + "; spf=pass x=a\\" * n + "\n\nhi\n"),
        "encoded words": (20000, lambda n: "From: a@example.test\nSubject: " + "=?utf-8?q?a?= =?iso-8859-1?q?b?= " * n + "\n\nhi\n"),
        "parameter comments": (20000, lambda n: "From: a@example.test\nMIME-Version: 1.0\nContent-Type: application/pdf\nContent-Disposition: attachment; " + "(c)" * n + ' filename="a.exe"\n\nAAAA\n'),
        "raw scan past the part limit": (2000, lambda n: "From: a@example.test\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n"
                                         + "--b\n\n" * (parser.MAX_PARTS + 1)
                                         + "".join(f'--b\nContent-Disposition: attachment; filename="f{i}.exe"\nContent-Transfer-Encoding: base64\n\nTVqQAAAA\n' for i in range(n)) + "--b--\n"),
        "unclosed quotes": (20000, lambda n: "From: a@example.test\nMIME-Version: 1.0\nContent-Type: application/pdf\nContent-Disposition: attachment; x=" + '"(' * n + "\n\nAAAA\n"),
    }

    def test_each_reader_is_linear(self):
        for label, (n, build) in self.SHAPES.items():
            with self.subTest(shape=label):
                small, large = build(n), build(4 * n)
                t1 = best_of(lambda: analyze(small))
                t4 = best_of(lambda: analyze(large))
                self.assertLess(t4, 8 * t1 + 0.05, f"{label}: {t1:.3f}s at n={n}, {t4:.3f}s at 4n")
                m1, m4 = peak_bytes(lambda: analyze(small)), peak_bytes(lambda: analyze(large))
                self.assertLess(m4, 6 * m1 + (1 << 20), f"{label}: {m1 >> 10} KB peak at n={n}, {m4 >> 10} KB at 4n")

    def test_raw_scan_merge_is_linear(self):
        """Merging many short text blocks found by the raw scan into the
        body, timed alone at n and 4n blocks, all under the text budget."""
        from atarus_phishcheck.analyzers import rawscan
        from atarus_phishcheck.models import EmailBody

        def merge(n):
            found = rawscan.RawScan()
            found.text = [f"n{i:06d}" for i in range(n + 1)]
            body = EmailBody()
            rawscan.merge(body, found)
            return body

        n = 30_000
        self.assertEqual(merge(4 * n).extra_text.count("\n"), 4 * n - 1)
        t1, t4 = best_of(lambda: merge(n)), best_of(lambda: merge(4 * n))
        self.assertLess(t4, 8 * t1 + 0.05, f"{t1:.3f}s at n={n}, {t4:.3f}s at 4n")

    def test_many_filename_parameters_finish_in_seconds(self):
        """300,000 names in one part finish in seconds."""
        raw = ("From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: application/pdf\nContent-Disposition: attachment"
               + "".join(f'; filename="f{i:07d}.pdf"' for i in range(300_000)) + "\n\nAAAA\n")
        start = time.perf_counter()
        result = analyze(raw)
        self.assertLess(time.perf_counter() - start, 5.0)
        att = result.body.attachments[0]
        self.assertEqual(len([att["filename"]] + att["other_names"]), parser.MAX_NAMES)
        self.assertIn(f"Attachment gives more than {parser.MAX_NAMES} file names", titles(result))

    def test_a_million_addresses_finish_in_seconds(self):
        """A 20 MB From of 1,000,000 addresses finishes in seconds."""
        raw = "From: " + ", ".join(f"u{i}@d{i}.test" for i in range(1_000_000)) + "\nSubject: x\n\nhi\n"
        self.assertGreater(len(raw), 20_000_000)
        start = time.perf_counter()
        analyze(raw)
        self.assertLess(time.perf_counter() - start, 5.0)


if __name__ == "__main__":
    unittest.main()
