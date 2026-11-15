"""Regression tests for hostile input.

Every input here is benign data shaped to break a parser or mislead a
verdict. Nothing touches the network: SocketGuard makes any socket use fail.
Standard library only.
"""
import email.header
import email.message
import email.policy
import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from click.testing import CliRunner

from atarus_phishcheck import cli, pipeline
from atarus_phishcheck.analyzers import parser

from test_safe_default import SocketGuard, SAMPLE


def encoded_words(n):
    return "=?utf-8?q?a?= " * n


class LibraryHeaderWork:
    """Counts every call into the standard library paths whose cost grows
    faster than linearly with one header: the structured header parser of
    the default email policy and the RFC 2047 decoder in email.header.
    The analysis must never reach them; it decodes headers itself."""

    TARGETS = (
        (email.policy.EmailPolicy, "header_fetch_parse"),
        (email.policy.EmailPolicy, "header_source_parse"),
        (email.header, "decode_header"),
        (email.header, "make_header"),
        (email.message.Message, "get_filename"),
        (email.message.Message, "get_content_charset"),
    )

    def __enter__(self):
        self.calls = 0
        self.patches = []
        for owner, name in self.TARGETS:
            original = getattr(owner, name)

            def counted(*args, _original=original, **kwargs):
                self.calls += 1
                return _original(*args, **kwargs)
            p = mock.patch.object(owner, name, counted)
            p.start()
            self.patches.append(p)
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()


class HeaderCostTests(SocketGuard):
    """32,000 encoded words in a 450 KB Subject used 7.5 GB under the
    default email policy. A pre-pass that cut headers before parsing could
    be walked around (U+2028 or U+0085 inside the header, a line of white
    space, folded lines) and hid attachment names and links. Now the
    library never parses or decodes a header; the analysis reads every
    header in full with linear routines."""

    SHAPES = {
        "one line": "Subject: " + encoded_words(8000) + "\n",
        "U+2028 breaks": "Subject: " + (" ".join(encoded_words(400) for _ in range(20))) + "\n",
        "U+0085 breaks": "Subject: " + ("\u0085".join(encoded_words(400) for _ in range(20))) + "\n",
        "white space line": "Subject: x\n \n" + "".join(" " + encoded_words(400) + "\n" for _ in range(20)),
        "folded": "Subject: x\n" + "".join(" " + encoded_words(400) + "\n" for _ in range(20)),
    }

    def test_storm_shapes_never_reach_the_library_header_parser(self):
        for label, subject in self.SHAPES.items():
            raw = ("From: a@example.test\n" + subject + "MIME-Version: 1.0\n"
                   'Content-Type: multipart/mixed; boundary="q"\n\n'
                   "--q\nContent-Type: text/plain\nX-Junk: " + encoded_words(8000) + "\n\nhello\n--q--\n")
            with LibraryHeaderWork() as work:
                result = pipeline.analyze_raw(raw, "x")
            self.assertEqual(work.calls, 0, label)
            self.assertEqual(result.headers.from_domain, "example.test", label)
            self.assertEqual(result.body.text.strip(), "hello", label)
            self.assertGreaterEqual(result.headers.subject.count("a"), 8000, label)

    def test_encoded_words_are_decoded_in_full(self):
        raw = "From: a@example.test\nSubject: " + encoded_words(8000) + "=?utf-8?q?urgent_wire_transfer?=\n\nhi\n"
        start = time.perf_counter()
        result = pipeline.analyze_raw(raw, "x")
        self.assertLess(time.perf_counter() - start, 10.0)
        self.assertTrue(result.headers.subject.endswith("urgent wire transfer"))

    def test_many_parts_with_encoded_parameters_with_wide_margin(self):
        """1,200 parts each carrying 8 KB of encoded words in Content-Type
        and Content-Disposition took 20 to 54 s; now about 0.2 s, so a
        10 s bound leaves a factor of 50 either way. Every part is read."""
        part = ('--q\nContent-Type: text/plain; name="' + encoded_words(570) + '"\n'
                'Content-Disposition: attachment; filename="' + encoded_words(560) + 'x.exe"\n\nx\n')
        raw = ("From: a@example.test\nSubject: x\nMIME-Version: 1.0\n"
               'Content-Type: multipart/mixed; boundary="q"\n\n' + part * 1200 + "--q--\n")
        start = time.perf_counter()
        result = pipeline.analyze_raw(raw, "x")
        self.assertLess(time.perf_counter() - start, 10.0)
        self.assertEqual(len(result.body.attachments), 1200)
        self.assertTrue(all(a["filename"].endswith("x.exe") for a in result.body.attachments))

    def test_attachment_hashes_come_from_one_parse(self):
        raw = ("From: a@example.test\nSubject: x\nMIME-Version: 1.0\n"
               'Content-Type: multipart/mixed; boundary="q"\n\n--q\nContent-Type: text/plain\n\nhi\n'
               '--q\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="a.bin"\n'
               "Content-Transfer-Encoding: base64\n\naGVsbG8=\n--q--\n")
        result = pipeline.analyze_raw(raw, "x")
        hashes = {i.value for i in result.indicators if i.type == "hash"}
        self.assertIn("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hashes)
        self.assertIn("5d41402abc4b2a76b9719d911017c592", hashes)


def titles(result):
    return " | ".join(f.title for f in result.findings)


class HiddenContentTests(SocketGuard):
    """Nothing in a header or a body may be dropped before detection runs."""

    PAD = "A" * 2100

    def exe_part(self, headers):
        return multipart(headers)

    def test_padding_before_a_filename_does_not_hide_it(self):
        shapes = [
            'Content-Type: application/octet-stream\nContent-Disposition: attachment;\n x-pad="' + self.PAD + '";\n filename="invoice.pdf.exe"',
            'Content-Type: application/octet-stream\nContent-Disposition: attachment; x-pad="' + self.PAD * 10 + '"; filename="invoice.pdf.exe"',
            'Content-Type: application/x-msdownload; x-pad="' + self.PAD + '"; name="invoice.pdf.exe"',
            "Content-Type: application/octet-stream\nContent-Disposition: attachment;\n" + "".join(" x%d=y;\n" % i for i in range(3000)) + ' filename="invoice.pdf.exe"',
            "Content-Type: application/octet-stream\nContent-Disposition: attachment; filename*0*=utf-8''invoice.pdf; filename*1=\".exe\"",
            "Content-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"=?utf-8?q?invoice=2Epdf?= =?utf-8?b?LmV4ZQ==?=\"",
        ]
        for headers in shapes:
            result = pipeline.analyze_raw(self.exe_part(headers), "x")
            found = titles(result)
            self.assertIn("Dangerous attachment type: invoice.pdf.exe", found, headers[:80])
            self.assertIn("Double extension attachment: invoice.pdf.exe", found, headers[:80])

    def test_a_second_name_on_the_part_is_checked_too(self):
        result = pipeline.analyze_raw(multipart('Content-Type: application/octet-stream; name="payload.scr"\nContent-Disposition: attachment; filename="report.pdf"'), "x")
        self.assertIn("Dangerous attachment type: payload.scr", titles(result))

    def test_body_lines_starting_with_dashes_stay_body(self):
        link = "http://login.paypa1-verify.example/reset"
        single = "From: a@example.test\nSubject: x\n\nHello,\n--\n" + "x" * 2100 + " " + link + "\n"
        self.assertIn(link, pipeline.analyze_raw(single, "x").body.urls)
        forwarded = ("From: a@example.test\nSubject: fwd\n\nsee below\n\n-----Original Message-----\n"
                     "From: b@example.test\n" + "word " * 600 + "https://www.example.net/agenda\n")
        result = pipeline.analyze_raw(forwarded, "x")
        self.assertIn("https://www.example.net/agenda", result.body.urls)
        self.assertFalse(any("header" in c.reason and "cut" in c.reason for c in result.checks_not_run))

    def test_attachment_hash_is_of_the_bytes_as_given(self):
        payload = b"--x\n" + b"y" * 3200 + b"\nlatin1 \xe9\xe8 bytes\n"
        raw = (b"From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"q\"\n\n"
               b"--q\nContent-Type: text/plain\n\nsee file\n--q\nContent-Type: application/javascript\n"
               b"Content-Disposition: attachment; filename=\"run.js\"\nContent-Transfer-Encoding: 8bit\n\n" + payload + b"\n--q--\n")
        result = pipeline.analyze_raw(raw, "x")
        self.assertEqual(result.body.attachments[0]["sha256"], hashlib.sha256(payload).hexdigest())

    def test_padding_before_the_from_address_does_not_hide_it(self):
        raw = 'From: "' + "a" * 20000 + '" <billing@paypa1.example>\nSubject: x\n\nhi\n'
        self.assertEqual(pipeline.analyze_raw(raw, "x").headers.from_domain, "paypa1.example")
        raw = "From: =?utf-8?q?service=40paypal=2Ecom_=3Cx=40y=2Etest=3E?= <attacker@evil.test>\nSubject: x\n\nhi\n"
        self.assertEqual(pipeline.analyze_raw(raw, "x").headers.from_email, "attacker@evil.test")

    def test_long_values_are_shown_cut_and_marked(self):
        from atarus_phishcheck.reports import json_export
        raw = "From: a@example.test\nSubject: " + "s" * 9000 + " urgent\n\nhi\n"
        result = pipeline.analyze_raw(raw, "x")
        self.assertTrue(result.headers.subject.endswith("urgent"))
        with tempfile.TemporaryDirectory() as d:
            path = json_export.generate(result, os.path.join(d, "r.json"))
            with open(path) as f:
                shown = json.load(f)["headers"]["subject"]
        self.assertIn("shown cut at 4,096 of 9,007 characters; all of it was analysed", shown)


class PartLimitTests(SocketGuard):
    """Every MIME part is inspected; a message with more parts than the
    limit, or nested deeply over many lines, is refused instead of being
    analysed with parts left out."""

    def test_an_executable_after_hundreds_of_parts_is_found(self):
        parts = ["Content-Type: text/plain\n\nx\n"] * 260
        raw = ("From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"q\"\n\n"
               + "".join("--q\n" + p for p in parts)
               + '--q\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="invoice.exe"\n\nMZ\n--q--\n')
        result = pipeline.analyze_raw(raw, "x")
        self.assertIn("Dangerous attachment type: invoice.exe", titles(result))
        self.assertGreaterEqual(result.phish_score, 25)

    def test_millions_of_empty_parts_stop_in_seconds_with_a_report(self):
        """24 MB of empty parts took 110 s and 1.1 GB. The parser now stops
        at part 10,001, and what was read still gets a report and a verdict."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "parts.eml")
            with open(path, "wb") as f:
                f.write(b"From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"q\"\n\n")
                f.write(b"--q\n\n" * 4_800_000)
            start = time.perf_counter()
            out = CliRunner().invoke(cli.main, ["-i", path, "--format", "terminal"])
            elapsed = time.perf_counter() - start
        self.assertEqual(out.exit_code, 0, out.output)
        flat = " ".join(out.output.split())
        self.assertIn("Limited analysis", flat)
        self.assertIn("more than 10,000 MIME parts", flat)
        self.assertIn("Verdict: LIKELY PHISHING", flat)
        self.assertLess(elapsed, 10.0)

    def test_part_limit_counts_what_the_parser_sees(self):
        raw = ("From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"q\"\n\n"
               + "--q\n\n" * (parser.MAX_PARTS + 1) + "--q--\n")
        self.assertIn("more than 10,000 MIME parts", parser.parse_email(raw)[1].limited)
        raw = ("From: a@example.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"q\"\n\n"
               + "--q\n\n" * (parser.MAX_PARTS - 5) + "--q--\n")
        headers, body = parser.parse_email(raw)
        self.assertEqual((len(body.attachments), body.limited), (0, ""))

    def test_deep_nesting_over_many_lines_is_limited(self):
        """The library checks every line against every enclosing boundary:
        300 levels over 400,000 lines took 6 s, and 25 MB would take minutes."""
        raw = "From: a@example.test\nSubject: x\nMIME-Version: 1.0\n"
        for i in range(60):
            raw += 'Content-Type: multipart/mixed; boundary="b%d"\n\n--b%d\n' % (i, i)
        raw += "Content-Type: text/plain\n\n" + "x\n" * 1_000_000
        start = time.perf_counter()
        result = pipeline.analyze_raw(raw, "x")
        self.assertLess(time.perf_counter() - start, 5.0)
        self.assertIn("nests MIME parts", result.analysis_limited)
        self.assertIn("MIME structure exceeds the analysis limits", titles(result))
        self.assertGreaterEqual(result.phish_score, 40)

    def test_ordinary_nesting_is_read(self):
        raw = "From: a@example.test\nSubject: x\nMIME-Version: 1.0\n"
        for i in range(12):
            raw += 'Content-Type: multipart/mixed; boundary="b%d"\n\n--b%d\n' % (i, i)
        raw += "Content-Type: text/plain\n\nsee http://deep.example.test/x\n"
        self.assertIn("http://deep.example.test/x", pipeline.analyze_raw(raw, "x").body.urls)


class EncodedWordTests(unittest.TestCase):
    def test_decoding(self):
        d = parser.decode_words
        self.assertEqual(d("=?utf-8?q?a?= =?utf-8?q?b?="), "ab")
        self.assertEqual(d("x =?utf-8?q?a_b?= y"), "x a b y")
        self.assertEqual(d("=?utf-8?b?w6k=?="), "é")
        self.assertEqual(d("=?utf-8?q?=C3?= =?utf-8?q?=A9?="), "é")  # one character split over two words
        self.assertEqual(d("=?iso-8859-1?q?caf=E9?="), "café")
        self.assertEqual(d("=?no-such-charset?q?abc?="), "abc")
        self.assertEqual(d("=?utf-8?x?abc?="), "=?utf-8?x?abc?=")
        self.assertEqual(d("plain text"), "plain text")

    def test_linear_on_hostile_shapes(self):
        start = time.perf_counter()
        for value in ("=?" * 400000, "=?a?q?" + "x" * 2000000, "=?utf-8?q?" * 200000, ("=?utf-8?b?" + "A" * 50 + "?= ") * 40000):
            parser.decode_words(value)
            parser._params("attachment; " + value)
        self.assertLess(time.perf_counter() - start, 10.0)


class MalformedInputTests(SocketGuard):
    """Ordinary mistakes and broken files get a plain refusal, not a
    traceback and not a quiet 'no strong indicators'."""

    def setUp(self):
        super().setUp()
        self.runner = CliRunner()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def run_cli(self, *args):
        return self.runner.invoke(cli.main, list(args))

    def test_deeply_nested_multipart_gets_a_limited_report(self):
        raw = "From: a@example.test\nMIME-Version: 1.0\n"
        for i in range(2000):
            raw += f'Content-Type: multipart/mixed; boundary="b{i}"\n\n--b{i}\n'
        raw += "Content-Type: text/plain\n\nhello\n"
        path = self.write("nested.eml", raw)
        res = self.run_cli("-i", path, "--format", "terminal")
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertIn("Limited analysis", res.output)
        self.assertIn("more than 100 levels deep", " ".join(res.output.split()))
        self.assertNotIn("Traceback", res.output)

    def test_empty_file_is_refused(self):
        res = self.run_cli("-i", self.write("zero.eml", b""), "--format", "terminal")
        self.assertEqual(res.exit_code, 2, res.output)
        self.assertIn("empty", res.output)

    def test_outlook_msg_is_refused_with_advice(self):
        res = self.run_cli("-i", self.write("mail.msg", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 600), "--format", "terminal")
        self.assertEqual(res.exit_code, 2, res.output)
        self.assertIn(".msg", res.output)
        self.assertNotIn("NO STRONG INDICATORS", res.output)

    def test_text_without_headers_says_so(self):
        result = pipeline.analyze_raw("just some words\nand more\n", "x")
        self.assertTrue(any("no email headers" in c.reason for c in result.checks_not_run))

    def test_utf8_bom_does_not_hide_the_headers(self):
        raw = "﻿From: a@example.test\nSubject: t\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\nhi\n"
        path = self.write("bom.eml", raw)
        result = pipeline.analyze_file(path)
        self.assertEqual(result.headers.from_domain, "example.test")
        self.assertEqual(result.auth.dmarc_result, "fail")
        self.assertEqual(pipeline.analyze_raw(raw, "x").headers.from_domain, "example.test")

    def test_utf16_with_bom_is_decoded(self):
        raw = "﻿From: a@example.test\nSubject: t\n\nhi\n"
        path = self.write("u16.eml", raw.encode("utf-16-le"))
        self.assertEqual(pipeline.analyze_file(path).headers.from_domain, "example.test")

    def test_output_path_that_is_a_file_is_a_plain_error(self):
        target = self.write("not-a-dir", b"x")
        res = self.run_cli("-i", SAMPLE, "-o", target, "--format", "json")
        self.assertEqual(res.exit_code, 2, res.output)
        self.assertIn("cannot write reports", res.output)
        self.assertIsInstance(res.exception, SystemExit)

    def test_batch_with_no_emails_exits_nonzero(self):
        empty = os.path.join(self.dir, "empty")
        os.mkdir(empty)
        res = self.run_cli("-i", empty, "-o", os.path.join(self.dir, "out"))
        self.assertEqual(res.exit_code, 2, res.output)

    def test_batch_with_a_file_that_could_not_be_analyzed_exits_1(self):
        src = os.path.join(self.dir, "src")
        os.mkdir(src)
        shutil.copy(SAMPLE, os.path.join(src, "a.eml"))
        with open(os.path.join(src, "b.eml"), "wb"):
            pass
        res = self.run_cli("-i", src, "-o", os.path.join(self.dir, "out"), "--format", "json")
        self.assertEqual(res.exit_code, 1, res.output)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "out", "phishcheck-a.json")))
        with open(os.path.join(self.dir, "out", "batch-summary.html")) as f:
            self.assertIn("b.eml", f.read())


def multipart(*parts):
    raw = ("From: a@example.test\nTo: b@example.test\nSubject: see file\nMIME-Version: 1.0\n"
           'Content-Type: multipart/mixed; boundary="q"\n\n--q\nContent-Type: text/plain\n\nsee file\n')
    for p in parts:
        raw += "--q\n" + p + "\nContent-Transfer-Encoding: base64\n\nTVqQAA==\n"
    return raw + "--q--\n"


class AttachmentDetectionTests(SocketGuard):
    """Executables were missed unless Content-Disposition said 'attachment'
    in lower case."""

    def titles(self, raw):
        return " | ".join(f.title for f in pipeline.analyze_raw(raw, "x").findings)

    def test_uppercase_disposition(self):
        titles = self.titles(multipart('Content-Type: application/octet-stream\nContent-Disposition: ATTACHMENT; filename="invoice.exe"'))
        self.assertIn("Dangerous attachment type: invoice.exe", titles)

    def test_inline_disposition_with_filename(self):
        titles = self.titles(multipart('Content-Type: application/x-msdownload\nContent-Disposition: inline; filename="invoice.pdf.exe"'))
        self.assertIn("Double extension attachment: invoice.pdf.exe", titles)

    def test_content_type_name_without_disposition(self):
        raw = multipart('Content-Type: application/x-msdownload; name="payload.scr"')
        result = pipeline.analyze_raw(raw, "x")
        self.assertIn("Dangerous attachment type: payload.scr", " | ".join(f.title for f in result.findings))
        self.assertTrue(any(i.type == "hash" and "payload.scr" in i.context for i in result.indicators))

    def test_unnamed_attachment_is_hashed(self):
        result = pipeline.analyze_raw(multipart("Content-Type: application/octet-stream\nContent-Disposition: attachment"), "x")
        self.assertTrue(any(i.type == "hash" and "unnamed" in i.context for i in result.indicators))

    def test_text_body_still_read(self):
        result = pipeline.analyze_raw(multipart('Content-Type: application/octet-stream\nContent-Disposition: attachment; filename="a.bin"'), "x")
        self.assertEqual(result.body.text.strip(), "see file")
        self.assertEqual(len(result.body.attachments), 1)


class AuthResultsCommentTests(SocketGuard):
    def test_results_inside_a_comment_are_ignored(self):
        raw = ("From: CEO <ceo@example.test>\nTo: b@example.test\nSubject: favor\n"
               "Authentication-Results: mx.example.test; arc=none (spf=pass dkim=pass (nested dmarc=pass) dmarc=pass);"
               " spf=fail smtp.mailfrom=evil.test; dkim=fail; dmarc=fail\n\nhi\n")
        result = pipeline.analyze_raw(raw, "x")
        self.assertEqual((result.auth.spf_result, result.auth.dkim_result, result.auth.dmarc_result), ("fail", "fail", "fail"))
        self.assertEqual(result.verdict, "likely_phishing")

    def test_plain_header_still_parses(self):
        from atarus_phishcheck.analyzers import auth
        results, malformed = auth.read_authentication_results('mx; spf=pass (sender ok \\) still comment) smtp.mailfrom="x(y)"; dkim=pass header.d=example.test')
        self.assertEqual(results, {"spf": "pass", "dkim": "pass"})
        self.assertIsNone(malformed)


class AuthResultsGrammarTests(SocketGuard):
    """Only the leading method=result of each ";" segment is a result
    (RFC 8601). Values that carry sender-controlled text must not flip or
    hide a result."""

    def analyze(self, value):
        raw = f"From: Billing <billing@paypal.com>\nTo: b@example.test\nSubject: invoice\nAuthentication-Results: {value}\n\nhi\n"
        return pipeline.analyze_raw(raw, "x")

    def auth(self, value):
        r = self.analyze(value).auth
        return r.spf_result, r.dkim_result, r.dmarc_result

    def test_result_text_inside_a_property_value_is_not_a_result(self):
        self.assertEqual(self.auth("mx.example.test; spf=fail smtp.mailfrom=dmarc=pass@evil.test; dkim=none; dmarc=fail header.from=paypal.com"), ("fail", "none", "fail"))
        self.assertEqual(self.auth('mx.example.test; spf=fail smtp.mailfrom="dmarc=pass"@evil.test; dkim=none; dmarc=fail'), ("fail", "none", "fail"))
        self.assertEqual(self.auth("mx.example.test; dkim=pass header.i=spf=pass@evil.test; spf=fail smtp.mailfrom=evil.test; dmarc=fail"), ("fail", "pass", "fail"))

    def test_unclosed_comment_does_not_hide_later_results(self):
        result = self.analyze("mx.example.test; spf=softfail smtp.mailfrom=a(b@evil.test; dkim=none; dmarc=fail header.from=paypal.com")
        self.assertEqual((result.auth.spf_result, result.auth.dkim_result, result.auth.dmarc_result), ("unknown", "none", "fail"))
        found = titles(result)
        self.assertIn("DMARC alignment failed", found)
        self.assertIn("Authentication-Results header is malformed", found)
        self.assertGreaterEqual(result.phish_score, 25)  # main scored 25

    def test_unreadable_fail_is_never_a_pass(self):
        """A fail written at the start of an unreadable segment is still a
        fail; a pass there would be unknown."""
        result = self.analyze("mx.example.test; spf=pass smtp.mailfrom=paypal.com; dmarc=fail header.from=a(b")
        self.assertEqual(result.auth.dmarc_result, "fail")
        self.assertIn("Authentication-Results header is malformed", titles(result))
        self.assertGreaterEqual(result.phish_score, 25)  # main read dmarc=fail: 25
        result = self.analyze("mx.example.test; spf=fail smtp.mailfrom=paypal.com; dmarc=pass header.from=a(b")
        self.assertEqual(result.auth.dmarc_result, "unknown")
        malformed = [f for f in result.findings if f.title == "Authentication-Results header is malformed"]
        self.assertEqual([f.severity for f in malformed], ["high"])

    def test_unclosed_quote_is_malformed_not_swallowing(self):
        result = self.analyze('mx.example.test; spf=pass smtp.mailfrom="abc; dkim=fail; dmarc=fail')
        self.assertEqual((result.auth.dkim_result, result.auth.dmarc_result), ("fail", "fail"))
        self.assertIn("Authentication-Results header is malformed", titles(result))

    def test_a_second_pass_does_not_hide_a_fail(self):
        self.assertEqual(self.auth("mx.example.test; dmarc=pass; dmarc=fail")[2], "fail")
        self.assertEqual(self.auth("mx.example.test; spf=pass; spf=fail")[0], "fail")

    def test_result_must_be_a_whole_token(self):
        self.assertEqual(self.auth("mx.example.test; dmarc=pass@evil.test; spf=pass"), ("pass", "unknown", "unknown"))

    def test_dmarc_policy_is_the_p_tag(self):
        from atarus_phishcheck.analyzers import auth
        self.assertEqual(auth._extract_dmarc_policy("v=DMARC1; rua=mailto:p=none@example.test; p=reject"), "reject")
        self.assertEqual(auth._extract_dmarc_policy("v=DMARC1; sp=none; p=quarantine"), "quarantine")



class SenderHeaderTests(SocketGuard):
    def test_two_from_headers_are_flagged(self):
        raw = ("From: Security <security@paypal.com>\nFrom: x <x@evil-sender.test>\nTo: v@example.test\n"
               "Subject: Account notice\n\nPlease review your paypal account.\n")
        result = pipeline.analyze_raw(raw, "x")
        self.assertIn("Message has more than one From header", " | ".join(f.title for f in result.findings))
        self.assertNotEqual(result.verdict, "no_strong_indicators")

    def test_from_with_two_mailboxes_keeps_a_sender_domain(self):
        raw = "From: security@paypal.com, x@evil-sender.test\nTo: v@example.test\nSubject: Account notice\n\nPlease review your paypal account.\n"
        result = pipeline.analyze_raw(raw, "x")
        self.assertEqual(result.headers.from_domain, "paypal.com")
        self.assertIn("From header names 2 mailboxes", " | ".join(f.title for f in result.findings))
        self.assertTrue(any(i.value == "x@evil-sender.test" for i in result.indicators))

    def test_single_from_is_quiet(self):
        result = pipeline.analyze_raw('From: "Doe, Jane" <jane@example.test>\nSubject: hi\n\nhello\n', "x")
        self.assertEqual(result.headers.from_email, "jane@example.test")
        self.assertFalse([f for f in result.findings if "From header" in f.title])


class LookalikeVerdictTests(SocketGuard):
    def verdict(self, raw):
        return pipeline.analyze_raw(raw, "x")

    def test_two_label_suffix_sender_is_not_a_lookalike_of_everything(self):
        raw = ("From: Dana <dana@shop.co.uk>\nTo: v@example.test\nSubject: Order 1182 shipped\n"
               "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
               "Hi Sam, your order has shipped. https://www.tesco.com/track?id=1182 and https://cocacola.com/promo\n")
        result = self.verdict(raw)
        self.assertFalse([f for f in result.findings if "Lookalike" in f.title], [f.title for f in result.findings])
        self.assertEqual(result.verdict, "no_strong_indicators")

    def test_short_sender_name_is_not_a_lookalike_of_everything(self):
        raw = ("From: Ops <ops@x.io>\nTo: v@example.test\nSubject: Notes\n\n"
               "Notes at https://docs.example-wiki.test/page and https://nextcloud.test/x\n")
        self.assertEqual(self.verdict(raw).verdict, "no_strong_indicators")

    def test_real_lookalikes_still_found(self):
        from atarus_phishcheck.analyzers import indicators
        self.assertTrue(indicators._is_lookalike("paypal-secure.test", "paypal.com"))
        self.assertTrue(indicators._is_lookalike("shopp.co.uk", "shop.co.uk"))
        self.assertFalse(indicators._is_lookalike("mail.shop.co.uk", "shop.co.uk"))

    def test_ascii_lookalike_in_a_subdomain_label(self):
        raw = "From: a@example.test\nSubject: t\n\nSign in at https://login.paypa1.com/x\n"
        titles = " | ".join(f.title for f in self.verdict(raw).findings)
        self.assertIn("ASCII lookalike detected: login.paypa1.com impersonates paypal", titles)


class UrlHandlingTests(SocketGuard):
    def analyze(self, body, extra=""):
        return pipeline.analyze_raw("From: a@example.test\nSubject: t\n" + extra + "\n" + body + "\n", "x")

    def test_malformed_bracketed_hosts_do_not_abort_the_analysis(self):
        for url in ("http://[abc", "http://[zz]/", "http://a]b/"):
            result = self.analyze("see " + url + " and http://203.0.113.45/login")
            self.assertIn("URL uses raw IP address: 203.0.113.45", " | ".join(f.title for f in result.findings), url)

    def test_upper_case_scheme_is_extracted(self):
        result = self.analyze("Sign in: HTTP://LOGIN.PAYPA1.COM/x")
        self.assertTrue(any(i.type == "domain" and i.value == "login.paypa1.com" for i in result.indicators))

    def test_ipv6_and_legacy_ipv4_hosts_are_raw_ip_urls(self):
        result = self.analyze("http://[2001:db8::5]/login http://3232235777/login http://0x7f000001/ http://0177.0.0.1/")
        titles = " | ".join(f.title for f in result.findings)
        for host in ("2001:db8::5", "3232235777", "0x7f000001", "0177.0.0.1"):
            self.assertIn(f"URL uses raw IP address: {host}", titles)

    def test_received_ipv6_literals_are_indicators(self):
        extra = ("Received: from a ([IPv6:2001:db8::7]) by mx; Mon, 2 Nov 2026 10:00:00 +0000\n"
                 "Received: from b ([2001:db8::8]) by mx; Mon, 2 Nov 2026 10:00:00 +0000\n"
                 "Received: from c ([999.1.1.1]) by mx; Mon, 2 Nov 2026 10:00:00 +0000\n")
        ips = {i.value for i in self.analyze("hi", extra).indicators if i.type == "ip"}
        self.assertEqual(ips, {"2001:db8::7", "2001:db8::8"})

    def test_malformed_location_does_not_abort_expansion(self):
        from unittest import mock
        from atarus_phishcheck.analyzers import urlexpand
        from atarus_phishcheck.models import Indicator
        from atarus_phishcheck.network import Policy
        with mock.patch.object(urlexpand, "public_addresses", return_value=["192.0.2.10"]), \
                mock.patch.object(urlexpand, "_head_once", return_value=(302, "http://[bad", None)):
            new, findings = urlexpand.expand_urls([Indicator(type="url", value="https://bit.ly/x")], Policy(online=True, expand_links=True))
        self.assertTrue(findings)

    def test_legacy_ipv4_redirect_target_is_flagged_non_public(self):
        from unittest import mock
        from atarus_phishcheck.analyzers import urlexpand
        from atarus_phishcheck.models import Indicator
        from atarus_phishcheck.network import Policy
        with mock.patch.object(urlexpand, "public_addresses", return_value=["192.0.2.10"]), \
                mock.patch.object(urlexpand, "_head_once", return_value=(302, "http://2852039166/latest/meta-data/", None)):
            _, findings = urlexpand.expand_urls([Indicator(type="url", value="https://bit.ly/x")], Policy(online=True, expand_links=True))
        self.assertIn("non-public address", findings[0].title)


class IdnAndShortenerTests(SocketGuard):
    def test_raw_unicode_sender_and_url_domains_are_flagged(self):
        raw = ("From: PayPal <service@p\u0430ypal.com>\nTo: v@example.test\nSubject: Account notice\n\n"
               "Review your account at https://p\u0430ypal.com/login\n")
        result = pipeline.analyze_raw(raw, "x")
        titles = " | ".join(f.title for f in result.findings)
        self.assertIn("Non-ASCII (IDN) domain detected: p\u0430ypal.com", titles)
        self.assertTrue(any("xn--" in f.evidence for f in result.findings))
        self.assertIn(result.verdict, ("suspicious", "likely_phishing"))

    def test_every_expandable_shortener_is_also_flagged_offline(self):
        from atarus_phishcheck.analyzers import indicators, urlexpand
        self.assertEqual(set(indicators.URL_SHORTENERS), set(urlexpand.SHORTENER_DOMAINS))
        result = pipeline.analyze_raw("From: a@example.test\nSubject: t\n\nhttps://x.co/abc\n", "x")
        self.assertIn("URL uses a shortener: x.co", " | ".join(f.title for f in result.findings))


class WrongFileTypeTests(SocketGuard):
    def test_mbox_named_eml_warns_that_only_one_message_was_read(self):
        raw = "".join(f"From a@example.test Mon Nov  2 10:00:00 2026\nFrom: a@example.test\nSubject: m{i}\n\nbody {i}\n\n" for i in range(3))
        result = pipeline.analyze_raw(raw, "x.eml")
        notes = [c for c in result.checks_not_run if c.check == "Other messages in the file"]
        self.assertEqual(len(notes), 1)
        self.assertIn("about 3 messages", notes[0].reason)

    def test_ordinary_email_has_no_mbox_note(self):
        result = pipeline.analyze_raw("From: a@example.test\nSubject: t\n\nFrom here on, see below.\n\nFrom me\n", "x")
        self.assertFalse([c for c in result.checks_not_run if c.check == "Other messages in the file"])

    def test_verbose_flag_is_not_advertised(self):
        res = CliRunner().invoke(cli.main, ["--help"])
        self.assertNotIn("--verbose", res.output)


if __name__ == "__main__":
    unittest.main()
