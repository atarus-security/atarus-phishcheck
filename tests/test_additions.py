"""Sender additions (padding, extra parts, extra headers, extra results,
malformed syntax) checked one shape at a time: each shape here must not
lower the score or hide a finding of the same message without it. Limits
bound cost, never what is reported. Benign payloads and reserved names
only."""
import socket
import time
import tracemalloc
import unittest

from atarus_phishcheck import pipeline
from atarus_phishcheck.analyzers import auth, parser

import corpus


class SocketGuard(unittest.TestCase):
    def setUp(self):
        def refuse(*a, **k):
            raise AssertionError("network use in an offline test")
        orig = socket.socket.connect
        socket.socket.connect = refuse
        self.addCleanup(setattr, socket.socket, "connect", orig)
        orig_gai = socket.getaddrinfo
        socket.getaddrinfo = refuse
        self.addCleanup(setattr, socket, "getaddrinfo", orig_gai)


def analyze(raw):
    return pipeline.analyze_raw(raw, "x.eml")


def titles(result):
    return [f.title for f in result.findings]


def peak_bytes(fn):
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


HEAD = "From: a <a@b.example>\nTo: c@d.example\nSubject: s\n"
LIMITED = HEAD + "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n" + "--b\n\n" * (parser.MAX_PARTS + 1)


def _lines(template, size):
    out, total, i = [], 0, 0
    while total < size:
        line = template.format(i % 1000)
        out.append(line)
        total += len(line)
        i += 1
    return "".join(out)


class MemoryTests(SocketGuard):
    """Peak memory grows with the input in proportion, at most a few bytes
    per input byte, so a 25 MB message stays near 300 MB, including 20 MB
    of obsolete header names and 10 MB of "(" in Authentication-Results."""

    SIZE = 1_500_000
    PER_BYTE = 10  # peak traced bytes allowed per input byte, plus a fixed allowance
    FIXED = 8 << 20

    SHAPES = {
        "obsolete header names": lambda n: HEAD + _lines("X{} : v\n", n) + "\nbody\n",
        "many headers": lambda n: HEAD + _lines("X{}: v\n", n) + "\nbody\n",
        "unclosed comments in Authentication-Results": lambda n: HEAD + "Authentication-Results: mx; spf=pass " + "(" * n + "\n\nbody\n",
        "lenient Content-Type scan": lambda n: HEAD + "MIME-Version: 1.0\nContent-Type: application/octet-stream; " + "name=a.exe x; " * (n // 14) + "\n\nTVqQ\n",
        "unclosed quotes in Content-Disposition": lambda n: HEAD + "MIME-Version: 1.0\nContent-Disposition: attachment; x=" + '"(' * (n // 2) + "\n\nAAAA\n",
        "many Received headers": lambda n: _lines("Received: from h{} ([192.0.2.1]) by mx.example.test\n", n) + HEAD + "\nbody\n",
        "many From headers": lambda n: _lines("From: u{}@b.example\n", n) + "Subject: s\n\nbody\n",
        "raw scan of dash lines": lambda n: LIMITED + "--b\nContent-Type: text/plain\n\nhi" + "\n--x" * (n // 4) + "\n--b--\n",
        "raw scan of named blocks": lambda n: LIMITED + _lines('--b\nContent-Disposition: attachment; filename="f{}.exe"\n\nTVqQ\n', n) + "--b--\n",
    }

    def test_peak_memory_is_proportional_to_the_input(self):
        for label, build in self.SHAPES.items():
            with self.subTest(shape=label):
                raw = build(self.SIZE).encode()
                peak = peak_bytes(lambda: analyze(raw))
                self.assertLess(peak, self.PER_BYTE * len(raw) + self.FIXED,
                                f"{label}: {peak >> 20} MB peak for {len(raw) >> 20} MB of input")

    def test_header_counts_survive_the_header_cap(self):
        raw = _lines("Received: from h{} ([192.0.2.1]) by mx.example.test\n", 200_000) + "From: x@evil.example\nFrom: y@evil.example\n" + _lines("X{}: v\n", 100_000) + "\nbody\n"
        result = analyze(raw)
        received = raw.count("Received:")
        self.assertEqual(result.headers.received_count, received)
        self.assertEqual(result.headers.from_header_count, 2)
        self.assertEqual(result.headers.header_count, raw.count("\n", 0, raw.index("\n\n")) + 1)
        self.assertIn("Message has more than one From header", titles(result))



def _deep(depth, tag="n"):
    inner = corpus.multi("mixed", [], f"{tag}{depth - 1}")
    for i in reversed(range(depth - 1)):
        inner = corpus.multi("mixed", [inner], f"{tag}{i}")
    return inner


PHISH_FINDINGS = ("Dangerous attachment type: Invoice.pdf.exe", "Double extension attachment: Invoice.pdf.exe",
                  "Brand impersonation: claims to be Paypal", "ASCII lookalike detected: paypa1-secure.example impersonates paypal",
                  "Link text does not match URL destination", "Hidden text detected in HTML body")


class RawScanTests(SocketGuard):
    """Past the structure limits, the bytes the parser did not reach are
    still read by a linear scan, every check runs on what it finds, and the
    score is at least 75. Each shape here keeps every finding of the
    message without it, adds the limit finding, and scores 100."""

    def check(self, msg_or_raw):
        raw = msg_or_raw if isinstance(msg_or_raw, bytes) else corpus.render(msg_or_raw)
        result = analyze(raw)
        found = titles(result)
        for title in PHISH_FINDINGS + ("MIME structure exceeds the analysis limits",):
            self.assertIn(title, found)
        self.assertEqual(result.verdict, "likely_phishing")
        self.assertEqual(result.phish_score, 100)
        return result

    def test_deep_block_in_front(self):
        msg = corpus.attacker_pass_phish()
        msg["root"]["children"].insert(0, _deep(parser.MAX_DEPTH + 1))
        self.assertLess(len(corpus.render(msg)), 8_000)
        self.check(msg)

    def test_ten_thousand_and_one_empty_parts_in_front(self):
        msg = corpus.attacker_pass_phish()
        msg["root"]["children"][0:0] = [{"headers": [], "body": ""} for _ in range(parser.MAX_PARTS + 1)]
        self.check(msg)

    def test_deep_block_between_body_and_attachment(self):
        msg = corpus.attacker_pass_phish()
        msg["root"]["children"].insert(1, _deep(parser.MAX_DEPTH + 1))
        result = self.check(msg)
        exe = [a for a in result.body.attachments if a["filename"] == "Invoice.pdf.exe"]
        self.assertEqual(len(exe), 1)
        self.assertTrue(exe[0]["sha256"])

    def test_nothing_is_reported_twice(self):
        msg = corpus.attacker_pass_phish()
        msg["root"]["children"].append(_deep(parser.MAX_DEPTH + 1))
        result = analyze(corpus.render(msg))
        plain = analyze(corpus.render(corpus.attacker_pass_phish()))
        self.assertEqual(sorted(titles(result)), sorted(titles(plain) + ["MIME structure exceeds the analysis limits"]))
        self.assertEqual(len(result.body.attachments), 1)

    def test_nameless_executable_after_the_limit(self):
        raw = (b"From: a@vendor-portal.example\nSubject: s\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n"
               + b"--b\n\n" * (parser.MAX_PARTS + 1) + b"--b\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\n"
               + corpus.MZ.encode() + b"--b--\n")
        result = analyze(raw)
        self.assertTrue(any(t.startswith("Executable attachment content") for t in titles(result)))

    def test_links_in_base64_and_quoted_printable_after_the_limit(self):
        import base64
        raw = (b"From: a@vendor-portal.example\nSubject: s\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n"
               + b"--b\n\n" * (parser.MAX_PARTS + 1)
               + b"--b\nContent-Type: application/pdf\nContent-Transfer-Encoding: base64\n\n" + base64.encodebytes(b"see http://192.0.2.7/a ok")
               + b"--b\nContent-Type: text/plain\nContent-Transfer-Encoding: quoted-printable\n\nhttp://claim=\n-prize.xyz/now\n--b--\n")
        found = titles(analyze(raw))
        self.assertIn("URL uses raw IP address: 192.0.2.7", found)
        self.assertIn("URL uses suspicious TLD: .xyz", found)

    def test_a_signature_line_does_not_end_a_part(self):
        """'-- ' before a signature is not a boundary: the raw scan used to
        cut the part there and lose the brand named after it."""
        msg = corpus.base("signature-dashes")
        plain = analyze(corpus.render(msg))
        self.assertIn("Brand impersonation: claims to be Paypal", titles(plain))
        msg = corpus.base("signature-dashes")
        msg["root"] = corpus.multi("mixed", [_deep(parser.MAX_DEPTH + 1), msg["root"]], "w")
        self.assertIn("Brand impersonation: claims to be Paypal", titles(analyze(corpus.render(msg))))

    def test_a_blank_first_part_does_not_displace_the_body(self):
        msg = corpus.base("signature-dashes")
        msg["root"] = corpus.multi("mixed", [corpus.leaf("text/plain", " " * 100_000), msg["root"]], "w")
        self.assertIn("Brand impersonation: claims to be Paypal", titles(analyze(corpus.render(msg))))

    def test_a_crlf_line_counts_once(self):
        data = b"a\r\n" * 1000 + b"b\n" * 10 + b"c\r" * 5
        self.assertEqual(parser._BoundedParse(data).lines, 1016)



def _ar_message(frm, ar, rp="<b@mailer.attacker.example>"):
    return f"Return-Path: {rp}\nAuthentication-Results: {ar}\nFrom: {frm}\nTo: u@recv.example\nSubject: Updated bank details\n\nPlease use our new account.\n"


class DkimAlignmentTests(SocketGuard):
    """A DKIM pass counts only when its signing domain aligns with the
    From domain; otherwise a fail anywhere wins, otherwise the first result.
    A sender orders its signatures, so a valid signature of its own domain
    listed first used to hide the failing one."""

    SUPPLIER = "Supplier Billing <billing@supplier.example>"

    def auth_of(self, frm, ar):
        result = analyze(_ar_message(frm, ar))
        return result, result.auth

    def test_unaligned_pass_first_no_longer_hides_the_fail(self):
        result, a = self.auth_of(self.SUPPLIER, "mx.recv.example; dkim=pass header.d=attacker.example header.s=a1; dkim=fail header.d=supplier.example; "
                                                "spf=pass smtp.mailfrom=mailer.attacker.example; dmarc=none header.from=supplier.example")
        self.assertEqual(a.dkim_result, "fail")
        self.assertIn("DKIM signature verification failed", titles(result))

    def test_order_does_not_matter(self):
        scores = set()
        for ar in ("mx; dkim=pass header.d=attacker.example; dkim=fail header.d=supplier.example; dmarc=none",
                   "mx; dkim=fail header.d=supplier.example; dkim=pass header.d=attacker.example; dmarc=none"):
            scores.add(analyze(_ar_message(self.SUPPLIER, ar)).phish_score)
        self.assertEqual(len(scores), 1)

    def test_unaligned_pass_alone_gets_no_credit_and_is_marked(self):
        _, a = self.auth_of(self.SUPPLIER, "mx; dkim=pass header.d=attacker.example; dmarc=none")
        self.assertEqual(a.dkim_result, "pass")
        self.assertFalse(a.alignment_dkim)
        self.assertEqual(a.dkim_shown, "pass (not aligned with From)")

    def test_aligned_pass_by_organizational_domain_and_by_header_i(self):
        for ar in ("mx; dkim=fail header.d=x.example; dkim=pass header.d=mail.supplier.example",
                   "mx; dkim=fail header.d=x.example; dkim=pass header.i=@supplier.example"):
            with self.subTest(ar=ar):
                _, a = self.auth_of(self.SUPPLIER, ar)
                self.assertEqual((a.dkim_result, a.alignment_dkim), ("pass", True))

    def test_rewritten_from_list_mail_is_never_higher_than_main(self):
        """Both orders of the author's broken signature and the list's valid
        one. Main took the first result: 'fail' for the author signature
        first, 'pass' for the list's first."""
        frm = "'Jane via Dev' <dev@lists.example>"
        tail = "spf=pass smtp.mailfrom=lists.example; dmarc=pass header.from=lists.example"
        scores = {"author first": None, "list first": None}
        for label, ar in (("author first", f"mx; dkim=fail header.d=corp.example; dkim=pass header.d=lists.example; {tail}"),
                          ("list first", f"mx; dkim=pass header.d=lists.example; dkim=fail header.d=corp.example; {tail}")):
            with self.subTest(order=label):
                result = analyze(_ar_message(frm, ar, rp="<dev-bounces@lists.example>"))
                self.assertEqual(result.auth.dkim_result, "pass")
                self.assertNotIn("DKIM signature verification failed", titles(result))
                scores[label] = result.phish_score
        self.assertEqual(scores["author first"], scores["list first"])

    def test_an_added_spf_or_dmarc_pass_never_replaces_a_weaker_result(self):
        for method, weak in (("spf", "softfail"), ("dmarc", "none"), ("spf", "fail"), ("dmarc", "fail")):
            for order in ("added first", "added last"):
                with self.subTest(method=method, weak=weak, order=order):
                    parts = [f"{method}=pass", f"{method}={weak}"] if order == "added first" else [f"{method}={weak}", f"{method}=pass"]
                    results, _ = auth.read_authentication_results("mx; " + "; ".join(parts))
                    self.assertEqual(results[method], weak)



def _two_at(frm, header_from="evil.example"):
    return (f"Return-Path: <bounce@evil.example>\nAuthentication-Results: mx.recv.example; spf=pass smtp.mailfrom=evil.example; "
            f"dkim=pass header.d=evil.example; dmarc=pass header.from={header_from}\nFrom: {frm}\nTo: u@recv.example\n"
            "Subject: PayPal: confirm your account\nMIME-Version: 1.0\nContent-Type: text/html\n\n"
            '<p>PayPal: we noticed unusual activity. Please confirm your account within 24 hours. '
            '<a href="https://www.evil.example/pp/confirm">Confirm now</a></p>\n')


class RecordedSenderTests(SocketGuard):
    """The receiving server's header.from is compared with the From domain
    read here, and the text after the last "@" is a sender candidate. These
    forms must not read the sender as paypal.com with DMARC pass, where the
    server authenticated evil.example."""

    FORMS = ("PayPal <service@paypal.com@evil.example>", "PayPal <service@paypal.com.@evil.example>", "PayPal <service@paypal.com;x@evil.example>")

    def test_brand_claim_is_checked_against_every_reading(self):
        for frm in self.FORMS:
            with self.subTest(frm=frm):
                result = analyze(_two_at(frm))
                found = titles(result)
                self.assertIn("Brand impersonation: claims to be Paypal", found)
                self.assertIn("evil.example", result.headers.sender_candidates)
                self.assertGreaterEqual(result.phish_score, analyze(_two_at("PayPal <service@evil.example>")).phish_score)

    def test_a_different_recorded_domain_is_a_finding(self):
        result = analyze(_two_at("PayPal <service@paypal.com@evil.example>"))
        mismatch = [f for f in result.findings if f.title == "The receiving server authenticated a different From domain"]
        self.assertEqual([f.severity for f in mismatch], ["high"])
        self.assertIn("evil.example", mismatch[0].evidence)

    def test_the_same_recorded_domain_is_quiet(self):
        result = analyze(_two_at("Shop <news@shop.example>", header_from="shop.example"))
        self.assertNotIn("The receiving server authenticated a different From domain", titles(result))
        self.assertEqual(result.headers.sender_candidates, ["shop.example"])
        sub = analyze(_two_at("Shop <news@mail.shop.example>", header_from="shop.example"))
        self.assertNotIn("The receiving server authenticated a different From domain", titles(sub))

    def test_lookalike_checks_see_the_domain_after_the_last_at(self):
        result = analyze(_two_at("Service <service@corp.example@paypa1-secure.example>", header_from="paypa1-secure.example"))
        self.assertTrue(any(t.startswith("ASCII lookalike detected: paypa1-secure.example") for t in titles(result)))


U_SHOP, A_SHOP = "bücher.example", "xn--bcher-kva.example"
U_RU, A_RU = "магазин.example", "xn--80aairftm.example"
MISMATCH = "The receiving server authenticated a different From domain"


def _idn_message(from_domain, header_from, extra="", link=None):
    link = link or f"https://{from_domain}/order/1"
    return (f"Authentication-Results: mx.recv.example; spf=pass smtp.mailfrom=b@{from_domain}; dkim=pass header.d={header_from}; "
            f"dmarc=pass header.from={header_from}\nFrom: Shop <info@{from_domain}>\nTo: u@recv.example\nSubject: Your order shipped\n"
            f"{extra}MIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n<p>Your order shipped.</p>{link}\n").encode("utf-8")


class IdnDomainTests(SocketGuard):
    """A domain written in Unicode and the same domain in its IDNA (xn--)
    form are one domain everywhere two domains are compared or deduplicated:
    the recorded header.from, DKIM alignment, Reply-To, Return-Path, link
    text against link target, lookalike links and the IDN finding itself."""

    PAIRS = ((U_SHOP, A_SHOP), (A_SHOP, U_SHOP), (U_RU, A_RU), (A_RU, U_RU))

    def test_canonical_form(self):
        for spelling in ("bücher.example", "BÜCHER.example.", "xn--bcher-kva.example", "XN--BCHER-KVA.EXAMPLE"):
            self.assertEqual(parser.canonical_domain(spelling), "xn--bcher-kva.example")
        self.assertEqual(parser.canonical_domain("a" * 300 + ".ü"), "a" * 300 + ".ü")
        self.assertEqual(parser.canonical_domain("bad..ü.example"), "bad..ü.example")

    def test_recorded_header_from_in_the_other_form_is_the_same_sender(self):
        for shown, recorded in self.PAIRS:
            with self.subTest(shown=shown, recorded=recorded):
                result = analyze(_idn_message(shown, recorded))
                same = analyze(_idn_message(shown, shown))
                self.assertNotIn(MISMATCH, titles(result))
                self.assertEqual(len(result.headers.sender_candidates), 1)
                self.assertEqual(result.auth.dkim_result, "pass")
                self.assertTrue(result.auth.alignment_dkim)
                self.assertEqual(result.phish_score, same.phish_score)
                self.assertEqual(sorted(titles(result)), sorted(titles(same)))

    def test_one_idn_finding_per_domain(self):
        for shown, other in self.PAIRS:
            with self.subTest(shown=shown, other=other):
                result = analyze(_idn_message(shown, shown, link=f"https://{other}/order/1"))
                idn = [t for t in titles(result) if "IDN" in t]
                self.assertEqual(len(idn), 1, idn)

    def test_reply_to_and_return_path_in_the_other_form_are_the_same(self):
        for shown, other in self.PAIRS:
            with self.subTest(shown=shown, other=other):
                result = analyze(_idn_message(shown, shown, extra=f"Reply-To: <info@{other}>\nReturn-Path: <b@{other}>\n"))
                found = titles(result)
                self.assertNotIn("Reply-To address differs from From address", found)
                self.assertNotIn("Return-Path domain differs from From domain", found)
                self.assertEqual(result.phish_score, analyze(_idn_message(shown, shown)).phish_score)

    def test_link_text_and_lookalike_compare_the_canonical_form(self):
        for shown, other in self.PAIRS:
            with self.subTest(shown=shown, other=other):
                anchor = f'<a href="https://{other}/order/1">https://{shown}/order/1</a>'
                found = titles(analyze(_idn_message(shown, shown, link=anchor)))
                self.assertNotIn("Link text does not match URL destination", found)
                self.assertFalse(any(t.startswith("Lookalike domain detected") for t in found), found)

    def test_a_different_idn_domain_is_still_a_mismatch(self):
        result = analyze(_idn_message(U_SHOP, A_RU))
        self.assertIn(MISMATCH, titles(result))


class AlignmentBoundaryTests(SocketGuard):
    """DKIM alignment, and the comparison of the recorded header.from with
    the From domain, count only the same domain or a parent and child at a
    label boundary. Two registrations under one public suffix (siblings)
    never count, whatever the suffix."""

    SIBLINGS = (("victim.pages.example", "evil.pages.example"), ("bank.com.example", "evil.com.example"),
                ("bank.co.example", "evil.co.example"))

    def test_a_sibling_pass_does_not_hide_the_fail(self):
        for victim, evil in self.SIBLINGS:
            for order in ("fail first", "pass first"):
                with self.subTest(victim=victim, order=order):
                    parts = [f"dkim=fail header.d={victim}", f"dkim=pass header.d={evil}"]
                    if order == "pass first":
                        parts.reverse()
                    ar = f"mx.recv.example; {'; '.join(parts)}; spf=pass smtp.mailfrom={evil}; dmarc=none header.from={victim}"
                    result = analyze(_ar_message(f"Billing <billing@{victim}>", ar))
                    self.assertEqual((result.auth.dkim_result, result.auth.alignment_dkim), ("fail", False))
                    self.assertIn("DKIM signature verification failed", titles(result))

    def test_a_sibling_recorded_header_from_is_a_mismatch(self):
        for victim, evil in self.SIBLINGS:
            with self.subTest(victim=victim):
                ar = f"mx.recv.example; dkim=pass header.d={evil}; spf=pass smtp.mailfrom={evil}; dmarc=pass header.from={evil}"
                self.assertIn(MISMATCH, titles(analyze(_ar_message(f"Bank <billing@{victim}>", ar))))

    def test_parent_and_child_align_in_both_directions(self):
        for sender, signer in (("supplier.example", "mail.supplier.example"), ("mail.supplier.example", "supplier.example"),
                               ("supplier.example", "supplier.example"), ("SUPPLIER.example.", "supplier.example")):
            with self.subTest(sender=sender, signer=signer):
                self.assertTrue(auth.same_organization(signer, sender))
        for a, b in (("supplier.example", "xsupplier.example"), ("upplier.example", "supplier.example"), ("", "supplier.example")):
            with self.subTest(a=a, b=b):
                self.assertFalse(auth.same_organization(a, b))

    def test_rewritten_from_list_mail_reads_as_a_pass(self):
        """A list that rewrites From to its own domain and signs with that
        domain or its parent: the author's broken signature is the expected
        effect of the rewrite, so the list's aligned pass counts."""
        for frm, signer in (("'Author via Dev' <dev@lists.example>", "lists.example"), ("'Author via Dev' <dev@lists.example.org>", "example.org")):
            tail = f"spf=pass smtp.mailfrom=lists.example; dmarc=pass header.from={frm.split('@')[1].rstrip('>')}"
            for ar in (f"mx; dkim=fail header.d=corp.example; dkim=pass header.d={signer}; {tail}",
                       f"mx; dkim=pass header.d={signer}; dkim=fail header.d=corp.example; {tail}"):
                with self.subTest(frm=frm, ar=ar):
                    result = analyze(_ar_message(frm, ar, rp="<dev-bounces@lists.example>"))
                    self.assertEqual((result.auth.dkim_result, result.auth.alignment_dkim), ("pass", True))
                    self.assertNotIn("DKIM signature verification failed", titles(result))
                    self.assertNotIn(MISMATCH, titles(result))



class MalformedFamilyTests(SocketGuard):
    """One finding per family of malformed headers, with a count; points
    only when the strict and lenient readings disagree on a value a check
    uses. Ordinary mail with punctuation in display names and unquoted file
    names must score as the same message with quoted names."""

    def severities(self, result, title):
        return [f.severity for f in result.findings if f.title == title]

    def test_ordinary_shapes_score_as_their_well_formed_versions(self):
        """Each shape against the same message with a quoted display name and
        quoted file names. Main could not read the sender of some of them at
        all, so this, not main's score, is the fair comparison."""
        shapes = {
            "comma-display-name": ('"Shop, The" <news@shop.example>', 'attachment; filename="Catalogue 2026.pdf"'),
            "bracket-display-name": ('"[Shop] News" <news@shop.example>', None),
            "colon-display-name": ('"Accounts: Shop" <accounts@shop.example>', 'attachment; filename="Statement Oct.pdf"'),
            "phone-photos": (None, 'attachment; filename="IMG 0001.JPG"'),
            "address-as-name": ('"news@shop.example" <news@shop.example>', None),
            "surname-first": ('"Smith, Jane" <jane@corp-mail.test>', None),
        }
        for name, (frm, disposition) in shapes.items():
            with self.subTest(shape=name):
                msg = corpus.base(name)
                result = analyze(corpus.render(msg))
                fixed = corpus.base(name)
                if frm:
                    fixed["headers"] = [(n, frm if n == "From" else v) for n, v in fixed["headers"]]
                if disposition:
                    for part in fixed["root"].get("children", []):
                        part["headers"] = [(n, disposition if n == "Content-Disposition" else (v.split(";")[0] if n == "Content-Type" and "name=" in v else v))
                                           for n, v in part["headers"]]
                well_formed = analyze(corpus.render(fixed))
                self.assertEqual(result.phish_score, well_formed.phish_score, f"{name}: {titles(result)} vs {titles(well_formed)}")
                for title in ("Address headers are malformed", "Attachment headers are malformed"):
                    self.assertIn(self.severities(result, title), ([], ["info"]))

    def test_one_finding_per_family_with_a_count(self):
        raw = ("From: Shop, The <news@shop.example>\nReply-To: Shop, The <news@shop.example>\nSubject: s\nMIME-Version: 1.0\n"
               "Content-Type: multipart/mixed; boundary=b\n\n" + "".join(f"--b\nContent-Disposition: attachment; filename=Part {i}.pdf\n\nAAAA\n" for i in range(5)) + "--b--\n")
        result = analyze(raw)
        self.assertEqual(self.severities(result, "Address headers are malformed"), ["info"])
        self.assertEqual(self.severities(result, "Attachment headers are malformed"), ["info"])
        self.assertTrue([f for f in result.findings if f.title == "Attachment headers are malformed"][0].description.startswith("5 attachment"))

    def test_obsolete_names_of_unread_headers_do_not_score(self):
        raw = "From: a <a@b.example>\nSubject: s\n" + "".join(f"X{i} : v\n" for i in range(5000)) + "\nbody\n"
        result = analyze(raw)
        self.assertEqual(self.severities(result, "Header names are malformed"), ["info"])
        self.assertLess(result.phish_score, 15)

    def test_disagreement_on_a_checked_value_scores_once(self):
        raw = ("From: PayPal <service@paypal.com@evil.example>\nReply-To: <a@corp.example@evil.example>\nSubject : s\nFrom : x@evil.example\n"
               "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=b\n\n"
               "--b\nContent-Disposition: attachment; filename=invoice.pdf .exe\n\nAAAA\n"
               "--b\nContent-Disposition: attachment; filename=statement.pdf .scr\n\nAAAA\n--b--\n")
        result = analyze(raw)
        self.assertEqual(self.severities(result, "Address headers are malformed"), ["medium"])
        self.assertEqual(self.severities(result, "Header names are malformed"), ["medium"])
        self.assertEqual(self.severities(result, "Attachment headers are malformed"), ["medium"])
        self.assertIn("Dangerous attachment type: invoice.pdf .exe", titles(result))



HOSTILE = "a\x1b[2Jb\x00c\u202ed\u200be\x07f\u2066g\ud800h\U000e0041i"


def _hostile(obj):
    """Every string field of a report dataclass, at any depth, set to HOSTILE."""
    import dataclasses
    for f in dataclasses.fields(obj):
        value = getattr(obj, f.name)
        if isinstance(value, str):
            setattr(obj, f.name, HOSTILE)
        elif isinstance(value, list) and value and all(isinstance(v, str) for v in value):
            setattr(obj, f.name, [HOSTILE] * len(value))
        elif dataclasses.is_dataclass(value):
            _hostile(value)
        elif isinstance(value, list):
            for item in value:
                if dataclasses.is_dataclass(item):
                    _hostile(item)
    return obj


def _hidden_chars(text):
    import unicodedata
    return sorted({f"U+{ord(c):04X}" for c in text if c not in "\n\t" and (unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Cn") or c in "\u2028\u2029")})


class ReportSanitizerTests(SocketGuard):
    """Every string written into an HTML report (the per-message report and
    the batch summary) passes through one sanitizer that makes control and
    bidi characters visible: no raw ESC or U+202E may reach the report, so
    a title such as 'Dangerous attachment type: x<U+202E>gpj.exe' cannot
    display as '...xexe.jpg'."""

    def hostile_result(self):
        import tempfile
        raw = (corpus.render(corpus.base("rlo-name")).decode() .replace("Subject: Pictures", "Subject: x\x1b[31m\u202ey")
               .replace("Content-Type: multipart/mixed", "Reply-To: r@x.example\nX-Mailer: m\nX-Originating-IP: 192.0.2.1\n"
                        "Received: from h ([192.0.2.1])\nAuthentication-Results: mx; spf=fail\nContent-Type: multipart/mixed"))
        result = analyze(raw.encode("utf-8", "surrogatepass"))
        result.headers.received_chain = ["r"]
        return _hostile(result), tempfile.mkdtemp()

    def test_every_field_of_the_html_report(self):
        import os
        import shutil
        from atarus_phishcheck.reports import html_report
        result, d = self.hostile_result()
        self.addCleanup(shutil.rmtree, d, True)
        result.verdict = "likely_phishing"
        self.assertTrue(result.findings and result.indicators and result.checks_not_run)
        path = html_report.generate(result, os.path.join(d, "r.html"))
        with open(path, encoding="utf-8", errors="surrogatepass") as f:
            text = f.read()
        self.assertEqual(_hidden_chars(text), [])
        self.assertIn("[U+202E]", text)
        self.assertIn("[U+001B]", text)

    def test_every_field_of_the_batch_summary(self):
        import os
        import shutil
        from atarus_phishcheck import batch
        from atarus_phishcheck.network import OFFLINE
        result, d = self.hostile_result()
        self.addCleanup(shutil.rmtree, d, True)
        result.verdict = "likely_phishing"
        batch._write_batch_summary([result], [(HOSTILE + ".eml", HOSTILE)], d, OFFLINE)
        with open(os.path.join(d, "batch-summary.html"), encoding="utf-8", errors="surrogatepass") as f:
            text = f.read()
        self.assertEqual(_hidden_chars(text), [])
        self.assertIn("[U+202E]", text)

    def test_the_disguised_name_is_shown_as_stored(self):
        import os
        import shutil
        import tempfile
        from atarus_phishcheck.reports import html_report
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = html_report.generate(analyze(corpus.render(corpus.base("rlo-name"))), os.path.join(d, "r.html"))
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("photo[U+202E]gpj.exe", text)
        self.assertNotIn("\u202e", text)

    def test_every_finding_reaches_the_html_report(self):
        """Technical findings (limited analysis, malformed headers) were left out of the HTML report."""
        import html
        import os
        import shutil
        import tempfile
        from atarus_phishcheck.reports import html_report
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        msg = corpus.base("comma-display-name")
        msg["root"]["children"].insert(0, _deep(parser.MAX_DEPTH + 1))
        result = analyze(corpus.render(msg))
        self.assertIn("technical", {f.category for f in result.findings})
        with open(html_report.generate(result, os.path.join(d, "r.html")), encoding="utf-8") as f:
            text = html.unescape(f.read())
        for title in titles(result):
            self.assertIn(title, text)



class OracleSeedTests(SocketGuard):
    """Found by rerunning the standard-library oracle with further seeds:
    white space inside a quoted charset is kept by the library and dropped
    here, so the two decoded the part with different charsets unflagged."""

    def test_white_space_inside_a_quoted_charset_is_flagged(self):
        for value in ('" windows-1252"', '"koi8-r\t"'):
            with self.subTest(value=value):
                _h, body = parser.parse_email(f"From: a@b.test\nMIME-Version: 1.0\nContent-Type: text/plain; charset={value}\n\nhi\n")
                self.assertTrue(body.part_problems)


if __name__ == "__main__":
    unittest.main()
