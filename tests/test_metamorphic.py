"""Every base message in ``corpus`` is transformed by each listed sender
addition (padding, extra parts, extra headers, extra results, malformed
syntax) and compared with itself: for these transforms, the score must not
drop and no finding may be lost. This checks the listed transforms only;
it is not a proof for every addition. Benign payloads and reserved names
only."""
import unittest

from atarus_phishcheck.analyzers import parser

import corpus
from test_additions import SocketGuard, analyze, titles


# ----- metamorphic: what a sender can add never lowers the score -----

def _root_multipart(msg):
    """The message with a multipart root: a single-part message is wrapped
    in multipart/mixed, which a mail client displays the same way."""
    root = msg["root"]
    if "children" not in root:
        msg["root"] = corpus.multi("mixed", [root], "wrap0")
    return msg["root"]


def _empty_nest(depth, tag):
    inner = corpus.multi("mixed", [], f"{tag}{depth - 1}")
    for i in reversed(range(depth - 1)):
        inner = corpus.multi("mixed", [inner], f"{tag}{i}")
    return inner


def _insert(where, part):
    def apply(msg):
        root = _root_multipart(msg)
        index = {"front": 0, "middle": len(root["children"]) // 2 + (len(root["children"]) % 2), "end": len(root["children"]),
                 "before-last": max(0, len(root["children"]) - 1)}[where]
        root["children"].insert(index, part() if callable(part) else part)
        return msg
    return apply


def _empty_parts(n):
    def apply(msg):
        root = _root_multipart(msg)
        root["children"][0:0] = [{"headers": [], "body": ""} for _ in range(n)]
        return msg
    return apply


def _padding(where, unit, size):
    def apply(msg):
        pad = unit * (size // len(unit))
        if where == "header":
            msg["headers"].insert(1, ("X-Padding", "x\n " + pad.replace("\n", "").replace("\r", "") + "x"))
            return msg
        root = _root_multipart(msg)
        if where == "preamble":
            root["preamble"] = pad + "\n"
        elif where == "epilogue":
            root["epilogue"] = pad
        else:  # a further empty-looking part in the middle
            root["children"].insert(len(root["children"]) // 2, corpus.leaf("text/plain", pad))
        return msg
    return apply


def _extra_headers(where, n):
    def apply(msg):
        extra = [(f"X-Extra-{i}", f"v{i}") for i in range(n)]
        if where == "front":
            msg["headers"][0:0] = extra
        else:
            msg["headers"].extend(extra)
        return msg
    return apply


def _duplicate_headers(msg):
    def double(headers):
        out = []
        for h in headers:
            out += [h, h]
        return out

    def walk(part):
        part["headers"] = double(part["headers"])
        for child in part.get("children", []):
            walk(child)
    msg["headers"] = double(msg["headers"])
    walk(msg["root"])
    return msg


ATTACKER_RESULTS = "dkim=pass header.d=attacker.example header.s=a1; spf=pass smtp.mailfrom=attacker.example"


def _extra_results(where):
    def apply(msg):
        headers = msg["headers"]
        index = next((i for i, (n, _) in enumerate(headers) if n.lower() == "authentication-results"), None)
        if where == "second header" or index is None:
            at = index + 1 if index is not None else len(headers)
            headers.insert(at, ("Authentication-Results", "mx.attacker.example; " + ATTACKER_RESULTS + "; dmarc=pass header.from=attacker.example"))
            return msg
        name, value = headers[index]
        authserv, _, rest = value.partition(";")
        value = f"{authserv}; {ATTACKER_RESULTS}; {rest.strip()}" if where == "first" else f"{value}; {ATTACKER_RESULTS}"
        headers[index] = (name, value)
        return msg
    return apply


BULK_UNITS = {"CR": "\r", "LF": "\n", "spaces": " ", "NUL": "\x00"}

TRANSFORMS = {
    "3 empty nested multiparts in front": _insert("front", lambda: _empty_nest(3, "e")),
    "3 empty nested multiparts in the middle": _insert("middle", lambda: _empty_nest(3, "e")),
    "3 empty nested multiparts at the end": _insert("end", lambda: _empty_nest(3, "e")),
    "101 empty nested multiparts in front": _insert("front", lambda: _empty_nest(parser.MAX_DEPTH + 1, "e")),
    "101 empty nested multiparts in the middle": _insert("middle", lambda: _empty_nest(parser.MAX_DEPTH + 1, "e")),
    "101 empty nested multiparts at the end": _insert("end", lambda: _empty_nest(parser.MAX_DEPTH + 1, "e")),
    "10,001 empty parts": _empty_parts(parser.MAX_PARTS + 1),
    "a deep block between body and attachment": _insert("before-last", lambda: _empty_nest(parser.MAX_DEPTH + 1, "d")),
    "3,000 extra headers in front": _extra_headers("front", 3000),
    "3,000 extra headers at the end": _extra_headers("end", 3000),
    "every header duplicated": _duplicate_headers,
    "extra results first": _extra_results("first"),
    "extra results last": _extra_results("last"),
    "a second Authentication-Results header": _extra_results("second header"),
}
BULK_POSITIONS = ("preamble", "epilogue", "middle part", "header")
BULK_SIZE = 1_000_000


def _bulk_transforms(index):
    """Four bulk paddings per base, one per position, the padding character
    rotating across bases so that every character is used in every position."""
    units = list(BULK_UNITS)
    out = {}
    for k, where in enumerate(BULK_POSITIONS):
        unit = units[(index + k) % len(units)]
        out[f"1 MB of {unit} in the {where}"] = _padding(where, BULK_UNITS[unit], BULK_SIZE)
    return out


def _check(test, name, label, base_result, raw):
    result = analyze(raw)
    test.assertGreaterEqual(result.phish_score, base_result.phish_score, f"{name} + {label}: score {result.phish_score} < {base_result.phish_score}")
    missing = sorted(set(titles(base_result)) - set(titles(result)))
    test.assertEqual(missing, [], f"{name} + {label}: findings lost")


class MetamorphicTests(SocketGuard):
    """Every base message in the corpus is transformed by each listed
    sender addition; the score must not drop and every finding title of the
    base must still be present."""

    def test_corpus_is_wide_enough(self):
        self.assertGreaterEqual(len(corpus.BASES), 31)
        self.assertIn("attacker-pass-phish", corpus.BASES)

    def test_additions_never_lower_the_score_or_hide_a_finding(self):
        for index, name in enumerate(sorted(corpus.BASES)):
            base_result = analyze(corpus.render(corpus.base(name)))
            transforms = dict(TRANSFORMS, **_bulk_transforms(index))
            for label, transform in transforms.items():
                with self.subTest(base=name, transform=label):
                    _check(self, name, label, base_result, corpus.render(transform(corpus.base(name))))

    def test_the_attacker_pass_phish_under_every_bulk_padding(self):
        base_result = analyze(corpus.render(corpus.attacker_pass_phish()))
        for unit, char in BULK_UNITS.items():
            for where in BULK_POSITIONS:
                with self.subTest(unit=unit, where=where):
                    _check(self, "attacker-pass-phish", f"3 MB of {unit} in the {where}", base_result,
                           corpus.render(_padding(where, char, 3_000_000)(corpus.attacker_pass_phish())))

    def test_the_attacker_pass_phish_with_21_mb_of_bare_cr_after_it(self):
        base_result = analyze(corpus.render(corpus.attacker_pass_phish()))
        raw = corpus.render(corpus.attacker_pass_phish()) + b"\r" * 21_000_000
        _check(self, "attacker-pass-phish", "21 MB of bare CR in the epilogue", base_result, raw)


if __name__ == "__main__":
    unittest.main()
