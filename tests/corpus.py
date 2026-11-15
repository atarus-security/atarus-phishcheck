"""Base messages for the metamorphic and regression tests, built from a
small structure so that transforms can add parts, headers and padding the
way a sender would. Reserved names (.example, .test) and documentation
addresses only; payloads are benign (an "MZ" header is two bytes and
padding, never a program)."""
import base64
import copy

MZ = base64.encodebytes(b"MZ\x90\x00" + b"\x00" * 200).decode()
PDF = base64.encodebytes(b"%PDF-1.4\n" + b"0" * 120).decode()
JPG = base64.encodebytes(b"\xff\xd8\xff\xe0" + b"\x00" * 120).decode()

AR_PASS_ATTACKER = ("Authentication-Results", "mx.recv.example; spf=pass smtp.mailfrom=vendor-portal.example; "
                    "dkim=pass header.d=vendor-portal.example; dmarc=pass header.from=vendor-portal.example")


def leaf(ctype, body="", cte=None, disposition=None, extra=()):
    headers = [("Content-Type", ctype)] if ctype else []
    if disposition:
        headers.append(("Content-Disposition", disposition))
    if cte:
        headers.append(("Content-Transfer-Encoding", cte))
    headers.extend(extra)
    return {"headers": headers, "body": body}


def multi(subtype, children, boundary, preamble="", epilogue=""):
    return {"headers": [("Content-Type", f'multipart/{subtype}; boundary="{boundary}"')], "boundary": boundary,
            "children": children, "preamble": preamble, "epilogue": epilogue}


def message(headers, root):
    return {"headers": list(headers), "root": root}


def _render_part(part, out):
    for name, value in part["headers"]:
        out.append(f"{name}: {value}\n")
    out.append("\n")
    if "children" in part:
        out.append(part.get("preamble", ""))
        b = part["boundary"]
        for child in part["children"]:
            out.append(f"--{b}\n")
            _render_part(child, out)
            out.append("\n")
        out.append(f"--{b}--\n")
        out.append(part.get("epilogue", ""))
    else:
        out.append(part["body"])


def render(msg) -> bytes:
    out = [f"{name}: {value}\n" for name, value in msg["headers"]]
    _render_part(msg["root"], out)
    return "".join(out).encode("utf-8", "surrogateescape")


def clone(msg):
    return copy.deepcopy(msg)


def html(text):
    return f"<html><body>{text}</body></html>"


def hdrs(frm, subject, ar=None, rp=None, extra=()):
    out = []
    if rp:
        out.append(("Return-Path", rp))
    if ar:
        out.append(("Authentication-Results", ar))
    out += [("From", frm), ("To", "u@recv.example"), ("Subject", subject), ("Date", "Mon, 2 Nov 2026 10:00:00 +0000"),
            ("Message-ID", "<1@mail.example>")]
    out += list(extra)
    out.append(("MIME-Version", "1.0"))
    return out


PHISH_HTML = html('<p>PayPal: your account is suspended. Verify immediately or it will be closed within 24 hours. Confirm your password.</p>'
                  '<a href="http://paypa1-secure.example/login">https://www.paypal.example/signin</a><div style="display:none">hello invoice</div>')
NEWSLETTER = html('<div style="display:none;max-height:0;overflow:hidden">Our biggest sale of the year starts now</div>'
                  '<p>Hello! See the attached catalogue.</p><a href="https://shop.example/sale">Shop the sale</a>')
AR_SHOP = "mx.recv.example; spf=pass smtp.mailfrom=news.shop.example; dkim=pass header.d=shop.example; dmarc=pass header.from=shop.example"
AR_FAIL = "mx.recv.example; spf=fail smtp.mailfrom=evil.example; dkim=fail header.d=evil.example; dmarc=fail header.from=bank.example"


def attacker_pass_phish():
    """Authentication passes for the attacker's own domain; a credential
    phish and an executable."""
    return message(
        [("Return-Path", "<billing@vendor-portal.example>"), AR_PASS_ATTACKER, ("From", "Accounts <billing@vendor-portal.example>"),
         ("To", "u@recv.example"), ("Subject", "Invoice 4471"), ("MIME-Version", "1.0")],
        multi("mixed", [
            leaf("text/html; charset=utf-8", PHISH_HTML),
            leaf('application/octet-stream; name="Invoice.pdf.exe"', MZ, "base64", 'attachment; filename="Invoice.pdf.exe"'),
        ], "m"))


def _bases():
    b = {"attacker-pass-phish": attacker_pass_phish()}
    b["plain-text"] = message(hdrs("Alice <alice@corp-mail.test>", "Lunch", ar="mx.corp-mail.test; spf=pass smtp.mailfrom=corp-mail.test; dkim=pass header.d=corp-mail.test; dmarc=pass header.from=corp-mail.test"),
                              leaf("text/plain; charset=utf-8", "Lunch at noon? See https://intranet.corp-mail.test/menu\n"))
    b["newsletter"] = message(hdrs('"Shop" <news@shop.example>', "Sale", ar=AR_SHOP, rp="<b@news.shop.example>"),
                              multi("alternative", [leaf("text/plain", "Sale now https://shop.example/sale\n"), leaf("text/html; charset=utf-8", NEWSLETTER)], "alt"))
    b["receipt-pdf"] = message(hdrs("Store <orders@store.example>", "Your receipt", ar="mx.recv.example; spf=pass smtp.mailfrom=store.example; dkim=pass header.d=store.example; dmarc=pass header.from=store.example"),
                               multi("mixed", [leaf("text/plain", "Thanks for your order. Receipt attached.\n"),
                                               leaf("application/pdf", PDF, "base64", 'attachment; filename="Receipt 2026.pdf"')], "r"))
    b["reply-to-mismatch"] = message(hdrs("CEO <ceo@corp-mail.test>", "Urgent wire transfer", extra=[("Reply-To", "ceo.private@freemail.example")]),
                                     leaf("text/plain", "I need you to process an urgent wire transfer today. Act now, this is confidential.\n"))
    b["ip-link"] = message(hdrs("IT Support <it@corp-mail.test>", "Password expires", ar=AR_FAIL),
                           leaf("text/html", html('<p>Your password expires today. Verify your account immediately.</p><a href="http://192.0.2.10/login">Log in</a>')))
    b["shortener"] = message(hdrs("Courier <notify@parcel.example>", "Delivery failed"),
                             leaf("text/plain", "Your parcel could not be delivered. Reschedule: https://bit.ly/3xYzAbc\n"))
    b["lookalike-sender"] = message(hdrs("Northwind <billing@northwind.test>", "Invoice"),
                                    leaf("text/html", html('<p>Your invoice is ready.</p><a href="https://northwlnd-billing.test/pay">Pay now</a>')))
    b["auth-fail"] = message(hdrs("Bank <alerts@bank.example>", "Account locked", ar=AR_FAIL),
                             leaf("text/plain", "Dear customer, your account has been locked. Confirm your identity within 24 hours.\n"))
    b["macro-doc"] = message(hdrs("HR <hr@corp-mail.test>", "Salary review"),
                             multi("mixed", [leaf("text/plain", "Please enable content to view.\n"),
                                             leaf("application/vnd.ms-word.document.macroEnabled.12", PDF, "base64", 'attachment; filename="review.docm"')], "d"))
    b["rfc2231-double-ext"] = message(hdrs("Scanner <scan@corp-mail.test>", "Scan"),
                                      multi("mixed", [leaf("text/plain", "Scanned document attached.\n"),
                                                      leaf("application/octet-stream", MZ, "base64", "attachment; filename*=utf-8''scan.pdf.exe")], "s"))
    b["idn-link"] = message(hdrs("Wallet <help@wallet.example>", "Security notice"),
                            leaf("text/plain", "Review activity at https://xn--pypal-4ve.example/login now\n"))
    b["unicode-link"] = message(hdrs("Wallet <help@wallet.example>", "Security notice"),
                                leaf("text/plain; charset=utf-8", "Review activity at https://pаypal.example/login\n"))
    b["base64-html-brand"] = message(hdrs("Microsoft 365 <no-reply@m365-alerts.example>", "Mailbox full"),
                                     leaf("text/html; charset=utf-8", base64.encodebytes(html("<p>Microsoft Outlook: your mailbox is full. Sign in to keep your password.</p><a href='http://m365-alerts.example/x'>Sign in</a>").encode()).decode(), "base64"))
    b["qp-html"] = message(hdrs("Docs <share@docs-share.example>", "Document shared"),
                           leaf("text/html; charset=utf-8", "<html><body><p>DocuSign: a document needs your signature.</p><a href=3D\"http://docs-share=\n.example.xyz/sign\">Review</a></body></html>\n", "quoted-printable"))
    inner = render(message(hdrs("PayPal <service@pp-alerts.example>", "Limited account"), leaf("text/html", PHISH_HTML))).decode()
    b["forward-rfc822"] = message(hdrs("Bob <bob@corp-mail.test>", "Fwd: is this real?"),
                                  multi("mixed", [leaf("text/plain", "Is this real?\n"), leaf("message/rfc822", inner, disposition="inline")], "f"))
    b["calendar"] = message(hdrs("Alice <alice@corp-mail.test>", "Invitation: sync"),
                            multi("alternative", [leaf("text/plain", "Sync on Monday\n"), leaf("text/calendar; method=REQUEST", "BEGIN:VCALENDAR\nVERSION:2.0\nEND:VCALENDAR\n")], "c"))
    b["intl-iso2022jp"] = message(hdrs("=?iso-2022-jp?b?GyRCRUQ3fBsoQg==?= <t@corp-mail.test>", "=?iso-2022-jp?b?GyRCJCIkJBsoQg==?="),
                                  leaf("text/plain; charset=iso-2022-jp", "\x1b$B$3$s$K$A$O\x1b(B https://corp-mail.test/a\n", "7bit"))
    b["intl-koi8r"] = message(hdrs("Shop <news@shop.example>", "Sale"),
                              leaf("text/html; charset=koi8-r", base64.encodebytes(html("Скидки https://shop.example/r").encode("koi8-r")).decode(), "base64"))
    b["list-rewritten-from"] = message(hdrs("'Jane via Dev' <dev@lists.example>", "[dev] build",
                                            ar="mx.recv.example; dkim=fail header.d=corp.example; dkim=pass header.d=lists.example; spf=pass smtp.mailfrom=lists.example; dmarc=pass header.from=lists.example",
                                            rp="<dev-bounces@lists.example>", extra=[("List-Id", "<dev.lists.example>")]),
                                       leaf("text/plain", "The build is green.\n"))
    b["bounce"] = message([("Return-Path", "<>")] + hdrs("Mail Delivery System <mailer-daemon@mx.corp-mail.test>", "Undelivered Mail Returned to Sender"),
                          multi("report; report-type=delivery-status", [leaf("text/plain", "Delivery failed.\n"), leaf("message/delivery-status", "Status: 5.1.1\n")], "bnc"))
    b["nameless-exe"] = message(hdrs("Billing <billing@vendor-portal.example>", "Statement"),
                                multi("mixed", [leaf("text/plain", "Statement attached.\n"), leaf("application/octet-stream", MZ, "base64")], "n"))
    b["html-attachment"] = message(hdrs("Payroll <payroll@pay-portal.example>", "Payslip"),
                                   multi("mixed", [leaf("text/plain", "Payslip attached.\n"),
                                                   leaf("text/html", html('<form action="http://pay-portal.example/collect"><p>Enter your password to view your payslip</p></form>'), disposition='attachment; filename="payslip.html"')], "h"))
    b["suspicious-tld"] = message(hdrs("Promo <promo@deals.example>", "You won"),
                                  leaf("text/plain", "Claim your prize at http://claim-prize.xyz/now\n"))
    b["two-from-headers"] = message(hdrs("Bank <alerts@bank.example>", "Notice", extra=[("From", "Attacker <x@evil.example>")]),
                                    leaf("text/plain", "Notice.\n"))
    b["multi-mailbox-from"] = message(hdrs("Bank <alerts@bank.example>, Attacker <x@evil.example>", "Notice"), leaf("text/plain", "Notice.\n"))
    # Ordinary mail with display-name punctuation and unquoted file names.
    b["comma-display-name"] = message(hdrs("Shop, The <news@shop.example>", "Sale", ar=AR_SHOP, rp="<b@news.shop.example>"),
                                      multi("mixed", [leaf("text/html; charset=utf-8", NEWSLETTER), leaf("application/pdf", PDF, "base64", "attachment; filename=Catalogue 2026.pdf")], "m"))
    b["bracket-display-name"] = message(hdrs("[Shop] News <news@shop.example>", "Sale", ar=AR_SHOP, rp="<b@news.shop.example>"),
                                        multi("mixed", [leaf("text/html; charset=utf-8", NEWSLETTER),
                                                        leaf("application/pdf", PDF, "base64", 'attachment; filename="=?utf-8?B?S2F0YWxvZyBNw6RyeiAyMDI2LnBkZg==?="')], "m"))
    b["colon-display-name"] = message(hdrs("Accounts: Shop <accounts@shop.example>", "Statement", ar=AR_SHOP, rp="<b@news.shop.example>"),
                                      multi("mixed", [leaf("text/html", NEWSLETTER),
                                                      leaf("application/pdf", PDF, "base64", "attachment; filename=Statement Oct.pdf"),
                                                      leaf("application/pdf", PDF, "base64", "attachment; filename=Statement (copy).pdf")], "m"))
    b["phone-photos"] = message(hdrs("Jane Doe <jane@shop.example>", "photos", ar=AR_SHOP),
                                multi("mixed", [leaf("text/plain", "photos from the trip\n"),
                                                leaf("image/jpeg; name=IMG 0001.JPG", JPG, "base64", "attachment; filename=IMG 0001.JPG"),
                                                leaf("image/jpeg; name=IMG 0002.JPG", JPG, "base64", "attachment; filename=IMG 0002.JPG")], "m"))
    b["address-as-name"] = message(hdrs("news@shop.example <news@shop.example>", "Digest", ar=AR_SHOP), leaf("text/plain", "Digest.\n"))
    b["surname-first"] = message(hdrs("Smith, Jane <jane@corp-mail.test>", "Notes"), leaf("text/plain", "Notes attached later.\n"))
    b["malformed-ar"] = message(hdrs("Billing <billing@vendor-portal.example>", "Invoice", ar='mx.recv.example; spf=pass smtp.mailfrom="a(b; dkim=fail header.d=vendor-portal.example; dmarc=fail header.from=vendor-portal.example'),
                                leaf("text/plain", "Invoice attached.\n"))
    b["rlo-name"] = message(hdrs("Photos <p@corp-mail.test>", "Pictures"),
                            multi("mixed", [leaf("text/plain", "See attached.\n"), leaf("application/octet-stream", MZ, "base64", 'attachment; filename="photo‮gpj.exe"')], "p"))
    b["nested-inline-image"] = message(hdrs("Shop <news@shop.example>", "Look", ar=AR_SHOP),
                                       multi("mixed", [multi("related", [multi("alternative", [leaf("text/plain", "Look https://shop.example/a\n"), leaf("text/html", NEWSLETTER)], "a2"),
                                                                         leaf("image/png", JPG, "base64", "inline", extra=[("Content-ID", "<img1>")])], "r2")], "m2"))
    b["two-at-from"] = message(hdrs("PayPal <service@paypal.com@evil.example>", "PayPal: confirm your account",
                                    ar="mx.recv.example; spf=pass smtp.mailfrom=evil.example; dkim=pass header.d=evil.example; dmarc=pass header.from=evil.example"),
                               leaf("text/html", '<p>PayPal: we noticed unusual activity. Please confirm your account within 24 hours. <a href="https://www.evil.example/pp/confirm">Confirm now</a></p>'))
    b["dkim-unaligned-first"] = message(hdrs("Supplier Billing <billing@supplier.example>", "Updated bank details", rp="<b@mailer.attacker.example>",
                                             ar="mx.recv.example; dkim=pass header.d=attacker.example header.s=a1; dkim=fail header.d=supplier.example header.s=s1; spf=pass smtp.mailfrom=mailer.attacker.example; dmarc=none header.from=supplier.example"),
                                        leaf("text/plain", "Please use our new account for the next payment.\n"))
    b["signature-dashes"] = message(hdrs('"Carol via dev" <dev@lists.example>', "[dev] Re: patch", rp="<dev-bounces@lists.example>",
                                         ar="mx.recv.example; spf=pass smtp.mailfrom=lists.example; dkim=pass header.d=lists.example; dmarc=pass header.from=lists.example"),
                                    leaf('text/plain; charset="utf-8"; format=flowed', "Hi all,\nThe patch is up.\n\n-- \nCarol, PayPal payments team\n", "7bit"))
    return b


BASES = _bases()


def base(name):
    return clone(BASES[name])
