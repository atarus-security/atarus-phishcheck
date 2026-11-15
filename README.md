# atarus-phishcheck

Defensive email analyzer. Point it at a suspicious email and get a structured analysis: a phishing likelihood score, the indicators found, a list of the checks that did and did not run, and a preview of the body that cannot load or execute anything.

Built for SOC analysts, incident responders, and anyone who needs to make a quick, defensible call on an email. Offline by default: a plain run sends nothing anywhere.

## What it does

**Parses email structure**
- Headers (From, Reply-To, Return-Path, Received chain, X-Mailer, X-Originating-IP, Authentication-Results)
- Body (every text and HTML part, HTML and text attachments included)
- Attachments (filename, content type, size, hashes)
- Addresses and MIME parameters are read by the RFC 5322, 2045, 2047 and 2231 grammar. When the strict reading finds nothing, or something other readers may see differently, a lenient reading runs too and every check runs on what it found. One finding per family of malformed headers (address headers, header names, attachment headers, part headers) records it with a count; it adds 10 points only when the strict and lenient readings disagree on a value a check uses (a different sender domain, an obsolete name on a header a check reads, a tolerant file name that a name check flags), and is otherwise info. A test compares these readings with the Python standard library's own parser on several thousand variants.

**Reads authentication results**
- SPF, DKIM and DMARC results as recorded by the receiving server in the Authentication-Results header, read by the RFC 8601 grammar: only the leading `method=result` of each `;` segment counts, so text in comments, quoted strings and property values is never read as a result, and a malformed header is reported. Only the first (topmost) Authentication-Results header is read. A backslash escapes only inside a quoted string or a comment; text outside the grammar makes only its own segment unknown.
- A DKIM pass counts only when its signing domain (`header.d`, or the domain of `header.i`) is the From domain or a parent or child of it at a label boundary (`mail.shop.example` and `shop.example`), since anyone can add a valid signature of their own domain and list it first. Two siblings under a shared suffix (`a.pages.example` and `b.pages.example`) never count as aligned: without a public suffix list, a shared organization cannot be told apart from two registrations under one public suffix. Otherwise a DKIM fail anywhere wins, otherwise the first result stands; an unaligned pass is shown as "pass (not aligned with From)" and gets no credit. For SPF and DMARC, of which a message has one each, a fail anywhere wins and an added pass never replaces a weaker result.
- The results are read even when no sender address can be read from From. Every domain the receiving server recorded as the From domain (`header.from`) is a sender candidate, and one that is neither the From domain read here nor a parent or child of it is a high-severity finding: the server and the tool saw different senders.
- Wherever two domains are compared or deduplicated (the recorded From domain, DKIM alignment, Reply-To, Return-Path, link text against link target, lookalike links, the IDN check), both are first put in one form: lower case, no trailing dot, IDNA labels, so `bücher.example` and `xn--bcher-kva.example` are the same domain.
- With `--online`: the sender domain's published SPF and DMARC records and DMARC policy
- The tool does not verify DKIM signatures itself; it says so in every report

**Extracts indicators of compromise**
- URLs, domains, IP addresses, email addresses, attachment hashes (MD5, SHA-256)
- The IP addresses from the headers are listed in the report as found. The tool does not look them up; country, ISP and ASN are left to you.
- Flags suspicious TLDs, raw IP URLs (IPv4, IPv6 and the decimal or hexadecimal forms browsers accept), URL shorteners, dangerous attachment types, double extensions, executable content in any part counted as an attachment, whatever its name (an executable Content-Type, or an `MZ` or ELF header), and names that hide their extension with direction overrides or other invisible characters, trailing dots or spaces
- A part counts as an attachment when its disposition is `attachment` in any letter case or when it names a file, so `inline` executables are checked too; up to 20 distinct names per part are checked (Content-Disposition `filename` and `name`, Content-Type `name`, RFC 2231 and RFC 2047 forms, and what a tolerant reading of a malformed header finds), and a part that gives more is a high-severity finding

**Analyzes content**
- Urgency language patterns
- Credential-harvesting phrases
- Authority impersonation (IT Support, CEO urgent)
- Financial pressure (wire transfers, gift cards)
- Generic greetings (Dear Customer)
- Hidden text in HTML (display:none, visibility:hidden, font-size:0, white text)
- Link text that names one domain while the href points to another

**Detects brand impersonation**

Library of 25 major brands (PayPal, Microsoft, Google, Apple, Amazon, Chase, Bank of America, Wells Fargo, Citibank, American Express, IRS, USPS, UPS, FedEx, DHL, DocuSign, Adobe, Zoom, Slack, GitHub, Okta, LinkedIn, Netflix, Dropbox, Facebook). Flags emails that name a brand when the sender domain is not one of that brand's known domains. Every domain a reader could take as the sender's is checked, up to the first five: the From address, the text after the last `@` in From, an address written in front of it as the display name, further mailboxes, the other lenient readings of a malformed From, and the domain the receiving server recorded; a brand claim with no readable sender at all is flagged too. The lookalike and homoglyph checks use the same candidates.

**Catches lookalike domains**
- Punycode/IDN decoding for homograph attacks, and any sender or link domain written with non-ASCII characters
- ASCII substitution detection in any label of the domain (paypa1 matches paypal, g00gle matches google, login.paypa1.com is caught)
- More than one From header, or more than one mailbox in it

**Reads where a URL shortener points (opt-in)**

With `--online --expand-links`, one HEAD request goes to each shortener host (bit.ly, tinyurl.com, t.co and 19 others) and the Location header is recorded. The destination is never contacted, only the first hop is read, and a shortener that resolves to a private or internal address is refused before any request. A destination inside a private, loopback, link-local or cloud-metadata range is reported as a high-severity finding.

**Checks threat intel feeds (opt-in)**
- URLhaus for malicious URL reputation
- MalwareBazaar for known malware attachment hashes

**Produces defensible output**
- Phish score 0-100 with verdict (no_strong_indicators, questionable, suspicious, likely_phishing)
- A "Checks not run" list in every report: what was not looked up and why, so a quiet report is never mistaken for a clean bill
- Dark-themed HTML report with every finding and a preview of the email body rebuilt from an allowlist of tags, inside an iframe with an empty `sandbox` attribute and a `default-src 'none'` Content-Security-Policy
- JSON for SIEM/SOAR integration
- Terminal summary with high-severity findings and checks not run called out; email text is stripped of terminal escape sequences before it is printed

**Batch mode for SOC triage**

Point at a directory of .eml files or an mbox archive. Get a progress bar, per-email reports, and a landing page with all results sorted by phish score. An mbox is split into a temporary directory under the output directory and the split is removed when the run ends.

## Install

```bash
git clone https://github.com/atarus-security/atarus-phishcheck.git
cd atarus-phishcheck
python3 -m venv venv
source venv/bin/activate
pip install .   # Python 3.10 or newer
```

`pip install -e .` works too for development. Runtime dependencies: click, rich, dnspython, requests, jinja2. The tests and all code added in 0.4.0 use the standard library only.

## Usage

### Single email

```bash
atarus-phishcheck -i suspicious.eml --format all
atarus-phishcheck -i suspicious.eml --format html
atarus-phishcheck -i suspicious.eml --format json
atarus-phishcheck -i suspicious.eml --format terminal
```

### Batch mode

```bash
atarus-phishcheck -i incoming-phish/ --batch --format all
atarus-phishcheck -i archive.mbox --batch --format all
atarus-phishcheck -i incoming-phish/ --batch -o ./reports --format all
```

Batch mode generates batch-summary.html in the output directory with a table of all results linking to each individual report, plus a list of any files that were not analyzed and why. Only files ending in `.eml` are read from a directory, and subdirectories are not searched. An mbox must end in `.mbox` to be split; a `.eml` file that is really an mbox is analyzed as one email and the report says so.

### Exit codes

- `0`: the run finished and every input was analyzed. The exit code does not depend on the verdict. A message past the part or nesting limits is analyzed as far as it was read and gets an ordinary report (exit `0`); see "Input limits".
- `1`: batch mode only: at least one file could not be analyzed; each is listed in batch-summary.html.
- `2`: no analysis was possible: a usage error, an input that was refused (over 25 MiB, empty, an Outlook `.msg`), a batch with no `.eml` files, or an output directory that cannot be written.

### Offline by default

A plain run makes no network connection of any kind: no DNS query, no reputation lookup, no shortener request. Everything that needs the network is listed under "Checks not run" in the terminal summary, the HTML report and the JSON output, with the flag that would enable it.

### Online lookups

```bash
atarus-phishcheck -i suspicious.eml --format all --online
atarus-phishcheck -i suspicious.eml --format all --online --expand-links
```

`--online` enables the DNS, URLhaus and MalwareBazaar lookups. Before anything is sent, the tool prints every destination the run may contact. `--expand-links` additionally sends one HEAD request to each URL shortener host in the email; it is refused without `--online`. A lookup that fails (timeout, HTTP error, a feed that now needs an API key) is listed under "Checks not run" rather than silently counted as a pass.

Things to know before going online:

- The sender domain's name servers may see the SPF and DMARC queries your resolver makes. If the attacker runs that domain, that is a signal the email was analyzed.
- Full URLs from the email, which often carry a per-recipient token, are sent to URLhaus.
- `--expand-links` tells the shortener service, but never the final destination, that the link was looked up.

`--offline` is still accepted and does nothing, since offline is the default.

### What this tool sends over the network

| Module | Destination | What is sent | When |
|---|---|---|---|
| parser, indicators, content, brands, homoglyph, scoring, reports | nothing | nothing; computed on your machine | every run |
| auth | your system DNS resolver (which may ask the sender domain's authoritative name servers) | TXT queries for the From domain and for `_dmarc.<From domain>` | `--online` only |
| reputation | urlhaus-api.abuse.ch over HTTPS | each URL found in the email, up to 10, as a POST form field | `--online` only |
| reputation | mb-api.abuse.ch over HTTPS | the SHA-256 of each attachment, up to 10, as a POST form field | `--online` only |
| urlexpand | the URL shortener host named in the email, only if it is in the built-in shortener list and all of its addresses are public | one HEAD request for the shortened path with User-Agent `atarus-phishcheck/<version>`; the Location header is read and never followed | `--online --expand-links` only |

Each of these modules declares the same information in a `NETWORK` list at the top of its source file. Nothing else in the package imports a network library.

## Try the sample

```bash
atarus-phishcheck -i examples/sample-phish.eml --format all
```

The included synthetic phishing email scores 100/100 offline, with 14 findings (9 high, 3 medium, 2 low):

- SPF, DKIM and DMARC failures as recorded in its Authentication-Results header
- Reply-To and From domain mismatch
- Raw IP address URL
- Hidden text in the HTML body
- Link text (paypal.com) that does not match the href (a raw IP)
- PayPal brand impersonation
- ASCII lookalike domain (paypa1 impersonates paypal)
- URL shortener (bit.ly)
- Urgency and credential-harvesting language
- Authority impersonation
- Generic greeting

The report also lists four checks that did not run offline: DKIM verification (never performed by this tool), the SPF and DMARC record lookup, shortener expansion and URLhaus reputation. With `--online` the lookups add DNS and reputation findings when those services return data.

## How the score works

Severity-weighted aggregation of findings:

- Each high-severity finding: 25 points
- Each medium: 10 points
- Each low: 3 points
- Bonus for multiple high-severity findings: +8 to +15
- A message past the MIME structure limits: at least 75
- Bonus for authentication failures combined with indicator findings: +15
- Content findings combined with auth or indicator findings: +10
- Capped at 100

Verdicts:
- 0-14: no_strong_indicators
- 15-39: questionable
- 40-74: suspicious
- 75-100: likely_phishing

The lowest band means the checks that ran found no strong indicator. It is never phrased as the email being legitimate, safe or clean, and the report lists the checks that did not run next to it.

## Input limits

- One email file: 25 MiB. Larger files are refused with a clear message (exit code 2; skipped and listed in batch mode). Empty files and Outlook `.msg` files (save the message as `.eml` first) are refused the same way. A MIME structure past the limits below is not refused; it gets a limited analysis.
- Every header and every MIME part is read in full. The message is parsed from its bytes by the standard library with the `compat32` policy, which keeps raw header text, and the tool reads addresses, encoded words and MIME parameters itself with routines that take time in proportion to the text. Padding in front of a filename, a sender address or an Authentication-Results entry does not hide it. Past 20,000 words and separators in one address or MIME header, the rest of that header is read only by the lenient scan, and the header is reported as malformed.
- Kept per part: 20 distinct file names, 20 mailboxes per address header, 500 distinct links per message. Passing a cap is a finding (high for file names, medium for mailboxes, low for links).
- A message with more than 10,000 MIME parts, nesting deeper than 100 levels, or nesting depth times line count over 40 million (for example 4 levels over 10 million lines) stops the MIME parser there. The limits bound cost, never what is reported: the whole message is then read again by a linear scan that does not depend on MIME structure (every Content-Type, Content-Disposition and Content-Transfer-Encoding block anywhere in the bytes with its file names and its body up to the next declared boundary, base64 and quoted-printable bodies decoded, links in the raw text, in the quoted-printable reading of the whole message and in every decoded block, base64 executable headers), and the attachment, link, content, brand and lookalike checks run on what it finds, merged with what the parser read and never repeated. A high-severity "MIME structure exceeds the analysis limits" finding is added and the score is at least 75 ("likely_phishing"), since such a structure has no ordinary use. A CRLF counts as one line. This is an ordinary report with exit code 0; batch mode lists it as analyzed with limits. The limits are counted inside the parser as it runs, because the standard library parser does work for every part and for every line once per enclosing multipart.
- Headers no check reads are counted rather than kept (the first 200 are kept), and of each header a check reads the first 1,000 are kept and all are counted; the checks use the first of each, the first 100 Received headers and the counts.
- Measured (Python 3.11.17, one laptop, whole analysis, peak resident memory): 20 MB of obsolete `X : v` header names 2.2 s and 0.29 GB; 10 MB of `(` in Authentication-Results 1.8 s and 0.12 GB; one part naming 300,000 files (7.5 MB) 0.2 s; a 20 MB From of 1,000,000 addresses 0.4 s; a 20 MB header of encoded words 1.3 s. Past the limits, the raw scan of 25 MB of distinct named blocks, distinct HTML blocks or `--x` lines takes 3.3 to 4.2 s and at most about 0.3 GB; 21 MB of bare CR after a message 1.2 s and 0.1 GB. The largest memory cases found are the standard library parser keeping one list entry per line, and are not bounded by this tool: 25 MB of two-character lines in one part takes 3.0 s and about 0.95 GB, 24 MB of one-space continuation lines in one header 3.2 s and about 1.1 GB. A test times every reader at n and 4n and compares peak traced memory the same way, and another holds peak traced memory under 10 bytes per input byte on nine header and raw-scan shapes.
- Reports show at most 4,096 characters of any value taken from the email and mark the cut ("shown cut at ... characters; all of it was analysed"); detection always reads the whole value. Each text or HTML body part is cut at 1,000,000 characters for the content checks, listed under "Checks not run"; links are taken from all of it.
- A leading byte order mark is ignored, and UTF-16 files with a byte order mark are decoded. Attachments are hashed from the bytes as stored. Headers are read as UTF-8, and body parts by their declared charset, with undecodable bytes replaced.
- URLs: 2,048 characters each, 500 distinct per email (more is listed under "Checks not run"). Hostnames over 253 characters are ignored.
- The HTML analysers walk the input once; there are no regular expressions over the body that can backtrack. A test feeds half a megabyte of each known pathological shape and requires the whole run to finish in bounded time.

## Privacy and safety

- Offline by default. Nothing leaves your machine unless you pass `--online`; the table above is the complete list of destinations.
- Reports contain the full parsed email, which is your data. Treat them as containing attacker-controlled content.
- The HTML preview is rebuilt from an allowlist (text, structure, tables, images with their source replaced by `#blocked-image`, links with their href replaced and the original kept in `data-original-href`). Scripts, style sheets, forms, frames, SVG and event handlers are dropped; inline `style` attributes are kept only when they contain no `url()`, `expression`, `@import` or escape. The result sits in an iframe with `sandbox=""` and a `default-src 'none'` Content-Security-Policy, so even an attribute the allowlist misses cannot fetch anything.
- Email-derived text printed to the terminal is stripped of escape sequences, control characters and Unicode format characters, and rich markup in it is escaped.
- Every string the HTML report and the batch summary write passes through one sanitizer that shows control, format (direction overrides, zero-width marks), surrogate, private use and unassigned characters as a visible `[U+XXXX]`, so a name such as `photo[U+202E]gpj.exe` is shown as stored, never as the disguise. JSON escapes them.

## Part of the atarus- tool suite

- [atarus-recon](https://github.com/atarus-security/atarus-recon) - External attack surface recon
- [atarus-cloud](https://github.com/atarus-security/atarus-cloud) - Multi-cloud security scanner (AWS + Azure)
- atarus-phishcheck - Email analyzer (you are here)
- [atarus-report-kit](https://github.com/atarus-security/atarus-report-kit) - Pentest report builder for juniors and students
- [atarus-webscan](https://github.com/atarus-security/atarus-webscan) - Web application security scanner

## Known issues

- abuse.ch's URLhaus and MalwareBazaar APIs may require an Auth-Key. The tool sends none; a refused lookup now shows under "Checks not run" with the HTTP status instead of passing silently. Key support is not implemented.
- The confusable-Unicode check in the homoglyph module depends on an optional library that is not a dependency and is skipped when absent. Punycode and ASCII lookalike checks always run.
- The preview removes style sheets, so a heavily styled email renders plainer than the original.

## Known limitations

Each of these also applies to version 0.5.0, except the raw scan item: 0.5.0 has no raw scan.

- Only the first (topmost) Authentication-Results header is read, its authserv-id is not checked against one the user trusts, and other Authentication-Results headers are not reported, so a forged header above the receiver's, or the only one, is read as the receiver's.
- A DKIM pass is not cross-checked against the DKIM-Signature headers in the message, so a pass that a receiver copied from unquoted sender text (an envelope sender containing `;dkim=pass header.d=...`) counts as an aligned pass even next to the receiver's recorded fail for the same domain.
- A part with no file name and no `attachment` disposition is not checked for an executable Content-Type or an `MZ` or ELF header, though some mail clients show it as an unnamed attachment.
- A Content-Transfer-Encoding that is quoted and followed by a comment (`"base64" (x)`) is not decoded, so the content and link checks do not see that part's text.
- Only the first Reply-To header is read, and a second Reply-To header is not a finding.
- The brand check reads the first 2,000 characters of the text and HTML bodies, and the content checks read the first 1,000,000 characters of each part, so markup, comments or prose placed before the real content can hide brand, language, hidden-text and link-text findings.
- Past 500 distinct links, further links are not checked, so many benign links placed before a malicious one can hide its lookalike, raw IP, shortener or TLD finding (a low finding says the cap was passed).
- With bare CR line endings, quoted-printable soft line breaks are not decoded, which can hide link-text and hidden-text findings in that part.
- The raw scan past the structure limits decodes only base64 and quoted-printable, finds links in the decoded bytes rather than the decoded text (so UTF-16 HTML links are missed), and reads only text/plain and text/html for the content checks; such a message already scores at least 75.
- The two-label suffix list is short, not the Public Suffix List, so lookalike base names under a missing suffix are computed from the last two labels.

## Testing

```bash
python -m unittest discover -s tests -v
```

Offline, standard library only. `tests/test_safe_default.py` replaces the socket layer with functions that raise, so any lookup that is not mocked fails the test instead of reaching the network; it covers the offline default, the `--online` destination list, lookup failures recorded as checks not run, the one-hop shortener read against a local server, the address guard, input caps, the pathological-input time bound, the sanitizer allowlist and the verdict wording. `tests/test_oracle.py` compares the sender, Reply-To, attachment names and charsets the tool reads with what the standard library's default policy reads, on 63 hand-written address forms, 63 MIME parameter forms, 19 charset forms and about 3,800 generated variants (fixed seed): wherever they differ, the tool must have raised a malformed-header finding. `tests/test_lenient_reads.py` covers the lenient reads, the Authentication-Results grammar, limited analysis, part decoding, file name tricks and the linear-cost test. `tests/test_metamorphic.py` checks a property for a listed set of transforms: 38 base messages in `tests/corpus.py` (phishing, newsletters, receipts, list mail, forwards, calendar, international, malformed-but-ordinary senders and file names) are each transformed by every kind of sender addition (empty nested multiparts in front, middle and end; 10,001 empty parts; a megabyte of CR, LF, spaces or NULs in the preamble, epilogue, a part or a header; thousands of extra headers; a deep block before the attachment; every header duplicated; extra authentication results), and each must score at least as high as its base and keep every finding. It covers those transforms only; it is not a guarantee for every addition (see "Known limitations"). `tests/test_additions.py` covers the raw scan, malformed-header families, DKIM alignment, the recorded From domain, IDN domain comparison, alignment boundaries, the HTML sanitizer walked over every report field, and peak memory. `tests/test_hostile_input.py` holds one regression test per hostile-input bug fixed (header storms and padding, part and nesting limits, deep nesting, byte order marks, hidden attachments, the Authentication-Results grammar, duplicate From headers, lookalike false positives, malformed and IP-literal URLs, raw Unicode domains). GitHub Actions runs the suite on every push. `constraints.txt` records the dependency versions it last passed with.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

MIT

## Built by

[Atarus Offensive Security](https://atarussecurity.com)
