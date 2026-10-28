# atarus-phishcheck

Defensive email analyzer. Point it at a suspicious email and get a structured analysis: a phishing likelihood score, the indicators found, a list of the checks that did and did not run, and a preview of the body that cannot load or execute anything.

Built for SOC analysts, incident responders, and anyone who needs to make a quick, defensible call on an email. Offline by default: a plain run sends nothing anywhere.

## What it does

**Parses email structure**
- Headers (From, Reply-To, Return-Path, Received chain, X-Mailer, X-Originating-IP, Authentication-Results)
- Body (text and HTML parts)
- Attachments (filename, content type, size, hashes)

**Reads authentication results**
- SPF, DKIM and DMARC results as recorded by the receiving server in the Authentication-Results header
- With `--online`: the sender domain's published SPF and DMARC records and DMARC policy
- The tool does not verify DKIM signatures itself; it says so in every report

**Extracts indicators of compromise**
- URLs, domains, IP addresses, email addresses, attachment hashes (MD5, SHA-256)
- The IP addresses from the headers are listed in the report as found. The tool does not look them up; country, ISP and ASN are left to you.
- Flags suspicious TLDs, raw IP URLs, URL shorteners, dangerous attachment types, double extensions

**Analyzes content**
- Urgency language patterns
- Credential-harvesting phrases
- Authority impersonation (IT Support, CEO urgent)
- Financial pressure (wire transfers, gift cards)
- Generic greetings (Dear Customer)
- Hidden text in HTML (display:none, visibility:hidden, font-size:0, white text)
- Link text that names one domain while the href points to another

**Detects brand impersonation**

Library of 25 major brands (PayPal, Microsoft, Google, Apple, Amazon, Chase, Bank of America, Wells Fargo, Citibank, American Express, IRS, USPS, UPS, FedEx, DHL, DocuSign, Adobe, Zoom, Slack, GitHub, Okta, LinkedIn, Netflix, Dropbox, Facebook). Flags emails that name a brand when the sender domain is not one of that brand's known domains.

**Catches lookalike domains**
- Punycode/IDN decoding for homograph attacks
- ASCII substitution detection (paypa1 matches paypal, g00gle matches google)

**Reads where a URL shortener points (opt-in)**

With `--online --expand-links`, one HEAD request goes to each shortener host (bit.ly, tinyurl.com, t.co and 19 others) and the Location header is recorded. The destination is never contacted, only the first hop is read, and a shortener that resolves to a private or internal address is refused before any request. A destination inside a private, loopback, link-local or cloud-metadata range is reported as a high-severity finding.

**Checks threat intel feeds (opt-in)**
- URLhaus for malicious URL reputation
- MalwareBazaar for known malware attachment hashes

**Produces defensible output**
- Phish score 0-100 with verdict (no_strong_indicators, questionable, suspicious, likely_phishing)
- A "Checks not run" list in every report: what was not looked up and why, so a quiet report is never mistaken for a clean bill
- Dark-themed HTML report with a preview of the email body rebuilt from an allowlist of tags, inside an iframe with an empty `sandbox` attribute and a `default-src 'none'` Content-Security-Policy
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

Batch mode generates batch-summary.html in the output directory with a table of all results linking to each individual report, plus a list of any files that were not analyzed and why.

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

- One email file: 25 MiB. Larger files are refused with a clear message (exit code 2; skipped and listed in batch mode).
- Each header value: 4,096 characters. Each text or HTML body part: 1,000,000 characters. Anything beyond is cut before analysis and the cut is listed under "Checks not run".
- URLs: 2,048 characters each, 500 per email. Hostnames over 253 characters are ignored.
- The HTML analysers walk the input once; there are no regular expressions over the body that can backtrack. A test feeds half a megabyte of each known pathological shape and requires the whole run to finish in bounded time.

## Privacy and safety

- Offline by default. Nothing leaves your machine unless you pass `--online`; the table above is the complete list of destinations.
- Reports contain the full parsed email, which is your data. Treat them as containing attacker-controlled content.
- The HTML preview is rebuilt from an allowlist (text, structure, tables, images with their source replaced by `#blocked-image`, links with their href replaced and the original kept in `data-original-href`). Scripts, style sheets, forms, frames, SVG and event handlers are dropped; inline `style` attributes are kept only when they contain no `url()`, `expression`, `@import` or escape. The result sits in an iframe with `sandbox=""` and a `default-src 'none'` Content-Security-Policy, so even an attribute the allowlist misses cannot fetch anything.
- Email-derived text printed to the terminal is stripped of escape sequences, control characters and Unicode format characters, and rich markup in it is escaped.

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

## Testing

```bash
python -m unittest discover -s tests -v
```

Offline, standard library only. `tests/test_safe_default.py` replaces the socket layer with functions that raise, so any lookup that is not mocked fails the test instead of reaching the network; it covers the offline default, the `--online` destination list, lookup failures recorded as checks not run, the one-hop shortener read against a local server, the address guard, input caps, the pathological-input time bound, the sanitizer allowlist and the verdict wording. GitHub Actions runs the suite on every push. `constraints.txt` records the dependency versions it last passed with.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

MIT

## Built by

[Atarus Offensive Security](https://atarussecurity.com)
