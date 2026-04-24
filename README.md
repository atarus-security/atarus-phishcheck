# atarus-phishcheck

Defensive email security analyzer. Paste in a suspicious email, get structured analysis with a phishing likelihood score, IOC inventory, and a safe rendered preview of the email body.

Built for SOC analysts, incident responders, and anyone who needs to make a quick, defensible call on whether an email is phishing.

## What it does

**Parses email structure**
- Headers (From, Reply-To, Return-Path, Received chain, X-Mailer, X-Originating-IP, Authentication-Results)
- Body (text and HTML parts)
- Attachments (filename, content type, size, hashes)

**Checks authentication**
- SPF record and result
- DKIM signature verification result
- DMARC policy and alignment
- Looks up live DNS records for the sender domain

**Extracts indicators of compromise**
- URLs, domains, IP addresses, email addresses, attachment hashes (MD5, SHA-1, SHA-256)
- Flags suspicious TLDs, raw IP URLs, URL shorteners, dangerous attachment types, double extensions

**Analyzes content**
- Urgency language patterns
- Credential-harvesting phrases
- Authority impersonation (IT Support, CEO urgent)
- Financial pressure (wire transfers, gift cards)
- Generic greetings (Dear Customer)
- Hidden text in HTML (display:none, font-size:0)
- Mismatched link text vs href destination

**Detects brand impersonation**

Library of 25+ major brands (PayPal, Microsoft, Google, Apple, Amazon, Chase, Bank of America, Wells Fargo, Citibank, American Express, IRS, USPS, UPS, FedEx, DHL, DocuSign, Adobe, Zoom, Slack, GitHub, Okta, LinkedIn, Netflix, Dropbox, Facebook). Flags emails that claim to be from a known brand when the sender domain is not legitimate.

**Catches lookalike domains**
- Punycode/IDN decoding for homograph attacks
- Unicode confusable character detection
- ASCII substitution detection (paypa1 matches paypal, g00gle matches google, rnicrosoft matches microsoft)

**Expands URL shorteners**

Safely follows redirect chains with HEAD requests (no page load) to reveal the real destination behind bit.ly, tinyurl, t.co, and 14 other shorteners.

**Geolocates sending infrastructure**

Looks up country, city, ISP, organization, and ASN for every IP in the Received chain. Flags proxy/VPN routing, hosting-provider origin, and geographic mismatches (email claims US brand but originates elsewhere).

**Checks threat intel feeds**
- URLhaus for malicious URL reputation
- MalwareBazaar for known malware attachment hashes

**Produces defensible output**
- Phish score 0-100 with verdict (clean, questionable, suspicious, likely_phishing)
- Dark-themed HTML report with sandboxed preview of the email body (scripts stripped, external resources blocked, links disabled)
- JSON for SIEM/SOAR integration
- Terminal summary with high-severity findings called out

**Batch mode for SOC triage**

Point at a directory of .eml files or an mbox archive. Get a progress bar, per-email reports, and a landing page with all results sorted by phish score.

## Install

```bash
git clone https://github.com/atarus-security/atarus-phishcheck.git
cd atarus-phishcheck
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

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

Batch mode generates batch-summary.html in the output directory with a sortable table of all results linking to each individual report.

### Offline mode

Skips all external lookups (URLhaus, MalwareBazaar, ip-api, URL expansion). Use for air-gapped environments or privacy-sensitive analysis.

```bash
atarus-phishcheck -i suspicious.eml --format all --offline
```

## Try the sample

```bash
atarus-phishcheck -i examples/sample-phish.eml --format all
```

The included synthetic phishing email triggers 14 findings (9 high-severity) with a phish score of 100/100:

- SPF, DKIM, DMARC authentication failures
- Reply-To and From domain mismatch
- Raw IP address URL
- PayPal brand impersonation
- ASCII lookalike domain (paypa1 impersonates paypal)
- Proxy/VPN origin
- Geographic mismatch (claims PayPal, originates from Austria)
- URL shortener (bit.ly)
- Urgency and credential-harvesting language
- Authority impersonation
- Generic greeting

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
- 0-14: clean
- 15-39: questionable
- 40-74: suspicious
- 75-100: likely_phishing

## Privacy and safety

- No data leaves your machine except DNS queries for SPF/DMARC lookups, optional URLhaus/MalwareBazaar/ip-api queries, and HEAD requests to expand URL shorteners.
- Use --offline to disable all external queries.
- The HTML preview is rendered in a sandboxed iframe with scripts stripped, external resources blocked (images replaced with #blocked-image), and links disabled with original destination preserved in data-original-href.
- No page content is loaded when expanding URL shorteners. HEAD requests only.

## Part of the atarus- tool suite

- [atarus-recon](https://github.com/atarus-security/atarus-recon) - External attack surface recon
- [atarus-cloud](https://github.com/atarus-security/atarus-cloud) - Multi-cloud security scanner (AWS + Azure)
- atarus-phishcheck - Email security analyzer (you are here)
- [atarus-report-kit](https://github.com/atarus-security/atarus-report-kit) - Pentest report builder for juniors and students

## License

MIT

## Built by

[Atarus Offensive Security](https://atarussecurity.com)
