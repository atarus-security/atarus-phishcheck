# atarus-phishcheck

Defensive email security analyzer. Paste in a suspicious email, get structured analysis with phishing likelihood score.

Built for SOC analysts, incident responders, and anyone who needs to make a quick, defensible call on whether an email is phishing.

## What it does

- Parses email headers, body, and attachments from `.eml` files or raw message content
- Checks SPF, DKIM, and DMARC authentication against the sender's real DNS records
- Extracts all indicators of compromise (URLs, domains, IPs, email addresses, attachments)
- Scans content for phishing language patterns (urgency, credential harvesting, authority impersonation)
- Detects lookalike domains, suspicious TLDs, URL shorteners, and hidden HTML tricks
- Scores the email 0-100 for phishing likelihood
- Outputs verdict: clean, questionable, suspicious, or likely_phishing
- Generates dark-themed HTML report and machine-readable JSON

## Install

```bash
git clone https://github.com/atarus-security/atarus-phishcheck.git
cd atarus-phishcheck
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Usage

```bash
# Analyze a .eml file with all outputs
atarus-phishcheck -i suspicious.eml --format all

# HTML report only
atarus-phishcheck -i suspicious.eml --format html

# JSON for integration with SOAR or SIEM
atarus-phishcheck -i suspicious.eml --format json

# Terminal output only, no files written
atarus-phishcheck -i suspicious.eml --format terminal
```

## Sample

Try the included example:

```bash
atarus-phishcheck -i examples/sample-phish.eml --format all
```

This is a synthetic phishing email that triggers most detection paths. You'll see a likely_phishing verdict with a phish score around 95.

## What's detected

### Authentication
- SPF record check and alignment
- DKIM signature verification
- DMARC policy and alignment
- Missing DMARC or policy=none

### Indicators
- Mismatched Reply-To and From addresses
- Return-Path domain spoofing
- Raw IP addresses in URLs
- Suspicious TLDs (.xyz, .top, .tk, etc.)
- URL shorteners hiding destinations
- Lookalike domains similar to sender domain
- Dangerous executable attachments
- Macro-enabled Office documents
- Double-extension filename tricks

### Content
- Urgency pressure ("account will be suspended")
- Credential-harvesting language ("verify your password")
- Authority impersonation ("IT Support urgent")
- Financial pressure (wire transfers, gift cards, crypto)
- Generic greetings ("Dear Customer")
- Hidden text in HTML (display:none, font-size:0)
- Link text that does not match href destination

## Part of the atarus- tool suite

- **[atarus-recon](https://github.com/atarus-security/atarus-recon)** - External attack surface recon
- **[atarus-cloud](https://github.com/atarus-security/atarus-cloud)** - Multi-cloud security scanner
- **atarus-phishcheck** - Email security analyzer (you are here)
- **atarus-report-kit** - Pentest report builder

## License

MIT

## Built by

[Atarus Offensive Security](https://atarussecurity.com)
