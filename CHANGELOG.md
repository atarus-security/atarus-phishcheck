# Changelog

All notable changes to atarus-phishcheck. Dates are commit dates.

## 0.4.0 (unreleased, refresh-2026-10)

### Security

- **Offline by default, DNS included; lookups need `--online`, shortener expansion needs `--online --expand-links`.**

  What was wrong: a plain `atarus-phishcheck -i mail.eml` contacted outside hosts before anyone asked it to. It queried DNS for the sender domain's SPF and DMARC records (a query the attacker's name servers can see), posted every URL in the email, often carrying a per-recipient token, to URLhaus, sent the IPs from the headers to ip-api.com over plain HTTP, and for every shortener link sent HEAD requests that followed each Location header to any host for up to eight hops. That chain usually ends on the phisher's own server, so analyzing the email told the sender it had been opened and from which address, could burn single-use links, and for a Location of `http://10.0.0.5/` or `http://169.254.169.254/` made blind requests into the analyst's own network. `--offline` stopped the HTTP lookups but not the DNS queries, although the README said it turned every outside query off.

  What changed, in plain terms: a plain run now makes no network connection of any kind, and every report lists the checks that did not run and the flag that would enable them. Passing `--online` turns on the DNS, URLhaus, MalwareBazaar and ip-api.com lookups and prints the full list of destinations before the first one. Passing `--expand-links` as well sends one HEAD request to each shortener host and records where it redirects; the destination is never contacted, only the first hop is read, a shortener that resolves to a non-public address is refused before any request, and a redirect into a private or metadata range is reported as a high-severity finding. `--offline` is still accepted and does nothing.

  Technically: `network.Policy(online, expand_links)` is passed through `pipeline.analyze_raw()` to every analyzer; the default `OFFLINE` policy makes each of `auth.check_authentication`, `reputation.check_urls`, `reputation.check_hashes_malwarebazaar`, `geoip.lookup_ips` and `urlexpand.expand_urls` return early and append a `(check, reason)` note instead. `AnalysisResult` gained `mode`, `lookups_enabled` and `checks_not_run`, which the terminal summary, HTML report ("Checks Not Run" section and mode line) and JSON output all carry. `urlexpand` is rewritten on the standard library: `network.public_addresses()` resolves the shortener host and refuses it unless every address is global (`ipaddress`, with explicit rejection of 100.64.0.0/10, 0.0.0.0/8, IPv4-mapped, 6to4 and Teredo forms); `_head_once()` connects to that checked address with `socket.create_connection`, wraps TLS with SNI for the real host name, sends one HEAD through `http.client` and reads the Location header; nothing follows it. Each network module declares a `NETWORK` list (destination, what is sent, which flag) and the README table is written from those lists. `--expand-links` without `--online`, and `--offline` with `--online`, are usage errors (exit code 2) before any file is read. `cli.py` and `batch.py` now share one pipeline, so there is one place where a lookup can happen.

- **No false clean: verdict wording, "not listed" reputation, failed lookups recorded.**

  What was wrong: a score under 15 was labelled "clean", shown in green, and the HTML report said the email "appears legitimate based on the analysis", even in a run where no reputation or DNS check had worked. A URL that URLhaus had no record of was marked "clean". Lookups that failed for any reason were skipped silently, so a run where every lookup failed looked the same as one where every lookup passed. The missing DMARC record finding fired whenever the DNS lookup failed, which offline was always.

  What changed: the lowest verdict is `no_strong_indicators`, its text says the checks that ran found no strong indicator and that this does not establish the email is genuine, and a test forbids the words legitimate, safe and clean in verdict text, verdict names and the template. URLhaus and MalwareBazaar misses set `reputation = "not_listed"`. Every failed lookup (timeout, HTTP status, non-JSON answer, unexpected `query_status`) is recorded under checks not run with the reason. DMARC-record findings are emitted only when the lookup actually ran and answered (`AuthResult.records_looked_up`). SPF, DKIM and DMARC results default to `unknown` when the Authentication-Results header carries none, and every report states that the results are the receiving server's and that DKIM is not verified by this tool.

- **Regular expressions on email content replaced with linear scanning; input limits added.**

  What was wrong: the mismatched-link regex took 1.2 s at 12 KB and 8.9 s at 24 KB of repeated `<a href='x' ` (roughly cubic), the Reply-To address regex 3.8 s at 40 KB (quadratic), the tag-stripping regex `<[^>]+>` and the hidden-text and sanitizer regexes were quadratic on repeated unclosed tags or quotes, and the whole input file was read with no size cap. One crafted email could stall a batch run over an inbox export.

  What changed: `analyzers/htmlscan.py` (standard library) walks HTML once with `str.find` and provides `strip_tags`, `iter_tags`, `iter_anchors` (with the `</a` positions collected once and found by bisect) and `parse_attrs`; `content`, `brands` and `sanitize` use it. Address extraction uses `email.utils`. Hostnames over 253 characters are ignored. `parser.read_email_file()` refuses files over 25 MiB (exit code 2, or skipped and listed in batch mode); header values are cut at 4,096 characters, body parts at 1,000,000 characters, URLs at 2,048 characters and 500 per email, and each cut is listed under checks not run. `tests/test_safe_default.py` feeds 300 to 540 KB of each known pathological shape through the full pipeline, the sanitizer and the HTML report and requires the lot to finish in under 5 seconds (it takes about 1.5 s on a laptop).

- **Preview rebuilt from an allowlist and actually rendered; iframe fully sandboxed with a CSP.**

  What was wrong: the preview iframe showed the sanitized email as escaped source, because `html_report.py` escaped the value and Jinja's autoescape escaped it again. Had that been fixed alone, the regex sanitizer let through unquoted `src=`, `srcset`, CSS `url()`, `<base>`, `<form>` and SVG, and the iframe's `sandbox="allow-same-origin"` blocked scripts but not image or CSS loads, so opening the report would have fired the sender's tracking pixels.

  What changed: `analyzers/sanitize.py` is an allowlist tokenizer: only known tags and attributes are kept, every attribute value is re-escaped, `href` becomes `#link-blocked` with the original kept in `data-original-href` (non-web schemes are described, not copied), `src` becomes `#blocked-image`, `style` is dropped when it contains `url`, `expression`, `@`, a backslash or similar, and `<script>`, `<style>`, `<iframe>`, `<object>`, `<svg>`, `<form>`, `<base>` and friends are dropped with their content. The result is a complete document with `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">`, embedded once-escaped in `<iframe sandbox="" referrerpolicy="no-referrer" srcdoc=...>`.

- **Terminal output: escape sequences stripped, rich markup escaped; mbox split no longer left beside the input.**

  From, Subject, finding titles and reasons are passed through `safe_output.safe_text()` (removes ANSI CSI and OSC sequences, control characters and Unicode format characters such as bidi overrides) and `rich.markup.escape()` before printing. Batch mode splits an mbox into a temporary directory under the output directory and removes it when the run ends, instead of writing `<mbox>_split/` next to the input and leaving it there; messages are capped at 10,000 per mbox.

### Fixed
- Hidden-text and mismatched-link checks ran only when the email had both a text and an HTML part; HTML-only emails, including the bundled sample, skipped them. They now run on any HTML body.
- JSON output reported version 0.3.0 regardless of the installed version, and the reputation User-Agent said 0.2.0. All version strings now come from `atarus_phishcheck.__version__`.
- Geolocation never sends private addresses from the Received chain to ip-api.com.
- HTML report template moved into the package so non-editable installs (`pip install .`, pipx) can write HTML reports.

### Removed
- Unused dependencies `weasyprint` and `python-dateutil` (never imported). Installs no longer pull WeasyPrint and its Pango requirement.
- `--offline` as a meaningful option: it is accepted and does nothing, since offline is the default.

### Added
- `--online` and `--expand-links` options; `network.py` (policy, address guard, URL splitting), `pipeline.py` (the single analysis path), `analyzers/htmlscan.py`, `safe_output.py`; `NETWORK` declarations in `auth`, `reputation`, `geoip` and `urlexpand`.
- Offline unit tests (`tests/`), GitHub Actions workflow, `constraints.txt`, SECURITY.md and this changelog. `tests/test_safe_default.py` guards the socket layer so an unmocked lookup fails the test, and covers the offline default, the online destination list and recorded lookup failures, the one-hop shortener read against a local server (including a redirect to 169.254.169.254 that is reported and not contacted), the address guard, input caps, the pathological-input time bound, the sanitizer allowlist, terminal escaping, batch mbox handling and the verdict wording.

### Changed
- Version 0.4.0. Verdict `clean` renamed `no_strong_indicators`; indicator reputation `clean` renamed `not_listed`; authentication results default to `unknown`. JSON output gained `mode`, `lookups_enabled`, `verdict_text`, `authentication.records_looked_up` and `checks_not_run`.
- Analyzer functions take `policy=` and `notes=` keyword arguments; `batch.analyze_batch(input, output, format, policy=None)` and `batch.analyze_single(path, policy=None)` replace the `offline=` argument.

### Docs
- README rewritten: offline default, `--online` and `--expand-links`, what to know before going online, a per-module table of what is sent over the network, input limits, the sample's offline results (14 findings, 9 high), verdict bands, Known issues (abuse.ch Auth-Key, ip-api.com terms and plain HTTP, optional confusables library, plainer preview). SECURITY.md "Using this tool" rewritten to match, with the list of what counts as a security bug.

## 0.3.0 (2026-04-23)
- URL shortener expansion, IP geolocation with ASN, homoglyph and IDN detection, sandboxed HTML preview, batch mode for directories and mbox files.

## 0.2.0 (2026-04-23)
- Brand impersonation detection (25+ brands), URLhaus URL reputation, MalwareBazaar attachment hash checks, offline mode.

## 0.1.0 (2026-04-23)
- Initial release: SPF, DKIM and DMARC checks, IOC extraction, content analysis, phish scoring, HTML and JSON reports.
