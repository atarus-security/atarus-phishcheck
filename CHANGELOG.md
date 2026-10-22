# Changelog

All notable changes to atarus-phishcheck. Dates are commit dates.

## Unreleased (refresh-2026-10)

### Fixed
- HTML report template moved into the package so non-editable installs (`pip install .`, pipx) can write HTML reports.

### Removed
- Unused dependencies `weasyprint` and `python-dateutil` (never imported). Installs no longer pull WeasyPrint and its Pango requirement.

### Added
- Offline unit tests (`tests/`), GitHub Actions workflow, `constraints.txt`, SECURITY.md and this changelog.

### Docs
- README: `--offline` still performs SPF and DMARC DNS lookups; offline sample results (12 findings, 7 high); known issue with the HTML preview; atarus-webscan added to the suite list.

## 0.3.0 (2026-04-23)
- URL shortener expansion, IP geolocation with ASN, homoglyph and IDN detection, sandboxed HTML preview, batch mode for directories and mbox files.

## 0.2.0 (2026-04-23)
- Brand impersonation detection (25+ brands), URLhaus URL reputation, MalwareBazaar attachment hash checks, offline mode.

## 0.1.0 (2026-04-23)
- Initial release: SPF, DKIM and DMARC checks, IOC extraction, content analysis, phish scoring, HTML and JSON reports.
