# Security policy

## Reporting a vulnerability

Please report security issues in atarus-phishcheck privately by email to info@atarussecurity.com. Do not open a public GitHub issue for a vulnerability.

Include:

- the version or commit you tested
- steps to reproduce, and a proof of concept if you have one (a crafted .eml is ideal)
- the impact you expect

We aim to acknowledge reports within 5 business days and to agree a fix and disclosure date with you. We are happy to credit reporters who want credit.

## Supported versions

Only the latest release on the default branch receives security fixes.

## Scope

In scope: the code in this repository, the reports it generates, and the preview it embeds in them.

Out of scope: the third-party services this project can query with `--online` (URLhaus, MalwareBazaar, ip-api.com, the public DNS system), and findings that require an attacker who already controls the machine running the tool.

## Using this tool

atarus-phishcheck parses untrusted email and is meant to be run on hostile input. It is offline by default: a plain run makes no network connection at all. `--online` enables DNS, URLhaus, MalwareBazaar and ip-api.com lookups and prints every destination before the first one; `--online --expand-links` adds one HEAD request to each URL shortener host in the email, never to the redirect destination. The README's network table is the complete list of destinations.

Treat generated reports as containing attacker-controlled content. The HTML preview is rebuilt from an allowlist inside a fully sandboxed iframe with a `default-src 'none'` Content-Security-Policy; open reports in a current browser.

Treat as a security bug and report it:

- any network connection made by a run without `--online`, including a DNS query
- any connection to a host not listed in the README's network table, or to a redirect destination with `--expand-links`
- any request to a private, loopback, link-local or cloud-metadata address
- a report or terminal summary that can read as clean when a check did not run, or verdict wording that calls an email legitimate or safe
- a preview that loads a remote resource, runs script, submits a form or navigates, or a link that is not disabled
- a crafted email that makes a run take more than a few seconds, or that is not cut at the documented input limits
- email text that reaches the terminal with escape sequences or rich markup intact
