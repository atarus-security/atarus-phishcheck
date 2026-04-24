"""Batch analyze a directory of .eml files or an mbox file"""
import os
import glob
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from atarus_phishcheck.analyzers import parser, auth, indicators, content, scoring, brands, reputation, urlexpand, geoip, homoglyph
from atarus_phishcheck.models import AnalysisResult
from atarus_phishcheck.reports import html_report, json_export

console = Console()


def analyze_single(path: str, offline: bool = False) -> AnalysisResult:
    """Analyze a single .eml file and return the full result"""
    with open(path, "r", errors="replace") as f:
        raw = f.read()

    headers, body = parser.parse_email(raw)
    auth_result, auth_findings = auth.check_authentication(headers)
    ioc_list, ioc_findings = indicators.extract_indicators(headers, body)
    content_findings = content.analyze_content(headers, body)
    brand_findings = brands.check_brand_impersonation(headers, body)
    homoglyph_findings = homoglyph.check_homoglyphs(headers, body)

    hash_indicators, _ = reputation.hash_attachments(body, raw)
    ioc_list.extend(hash_indicators)

    rep_findings = []
    expand_findings = []
    geo_findings = []

    if not offline:
        expanded_indicators, expand_findings = urlexpand.expand_urls(ioc_list, offline=offline)
        ioc_list.extend(expanded_indicators)

        url_findings = reputation.check_urls(ioc_list, offline=offline)
        rep_findings.extend(url_findings)

        if hash_indicators:
            mb_findings = reputation.check_hashes_malwarebazaar(ioc_list, offline=offline)
            rep_findings.extend(mb_findings)

        geo_findings = geoip.lookup_ips(ioc_list, headers, offline=offline)

    result = AnalysisResult(
        source_file=path,
        headers=headers,
        body=body,
        auth=auth_result,
    )
    result.indicators = ioc_list
    all_findings = auth_findings + ioc_findings + content_findings + brand_findings + homoglyph_findings + expand_findings + rep_findings + geo_findings
    for f in all_findings:
        result.add_finding(f)

    scoring.score_result(result)
    return result


def analyze_batch(input_path: str, output_dir: str, out_format: str, offline: bool = False) -> list:
    """Analyze a directory of .eml files or an mbox. Returns list of results."""
    files = _collect_files(input_path)

    if not files:
        console.print(f"[bold red]No .eml files found in {input_path}[/]")
        return []

    console.print(f"[bold white]Found {len(files)} email(s) to analyze[/]")
    os.makedirs(output_dir, exist_ok=True)

    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing...", total=len(files))
        for f in files:
            progress.update(task, description=f"Analyzing {os.path.basename(f)}")
            try:
                r = analyze_single(f, offline=offline)
                results.append(r)

                base = os.path.splitext(os.path.basename(f))[0]
                if out_format in ("html", "all"):
                    html_report.generate(r, os.path.join(output_dir, f"phishcheck-{base}.html"))
                if out_format in ("json", "all"):
                    json_export.generate(r, os.path.join(output_dir, f"phishcheck-{base}.json"))
            except Exception as e:
                console.print(f"[bold red]Error analyzing {f}:[/] {e}")
            progress.advance(task)

    _print_batch_summary(results, output_dir)
    _write_batch_summary(results, output_dir)
    return results


def _collect_files(input_path: str) -> list:
    if os.path.isfile(input_path):
        if input_path.lower().endswith(".eml"):
            return [input_path]
        if input_path.lower().endswith(".mbox"):
            return _split_mbox(input_path)
        return [input_path]

    if os.path.isdir(input_path):
        files = sorted(glob.glob(os.path.join(input_path, "*.eml")))
        return files

    return []


def _split_mbox(mbox_path: str) -> list:
    """Split an mbox into individual .eml files in a temp subdirectory. Returns list of paths."""
    import mailbox
    out_dir = mbox_path + "_split"
    os.makedirs(out_dir, exist_ok=True)

    paths = []
    try:
        mbox = mailbox.mbox(mbox_path)
        for i, msg in enumerate(mbox):
            out_path = os.path.join(out_dir, f"message-{i:04d}.eml")
            with open(out_path, "w") as f:
                f.write(msg.as_string())
            paths.append(out_path)
    except Exception as e:
        console.print(f"[bold red]Error splitting mbox:[/] {e}")

    return paths


def _print_batch_summary(results: list, output_dir: str):
    if not results:
        return

    results_sorted = sorted(results, key=lambda r: r.phish_score, reverse=True)

    table = Table(title="Batch Analysis Summary", show_lines=False)
    table.add_column("Score", style="bold", justify="right", width=6)
    table.add_column("Verdict", width=18)
    table.add_column("From")
    table.add_column("Subject")
    table.add_column("File", style="dim")

    for r in results_sorted:
        verdict_color = {
            "clean": "green",
            "questionable": "yellow",
            "suspicious": "bright_yellow",
            "likely_phishing": "red",
        }.get(r.verdict, "white")

        from_display = (r.headers.from_email or r.headers.from_header or "(empty)")[:50]
        subject = (r.headers.subject or "(empty)")[:60]
        filename = os.path.basename(r.source_file)

        table.add_row(
            f"{r.phish_score}",
            f"[{verdict_color}]{r.verdict.replace('_', ' ').upper()}[/]",
            from_display,
            subject,
            filename,
        )

    console.print()
    console.print(table)
    console.print()

    verdict_counts = {}
    for r in results:
        verdict_counts[r.verdict] = verdict_counts.get(r.verdict, 0) + 1

    console.print(f"[bold white]Total analyzed:[/] {len(results)}")
    for v in ("likely_phishing", "suspicious", "questionable", "clean"):
        if v in verdict_counts:
            color = {"clean": "green", "questionable": "yellow", "suspicious": "bright_yellow", "likely_phishing": "red"}[v]
            console.print(f"  [{color}]{v.replace('_', ' ').upper()}:[/] {verdict_counts[v]}")
    console.print(f"\n[bold green]Reports written to:[/] {output_dir}")


def _write_batch_summary(results: list, output_dir: str):
    """Write batch-summary.html with overview of all analyzed emails"""
    if not results:
        return

    results_sorted = sorted(results, key=lambda r: r.phish_score, reverse=True)

    rows_html = ""
    for r in results_sorted:
        verdict_class = r.verdict
        score_class = "high" if r.phish_score >= 75 else "medium" if r.phish_score >= 40 else "low" if r.phish_score >= 15 else "clean"
        filename = os.path.basename(r.source_file)
        base = os.path.splitext(filename)[0]

        rows_html += f'''
        <tr>
            <td class="score-cell {score_class}">{r.phish_score}</td>
            <td><span class="verdict-pill {verdict_class}">{r.verdict.replace('_', ' ').upper()}</span></td>
            <td>{_esc(r.headers.from_email or r.headers.from_header or '(empty)')}</td>
            <td>{_esc(r.headers.subject or '(empty)')}</td>
            <td><a href="phishcheck-{_esc(base)}.html">{_esc(filename)}</a></td>
        </tr>'''

    html = f'''<!DOCTYPE html>
<html><head><title>atarus-phishcheck batch summary</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #060606; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 40px 20px; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ font-size: 26px; margin-bottom: 6px; letter-spacing: 1px; }}
h1 span {{ color: #D4263E; }}
.subtitle {{ color: #888; font-size: 13px; margin-bottom: 28px; padding-bottom: 16px; border-bottom: 2px solid #D4263E; }}
table {{ width: 100%; border-collapse: collapse; background: #111; border-radius: 8px; overflow: hidden; }}
th {{ text-align: left; padding: 12px 16px; background: #1a1a1a; color: #888; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
td {{ padding: 12px 16px; border-bottom: 1px solid #1a1a1a; font-size: 13px; }}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: #0a0a0a; }}
.score-cell {{ font-weight: 700; font-size: 18px; width: 70px; text-align: center; font-family: 'Courier New', monospace; }}
.score-cell.high {{ color: #ef4444; }}
.score-cell.medium {{ color: #f97316; }}
.score-cell.low {{ color: #eab308; }}
.score-cell.clean {{ color: #22c55e; }}
.verdict-pill {{ padding: 3px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }}
.verdict-pill.likely_phishing {{ background: #450a0a; color: #fca5a5; }}
.verdict-pill.suspicious {{ background: #431407; color: #fdba74; }}
.verdict-pill.questionable {{ background: #422006; color: #fcd34d; }}
.verdict-pill.clean {{ background: #052e16; color: #86efac; }}
a {{ color: #D4263E; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.footer {{ margin-top: 32px; text-align: center; font-size: 11px; color: #555; }}
.footer a {{ color: #D4263E; }}
</style></head>
<body>
<div class="container">
<h1>ATARUS <span>PHISHCHECK</span></h1>
<div class="subtitle">Batch analysis summary &middot; {len(results)} emails analyzed</div>
<table>
<thead><tr><th>Score</th><th>Verdict</th><th>From</th><th>Subject</th><th>Report</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
<div class="footer">Generated by <a href="https://github.com/atarus-security/atarus-phishcheck">atarus-phishcheck</a></div>
</div>
</body></html>'''

    summary_path = os.path.join(output_dir, "batch-summary.html")
    with open(summary_path, "w") as f:
        f.write(html)


def _esc(s: str) -> str:
    import html as _html
    return _html.escape(s or "", quote=True)
