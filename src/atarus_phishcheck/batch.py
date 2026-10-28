"""Batch analyze a directory of .eml files or an mbox file"""
import os
import glob
import html as _html
import shutil
import tempfile
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from atarus_phishcheck.analyzers import scoring
from atarus_phishcheck.analyzers.parser import InputTooLarge, MAX_INPUT_BYTES
from atarus_phishcheck.models import AnalysisResult
from atarus_phishcheck.network import Policy, OFFLINE
from atarus_phishcheck.pipeline import analyze_file
from atarus_phishcheck.reports import html_report, json_export
from atarus_phishcheck.safe_output import safe_text

console = Console()

MAX_MBOX_MESSAGES = 10000

VERDICT_COLORS = {
    "no_strong_indicators": "green",
    "questionable": "yellow",
    "suspicious": "bright_yellow",
    "likely_phishing": "red",
}


def analyze_single(path: str, policy: Policy = None) -> AnalysisResult:
    """Analyze a single .eml file and return the full result"""
    return analyze_file(path, policy=policy or OFFLINE)


def analyze_batch(input_path: str, output_dir: str, out_format: str, policy: Policy = None) -> list:
    """Analyze a directory of .eml files or an mbox. Returns list of results."""
    policy = policy or OFFLINE
    os.makedirs(output_dir, exist_ok=True)
    split_dir = None
    try:
        files, split_dir = _collect_files(input_path, output_dir)

        if not files:
            console.print(f"[bold red]No .eml files found in {escape(input_path)}[/]")
            return []

        console.print(f"[bold white]Found {len(files)} email(s) to analyze[/]")

        results = []
        skipped = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing...", total=len(files))
            for f in files:
                progress.update(task, description=f"Analyzing {escape(safe_text(os.path.basename(f), 60))}")
                try:
                    r = analyze_single(f, policy=policy)
                    results.append(r)

                    base = os.path.splitext(os.path.basename(f))[0]
                    if out_format in ("html", "all"):
                        html_report.generate(r, os.path.join(output_dir, f"phishcheck-{base}.html"))
                    if out_format in ("json", "all"):
                        json_export.generate(r, os.path.join(output_dir, f"phishcheck-{base}.json"))
                except InputTooLarge as e:
                    skipped.append((f, str(e)))
                    console.print(f"[bold yellow]Skipped {escape(safe_text(f, 120))}:[/] {escape(safe_text(str(e)))}")
                except Exception as e:
                    skipped.append((f, f"{type(e).__name__}: {e}"))
                    console.print(f"[bold red]Error analyzing {escape(safe_text(f, 120))}:[/] {escape(safe_text(str(e)))}")
                progress.advance(task)

        _print_batch_summary(results, skipped, output_dir, policy)
        _write_batch_summary(results, skipped, output_dir, policy)
        return results
    finally:
        if split_dir and os.path.isdir(split_dir):
            shutil.rmtree(split_dir, ignore_errors=True)


def _collect_files(input_path: str, output_dir: str) -> tuple:
    """(files, temp_dir_to_remove)"""
    if os.path.isfile(input_path):
        if input_path.lower().endswith(".mbox"):
            return _split_mbox(input_path, output_dir)
        return [input_path], None

    if os.path.isdir(input_path):
        files = sorted(glob.glob(os.path.join(input_path, "*.eml")))
        return files, None

    return [], None


def _split_mbox(mbox_path: str, output_dir: str) -> tuple:
    """Split an mbox into .eml files in a temporary directory under the output
    directory. The caller removes the directory when the batch is done, so no
    copy of the mailbox is left next to the input. Returns (paths, temp_dir)."""
    import mailbox
    out_dir = tempfile.mkdtemp(prefix="mbox-split-", dir=output_dir)

    paths = []
    try:
        mbox = mailbox.mbox(mbox_path)
        for i, msg in enumerate(mbox):
            if i >= MAX_MBOX_MESSAGES:
                console.print(f"[bold yellow]mbox has more than {MAX_MBOX_MESSAGES} messages; the rest were not analyzed[/]")
                break
            out_path = os.path.join(out_dir, f"message-{i:04d}.eml")
            data = msg.as_bytes()
            with open(out_path, "wb") as f:
                f.write(data[:MAX_INPUT_BYTES + 1])
            paths.append(out_path)
    except Exception as e:
        console.print(f"[bold red]Error splitting mbox:[/] {escape(safe_text(str(e)))}")

    return paths, out_dir


def _print_batch_summary(results: list, skipped: list, output_dir: str, policy: Policy):
    if not results and not skipped:
        return

    results_sorted = sorted(results, key=lambda r: r.phish_score, reverse=True)

    table = Table(title=f"Batch Analysis Summary ({policy.mode} mode)", show_lines=False)
    table.add_column("Score", style="bold", justify="right", width=6)
    table.add_column("Verdict", width=22)
    table.add_column("From")
    table.add_column("Subject")
    table.add_column("File", style="dim")

    for r in results_sorted:
        verdict_color = VERDICT_COLORS.get(r.verdict, "white")

        from_display = escape(safe_text(r.headers.from_email or r.headers.from_header or "(empty)", 50))
        subject = escape(safe_text(r.headers.subject or "(empty)", 60))
        filename = escape(safe_text(os.path.basename(r.source_file), 80))

        table.add_row(
            f"{r.phish_score}",
            f"[{verdict_color}]{scoring.verdict_label(r.verdict)}[/]",
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
    for v in ("likely_phishing", "suspicious", "questionable", "no_strong_indicators"):
        if v in verdict_counts:
            console.print(f"  [{VERDICT_COLORS[v]}]{scoring.verdict_label(v)}:[/] {verdict_counts[v]}")
    if skipped:
        console.print(f"[bold yellow]Not analyzed:[/] {len(skipped)} file(s), listed in batch-summary.html")
    if policy.mode == "offline":
        console.print("[yellow]Offline mode: DNS, reputation and shortener lookups were not run (see each report).[/]")
    console.print(f"\n[bold green]Reports written to:[/] {escape(output_dir)}")


def _write_batch_summary(results: list, skipped: list, output_dir: str, policy: Policy):
    """Write batch-summary.html with overview of all analyzed emails"""
    if not results and not skipped:
        return

    results_sorted = sorted(results, key=lambda r: r.phish_score, reverse=True)

    rows_html = ""
    for r in results_sorted:
        verdict_class = r.verdict
        score_class = "high" if r.phish_score >= 75 else "medium" if r.phish_score >= 40 else "low" if r.phish_score >= 15 else "none"
        filename = os.path.basename(r.source_file)
        base = os.path.splitext(filename)[0]

        rows_html += f'''
        <tr>
            <td class="score-cell {score_class}">{r.phish_score}</td>
            <td><span class="verdict-pill {verdict_class}">{_esc(scoring.verdict_label(r.verdict))}</span></td>
            <td>{_esc(r.headers.from_email or r.headers.from_header or '(empty)')}</td>
            <td>{_esc(r.headers.subject or '(empty)')}</td>
            <td><a href="phishcheck-{_esc(base)}.html">{_esc(filename)}</a></td>
        </tr>'''

    skipped_html = ""
    if skipped:
        items = "".join(f"<li><code>{_esc(os.path.basename(p))}</code>: {_esc(reason)}</li>" for p, reason in skipped)
        skipped_html = f'<h2>Not analyzed ({len(skipped)})</h2><ul class="skipped">{items}</ul>'

    mode_note = "Offline mode: no DNS, reputation or shortener lookups were made. Each report lists the checks that did not run." if policy.mode == "offline" else "Online mode: lookups enabled (" + ", ".join(_esc(x) for x in (results[0].lookups_enabled if results else [])) + "). Failed lookups are listed in each report."

    html = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>atarus-phishcheck batch summary</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #060606; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 40px 20px; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ font-size: 26px; margin-bottom: 6px; letter-spacing: 1px; }}
h1 span {{ color: #D4263E; }}
h2 {{ font-size: 16px; margin: 28px 0 10px; color: #eab308; }}
.subtitle {{ color: #888; font-size: 13px; margin-bottom: 12px; }}
.mode {{ color: #fcd34d; font-size: 12px; margin-bottom: 28px; padding-bottom: 16px; border-bottom: 2px solid #D4263E; }}
table {{ width: 100%; border-collapse: collapse; background: #111; border-radius: 8px; overflow: hidden; }}
th {{ text-align: left; padding: 12px 16px; background: #1a1a1a; color: #888; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
td {{ padding: 12px 16px; border-bottom: 1px solid #1a1a1a; font-size: 13px; }}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: #0a0a0a; }}
.score-cell {{ font-weight: 700; font-size: 18px; width: 70px; text-align: center; font-family: 'Courier New', monospace; }}
.score-cell.high {{ color: #ef4444; }}
.score-cell.medium {{ color: #f97316; }}
.score-cell.low {{ color: #eab308; }}
.score-cell.none {{ color: #22c55e; }}
.verdict-pill {{ padding: 3px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }}
.verdict-pill.likely_phishing {{ background: #450a0a; color: #fca5a5; }}
.verdict-pill.suspicious {{ background: #431407; color: #fdba74; }}
.verdict-pill.questionable {{ background: #422006; color: #fcd34d; }}
.verdict-pill.no_strong_indicators {{ background: #052e16; color: #86efac; }}
.skipped {{ font-size: 13px; color: #ccc; padding-left: 20px; }}
.skipped code {{ color: #fcd34d; }}
a {{ color: #D4263E; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.footer {{ margin-top: 32px; text-align: center; font-size: 11px; color: #555; }}
.footer a {{ color: #D4263E; }}
</style></head>
<body>
<div class="container">
<h1>ATARUS <span>PHISHCHECK</span></h1>
<div class="subtitle">Batch analysis summary &middot; {len(results)} emails analyzed</div>
<div class="mode">{mode_note}</div>
<table>
<thead><tr><th>Score</th><th>Verdict</th><th>From</th><th>Subject</th><th>Report</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
{skipped_html}
<div class="footer">Generated by <a href="https://github.com/atarus-security/atarus-phishcheck">atarus-phishcheck</a></div>
</div>
</body></html>'''

    summary_path = os.path.join(output_dir, "batch-summary.html")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(html)


def _esc(s: str) -> str:
    return _html.escape(s or "", quote=True)
