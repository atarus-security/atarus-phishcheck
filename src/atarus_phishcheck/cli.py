import os
import sys
import click
from rich.console import Console
from rich.markup import escape
from atarus_phishcheck import __version__
from atarus_phishcheck.analyzers import scoring
from atarus_phishcheck.analyzers.parser import InputTooLarge
from atarus_phishcheck.batch import analyze_batch
from atarus_phishcheck.network import Policy
from atarus_phishcheck.pipeline import analyze_file
from atarus_phishcheck.reports import html_report, json_export
from atarus_phishcheck.safe_output import safe_text

console = Console()

VERSION = __version__

BANNER = f"""
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╔═╗╦ ╦╦╔═╗╦ ╦╔═╗╦ ╦╔═╗╔═╗╦╔═
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ╠═╝╠═╣║╚═╗╠═╣║  ╠═╣║╣ ║  ╠╩╗
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╩  ╩ ╩╩╚═╝╩ ╩╚═╝╩ ╩╚═╝╚═╝╩ ╩
   Atarus Offensive Security | v{VERSION}
"""

VERDICT_COLORS = {
    "no_strong_indicators": "green",
    "questionable": "yellow",
    "suspicious": "bright_yellow",
    "likely_phishing": "red",
}


@click.command()
@click.option("-i", "--input", "input_path", type=click.Path(exists=True), required=True, help="Path to .eml file, .mbox file, or directory of .eml files (batch mode)")
@click.option("-o", "--output", default="./output", help="Output directory")
@click.option("--format", "out_format", default="all", type=click.Choice(["html", "json", "all", "terminal"]), help="Output format")
@click.option("--online", is_flag=True, help="Allow network lookups: DNS for SPF and DMARC records, URLhaus, MalwareBazaar and ip-api.com. The destinations are printed before any lookup. Default is offline.")
@click.option("--expand-links", is_flag=True, help="With --online: send one HEAD request to each URL shortener in the email and record where it redirects. The destination is never contacted.")
@click.option("--offline", is_flag=True, hidden=True, help="Accepted for compatibility; offline is the default.")
@click.option("--batch", is_flag=True, help="Batch mode: analyze a directory of .eml files or an .mbox file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.version_option(version=VERSION, prog_name="atarus-phishcheck")
def main(input_path, output, out_format, online, expand_links, offline, batch, verbose):
    """atarus-phishcheck: defensive email analysis. Offline by default; nothing leaves your machine unless you pass --online."""

    if offline and online:
        raise click.UsageError("--offline and --online cannot be combined.")
    if expand_links and not online:
        raise click.UsageError("--expand-links needs --online: expanding a shortener sends a request to its host.")

    policy = Policy(online=online, expand_links=expand_links)

    console.print(BANNER, style="bold red")

    if policy.online:
        console.print("[bold yellow]Online mode:[/] this run may contact")
        for line in policy.destinations():
            console.print(f"  [yellow]•[/] {escape(line)}")
        console.print("  Lookups that fail are listed under 'Checks not run' in the output.")
        console.print()
    else:
        console.print("[bold green]Offline mode (default):[/] no network lookups. Pass --online to enable them.")
        console.print()

    if batch or os.path.isdir(input_path) or input_path.lower().endswith(".mbox"):
        console.print(f"[bold white]Batch mode:[/] {escape(input_path)}")
        analyze_batch(input_path, output, out_format, policy=policy)
        return

    console.print(f"[bold white]Analyzing:[/] {escape(input_path)}")

    try:
        result = analyze_file(input_path, policy=policy)
    except InputTooLarge as e:
        console.print(f"[bold red]Refused:[/] {escape(str(e))}")
        sys.exit(2)

    _print_summary(result)

    if out_format == "terminal":
        return

    os.makedirs(output, exist_ok=True)
    base = os.path.splitext(os.path.basename(input_path))[0]

    if out_format in ("html", "all"):
        html_path = os.path.join(output, f"phishcheck-{base}.html")
        html_report.generate(result, html_path)
        console.print(f"[bold green]HTML report:[/] {escape(html_path)}")

    if out_format in ("json", "all"):
        json_path = os.path.join(output, f"phishcheck-{base}.json")
        json_export.generate(result, json_path)
        console.print(f"[bold green]JSON report:[/] {escape(json_path)}")


def _show(value) -> str:
    """Email-derived text, with control characters and rich markup neutralised."""
    return escape(safe_text(value))


def _print_summary(result):
    color = VERDICT_COLORS.get(result.verdict, "white")

    console.print()
    console.print(f"[bold white]From:[/] {_show(result.headers.from_header)}")
    console.print(f"[bold white]Subject:[/] {_show(result.headers.subject)}")
    console.print()

    console.print(f"[bold white]Authentication (from headers):[/] SPF={_show(result.auth.spf_result)}, DKIM={_show(result.auth.dkim_result)}, DMARC={_show(result.auth.dmarc_result)}")
    console.print(f"[bold white]Indicators:[/] {len(result.indicators)}")
    console.print(f"[bold white]Findings:[/] {len(result.findings)} ({result.severity_counts['high']} high, {result.severity_counts['medium']} medium, {result.severity_counts['low']} low)")
    console.print()

    console.print(f"[bold white]Phish score:[/] {result.phish_score}/100")
    console.print(f"[bold {color}]Verdict: {scoring.verdict_label(result.verdict)}[/]")
    console.print(f"[dim]{escape(scoring.VERDICT_TEXT.get(result.verdict, ''))}[/]")
    console.print()

    highs = [f for f in result.findings if f.severity == "high"]
    if highs:
        console.print("[bold red]High-severity findings:[/]")
        for f in highs:
            console.print(f"  [red]•[/] {_show(f.title)}")
        console.print()

    if result.checks_not_run:
        console.print(f"[bold yellow]Checks not run ({result.mode} mode):[/]")
        for c in result.checks_not_run:
            console.print(f"  [yellow]•[/] {_show(c.check)}: {_show(c.reason)}")
        console.print()


if __name__ == "__main__":
    main()
