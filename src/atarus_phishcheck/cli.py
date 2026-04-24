import os
import click
from rich.console import Console
from atarus_phishcheck.analyzers import parser, auth, indicators, content, scoring, brands, reputation, urlexpand, geoip, homoglyph
from atarus_phishcheck.models import AnalysisResult
from atarus_phishcheck.reports import html_report, json_export
from atarus_phishcheck.batch import analyze_batch

console = Console()

VERSION = "0.3.0"

BANNER = f"""
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╔═╗╦ ╦╦╔═╗╦ ╦╔═╗╦ ╦╔═╗╔═╗╦╔═
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ╠═╝╠═╣║╚═╗╠═╣║  ╠═╣║╣ ║  ╠╩╗
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╩  ╩ ╩╩╚═╝╩ ╩╚═╝╩ ╩╚═╝╚═╝╩ ╩
   Atarus Offensive Security | v{VERSION}
"""


@click.command()
@click.option("-i", "--input", "input_path", type=click.Path(exists=True), required=True, help="Path to .eml file, .mbox file, or directory of .eml files (batch mode)")
@click.option("-o", "--output", default="./output", help="Output directory")
@click.option("--format", "out_format", default="all", type=click.Choice(["html", "json", "all", "terminal"]), help="Output format")
@click.option("--offline", is_flag=True, help="Skip external reputation lookups")
@click.option("--batch", is_flag=True, help="Batch mode: analyze a directory of .eml files or an .mbox file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.version_option(version=VERSION, prog_name="atarus-phishcheck")
def main(input_path, output, out_format, offline, batch, verbose):
    """atarus-phishcheck: defensive email security analyzer"""

    console.print(BANNER, style="bold red")

    if batch or os.path.isdir(input_path) or input_path.lower().endswith(".mbox"):
        console.print(f"[bold white]Batch mode:[/] {input_path}")
        if offline:
            console.print(f"[bold yellow]Offline mode:[/] skipping external lookups")
        analyze_batch(input_path, output, out_format, offline=offline)
        return

    console.print(f"[bold white]Analyzing:[/] {input_path}")
    if offline:
        console.print(f"[bold yellow]Offline mode:[/] skipping external lookups")

    with open(input_path, "r", errors="replace") as f:
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
        with console.status("[bold cyan]Expanding URL shorteners..."):
            expanded_indicators, expand_findings = urlexpand.expand_urls(ioc_list, offline=offline)
            ioc_list.extend(expanded_indicators)

        with console.status("[bold cyan]Checking URLs against URLhaus..."):
            url_findings = reputation.check_urls(ioc_list, offline=offline)
            rep_findings.extend(url_findings)

        if hash_indicators:
            with console.status("[bold cyan]Checking attachment hashes against MalwareBazaar..."):
                mb_findings = reputation.check_hashes_malwarebazaar(ioc_list, offline=offline)
                rep_findings.extend(mb_findings)

        with console.status("[bold cyan]Looking up IP geolocation..."):
            geo_findings = geoip.lookup_ips(ioc_list, headers, offline=offline)

    result = AnalysisResult(
        source_file=input_path,
        headers=headers,
        body=body,
        auth=auth_result,
    )
    result.indicators = ioc_list
    all_findings = auth_findings + ioc_findings + content_findings + brand_findings + homoglyph_findings + expand_findings + rep_findings + geo_findings
    for f in all_findings:
        result.add_finding(f)

    scoring.score_result(result)

    _print_summary(result)

    if out_format == "terminal":
        return

    os.makedirs(output, exist_ok=True)
    base = os.path.splitext(os.path.basename(input_path))[0]

    if out_format in ("html", "all"):
        html_path = os.path.join(output, f"phishcheck-{base}.html")
        html_report.generate(result, html_path)
        console.print(f"[bold green]HTML report:[/] {html_path}")

    if out_format in ("json", "all"):
        json_path = os.path.join(output, f"phishcheck-{base}.json")
        json_export.generate(result, json_path)
        console.print(f"[bold green]JSON report:[/] {json_path}")


def _print_summary(result):
    verdict_colors = {
        "clean": "green",
        "questionable": "yellow",
        "suspicious": "bright_yellow",
        "likely_phishing": "red",
    }
    color = verdict_colors.get(result.verdict, "white")

    console.print()
    console.print(f"[bold white]From:[/] {result.headers.from_header}")
    console.print(f"[bold white]Subject:[/] {result.headers.subject}")
    console.print()

    console.print(f"[bold white]Authentication:[/] SPF={result.auth.spf_result}, DKIM={result.auth.dkim_result}, DMARC={result.auth.dmarc_result}")
    console.print(f"[bold white]Indicators:[/] {len(result.indicators)}")
    console.print(f"[bold white]Findings:[/] {len(result.findings)} ({result.severity_counts['high']} high, {result.severity_counts['medium']} medium, {result.severity_counts['low']} low)")
    console.print()

    console.print(f"[bold white]Phish score:[/] {result.phish_score}/100")
    console.print(f"[bold {color}]Verdict: {result.verdict.replace('_', ' ').upper()}[/]")
    console.print()

    highs = [f for f in result.findings if f.severity == "high"]
    if highs:
        console.print(f"[bold red]High-severity findings:[/]")
        for f in highs:
            console.print(f"  [red]•[/] {f.title}")
        console.print()


if __name__ == "__main__":
    main()
