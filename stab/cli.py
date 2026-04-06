"""
STAB - Subdomain Takeover And Brute-force
drew's subdomain takeover scanner
"""
import asyncio
import sys
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from stab.core.checks import run_checks
from stab.core.enumerate import enumerate_subdomains
from stab.output.writer import write_jsonl, write_report

app = typer.Typer(
    name="stab",
    help="subdomain takeover scanner - find dangling CNAMEs, unclaimed S3 buckets, NS takeovers",
    add_completion=False,
)
console = Console()

LOGO = r"""
         __         __
   _____/ /_____ _/ /_
  / ___/ __/ __ `/ __ \
 (__  ) /_/ /_/ / /_/ /
/____/\__/\__,_/_.___/

  subdomain takeover and brute-force
  andrew@cyberdiary.net
"""


@app.command()
def scan(
    domain: Annotated[str, typer.Argument(help="target domain (e.g. example.com)")],
    output: Annotated[str, typer.Option("--output", "-o", help="output directory")] = ".",
    input_file: Annotated[str, typer.Option("--input", "-i", help="file with subdomains (one per line), skips enumeration")] = "",
    concurrency: Annotated[int, typer.Option("--concurrency", "-c", help="concurrent checks")] = 20,
    no_enumerate: Annotated[bool, typer.Option("--no-enumerate", help="skip subdomain enumeration, only use -i input")] = False,
):
    """
    scan a domain for subdomain takeover vulnerabilities.

    examples:
        stab scan example.com
        stab scan example.com --output ./results
        cat subdomains.txt | stab scan example.com -i -
        stab scan example.com -i subdomains.txt --no-enumerate
    """
    console.print(LOGO, markup=False, highlight=False)

    domain = domain.lower().strip().lstrip("*.").rstrip(".")

    subdomains: list[str] = []

    # Load from input file or stdin
    if input_file:
        if input_file == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(input_file) as f:
                lines = f.read().splitlines()
        subdomains = [l.strip() for l in lines if l.strip()]
        console.print(f"[dim]loaded {len(subdomains)} subdomains from input[/dim]")

    # Enumerate unless skipped
    if not no_enumerate:
        console.print(f"[dim]enumerating subdomains for {domain}...[/dim]")
        found = asyncio.run(enumerate_subdomains(domain))
        new = [s for s in found if s not in subdomains]
        subdomains = list(dict.fromkeys(subdomains + new))
        console.print(f"[dim]found {len(found)} subdomains ({len(new)} new)[/dim]")

    if not subdomains:
        console.print("[yellow]no subdomains to check[/yellow]")
        raise typer.Exit()

    console.print(f"[dim]checking {len(subdomains)} subdomains for takeover (concurrency={concurrency})...[/dim]\n")

    findings = asyncio.run(run_checks(subdomains, concurrency=concurrency))

    vuln = [f for f in findings if f["type"] in ("cname_takeover", "s3_takeover", "ns_takeover")]

    if vuln:
        table = Table(title="takeover candidates", style="red")
        table.add_column("subdomain", style="bold white")
        table.add_column("type", style="yellow")
        table.add_column("service", style="cyan")
        table.add_column("evidence", style="dim")

        for v in sorted(vuln, key=lambda x: x["subdomain"]):
            evidence = str(v.get("evidence") or v.get("ns_record") or v.get("bucket") or "-")
            table.add_row(v["subdomain"], v["type"], v["service"], evidence)

        console.print(table)
    else:
        console.print("[green]no takeover candidates found[/green]")

    # Write output
    if findings:
        jsonl_path = write_jsonl(findings, output, domain)
        report_path = write_report(findings, output, domain)
        console.print(f"\n[dim]jsonl:[/dim] {jsonl_path}")
        console.print(f"[dim]report:[/dim] {report_path}")

    console.print(f"\n[dim]scanned {len(subdomains)} subdomains, {len(vuln)} takeover candidate(s)[/dim]")


def main():
    app()


if __name__ == "__main__":
    main()
