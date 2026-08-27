from __future__ import annotations

import argparse
import asyncio
import csv
import json
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .scanner import ProbeResult, parse_domains, scan

BANNER = r"""
   _____       __                    __       __
  / ___/__  __/ /_ _      ______ _ / /______/ /_
  \__ \/ / / / __ \ | /| / / __ `// __/ ___/ __ \
 ___/ / /_/ / /_/ / |/ |/ / /_/ // /_/ /__/ / / /
/____/\__,_/_.___/|__/|__/\__,_/ \__/\___/_/ /_/
"""

STATE_MARKS = {
    "public": ("+", "bold green"),
    "closed": ("-", "yellow"),
    "dns-failed": ("-", "dim"),
    "non-public-ip": ("!", "yellow"),
    "api-error": ("!", "bold red"),
}


def result_line(item: ProbeResult) -> Text:
    mark, style = STATE_MARKS.get(item.state, ("!", "red"))
    line = Text.assemble((f"[{mark}] ", style), (item.host, "bold"))
    if item.state == "public":
        line.append(f"  {item.status}  ", style="green")
        line.append(item.url)
        line.append(f"  ({item.elapsed_ms} ms)", style="dim")
        if item.title:
            line.append(f"  {item.title}", style="cyan")
    else:
        line.append(f"  {item.state}", style=style)
        if item.detail:
            line.append(f"  {item.detail}", style="dim")
    return line


def write_reports(results: list[ProbeResult], output: Path, json_report: bool, csv_report: bool) -> list[Path]:
    if not results or not (json_report or csv_report):
        return []
    output.mkdir(parents=True, exist_ok=True)
    rows = [result.dict() for result in results]
    written: list[Path] = []
    if json_report:
        target = output / "subwatch-results.json"
        target.write_text(json.dumps(rows, indent=2) + "\n")
        written.append(target)
    if csv_report:
        target = output / "subwatch-results.csv"
        with target.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=rows[0])
            writer.writeheader()
            writer.writerows(rows)
        written.append(target)
    return written


async def run_scan(
    domains: list[str], concurrency: int, timeout: float, console: Console,
    show_all: bool, discovery_url: str, discovery_source: str, max_pages: int,
) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    total = 0
    progress = Progress(
        SpinnerColumn(style="cyan"), TextColumn("{task.description}"), BarColumn(bar_width=28),
        MofNCompleteColumn(), TimeElapsedColumn(), console=console,
    )
    task = progress.add_task("Discovering certificates", total=None)

    async def discovered(apex: str, count: int) -> None:
        nonlocal total
        total += count
        progress.update(task, total=total, description=f"Checking [bold]{apex}[/bold]")
        progress.console.print(f"[cyan][*][/cyan] {apex}: discovered [bold]{count}[/bold] in-scope hosts")

    async def receive(item: ProbeResult) -> None:
        results.append(item)
        progress.advance(task)
        if show_all or item.state in {"public", "api-error"}:
            progress.console.print(result_line(item))

    with progress:
        await scan(
            domains, concurrency, timeout, discovered, receive,
            discovery_url, discovery_source, max_pages,
        )
        progress.update(task, description="Complete")
    return results


def print_summary(console: Console, results: list[ProbeResult]) -> None:
    counts = {state: sum(item.state == state for item in results) for state in STATE_MARKS}
    table = Table(title="Scan summary", box=None, show_header=False, pad_edge=False)
    table.add_column(style="dim")
    table.add_column(justify="right", style="bold")
    table.add_row("Hosts checked", str(len(results)))
    table.add_row("Public web services", f"[green]{counts['public']}[/green]")
    table.add_row("Closed / no response", str(counts["closed"]))
    table.add_row("DNS failures", str(counts["dns-failed"]))
    table.add_row("Non-public addresses", str(counts["non-public-ip"]))
    table.add_row("API errors", f"[red]{counts['api-error']}[/red]")
    console.print()
    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Discover certificate hostnames and test public web reachability")
    parser.add_argument("domains", nargs="*", help="apex domains (or use --file)")
    parser.add_argument("-f", "--file", type=Path, help="newline/comma-separated domains")
    parser.add_argument("-c", "--concurrency", type=int, default=30)
    parser.add_argument("-t", "--timeout", type=float, default=7.0)
    parser.add_argument("-o", "--output", type=Path, default=Path("."), help="report directory")
    parser.add_argument("--json", action="store_true", help="write a JSON report")
    parser.add_argument("--csv", action="store_true", help="write a CSV report")
    parser.add_argument("-a", "--show-all", action="store_true", help="print closed and unresolved hosts too")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument(
        "--discovery-url", default="https://crt.name/v1/search",
        help="newline discovery API used by the 'api' source",
    )
    parser.add_argument(
        "--source", choices=("openct", "api"), default="api",
        help="CT discovery source (default: api, using crt.name)",
    )
    parser.add_argument(
        "--openct", action="store_true",
        help="use the experimental on-demand OpenCT source instead of crt.name",
    )
    parser.add_argument("--ct-pages", type=int, default=10, help="maximum on-demand CT result pages")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    console = Console(no_color=args.no_color)
    raw = list(args.domains)
    banner_shown = False
    if args.file:
        try:
            raw.append(args.file.read_text())
        except OSError as exc:
            parser.error(str(exc))
    if not raw:
        console.print(BANNER, style="bold cyan", highlight=False)
        banner_shown = True
        value = console.input("[bold]Domain(s)[/bold] (comma-separated): ").strip()
        if not value:
            parser.error("at least one domain is required")
        raw.append(value)
    try:
        domains = parse_domains(raw)
    except ValueError as exc:
        parser.error(str(exc))
    if not 1 <= args.concurrency <= 200:
        parser.error("concurrency must be between 1 and 200")
    if args.timeout <= 0:
        parser.error("timeout must be greater than zero")
    if not 1 <= args.ct_pages <= 100:
        parser.error("ct-pages must be between 1 and 100")

    if not banner_shown:
        console.print(BANNER, style="bold cyan", highlight=False)
    console.print(f"[dim]Targets:[/dim] {', '.join(domains)}")
    selected_source = "openct" if args.openct else args.source
    source_label = "openct" if selected_source == "openct" else "crt.name"
    console.print(
        f"[dim]Source:[/dim] {source_label}  [dim]Workers:[/dim] {args.concurrency}  "
        f"[dim]Timeout:[/dim] {args.timeout:g}s\n"
    )
    try:
        results = asyncio.run(run_scan(
            domains, args.concurrency, args.timeout, console, args.show_all,
            args.discovery_url, "openct" if selected_source == "openct" else "crt-name", args.ct_pages,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Scan interrupted[/yellow]")
        raise SystemExit(130)

    print_summary(console, results)
    for path in write_reports(results, args.output, args.json, args.csv):
        console.print(f"[cyan][*][/cyan] Report written to {path.resolve()}")


if __name__ == "__main__":
    main()
