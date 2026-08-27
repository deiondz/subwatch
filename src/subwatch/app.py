from __future__ import annotations

import argparse
import asyncio
import csv
import json
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Input, Label, ProgressBar, Static
from textual.worker import Worker, WorkerState

from .scanner import ProbeResult, parse_domains, scan


class Subwatch(App):
    TITLE = "SUBWATCH"
    SUB_TITLE = "certificate discovery · public web reachability"
    CSS = """
    Screen { background: #090d16; }
    #hero { height: 3; padding: 1 2; color: #80f5d2; text-style: bold; }
    #controls { height: 3; padding: 0 1; }
    Input { border: tall #31445f; }
    Input:focus { border: tall #35d6ad; }
    #stats { height: 3; padding: 1 2; background: #101827; color: #a9bdd6; }
    ProgressBar { height: 1; margin: 0 2; }
    DataTable { margin: 1 2; border: round #24354e; }
    .public { color: #50e3a4; }
    .closed { color: #f0b65b; }
    .error { color: #ff6b7a; }
    """
    BINDINGS = [("q", "quit", "Quit"), ("r", "run_scan", "Run"), ("e", "export", "Export JSON/CSV"), ("c", "clear", "Clear")]

    def __init__(self, initial: list[str], concurrency: int, timeout: float, output: Path):
        super().__init__()
        self.initial = initial
        self.concurrency = concurrency
        self.timeout = timeout
        self.output = output
        self.results: list[ProbeResult] = []
        self.total = self.done = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("◈ SUBWATCH  /  map the public edge", id="hero")
        with Horizontal(id="controls"):
            yield Input(value=", ".join(self.initial), placeholder="example.com, example.org", id="domains")
        yield Label("Ready — enter apex domains and press R", id="stats")
        yield ProgressBar(total=1, show_eta=False, id="progress")
        yield DataTable(zebra_stripes=True, cursor_type="row", id="table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("STATE", "HOST", "HTTP", "LATENCY", "IP", "TITLE")
        if self.initial:
            self.action_run_scan()
        else:
            self.query_one(Input).focus()

    def action_clear(self) -> None:
        self.results.clear(); self.total = self.done = 0
        self.query_one(DataTable).clear()
        self.query_one(ProgressBar).update(total=1, progress=0)
        self.query_one("#stats", Label).update("Ready")

    def action_run_scan(self) -> None:
        if any(w.is_running for w in self.workers):
            self.notify("A scan is already running", severity="warning"); return
        try:
            domains = parse_domains([self.query_one(Input).value])
        except ValueError as exc:
            self.notify(str(exc), severity="error"); return
        if not domains:
            self.notify("Enter at least one apex domain", severity="error"); return
        self.action_clear()
        self.run_worker(self._scan(domains), name="scan", exit_on_error=False)

    async def _scan(self, domains: list[str]) -> None:
        async def discovered(apex: str, count: int) -> None:
            self.total += count
            self.query_one(ProgressBar).update(total=max(1, self.total))
            self.query_one("#stats", Label).update(f"Discovered {self.total} hosts · probing {apex}")

        async def result(item: ProbeResult) -> None:
            self.results.append(item); self.done += 1
            style = "green" if item.state == "public" else "yellow" if item.state == "closed" else "red"
            self.query_one(DataTable).add_row(
                f"[{style}]{item.state.upper()}[/{style}]", item.host,
                str(item.status or "—"), f"{item.elapsed_ms} ms", item.ip or "—", item.title or item.detail or "—",
            )
            self.query_one(ProgressBar).advance(1)
            public = sum(r.state == "public" for r in self.results)
            self.query_one("#stats", Label).update(f"{self.done}/{self.total} checked · {public} public · concurrency {self.concurrency}")

        await scan(domains, self.concurrency, self.timeout, discovered, result)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state == WorkerState.SUCCESS:
            self.notify(f"Scan complete: {len(self.results)} results")
        elif event.state == WorkerState.ERROR:
            self.notify(f"Scan failed: {event.worker.error}", severity="error")

    def action_export(self) -> None:
        if not self.results:
            self.notify("Nothing to export", severity="warning"); return
        self.output.mkdir(parents=True, exist_ok=True)
        rows = [r.dict() for r in self.results]
        (self.output / "subwatch-results.json").write_text(json.dumps(rows, indent=2) + "\n")
        with (self.output / "subwatch-results.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=rows[0]); writer.writeheader(); writer.writerows(rows)
        self.notify(f"Exported to {self.output.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover certificate hostnames and test public web reachability")
    parser.add_argument("domains", nargs="*", help="apex domains (or use --file)")
    parser.add_argument("-f", "--file", type=Path, help="newline/comma-separated domains")
    parser.add_argument("-c", "--concurrency", type=int, default=30)
    parser.add_argument("-t", "--timeout", type=float, default=7.0)
    parser.add_argument("-o", "--output", type=Path, default=Path("."))
    args = parser.parse_args()
    raw = list(args.domains)
    if args.file:
        raw.append(args.file.read_text())
    if not 1 <= args.concurrency <= 200:
        parser.error("concurrency must be between 1 and 200")
    Subwatch(parse_domains(raw), args.concurrency, args.timeout, args.output).run()


if __name__ == "__main__":
    main()
