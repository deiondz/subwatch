from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

from .scanner import normalize_domain

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
DEFAULT_DB = Path.home() / ".local" / "share" / "subwatch" / "openct.sqlite3"


@dataclass(frozen=True, slots=True)
class NameRecord:
    apex: str
    subdomain: str
    first_seen: str
    source: str = "certspotter"


def names_from_issuances(payload: list[dict], apex: str) -> list[NameRecord]:
    suffix = "." + apex
    earliest: dict[str, str] = {}
    for issuance in payload:
        seen = str(issuance.get("not_before") or "")
        for raw_name in issuance.get("dns_names") or []:
            name = str(raw_name).strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            try:
                name = normalize_domain(name)
            except ValueError:
                continue
            if name != apex and not name.endswith(suffix):
                continue
            if name not in earliest or (seen and seen < earliest[name]):
                earliest[name] = seen
    return [NameRecord(apex, name, earliest[name]) for name in sorted(earliest, key=lambda n: (n.count("."), n))]


def next_link(value: str | None) -> str | None:
    if not value:
        return None
    for part in value.split(","):
        bits = [bit.strip() for bit in part.split(";")]
        if len(bits) > 1 and 'rel="next"' in bits[1:] and bits[0].startswith("<"):
            return bits[0][1:-1]
    return None


async def fetch_certspotter(apex: str, max_pages: int = 10, timeout: float = 20.0) -> list[NameRecord]:
    apex = normalize_domain(apex)
    params = {"domain": apex, "include_subdomains": "true", "expand": "dns_names"}
    headers = {"User-Agent": "subwatch-openct/0.1 (+https://github.com/deiondz/subwatch)"}
    payload: list[dict] = []
    url: str | None = CERTSPOTTER_URL
    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
        for _ in range(max_pages):
            response = await client.get(url, params=params if url == CERTSPOTTER_URL else None)
            response.raise_for_status()
            page = response.json()
            if not isinstance(page, list):
                raise ValueError("CT source returned a non-list response")
            payload.extend(page)
            url = next_link(response.headers.get("link"))
            if not url:
                break
    return names_from_issuances(payload, apex)


class Index:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""
                CREATE TABLE IF NOT EXISTS names (
                    apex TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    source TEXT NOT NULL,
                    indexed_at TEXT NOT NULL,
                    PRIMARY KEY (apex, subdomain)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS names_apex_idx ON names(apex)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    source TEXT PRIMARY KEY,
                    next_index INTEGER NOT NULL,
                    observed_tree_size INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30)

    def upsert(self, records: list[NameRecord]) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.executemany("""
                INSERT INTO names(apex, subdomain, first_seen, source, indexed_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(apex, subdomain) DO UPDATE SET
                    first_seen = CASE
                        WHEN excluded.first_seen != '' AND (names.first_seen = '' OR excluded.first_seen < names.first_seen)
                        THEN excluded.first_seen ELSE names.first_seen END,
                    indexed_at = excluded.indexed_at
            """, [(r.apex, r.subdomain, r.first_seen, r.source, now) for r in records])
        return len(records)

    def search(self, apex: str) -> list[NameRecord]:
        apex = normalize_domain(apex)
        with self.connect() as db:
            rows = db.execute(
                "SELECT apex, subdomain, first_seen, source FROM names WHERE apex = ? ORDER BY subdomain",
                (apex,),
            ).fetchall()
        return [NameRecord(*row) for row in rows]

    def checkpoint(self, source: str) -> int | None:
        with self.connect() as db:
            row = db.execute("SELECT next_index FROM checkpoints WHERE source = ?", (source,)).fetchone()
        return int(row[0]) if row else None

    def set_checkpoint(self, source: str, next_index: int, tree_size: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute("""
                INSERT INTO checkpoints(source, next_index, observed_tree_size, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET next_index=excluded.next_index,
                    observed_tree_size=excluded.observed_tree_size, updated_at=excluded.updated_at
            """, (source, next_index, tree_size, now))


async def refresh(index: Index, apex: str, max_pages: int = 10) -> list[NameRecord]:
    records = await fetch_certspotter(apex, max_pages=max_pages)
    index.upsert(records)
    return index.search(apex)


def render(records: list[NameRecord], fmt: str, dates: bool) -> str:
    if fmt == "json":
        if dates:
            data = [asdict(record) for record in records]
        else:
            data = [record.subdomain for record in records]
        return json.dumps(data, indent=2) + "\n"
    return "".join(
        f"{record.subdomain}\t{record.first_seen}\n" if dates else f"{record.subdomain}\n"
        for record in records
    )


class SearchHandler(BaseHTTPRequestHandler):
    index: Index
    refresh_on_query = True
    max_pages = 10

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        if parsed.path == "/healthz":
            self.respond(HTTPStatus.OK, "ok\n")
            return
        if parsed.path != "/v1/search":
            self.respond(HTTPStatus.NOT_FOUND, "not found\n")
            return
        query = parse_qs(parsed.query)
        try:
            apex = normalize_domain(query.get("apex", [""])[0])
            if self.refresh_on_query:
                records = asyncio.run(refresh(self.index, apex, self.max_pages))
            else:
                records = self.index.search(apex)
            fmt = "json" if query.get("format", [""])[0] == "json" else "text"
            body = render(records, fmt, query.get("dates", ["0"])[0] == "1")
            content_type = "application/json" if fmt == "json" else "text/plain; charset=utf-8"
            self.respond(HTTPStatus.OK, body, content_type)
        except ValueError as exc:
            self.respond(HTTPStatus.BAD_REQUEST, f"{exc}\n")
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            self.respond(HTTPStatus.BAD_GATEWAY, f"upstream CT source failed: {exc}\n")

    def respond(self, status: HTTPStatus, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[openct] {self.address_string()} {fmt % args}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and query an open local certificate-transparency name index")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite index (default: {DEFAULT_DB})")
    sub = parser.add_subparsers(dest="command", required=True)
    search = sub.add_parser("search", help="fetch, index, and print names for an apex")
    search.add_argument("apex")
    search.add_argument("--format", choices=("text", "json"), default="text")
    search.add_argument("--dates", action="store_true")
    search.add_argument("--max-pages", type=int, default=10)
    search.add_argument("--cached", action="store_true", help="query local data without refreshing")
    serve = sub.add_parser("serve", help="serve a crt.name-compatible local API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--max-pages", type=int, default=10)
    serve.add_argument("--cached", action="store_true", help="never refresh during API requests")
    logs = sub.add_parser("logs", help="list logs in the official Chrome and Apple programs")
    logs.add_argument("--active", action="store_true", help="show only qualified/usable logs")
    tail = sub.add_parser("tail", help="ingest new entries directly from RFC 6962 CT logs")
    tail.add_argument("--log", action="append", default=[], help="case-insensitive description filter (repeatable)")
    tail.add_argument("--limit-logs", type=int, default=1)
    tail.add_argument("--batch-size", type=int, default=256)
    tail.add_argument("--max-batches", type=int, default=1, help="batches per log per run; 0 means unlimited")
    tail.add_argument("--from-tail", type=int, default=1000, help="entries to backfill when no checkpoint exists")
    importer = sub.add_parser("import", help="import historical names from a file or URL")
    importer.add_argument("location", help="local file or HTTP(S) URL")
    importer.add_argument("--source", required=True, choices=("archive", "commoncrawl", "czds", "chaos", "hagezi", "custom"))
    probe = sub.add_parser("probe", help="resolve common hostname prefixes for an apex")
    probe.add_argument("apex")
    probe.add_argument("--wordlist", type=Path)
    probe.add_argument("--concurrency", type=int, default=100)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    index = Index(args.db)
    if args.command == "search":
        records = index.search(args.apex) if args.cached else asyncio.run(refresh(index, args.apex, args.max_pages))
        print(render(records, args.format, args.dates), end="")
        return
    if args.command in {"logs", "tail"}:
        from .ctlog import ingest_log, load_logs

        async def ct_command() -> None:
            async with httpx.AsyncClient(timeout=30) as client:
                logs = await load_logs(client)
            active = [log for log in logs if log.state in {"usable", "qualified", "readonly"}]
            if args.command == "logs":
                for log in active if args.active else logs:
                    print(f"{log.program:7} {log.state:10} {log.description}  {log.url}")
                return
            selected = active
            if args.log:
                selected = [log for log in selected if any(term.lower() in log.description.lower() for term in args.log)]
            selected = selected[:args.limit_logs]
            if not selected:
                raise SystemExit("no matching active RFC 6962 logs")
            for log in selected:
                print(f"Tailing {log.description} from {log.url}")
                try:
                    entries, names = await ingest_log(
                        index, log, args.batch_size, args.max_batches or None, args.from_tail
                    )
                    print(f"  indexed {entries} entries / {names} SAN names")
                except httpx.HTTPError as exc:
                    print(f"  skipped: {exc}")

        asyncio.run(ct_command())
        return
    if args.command == "import":
        from .datasets import import_location
        count = asyncio.run(import_location(index, args.location, args.source))
        print(f"indexed {count} unique names from {args.source}")
        return
    if args.command == "probe":
        from .datasets import DEFAULT_WORDS, probe_apex
        words = list(DEFAULT_WORDS)
        if args.wordlist:
            words = [line.strip() for line in args.wordlist.read_text().splitlines() if line.strip()]
        records = asyncio.run(probe_apex(index, args.apex, words, args.concurrency))
        print(render(records, "text", False), end="")
        print(f"found {len(records)} names")
        return
    SearchHandler.index = index
    SearchHandler.refresh_on_query = not args.cached
    SearchHandler.max_pages = args.max_pages
    server = ThreadingHTTPServer((args.host, args.port), SearchHandler)
    print(f"OpenCT API listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping OpenCT API")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
