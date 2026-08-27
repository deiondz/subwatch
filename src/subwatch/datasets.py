from __future__ import annotations

import asyncio
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from publicsuffix2 import get_sld

from .openct import Index, NameRecord
from .scanner import normalize_domain

HOST_PATTERN = re.compile(r"(?i)(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}")
DEFAULT_WORDS = ("www", "api", "mail", "dev", "staging", "admin", "portal", "vpn", "status", "app", "cdn", "assets")


def records_from_text(text: str, source: str, seen: str | None = None) -> list[NameRecord]:
    seen = seen or datetime.now(timezone.utc).isoformat()
    records: dict[tuple[str, str], NameRecord] = {}
    for match in HOST_PATTERN.finditer(text):
        name = match.group().lower().lstrip("*.").replace("_", "-")
        try:
            name = normalize_domain(name)
        except ValueError:
            continue
        apex = get_sld(name, strict=True)
        if apex:
            records[(apex, name)] = NameRecord(apex, name, seen, source)
    return list(records.values())


async def import_location(index: Index, location: str, source: str, timeout: float = 60) -> int:
    if urlsplit(location).scheme in {"http", "https"}:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(location)
            response.raise_for_status()
            text = response.text
    else:
        text = Path(location).read_text(errors="replace")
    records = records_from_text(text, source)
    index.upsert(records)
    return len(records)


async def probe_apex(index: Index, apex: str, words: list[str], concurrency: int = 100) -> list[NameRecord]:
    apex = normalize_domain(apex)
    semaphore = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()
    seen = datetime.now(timezone.utc).isoformat()

    async def check(word: str) -> NameRecord | None:
        host = normalize_domain(f"{word.strip().lower()}.{apex}")
        async with semaphore:
            try:
                await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                return NameRecord(apex, host, seen, "dns-probe")
            except (OSError, socket.gaierror):
                return None

    found = [record for record in await asyncio.gather(*(check(word) for word in words)) if record]
    index.upsert(found)
    return found
