from __future__ import annotations

import base64
import asyncio
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from publicsuffix2 import get_sld

from .openct import Index, NameRecord
from .scanner import normalize_domain

CHROME_LOG_LIST = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
APPLE_LOG_LIST = "https://valid.apple.com/ct/log_list/current_log_list.json"


@dataclass(frozen=True, slots=True)
class CTLog:
    log_id: str
    description: str
    url: str
    state: str
    program: str
    protocol: str = "rfc6962"


def parse_log_list(payload: dict, program: str) -> list[CTLog]:
    logs: list[CTLog] = []
    for operator in payload.get("operators", []):
        for raw in operator.get("logs", []):
            url = str(raw.get("url") or "").rstrip("/") + "/"
            if not url.startswith("https://"):
                continue
            state_data = raw.get("state") or {}
            state = next(iter(state_data), str(raw.get("status") or "unknown"))
            # Chrome's list exposes the submission URL even for Static CT logs.
            # Prefer RFC 6962 whenever get-sth is available; static monitoring is
            # implemented by a separate adapter.
            logs.append(CTLog(
                str(raw.get("log_id") or raw.get("logID") or ""),
                str(raw.get("description") or "unnamed log"), url, state, program,
            ))
    return logs


async def load_logs(client: httpx.AsyncClient) -> list[CTLog]:
    chrome, apple = await asyncio.gather(
        client.get(CHROME_LOG_LIST), client.get(APPLE_LOG_LIST)
    )
    chrome.raise_for_status(); apple.raise_for_status()
    merged: dict[str, CTLog] = {}
    for item in parse_log_list(chrome.json(), "chrome") + parse_log_list(apple.json(), "apple"):
        merged[item.url] = item
    return sorted(merged.values(), key=lambda log: (log.program, log.description))


def _u24(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 3 > len(data):
        raise ValueError("truncated uint24")
    return int.from_bytes(data[offset:offset + 3], "big"), offset + 3


def certificate_from_entry(entry: dict) -> tuple[bytes, int]:
    leaf = base64.b64decode(entry["leaf_input"], validate=True)
    if len(leaf) < 12 or leaf[0] != 0 or leaf[1] != 0:
        raise ValueError("unsupported or truncated MerkleTreeLeaf")
    timestamp_ms = struct.unpack_from(">Q", leaf, 2)[0]
    entry_type = struct.unpack_from(">H", leaf, 10)[0]
    if entry_type == 0:  # x509_entry
        size, offset = _u24(leaf, 12)
        certificate = leaf[offset:offset + size]
    elif entry_type == 1:  # precert_entry; full precertificate is in extra_data
        extra = base64.b64decode(entry["extra_data"], validate=True)
        size, offset = _u24(extra, 0)
        certificate = extra[offset:offset + size]
    else:
        raise ValueError(f"unknown log entry type {entry_type}")
    if len(certificate) != size:
        raise ValueError("truncated certificate")
    return certificate, timestamp_ms


def records_from_entry(entry: dict) -> list[NameRecord]:
    der, timestamp_ms = certificate_from_entry(entry)
    certificate = x509.load_der_x509_certificate(der)
    try:
        san = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        raw_names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        raw_names = []
    seen = datetime.fromtimestamp(timestamp_ms / 1000, timezone.utc).isoformat()
    records: list[NameRecord] = []
    for raw in raw_names:
        name = raw.lower().rstrip(".")
        if name.startswith("*."):
            name = name[2:]
        try:
            name = normalize_domain(name)
        except ValueError:
            continue
        apex = get_sld(name, strict=True)
        if not apex:
            continue
        records.append(NameRecord(apex, name, seen, "ct-log"))
    return records


async def tree_size(client: httpx.AsyncClient, log: CTLog) -> int:
    response = await client.get(log.url + "ct/v1/get-sth")
    response.raise_for_status()
    return int(response.json()["tree_size"])


async def fetch_entries(client: httpx.AsyncClient, log: CTLog, start: int, end: int) -> list[dict]:
    response = await client.get(log.url + "ct/v1/get-entries", params={"start": start, "end": end})
    response.raise_for_status()
    return response.json().get("entries", [])


async def ingest_log(
    index: Index, log: CTLog, batch_size: int = 256, max_batches: int | None = None,
    from_tail: int = 1000, timeout: float = 30,
) -> tuple[int, int]:
    headers = {"User-Agent": "subwatch-openct/0.2 (+https://github.com/deiondz/subwatch)"}
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        size = await tree_size(client, log)
        cursor = index.checkpoint(log.url)
        if cursor is None:
            cursor = max(0, size - from_tail)
        entries_seen = names_seen = batches = 0
        while cursor < size and (max_batches is None or batches < max_batches):
            entries = await fetch_entries(client, log, cursor, min(size - 1, cursor + batch_size - 1))
            if not entries:
                break
            records: list[NameRecord] = []
            for entry in entries:
                try:
                    records.extend(records_from_entry(entry))
                except (ValueError, x509.InvalidVersion):
                    continue
            index.upsert(records)
            cursor += len(entries)
            index.set_checkpoint(log.url, cursor, size)
            entries_seen += len(entries); names_seen += len(records); batches += 1
        return entries_seen, names_seen
