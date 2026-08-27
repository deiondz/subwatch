from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import asdict, dataclass
from time import perf_counter
from urllib.parse import urlsplit

import httpx

API_URL = "https://crt.name/v1/search"


@dataclass(slots=True)
class ProbeResult:
    apex: str
    host: str
    state: str
    url: str = ""
    status: int | None = None
    ip: str = ""
    title: str = ""
    elapsed_ms: int = 0
    detail: str = ""

    def dict(self) -> dict:
        return asdict(self)


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        value = (urlsplit(value).hostname or "").rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized domain") from exc
    if not value or len(value) > 253 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not all(c.isalnum() or c == "-" for c in label)
        for label in value.split(".")
    ):
        raise ValueError(f"invalid domain: {value!r}")
    return value


def parse_domains(values: list[str]) -> list[str]:
    result: list[str] = []
    for raw in values:
        for value in raw.replace(",", "\n").splitlines():
            if value.strip():
                domain = normalize_domain(value)
                if domain not in result:
                    result.append(domain)
    return result


def parse_crt_response(text: str, apex: str) -> list[str]:
    suffix = "." + apex
    hosts: set[str] = set()
    for line in text.splitlines():
        host = line.strip().lower().rstrip(".")
        if host.startswith("*."):
            host = host[2:]
        try:
            host = normalize_domain(host)
        except ValueError:
            continue
        if host == apex or host.endswith(suffix):
            hosts.add(host)
    return sorted(hosts, key=lambda h: (h.count("."), h))


async def discover(client: httpx.AsyncClient, apex: str) -> list[str]:
    response = await client.get(API_URL, params={"apex": apex})
    response.raise_for_status()
    return parse_crt_response(response.text, apex)


async def resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(ipaddress.ip_address(info[4][0])) for info in infos})


def extract_title(body: str) -> str:
    lowered = body.lower()
    start = lowered.find("<title")
    if start < 0:
        return ""
    start = lowered.find(">", start)
    end = lowered.find("</title>", start)
    if start < 0 or end < 0:
        return ""
    return " ".join(body[start + 1 : end].split())[:80]


async def probe(client: httpx.AsyncClient, apex: str, host: str) -> ProbeResult:
    started = perf_counter()
    try:
        ips = await resolve(host)
    except (OSError, socket.gaierror) as exc:
        return ProbeResult(apex, host, "dns-failed", elapsed_ms=int((perf_counter()-started)*1000), detail=str(exc))

    if not any(ipaddress.ip_address(ip).is_global for ip in ips):
        return ProbeResult(
            apex, host, "non-public-ip", ip=", ".join(ips),
            elapsed_ms=int((perf_counter()-started)*1000),
            detail="DNS resolved only to private/reserved addresses",
        )

    errors: list[str] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            response = await client.get(url)
            return ProbeResult(
                apex, host, "public", str(response.url), response.status_code,
                ", ".join(ips), extract_title(response.text),
                int((perf_counter()-started)*1000),
            )
        except httpx.HTTPError as exc:
            errors.append(f"{scheme}: {exc.__class__.__name__}")
    return ProbeResult(apex, host, "closed", ip=", ".join(ips), elapsed_ms=int((perf_counter()-started)*1000), detail="; ".join(errors))


async def scan(domains: list[str], concurrency: int, timeout: float, on_discovered, on_result) -> None:
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    headers = {"User-Agent": "subwatch/0.1 (+authorized asset discovery)"}
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, limits=limits, headers=headers, verify=True) as client:
        semaphore = asyncio.Semaphore(concurrency)
        for apex in domains:
            try:
                hosts = await discover(client, apex)
            except httpx.HTTPError as exc:
                await on_result(ProbeResult(apex, apex, "api-error", detail=str(exc)))
                continue
            await on_discovered(apex, len(hosts))

            async def guarded(host: str) -> None:
                async with semaphore:
                    await on_result(await probe(client, apex, host))

            await asyncio.gather(*(guarded(host) for host in hosts))
