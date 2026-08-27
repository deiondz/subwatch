<div align="center">

# ◈ Subwatch

**Discover certificate-derived subdomains and see which ones answer on the public web.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-35d6ad.svg)](LICENSE)

</div>

Subwatch is a fast, Maigret-style command-line tool for mapping the public-facing web services associated with domains you control. It queries the [`crt.name`](https://crt.name/) certificate search API, cleans and scopes the returned hostnames, resolves DNS, then checks HTTPS and HTTP concurrently.

```text
[*] example.com: discovered 42 in-scope hosts
[+] www.example.com  200  https://www.example.com  (184 ms)  Example
[+] api.example.com  403  https://api.example.com  (207 ms)
  Checking example.com ━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 42/42 0:00:03

          Scan summary
Hosts checked                 42
Public web services           17
Closed / no response          20
DNS failures                   5
```

## Features

- Certificate-derived discovery through `crt.name/v1/search?apex=<domain>`
- Multiple apex domains, URL input, IDNs, and newline/comma-separated files
- Concurrent HTTPS and HTTP reachability checks with redirect following
- Clear `PUBLIC`, `CLOSED`, `DNS-FAILED`, `NON-PUBLIC-IP`, and `API-ERROR` states
- Status code, latency, resolved address, final URL, and page-title capture
- JSON and CSV exports
- TLS verification, private/reserved address protection, configurable timeouts
- Maigret-style colored streaming output with a compact progress bar and summary

## Install

Subwatch requires Python 3.10 or newer.

For a globally available `subwatch` command, install it with [`pipx`](https://pipx.pypa.io/):

```bash
pipx install git+https://github.com/deiondz/subwatch.git
subwatch example.com
```

The command can then be run from any directory. Upgrade it later with:

```bash
pipx upgrade subwatch
```

For development, clone the repository and use an editable virtual-environment install:

```bash
git clone https://github.com/deiondz/subwatch.git
cd subwatch
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e .
```

Then launch it with one or more domains:

```bash
subwatch example.com
subwatch example.com example.org --concurrency 30 --timeout 7
subwatch --file domains.txt --output ./reports
```

Launching `subwatch` without arguments opens an empty interface where domains can be entered interactively.

By default, Subwatch prints discoveries and public services while keeping failed probes out of the way. Use `--show-all` to print every result, `--json` or `--csv` to save reports, and `Ctrl+C` to stop a scan.

```bash
subwatch example.com --show-all
subwatch example.com --json --csv --output ./reports
```

## What the states mean

`PUBLIC` means the hostname resolved to at least one globally routable address and an HTTP(S) request received a response. A `401`, `403`, or `500` still proves that a web server is reachable, so it counts as public.

`CLOSED` means public DNS resolved, but neither HTTPS nor HTTP returned a response before the timeout. `DNS-FAILED` means resolution failed. `NON-PUBLIC-IP` means the hostname resolved only to private or reserved ranges, and Subwatch intentionally did not request it.

This is an availability signal—not a vulnerability assessment. A public result does not mean a service is insecure, and a closed result does not prove that every port is closed.

## Experimental OpenCT index

The `feature/open-ct-enumerator` branch includes `subwatch-ct`, an independent open-source name index that does not call `crt.name`. It can tail RFC 6962 logs directly, ingest historical name datasets, probe DNS, normalize everything into a local append-only SQLite index, and expose a compatible newline-first search endpoint.

List active logs from the official Chrome and Apple programs:

```bash
subwatch-ct logs --active
```

Tail active logs directly. The first run begins near the live edge rather than attempting to download billions of historical entries; subsequent runs continue from durable per-log checkpoints:

```bash
# Ingest one batch from one active log
subwatch-ct tail --limit-logs 1 --max-batches 1

# Keep reading the selected log until caught up
subwatch-ct tail --log 'Argon 2026H2' --max-batches 0

# Backfill the most recent 100,000 entries when establishing a checkpoint
subwatch-ct tail --log Argon --from-tail 100000 --max-batches 0
```

Each RFC 6962 entry is decoded in memory. Subwatch extracts DNS SANs, determines the eTLD+1 using the Public Suffix List, updates `(apex, subdomain, first_seen)`, and discards the certificate. A checkpoint is committed after every successful batch.

Historical sources are deliberately independent workers. Download gated datasets such as CZDS or Chaos under their own terms, then import them; public URLs and plain local files are both accepted:

```bash
subwatch-ct import ./chaos-names.txt --source chaos
subwatch-ct import ./czds-zone.txt --source czds
subwatch-ct import https://example.net/hagezi-hosts.txt --source hagezi
subwatch-ct import ./common-crawl-hosts.txt --source commoncrawl
subwatch-ct import ./retired-log-names.txt --source archive
```

The importer extracts and normalizes hostnames, commits only name records, and does not retain input documents. A bounded common-name DNS prober can feed the same index:

```bash
subwatch-ct probe example.com
subwatch-ct probe example.com --wordlist ./prefixes.txt --concurrency 100
```

Fetch and query an apex directly:

```bash
subwatch-ct search example.com
subwatch-ct search example.com --dates
subwatch-ct search example.com --format json
```

Run the local API:

```bash
subwatch-ct serve --host 127.0.0.1 --port 8787
curl 'http://127.0.0.1:8787/v1/search?apex=example.com'
curl 'http://127.0.0.1:8787/v1/search?apex=example.com&format=json&dates=1'
```

Point the reachability scanner at your own index:

```bash
subwatch example.com --discovery-url http://127.0.0.1:8787/v1/search
```

Data is stored at `~/.local/share/subwatch/openct.sqlite3` by default; override it with `subwatch-ct --db ./openct.sqlite3 ...`. Direct RFC 6962 ingestion uses the CT entry timestamp as `first_seen`. On-demand API refreshes and `search` still use Cert Spotter as a convenience source and use certificate `not_before`, which is only an approximation. Use `--cached` to query or serve exclusively from data populated by your own workers.

### Current scope

The direct worker implements RFC 6962 `get-sth` and `get-entries`. Static CT data-tile ingestion (Sunlight/Raio/Geomys) requires a separate tile/checkpoint verifier and is not yet enabled; such logs may still expose an RFC 6962 compatibility read endpoint. The importer provides the ingestion boundary for archived and third-party datasets, but it does not circumvent authentication or licensing for CZDS, Chaos, or other gated sources. SQLite is intended for a personal or research index, not a multi-billion-name public service.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes. Automated coding agents should also read [AGENTS.md](AGENTS.md).

## Responsible use

Only scan domains you own or have explicit permission to assess. Subwatch makes standard DNS queries and HTTP GET requests; it does not authenticate, scan arbitrary ports, bypass access controls, or exploit vulnerabilities. You are responsible for complying with applicable laws and third-party terms.

## License

Subwatch is available under the [MIT License](LICENSE).
