<div align="center">

# ◈ Subwatch

**Discover certificate-derived subdomains and see which ones answer on the public web.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-35d6ad.svg)](LICENSE)

</div>

Subwatch is a fast, Maigret-style command-line tool for mapping public-facing web services associated with domains you control.

## Install

Requires Python 3.10 or newer. Use [`pipx`](https://pipx.pypa.io/) to make `subwatch` available from any directory:

```bash
pipx install git+https://github.com/deiondz/subwatch.git
```

Upgrade later with:

```bash
pipx upgrade subwatch
```

## Usage

```bash
subwatch example.com
```

`crt.name` is used for discovery by default. Subwatch cleans the returned hostnames, resolves DNS, checks HTTPS and HTTP concurrently, and streams responding services to the terminal.

```text
[*] example.com: discovered 42 in-scope hosts
[+] www.example.com  200  https://www.example.com  (184 ms)  Example
[+] api.example.com  403  https://api.example.com  (207 ms)
  Complete ━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 42/42 0:00:03
```

Useful options:

```bash
# Multiple domains
subwatch example.com example.org

# Domains from a file
subwatch --file domains.txt

# Print failed probes too
subwatch example.com --show-all

# Save reports
subwatch example.com --json --csv --output ./reports

# Use experimental on-demand OpenCT discovery
subwatch example.com --openct
```

Run `subwatch --help` for every option.

## Result states

- `PUBLIC` — a globally routable address returned an HTTP response, including `4xx` or `5xx`.
- `CLOSED` — public DNS resolved, but HTTPS and HTTP did not respond.
- `DNS-FAILED` — the hostname did not resolve.
- `NON-PUBLIC-IP` — only private or reserved addresses resolved, so no request was sent.
- `API-ERROR` — the discovery source failed.

## Documentation

- [How Subwatch works](docs/how-it-works/README.md) — discovery, normalization, safety checks, probing, and reports.
- [Experimental OpenCT index](docs/openct/README.md) — direct CT ingestion, historical imports, DNS probing, SQLite, and the local API.

## Development

```bash
git clone https://github.com/deiondz/subwatch.git
cd subwatch
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes.

## Responsible use

Only scan domains you own or have explicit permission to assess. Subwatch performs DNS resolution and ordinary HTTP requests; it does not authenticate, scan arbitrary ports, bypass access controls, or exploit vulnerabilities.

## License

[MIT](LICENSE)
