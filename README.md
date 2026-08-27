<div align="center">

# ◈ Subwatch

**Discover certificate-derived subdomains and see which ones answer on the public web.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-35d6ad.svg)](LICENSE)

</div>

Subwatch is a fast, keyboard-driven terminal UI for mapping the public-facing web services associated with domains you control. It queries the [`crt.name`](https://crt.name/) certificate search API, cleans and scopes the returned hostnames, resolves DNS, then checks HTTPS and HTTP concurrently.

```text
 ◈ SUBWATCH  /  map the public edge
 ┌──────────────────────────────────────────────────────────────────────┐
 │ example.com, example.org                                            │
 └──────────────────────────────────────────────────────────────────────┘
  42/42 checked · 17 public · concurrency 30

  STATE       HOST                    HTTP   LATENCY    IP          TITLE
  PUBLIC      www.example.com         200    184 ms     93.184…     Example
  CLOSED      old.example.com         —      7004 ms    192.0…      —
  DNS-FAILED  removed.example.com     —      12 ms      —           —
```

## Features

- Certificate-derived discovery through `crt.name/v1/search?apex=<domain>`
- Multiple apex domains, URL input, IDNs, and newline/comma-separated files
- Concurrent HTTPS and HTTP reachability checks with redirect following
- Clear `PUBLIC`, `CLOSED`, `DNS-FAILED`, `NON-PUBLIC-IP`, and `API-ERROR` states
- Status code, latency, resolved address, final URL, and page-title capture
- JSON and CSV exports
- TLS verification, private/reserved address protection, configurable timeouts
- A responsive [Textual](https://textual.textualize.io/) interface

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

## Controls

| Key | Action |
|---|---|
| `R` | Run the scan |
| `C` | Clear results |
| `E` | Export JSON and CSV |
| `Q` | Quit |

## What the states mean

`PUBLIC` means the hostname resolved to at least one globally routable address and an HTTP(S) request received a response. A `401`, `403`, or `500` still proves that a web server is reachable, so it counts as public.

`CLOSED` means public DNS resolved, but neither HTTPS nor HTTP returned a response before the timeout. `DNS-FAILED` means resolution failed. `NON-PUBLIC-IP` means the hostname resolved only to private or reserved ranges, and Subwatch intentionally did not request it.

This is an availability signal—not a vulnerability assessment. A public result does not mean a service is insecure, and a closed result does not prove that every port is closed.

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
