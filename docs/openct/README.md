# Experimental OpenCT index

[← Back to the main README](../../README.md)

`subwatch-ct` builds and serves an independent certificate-derived hostname index. It can tail RFC 6962 logs, ingest historical datasets, probe DNS, and expose a `crt.name`-compatible local API.

## Storage model

Certificates are parsed in memory. DNS SANs are extracted, the correct eTLD+1 is calculated with the Public Suffix List, and certificate bytes are discarded. The append-only SQLite index retains:

```text
(apex, subdomain, first_seen)
```

The default database is:

```text
~/.local/share/subwatch/openct.sqlite3
```

Use `--db` before the subcommand to choose another path:

```bash
subwatch-ct --db ./openct.sqlite3 search example.com --cached
```

## Direct CT ingestion

List logs from the official Chrome and Apple programs:

```bash
subwatch-ct logs --active
```

Tail an RFC 6962 log:

```bash
# One batch near the live edge
subwatch-ct tail --limit-logs 1 --max-batches 1

# Continue until caught up
subwatch-ct tail --log 'Argon 2026H2' --max-batches 0

# Establish a checkpoint 100,000 entries behind the live edge
subwatch-ct tail --log Argon --from-tail 100000 --max-batches 0
```

Each successful batch advances a durable per-log cursor, allowing later runs to resume without replaying processed entries.

## Historical sources

Download gated datasets under their respective terms, then import local files or public URLs:

```bash
subwatch-ct import ./chaos-names.txt --source chaos
subwatch-ct import ./czds-zone.txt --source czds
subwatch-ct import ./common-crawl-hosts.txt --source commoncrawl
subwatch-ct import ./retired-log-names.txt --source archive
subwatch-ct import https://example.net/hagezi-hosts.txt --source hagezi
```

The importer extracts normalized names and does not retain the original documents.

## DNS probing

Probe a bounded list of common prefixes:

```bash
subwatch-ct probe example.com
subwatch-ct probe example.com --wordlist ./prefixes.txt --concurrency 100
```

Discovered names enter the same index with `dns-probe` as their source.

## Search and API

Search directly:

```bash
subwatch-ct search example.com
subwatch-ct search example.com --dates
subwatch-ct search example.com --format json
```

Without `--cached`, `search` refreshes through Cert Spotter for convenience. Use `--cached` to query only independently collected local records.

Serve the index:

```bash
subwatch-ct serve --host 127.0.0.1 --port 8787 --cached
curl 'http://127.0.0.1:8787/v1/search?apex=example.com'
curl 'http://127.0.0.1:8787/v1/search?apex=example.com&format=json&dates=1'
```

Point Subwatch at it:

```bash
subwatch example.com \
  --source api \
  --discovery-url http://127.0.0.1:8787/v1/search
```

## Current scope

Direct ingestion implements RFC 6962 `get-sth` and `get-entries`. Static CT data-tile ingestion for Sunlight, Raio, and Geomys is not yet implemented. Dataset imports do not bypass authentication or licensing for CZDS, Chaos, or other gated sources.

SQLite is suitable for a personal or research index. A multi-billion-name public service would require distributed ingestion and production database infrastructure.
