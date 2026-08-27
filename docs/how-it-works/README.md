# How Subwatch works

[← Back to the main README](../../README.md)

Subwatch separates certificate-name discovery from live reachability checks. A certificate proves that a name appeared in a certificate; it does not prove the hostname still exists or currently serves a website.

```text
apex domain
    │
    ├─ certificate-name discovery
    │      crt.name by default
    │      Cert Spotter when --openct is supplied
    │
    ├─ validation and normalization
    │      IDN conversion · wildcard cleanup · apex scoping · deduplication
    │
    └─ concurrent reachability checks
           DNS → public-address guard → HTTPS → HTTP fallback
                              │
                              └─ status · URL · latency · IP · title
```

## Discovery

By default, `subwatch example.com` requests names from:

```text
https://crt.name/v1/search?apex=example.com
```

The response contains one hostname per line. Subwatch accepts the apex and names ending in `.example.com`; malformed or out-of-scope values such as `evil-example.com` are discarded.

With `--openct`, Subwatch performs an on-demand lookup through Cert Spotter instead. Raw CT logs are global append-only streams and do not support lookup by domain, so a searchable provider or a previously built local index is required for on-demand searches.

## Normalization

Subwatch:

- lowercases hostnames;
- removes trailing dots and wildcard prefixes;
- converts internationalized domains to IDNA ASCII;
- validates labels and lengths;
- restricts results to the requested apex; and
- deduplicates names before probing.

## Reachability checks

Each hostname is resolved concurrently up to the configured worker limit. Hosts resolving only to private, loopback, link-local, or reserved addresses are marked `NON-PUBLIC-IP` and are not requested.

For globally routable addresses, Subwatch requests HTTPS first with TLS verification enabled. If HTTPS fails at the connection or TLS layer, it tries HTTP. Redirects are followed.

Any HTTP response counts as `PUBLIC`. A `401`, `403`, or `500` still demonstrates that a web service answered; it does not imply the service is healthy or vulnerable.

For each result, Subwatch can record:

- state and HTTP status;
- original hostname and final URL;
- resolved addresses;
- elapsed time; and
- HTML page title.

## Output and reports

Public services stream to the terminal as they are found. `--show-all` also prints failures. The final summary counts each result state.

Reports are opt-in and contain the complete result set:

```bash
subwatch example.com --json --csv --output ./reports
```

This is a reachability check, not a vulnerability assessment. `PUBLIC` does not mean insecure, and `CLOSED` does not prove every network port is closed.
