# Agent instructions

These instructions apply to the entire repository.

## Project overview

Subwatch is a Python 3.10+ Textual application. `src/subwatch/scanner.py` owns domain validation, API discovery, DNS resolution, and HTTP probing. `src/subwatch/app.py` owns the terminal interface and exports. Keep network logic independent from Textual so it remains testable.

## Working agreement

- Preserve the definition of `PUBLIC`: a globally routable DNS result plus any HTTP response.
- Never weaken TLS verification or private/reserved-address protection silently.
- Keep discovery scoped to the requested apex domain and deduplicate results.
- Bound all network work with concurrency limits and timeouts.
- Do not add intrusive scanning, authentication attempts, access-control bypasses, or exploitation features.
- Add or update tests for behavioral changes.
- Run `pytest` and `python -m compileall -q src` before handing off changes.
- Do not commit virtual environments, caches, scan results, secrets, or credentials.

## Style

Prefer small typed functions, async I/O, standard-library data structures, and plain error states that the TUI can display. Keep dependencies minimal and document user-visible CLI changes in the README.
