---
type: log
title: Wormhole Development Log
description: Chronological log of development milestones, code audits, and architectural updates.
timestamp: "2026-09-22T09:50:00Z"
---

# Wormhole Development Log

[⬅️ Back to Development Index](index.md)

### 2026-09-22 — v3.6.0: Optional Tor Support, Relay Throughput & Documentation
- **Tor Support (`--tor`)**: New `wormhole/tor.py` spawns a private tor daemon on random loopback ports with a `0700` per-rung data directory and `__OwningControllerProcess` lifetime; bootstrap ladder (direct → obfs4/lyrebird → opt-in snowflake → webtunnel), BridgeDB Moat bridge fetch with bounded retries, failure classification, and exit codes `2` (missing tor/deps) / `3` (all attempts failed).
- **SOCKS5 transport**: `python-socks` with 60 s clearnet / 250 s onion connect budgets; tor `SocksTimeout 240`; `.onion` hostnames pass through untouched for remote DNS.
- **Handler**: Tor-aware connect path skips local DNS and the private-IP filter (resolution happens at the exit) while keeping ad-block and allowlist checks.
- **Throughput**: 64 KB relay read chunks (`STREAM_CHUNK_SIZE`) and a 256 KB stream buffer limit.
- **Packaging**: self-contained `Dockerfile.tor` (Alpine tor, lyrebird, snowflake) for a Quay.io tor image variant; Dockerfiles kept in the build context for Quay build triggers.
- **Docs**: Tor implementation plan, user guide (`docs/user-guide/tor.md`), README Tor section, and refreshed `--help` output for 3.6.0.
- **Tests**: `tests/test_tor.py` unit coverage (discovery, rung planning, configs, classification, Moat, transport, manager); suite at 285 passed / 88.7% coverage.
- **Talyn compatibility**: reported and verified the upstream fix (talyn BUG-331, v0.9.8) for keyword-argument dispatch in `METH_FASTCALL` loop methods, unblocking `--tor` on the talyn event loop.

### 2026-08-13 — Full Codebase Audit & OKF Documentation Setup
- **Code Audit**: Conducted comprehensive static analysis across all 11 Python modules in `wormhole/`.
- **Bug Discovery**: Identified 19 specific defect entries categorized into Critical Security, Memory/Resource Leaks, Logic Bugs, Performance Unoptimizations, and Dead Code.
- **OKF Documentation Bundle**: Built `docs/` structure adhering to Google Open Knowledge Format (OKF v0.1), creating master index maps, user guides, architecture specifications, and bug tracker files (`001.md` – `019.md`).

### 2026-08-01 — Performance & Event Loop Optimization
- Added event loop auto-selection (`uvloop`, `winloop`, `talyn`) in `proxy.py`.
- Refactored `handler.py` to utilize `asyncio.TaskGroup` for bidirectional stream relaying.
- Implemented TTL-based DNS caching in `resolver.py`.

### 2026-07-15 — Ad-Blocker Engine & SQLite Integration
- Built asynchronous blocklist downloader and parser (`ad_blocker.py`).
- Implemented subdomain redundancy filter `_filter_redundant_domains`.
- Integrated SQLite database read-only querying in `safeguards.py`.

### 2026-06-20 — Initial Core Proxy Engine
- Created initial server listener (`server.py`) and protocol handler (`handler.py`).
- Implemented HTTPS `CONNECT` tunneling and HTTP forwarding.
- Implemented HTTP Digest SHA-256 authentication (`authentication.py`, `auth_manager.py`).
