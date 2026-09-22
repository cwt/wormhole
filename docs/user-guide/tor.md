---
type: user_guide
title: Tor Support
description: Running Wormhole through a private local tor daemon, the bridge bootstrap ladder, onion services, and operational limits.
timestamp: "2026-09-22T09:35:00Z"
---

# Tor Support

[⬅️ Back to User Guide Index](index.md)

Wormhole can route every outbound request through the Tor network. It spawns
and owns a **private tor daemon** on random loopback ports with a private data
directory, instead of trusting whatever may already be listening on
`9050`/`9150`.

## Requirements

1. Optional Python dependencies:

```bash
pip install 'wormhole-proxy[tor]'
```

2. A system **tor** binary — the daemon is never downloaded by Wormhole:

| Platform | Install command |
|---|---|
| Fedora | `sudo dnf install tor` |
| Debian / Ubuntu | `sudo apt install tor` |
| Arch | `sudo pacman -S tor` |
| Alpine | `apk add tor` |
| macOS | `brew install tor` |
| Windows | Install Tor Browser or the Tor Expert Bundle and pass `--tor-binary PATH` |

3. Optional pluggable transports for censored networks. **Fedora 44** example
   (installs `snowflake` and `webtunnel`):

```bash
sudo dnf copr enable vgaetera/extras
sudo dnf install snowflake webtunnel
```

## Quick Start

```bash
wormhole --tor
```

Verify that traffic exits through Tor:

```bash
curl -x http://127.0.0.1:8800 https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"..."}
```

## Command-Line Options

| Flag | Description | Default |
|---|---|---|
| `--tor` | Route outbound traffic through the private tor daemon | off |
| `--tor-binary PATH` | Explicit tor binary path (skips `PATH` lookup) | search `PATH` |
| `--tor-bridge LINE` | Bridge line; repeatable to build a pool; implies `--tor` | — |
| `--tor-bridge-file PATH` | File with one bridge line per line; implies `--tor` | — |
| `--tor-timeout SECONDS` | Bootstrap budget per attempt | `90` |
| `--tor-data-dir PATH` | Persistent state root (`<dir>/<rung>` per attempt) | platform data dir |
| `--tor-pt-dir PATH` | Directory containing pluggable transport binaries | auto-discovered |
| `--tor-no-bridges` | Only try a direct connection (skip the ladder) | off |
| `--tor-snowflake` | Enable the snowflake rung (slow to bootstrap) | off |
| `--tor-isolate-dest` | Isolate streams per destination address | off |

## Bootstrap Ladder

If the direct connection fails, Wormhole climbs a bounded ladder of attempts:

| # | Rung | Requires |
|---|---|---|
| 1 | direct | — |
| 2 | obfs4 | `lyrebird` (renamed `obfs4proxy`) |
| 3 | snowflake | `snowflake-client` (enabled with `--tor-snowflake`) |
| 4 | webtunnel | `webtunnel-client` |

Rungs whose transport binaries are missing are skipped with a warning. The
whole bridge pool is handed to tor, which selects and pins a guard and fails
over on its own. When a bridge rung fails, Wormhole requests a fresh batch from
BridgeDB (up to three batches per run); you can also supply your own bridges
from [BridgeDB](https://bridges.torproject.org/):

```bash
wormhole --tor --tor-bridge "obfs4 <address> <fingerprint> <params>"
```

## Onion Services

Hostnames are passed to the SOCKS proxy untouched (remote DNS), so `.onion`
addresses work without any explicit configuration:

```bash
curl -x http://127.0.0.1:8800 \
  http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/
```

The first visit to an onion service can take a couple of minutes while Tor
fetches its descriptor and completes a rendezvous; subsequent visits are fast.
Clearnet streams get a 60-second connect budget, onion streams 250 seconds, and
the daemon runs with `SocksTimeout 240`.

## State & Lifetime

- State lives under `~/.local/share/wormhole/tor/<rung>` (Linux),
  `~/Library/Application Support/wormhole/tor` (macOS), or
  `%LOCALAPPDATA%\wormhole\tor` (Windows), created with `0700` permissions on
  POSIX.
- Use `--tor-data-dir` to relocate it; in the container image mount a volume
  and pass `--tor-data-dir /config/tor`.
- The daemon is owned by Wormhole (`__OwningControllerProcess`) and stops when
  the proxy exits, including after `kill -9`; it also survives `--auto-ipv6`
  server restarts within the same process.

## Failure Reporting

Each attempt is logged (`Tor attempt 1/3 (direct)...`). When every rung fails,
Wormhole first distinguishes "no internet connectivity" from a filtered
network, then reports per-rung reasons:

- **Exit code 2** — the tor binary or the optional dependencies are missing.
- **Exit code 3** — all bootstrap attempts failed (Tor blocked or offline).

Use `-vv` for full bootstrap logs (log throttling is disabled at `-vv`) and
`-vvv` to include tracebacks.

## Security Notes

- **SSRF:** in Tor mode, local DNS resolution and the private/reserved IP check
  are bypassed because resolution happens at the Tor exit. Tor exit policies
  reject RFC1918/loopback destinations by default, so exposure is bounded;
  ad-block and allowlist domain filtering still apply.
- `--allow-private` has no effect in Tor mode (a warning is logged).
- Bridge lines are logged only at debug level; guard and bridge state stays in
  the `0700` data directory.
- **No fallback:** if the private daemon cannot start, Wormhole fails — it
  never silently uses an unknown listener on `9050`/`9150`.

## Corporate Networks

Many enterprise networks block or classify Tor (anonymizer categories, relay
IP blocklists, DPI, TLS-intercepting proxies). In those environments `--tor`
will usually fail to bootstrap, and security tooling may flag the binary even
when bundled in an image. Check your organization's acceptable-use policy
before enabling Tor mode.
