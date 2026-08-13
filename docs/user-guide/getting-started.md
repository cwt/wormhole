---
type: user_guide
title: Getting Started with Wormhole
description: Quickstart guide for installing, running, and configuring the Wormhole proxy.
timestamp: "2026-08-13T11:00:00Z"
---

# Getting Started with Wormhole

[⬅️ Back to User Guide Index](index.md)

Wormhole is an asynchronous HTTP/HTTPS proxy designed for high throughput, low memory footprint, and enhanced privacy.

## Prerequisites

- **Python Version**: Python 3.11 or newer is required.
- **Operating System**: Linux, macOS, or Windows (NTFS recommended for secure auth storage).

## Installation

Clone the repository and install dependencies using Poetry:

```bash
git clone https://github.com/example/wormhole.git
cd wormhole
poetry install
```

## Running the Proxy

Start the proxy server on default address `0.0.0.0:8800`:

```bash
poetry run python -m wormhole
```

### Common Command-Line Options

| Flag | Long Option | Description | Default |
|---|---|---|---|
| `-H` | `--host` | IP address to bind server | `0.0.0.0` |
| `-p` | `--port` | Port number to listen on (1024-65535) | `8800` |
| `-v` | `--verbose` | Increase logging verbosity (`-v`, `-vv`) | `0` |
| | `--allow-private` | Allow proxying to private/loopback IPs | `False` |
| | `--auto-ipv6` | Monitor network for IPv6 and restart automatically | `False` |
| `-S` | `--syslog-host` | Remote syslog server or UNIX socket path | `None` |
| `-P` | `--syslog-port` | Syslog port number | `514` |

## High-Performance Event Loops

Wormhole automatically detects and utilizes accelerated event loops when available:
- **Linux (Python 3.13+)**: Automatically prefers [Talyn](https://github.com/cwt/talyn) (experimental) or `uvloop`.
- **Linux / macOS**: Uses `uvloop` if installed.
- **Windows**: Uses `winloop` if installed.
- **Fallback**: Standard `asyncio` loop.
