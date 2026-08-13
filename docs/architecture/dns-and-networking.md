---
type: architecture_guideline
title: DNS & Networking Engine
description: Asynchronous DNS resolution, local hosts file parsing, Happy Eyeballs race algorithm, and dual-stack IPv6 handling.
timestamp: "2026-08-13T11:00:00Z"
---

# DNS & Networking Engine

[⬅️ Back to Architecture Index](index.md)

High-speed DNS resolution and connection establishment are critical to proxy performance.

## Asynchronous DNS & Hosts File Caching

Wormhole utilizes a custom singleton resolver ([`resolver.py`](../../wormhole/resolver.py)) combining two resolution tiers:

1. **Local System Hosts Cache**: Parses `/etc/hosts` (or Windows `%SYSTEMROOT%\System32\drivers\etc\hosts`) at startup, caching static IP overrides in memory.
2. **Async DNS Resolution**: Uses `aiodns` to query `A` (IPv4) and `AAAA` (IPv6) records concurrently using C-ARES non-blocking lookups. Extracted TTL values determine dynamic `DNS_CACHE` expiration.

## Happy Eyeballs Connection Race (`_create_fastest_connection`)

When a hostname resolves to multiple IP addresses (or dual-stack IPv4/IPv6 addresses), Wormhole initiates a concurrent connection race based on RFC 8305 (Happy Eyeballs):

1. IPv6 addresses are prioritized when public IPv6 connectivity is available.
2. Asynchronous tasks spawn connection attempts (`asyncio.open_connection`) across all candidate IPs concurrently.
3. The first connection to complete `asyncio.FIRST_COMPLETED` wins and is returned for data streaming; pending tasks are cancelled.

## IPv6 Auto-Tuning (`--auto-ipv6`)

When `--auto-ipv6` is enabled, Wormhole spawns a background monitoring task ([`network_monitor.py`](../../wormhole/network_monitor.py)) that periodically checks for system IPv6 availability. If IPv6 support becomes active, the monitor signals the main process to gracefully restart the server socket with IPv6 dual-stack binding (`IPV6_V6ONLY = 0`).
