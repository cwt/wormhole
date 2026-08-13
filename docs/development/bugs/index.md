---
type: index
title: "Bug Tracker — Wormhole"
description: "Individual bug entries for Wormhole, one file per bug. 19 bugs discovered across code audit."
timestamp: "2026-08-13T10:57:30Z"
---

# Bugs — Wormhole

[⬅️ Back to Development Index](../index.md)

Sorted by bug number. See individual bug files for details.

## Summary by Severity

| Severity | Count |
|---|---:|
| Critical | 3 |
| High | 6 |
| Medium | 6 |
| Low | 4 |
| **Total** | **19** |

## Summary by Status

| Status | Count |
|---|---:|
| Open | 0 |
| Fixed | 19 |
| **Total** | **19** |

## All Bugs

| # | Title | Severity | Status |
|---|---|---|---|
| [1](001.md) | Unvalidated Nonces in HTTP Digest Authentication (Replay Attack) | Critical | Fixed |
| [2](002.md) | SSRF Security Bypass via Global DNS Cache Pollution | Critical | Fixed |
| [3](003.md) | Unbounded Content-Length Payload Allocation (DoS Risk) | Critical | Fixed |
| [4](004.md) | Connection Stream Socket Leak in Happy Eyeballs Race | High | Fixed |
| [5](005.md) | Lack of Read/Idle Timeouts in Stream Relaying | High | Fixed |
| [6](006.md) | Unbounded Growth of Global DNS Cache Dictionary | Medium | Fixed |
| [7](007.md) | Stale Event Loop Reference in Singleton Resolver | High | Fixed |
| [8](008.md) | LogThrottler Timer Handle Accumulation on Logger Setup | Medium | Fixed |
| [9](009.md) | Recursion Stack Overflow on Network Interface Toggles | High | Fixed |
| [10](010.md) | Invalid setsockopt Sequence for Dual-Stack Socket Binding | High | Fixed |
| [11](011.md) | Zero-Index Assignment Evaluation Bug in relay_stream | Medium | Fixed |
| [12](012.md) | Permanent lru_cache Prevents Network Interface Tracking | Medium | Fixed |
| [13](013.md) | Global Auth File Cache Invalidation Bug | Medium | Fixed |
| [14](014.md) | /etc/hosts Multi-IP Overwrite in Host Cache Parsing | Medium | Fixed |
| [15](015.md) | Bracketed IPv6 Host String Regex Parsing Bug | Medium | Fixed |
| [16](016.md) | Subdomain Optimization Complexity in Ad-Block Compiler | Low | Fixed |
| [17](017.md) | Triplicated Parent Domain String Splitting in is_ad_domain | Low | Fixed |
| [18](018.md) | EasyList Regular Expression Mis-match and Ingestion Bug | Low | Fixed |
| [19](019.md) | Unenforced Concurrency Limit (MAX_TASKS) | Low | Fixed |
