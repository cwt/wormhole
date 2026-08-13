---
type: index
title: Wormhole Architecture & System Design
description: Architectural specifications, component topologies, request pipelines, and networking engines.
timestamp: "2026-08-13T11:00:00Z"
---

# Wormhole Architecture & System Design

[⬅️ Back to Main Index](../index.md)

This section documents the internal design, concurrency models, and security mechanics of Wormhole.

## Architectural Topics

- [🏛️ System Architecture Overview](overview.md)
  Module structure, runtime context passing, and system topology map.

- [🔄 Request Handling Pipeline](request-handling.md)
  Detailed walkthrough of HTTPS `CONNECT` tunneling, HTTP/1.0 -> HTTP/1.1 protocol upgrades, and bi-directional stream relaying.

- [🔒 Security & Safeguards](security-safeguards.md)
  Anti-SSRF private IP protection, domain evaluation precedence, and SHA-256 Digest authentication.

- [🌐 DNS & Networking Engine](dns-and-networking.md)
  Asynchronous `aiodns` resolution, local `/etc/hosts` caching, Happy Eyeballs multi-IP connection race, and dynamic IPv6 dual-stack auto-restart.
