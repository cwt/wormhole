---
type: index
title: Wormhole Proxy Documentation Master Index
description: Comprehensive documentation portal for Wormhole, an asynchronous HTTP/HTTPS proxy engine.
timestamp: "2026-08-13T11:00:00Z"
---

# Wormhole Documentation Index

Welcome to the **Wormhole** documentation portal. Wormhole is a high-performance, asynchronous HTTP and HTTPS proxy server built in Python with `asyncio`, `aiodns`, and Digest SHA-256 authentication.

## 📖 User Guide

- [🚀 Getting Started](user-guide/getting-started.md) — Installation, quickstart, CLI options, and event loop configuration.
- [🔐 Authentication Management](user-guide/authentication.md) — Setting up Digest SHA-256 user accounts and security enforcement.
- [🛡️ Ad-Blocking & Safeguards](user-guide/ad-blocking.md) — SQLite blocklist generation, custom blocklists, and domain allowlists.

## 🏗️ Architecture & System Design

- [🏛️ System Architecture Overview](architecture/overview.md) — High-level components, module topology, and request flows.
- [🔄 Request Handling Pipeline](architecture/request-handling.md) — HTTPS `CONNECT` tunneling, HTTP/1.0 to HTTP/1.1 upgrading, and stream relaying.
- [🔒 Security & Safeguards](architecture/security-safeguards.md) — Anti-SSRF private IP filtering, domain evaluation priority, and authentication.
- [🌐 DNS & Networking Engine](architecture/dns-and-networking.md) — Asynchronous DNS caching, hosts file integration, Happy Eyeballs, and dual-stack IPv6 auto-tuning.

## 🛠️ Development & Quality

- [📋 Development Index](development/index.md) — Master portal for development mandates, logs, lessons learned, and bug tracking.
- [📜 Architectural Mandates](development/architectural-mandates.md) — Core design constraints and coding guidelines.
- [📝 Chronological Log](development/log.md) — Development journey and version history.
- [🎓 Lessons Learned](development/lessons/index.md) — Engineering retrospectives and systemic defect analysis.
- [⚡ Experimental Talyn Event Loop](development/talyn-event-loop.md) — Dogfooding setup, target Linux architectures, and fallback mechanics.
- [🐛 Bug Tracker](development/bugs/index.md) — Detailed registry of audited issues (`001.md` – `019.md`).
