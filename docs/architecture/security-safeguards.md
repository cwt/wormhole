---
type: architecture_guideline
title: Security & Safeguards Specification
description: Technical specification of anti-SSRF protections, domain evaluation priorities, and Digest SHA-256 security.
timestamp: "2026-08-13T11:00:00Z"
---

# Security & Safeguards Specification

[⬅️ Back to Architecture Index](index.md)

Wormhole incorporates defense-in-depth security measures to protect internal infrastructure and prevent malicious misuse.

## Anti-SSRF Protection (`is_private_ip`)

By default, Wormhole blocks requests attempting to target internal, private, loopback, or reserved IP addresses:

- IPv4 Private Ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`
- IPv6 Private Ranges: `::1/128`, `fc00::/7`, `fe80::/10`

If host resolution returns only private IP addresses, the request is rejected with `HTTP/1.1 403 Forbidden` unless the `--allow-private` CLI flag is explicitly enabled.

## Domain Evaluation Precedence (`is_ad_domain`)

When checking whether a request should be blocked or allowed, [`safeguards.is_ad_domain`](../../wormhole/safeguards.py) evaluates rules in strict hierarchical order:

1. **Exact Match in Custom Blocklist** (`--blocklist` file) -> **BLOCK**
2. **Exact Match in Ad Blocklist Database** (`--ad-block-db` file) -> **BLOCK**
3. **Exact Match in Allowlist** (`--allowlist` file or defaults) -> **ALLOW**
4. **Parent Domain Match in Custom Blocklist** (e.g. `example.com` blocks `sub.example.com`) -> **BLOCK**
5. **Parent Domain Match in Ad Blocklist Database** -> **BLOCK**
6. **Parent Domain Match in Allowlist** (e.g. `x.com` allows `api.x.com`) -> **ALLOW**
7. **Default** -> **ALLOW**

## Digest SHA-256 Authentication

When authentication is enabled (`--auth`), Wormhole calculates Digest HA1 values as:

- `HA1 = SHA256(username : realm : password)`
- `HA2 = SHA256(method : uri)`
- `Expected Response = SHA256(HA1 : nonce : nc : cnonce : qop : HA2)`

Comparing hashes via `secrets.compare_digest` prevents timing side-channel attacks.
