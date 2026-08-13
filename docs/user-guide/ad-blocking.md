---
type: user_guide
title: Ad-Blocking & Custom Domain Lists
description: Compiling and running SQLite ad-block databases and custom allowlists/blocklists.
timestamp: "2026-08-13T11:00:00Z"
---

# Ad-Blocking & Custom Domain Lists

[⬅️ Back to User Guide Index](index.md)

Wormhole includes an integrated ad-blocking engine capable of matching host requests against hundreds of thousands of ad-serving and tracking domains in real time.

## Compiling an Ad-Block Database

Wormhole fetches curated public blocklists (StevenBlack hosts, EasyList, EasyPrivacy, AdAway, etc.), parses host formats, removes redundant subdomains, and compiles them into a SQLite database.

Run the update utility:

```bash
poetry run python -m wormhole --update-ad-block-db ads.sqlite3
```

You can also pass custom allowlists or blocklists during database compilation:

```bash
poetry run python -m wormhole --update-ad-block-db ads.sqlite3 \
    --allowlist custom-allow.txt \
    --blocklist custom-block.txt
```

## Enabling Ad-Blocking at Runtime

To run the proxy server with ad-blocking enabled:

```bash
poetry run python -m wormhole --ad-block-db ads.sqlite3
```

## Custom Allowlists and Blocklists

- **Allowlist (`--allowlist <file>`)**: Domains in this file are permitted even if present in public ad blocklists.
- **Blocklist (`--blocklist <file>`)**: Domains in this file are explicitly blocked with top priority.

File format is simple plain text (one domain per line, `#` comments allowed):

```text
# custom-allow.txt
analytics.example.com
studiostaticassets.azureedge.net
```
