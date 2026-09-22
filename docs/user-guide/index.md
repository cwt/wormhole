---
type: index
title: Wormhole User Guide
description: User documentation covering setup, CLI commands, Digest authentication, ad-blocking, and Tor support.
timestamp: "2026-08-13T11:00:00Z"
---

# Wormhole User Guide

[⬅️ Back to Main Index](../index.md)

This section provides operational instructions for deploying and configuring the Wormhole proxy.

## User Manuals

- [🚀 Getting Started](getting-started.md)
  System requirements, installation, server execution, command-line flags, and high-performance event loop backends (`uvloop`, `winloop`, `talyn`).

- [🔐 Authentication Management](authentication.md)
  Creating, modifying, and deleting user accounts with Digest SHA-256 authentication (`--auth-add`, `--auth-mod`, `--auth-del`, `--auth`).

- [🛡️ Ad-Blocking & Safeguards](ad-blocking.md)
  Compiling blocklists from public feeds into SQLite database format (`--update-ad-block-db`), custom domain blocklists, and allowlists.

- [🧅 Tor Support](tor.md)
  Routing through a private local tor daemon (`--tor`), the bridge bootstrap ladder (`--tor-bridge`, `--tor-snowflake`), onion services, and failure reporting.
