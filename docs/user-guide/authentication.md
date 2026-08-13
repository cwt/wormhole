---
type: user_guide
title: Digest Authentication Management
description: Configuring Digest SHA-256 authentication and user credentials in Wormhole.
timestamp: "2026-08-13T11:00:00Z"
---

# Digest Authentication Management

[⬅️ Back to User Guide Index](index.md)

Wormhole supports HTTP Digest Authentication using SHA-256 hashing (`RFC 7616`) to secure proxy access. Passwords are never stored in plaintext.

## Managing Users

User credentials are managed using CLI subcommands.

### Adding a User

```bash
poetry run python -m wormhole --auth-add auth.db alice
```
You will be prompted securely to enter and confirm the user's password. The file `auth.db` is automatically created with restricted file permissions (`0600` on POSIX).

### Modifying a User Password

```bash
poetry run python -m wormhole --auth-mod auth.db alice
```

### Deleting a User

```bash
poetry run python -m wormhole --auth-del auth.db alice
```

## Running the Proxy with Authentication

To enforce authentication on all incoming proxy connections, pass the `--auth` flag:

```bash
poetry run python -m wormhole --auth auth.db -p 8800
```

Unauthenticated requests will receive `HTTP/1.1 407 Proxy Authentication Required` responses containing a SHA-256 Digest challenge.
