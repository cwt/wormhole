---
type: architecture_guideline
title: Request Handling Pipeline
description: Technical specification of CONNECT HTTPS tunneling, HTTP upgrading, and stream relaying.
timestamp: "2026-08-13T11:00:00Z"
---

# Request Handling Pipeline

[⬅️ Back to Architecture Index](index.md)

Wormhole differentiates between HTTP proxying and HTTPS tunneling requests.

## 1. HTTPS Tunneling (`CONNECT` Method)

When a client sends an HTTP `CONNECT host:port` request (e.g. for TLS/HTTPS traffic):

1. **Host Extraction**: [`tools.get_host_and_port`](../../wormhole/tools.py) parses the target authority.
2. **Ad-Block & Security Check**: `_resolve_and_validate_host` verifies the domain against ad blocklists and ensures resolved IPs are non-private.
3. **Connection Establishment**: `_create_fastest_connection` connects to the destination using Happy Eyeballs race logic.
4. **Client Handshake**: Sends `HTTP/1.1 200 Connection established\r\n\r\n` back to the client.
5. **Bidirectional Relay**: Launches two concurrent `relay_stream` coroutines inside an `asyncio.TaskGroup`:
   - Task A: Client StreamReader -> Server StreamWriter
   - Task B: Server StreamReader -> Client StreamWriter

## 2. HTTP Request Forwarding

For standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, etc.):

1. **URI & Header Parsing**: Extracts target host from `Host` header or absolute URI string.
2. **Protocol Upgrade**: If the client sends an `HTTP/1.0` request, Wormhole attempts to upgrade the request to `HTTP/1.1` by adding `Host` headers and setting `Connection: close`. If the upstream server rejects HTTP/1.1, Wormhole falls back to original HTTP/1.0 headers.
3. **Payload Forwarding**: Reads payload bytes based on `Content-Length` and streams response headers and body back to the client.

## 3. Stream Relaying (`relay_stream`)

The core streaming loop reads chunks of 4096 bytes and writes directly to destination stream writers with `drain()` calls to enforce backpressure.
