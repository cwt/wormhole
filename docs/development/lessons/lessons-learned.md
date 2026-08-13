---
type: lessons_learned
title: Engineering Lessons Learned
description: Critical engineering insights on socket leaks, singleton event loop bindings, SSRF cache pollution, and async memory safety.
timestamp: "2026-08-13T11:00:00Z"
---

# Engineering Lessons Learned

[⬅️ Back to Lessons Index](index.md)

Key technical lessons learned from codebase audits and system testing in Wormhole.

## 1. Async Concurrency: Socket Leak in Cancelled Tasks

### Finding
When cancelling concurrent connection tasks in Happy Eyeballs (`asyncio.gather(*pending, return_exceptions=True)`), secondary connection tasks that finished right before cancellation returned active `(reader, writer)` socket pairs that were ignored and never closed ([`004.md`](../bugs/004.md)).

### Lesson
Always inspect gathered task results after cancellation to explicitly close any socket streams returned by tasks that completed prior to cancellation.

## 2. Event Loops & Singletons: The Closed Loop Trap

### Finding
Lazy initialization inside singleton classes (like `Resolver`) that binds `aiodns.DNSResolver(loop=loop)` creates hard failures when event loops are recreated during testing or dynamic server restarts ([`007.md`](../bugs/007.md)).

### Lesson
Never cache event-loop-bound objects across process lifetimes inside singletons. Provide explicit `rebind()` or `reset()` mechanisms when event loops change.

## 3. Security: Global DNS Cache Pollution and SSRF

### Finding
Caching hostname IP resolutions before applying security filters (`is_private_ip`) allowed cached internal IPs resolved under `allow_private=True` to be served to subsequent requests running under `allow_private=False` ([`002.md`](../bugs/002.md)).

### Lesson
Security validation checks must always run *after* retrieving records from a cache, never solely before cache insertion.

## 4. Input Validation: Unbounded Allocation DoS

### Finding
Directly trusting untrusted HTTP headers (`Content-Length`) in `readexactly(content_length)` allows clients to trigger arbitrary RAM allocations ([`003.md`](../bugs/003.md)).

### Lesson
Always enforce explicit upper bounds on untrusted allocation inputs before invoking memory-allocating I/O routines.
