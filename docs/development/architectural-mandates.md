---
type: architecture_guideline
title: Architectural Mandates & Design Constraints
description: Mandatory rules, Python target constraints, and coding guidelines for Wormhole contributors.
timestamp: "2026-08-13T11:00:00Z"
---

# Architectural Mandates & Design Constraints

[⬅️ Back to Development Index](index.md)

All additions and refactoring in Wormhole must comply with the following architectural mandates.

## 1. Python Target & Compatibility

- **Target Version**: Python 3.11+ syntax and features (`asyncio.TaskGroup`, `ExceptionGroup`, modern type hint unions `X | Y`).
- **No Unapproved 3.12+ Syntax**: Do not use features introduced in Python 3.12+ unless explicitly mandated by project priorities.

## 2. Coding Style & Quality Rules

- **Readability First**: Code clarity is prioritized above clever one-liners.
- **Strict Anti-Lambda Policy**: Do **NOT** use `lambda` functions under any circumstances. Always declare named functions with `def`.
- **Explicit Typing**: Maintain full type hints across function parameters and return types checked by `mypy`.
- **Parameter Overhead Reduction**: Group request-scoped metadata into `RequestContext` objects instead of passing long lists of scalar arguments.

## 3. Concurrency & Resource Discipline

- **Non-blocking IO**: Never execute blocking file I/O or synchronous socket calls on the asyncio event loop.
- **Resource Cleanup**: Every socket writer, file handle, or async generator **MUST** be safely closed in `finally` blocks or context managers.
- **Structured Concurrency**: Use `asyncio.TaskGroup` for concurrent task management to guarantee child task cancellation on failures.
