# 0010 — Fail fast on non-seekable random access; no silent buffering

- **Status:** accepted
- **Date:** access-mode hardening (e.g. commit messaging around non-seekable RA)
- **Provenance:** OpenSpec `access-mode-and-cost`; related fix notes in git history

## Context

A convenience path that buffers a pipe into memory or a temp file to “make ZIP work”
hides unbounded resource use and surprises callers who thought they were streaming.

## Decision

With `streaming=False`, if the format needs seek and the source is non-seekable, **error
at open**. Do not implicitly buffer. Callers choose `streaming=True` or a seekable
source.

## Consequences

- Honest failure mode for pipes + ZIP/ISO/etc.
- Streaming mode remains the supported non-seekable path where the backend can adapt.

## Update (2026-11-21)

The maintainer made reading a non-seekable source opt-in: only `open_archive(pipe=True)`
reads one, and without it such a source raises `StreamNotSeekableError` at open in both
`streaming=False` and `streaming=True`. `pipe=True` also reads a seekable source the way
a pipe is read. The decision above still holds: nothing buffers a pipe to make it work.
