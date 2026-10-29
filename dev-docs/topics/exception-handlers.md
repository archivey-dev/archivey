# Blind exception handlers

When `except Exception` or `except BaseException` is the right handler in `src/`, and
which shape it takes. The contract these serve is `CONTRIBUTING.md` §Exception
translation: archive problems surface as `ArchiveyError` subclasses through a translator,
an unrecognized exception propagates unchanged, and `OSError` / `KeyboardInterrupt` /
`MemoryError` propagate unless a spec says otherwise.

Every blind handler in `src/` fits one of the seven shapes below. A new one should too;
if it does not, that is worth a sentence in review. The census that produced this page
is `review/archive/2026-09-25-exception-catchalls/SUMMARY.md`.

## 1. The rule

**A blind handler either re-raises the exception it caught, or says on the same line why
dropping it is correct.** "Re-raises" means the *same* exception object leaves: a handler
that ends in `raise SomeArchiveyError(...) from exc` converts every exception to one type,
which is the catch-all the contract forbids. Ruff's BLE001 does not flag that form, so
its silence proves nothing about it. The 2026-09-25 review found three such handlers, all
unmarked.

Dropping an exception is marked `# noqa: BLE001 - <reason>`, and the reason names the
shape.

## 2. The shapes

| Shape | Catches | What leaves | Example |
|---|---|---|---|
| **Cleanup and re-raise** | `BaseException` | the original | `core.open_archive`, `SequentialReaderAdapter._span_parts`, `_bounded_member_pipe` |
| **Error combination** | `Exception` (or `BaseException` when an interrupt must not skip the mandatory step) | the first error, or an `ExceptionGroup`; never nothing | `ArchiveStream.close`, `_maybe_teardown`, `ProcessOutputStream.close` |
| **Primary error wins** | `Exception` | the error already in flight; the cleanup failure is attached as a note or dropped | `BaseArchiveReader.open`, `note_raised_seek` |
| **Translator handoff** | `Exception` | a translated `ArchiveyError` `from` the original, or the original unchanged | `ArchiveStreamImpl._fail`, `_TranslatedErrorBoundary` |
| **Teardown hygiene** | `Exception` | nothing | finalizers, `PpmdDecoder._quiesce_worker` |
| **C-boundary trap** | `Exception` | nothing now; the parked exception later | `RapidgzipChildStream._answer_source` |
| **Diagnostic probe** | `Exception`, narrowed | a fallback value | `nearest_resume_offset`, `_probe_past_declared` |

### Cleanup and re-raise

`except BaseException: release(); raise`. Guards the window where something has been
built (a subprocess, a temp file, a decoder, a reader) and ownership has not yet passed to
an object whose `close()` would release it. `BaseException` is the point: an interrupt
that skips the release leaks an `unrar` process or pins a file. No marker needed; ruff
exempts a bare `raise`.

A failing `release()` replaces the original error (the original becomes its
`__context__`). Where cleanup can plausibly fail after the primary error, use "primary
error wins" instead.

### Error combination

Capture, finish the step that must happen regardless (mark closed, reap the process,
close the source), then raise. Every exit path reaches a `raise`; an early `return` in
between would turn "both failed" into "neither did". Two failures become an
`ExceptionGroup`.

### Primary error wins

Inside a failure path, a second failure from cleanup is secondary. Attach it with
`add_note` where a reader of the traceback would want it; drop it where it only restates
the first.

### Translator handoff

`except Exception as e: self._fail(e)`. The translator returns `None` for what it does
not recognize, and the handoff then re-raises the original. It never converts an
unrecognized exception, and it never catches `BaseException`.

### Teardown hygiene

Swallow during close or finalization, when there is no caller to receive the error or the
object is being replaced. Allowed only after every content verdict has been given: those
fire from reads (ADR 0014), never from close. `Exception` only, so an interrupt still
propagates.

### C-boundary trap

rapidgzip's decoders call back into a caller-owned Python stream from C++, and a Python
exception unwinding through those frames aborts the process. Every codec rapidgzip decodes
(gzip, zlib, deflate and bzip2) runs it in a child process. The worker's source object
never raises (a failed read is an end of input). `RapidgzipChildStream` serves its reads
from the caller's stream in this process, parks an `Exception` from it and raises it when
the call ends; an interrupt propagates at once, and the child, left mid-exchange, is
killed. archivey runs no rapidgzip decoder in its own process; a new in-process
accelerator that reads a caller-owned stream would need the same guard.

### Diagnostic probe

A probe answers a side question (a cost estimate) and must not break the read it serves.
Narrow it: let `ArchiveyError`, `OSError` and `MemoryError` through, and say what verdict
the fallback gives up. A probe whose answer is a content verdict narrows further. The
verifier's read of one byte past a member's declared size (`_probe_past_declared`) lets
every decoder error through, because an error there is damage and a fallback of "no more
data" would hand the member over as verified. It catches only a closed source, which
another thread's `close()` can cause once every declared byte was delivered.

## 3. `BaseException`

A handler reaches past `Exception` only when an interrupt must not skip what it does:
releasing a resource (cleanup and re-raise), reaping a process or marking an object closed
before raising (error combination, e.g. `ProcessOutputStream.close`), or keeping the
exception out of C++ (the trap). All three hand the interrupt back. None swallows
`KeyboardInterrupt`, `SystemExit` or `MemoryError`, and a new `BaseException` handler that
would needs its reason stated in the code.
