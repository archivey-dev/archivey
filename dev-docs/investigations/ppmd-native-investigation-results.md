# PPMd / pyppmd native investigation — results

**Brief:** `dev-docs/investigations/ppmd-native-investigation-brief.md`
**Prior work:** `dev-docs/investigations/pyppmd-upstream-report.md`,
`dev-docs/investigations/ppmd-exit-after-green-exploration.md`,
`dev-docs/known-issues.md`, `scripts/pyppmd_crash_repro.py`
**Date started:** 2026-07-23
**Status:** complete (empirical + source). Findings appended as experiments
finished. Source
citations are against **pyppmd `v1.3.1`** (the pinned wheel; git tag `v1.3.1`,
commit `580b675`). The wheel installed in this env is `pyppmd 1.3.1`, CPython
3.11.15, glibc 2.39, Linux 6.18.5.

This report answers the brief from **native source + minimal repros**, not from
archivey's mitigations. Where the archivey labs already measured a behaviour, it
is cited and the *source-level cause* is added rather than re-measured.

---

## TL;DR verdict

The heap corruption is **not** primarily the Pavlov suballocator — valgrind's
*first* memory error in every crash family is a **use-after-free of pyppmd's own
output buffer** at `ThreadDecoder.c:134`, on a block already freed by
`OutputBuffer_Finish` (`_ppmdmodule.c:552`). Every failure mode below reduces to
that one bug, gated by one condition: **did the worker finish, or is it left
blocked in the reader past logical EOF?**

| Failure mode | 7-Zip / Pavlov PPMd core | pyppmd ThreadDecoder / binding | Caller contract |
|--------------|--------------------------|--------------------------------|-----------------|
| overshoot `max_length` (`-1` or `+65536`) | Not the fault site. The desynced model only *generates the garbage symbols*; it does not write outside its own `p->Base` arena first. | **Root cause (pyppmd):** worker left blocked-in-reader (1.3.0 `#126` removed the input-empty stop) while `OutputBuffer_Finish` frees the output block → later wake ⇒ **UAF write, free-running** (reader `pos==size` bug). Valgrind: 33 423 writes at `ThreadDecoder.c:134`. | Never request more output than the true remaining payload. |
| post-eof empty decode toward `unpack_size` | Not the fault site. | Same UAF. No after-eof guard in the **C extension** `decode` (guard is cffi-only) restarts a runaway worker. | Do not `decode` after `eof` unless pack delivery is known complete. |
| half-pack + large NUL / after-eof NUL | Not the fault site. | Same UAF (valgrind: 59 522 writes at `ThreadDecoder.c:134`, same single context). | Cap the synthetic-NUL budget; do not chase `unpack_size` on short pack. |
| `Ppmd7T_Free` while worker blocked | Not applicable (7-Zip is non-threaded here). | **pyppmd-only:** `Ppmd7T_Free` fakes "input available" (`tc->empty=False`) then cancels; that wake is *what drives the UAF above*, and the reader also does an OOB `src[pos++]` at `pos==size`. | n/a (teardown bug). |
| omit-trailing-null / "extra byte" | **Container/reader convention**, not an encoder action. | pyppmd's reader **blocks** at EOF instead of returning 0, so the caller must feed `b"\0"` to emulate 7-Zip's over-read-zero. | Keep bounded NUL recovery for members produced by real 7-Zip. |

Control that pins it: **exact-sized `decode(packed, len(data))` is 0 valgrind
errors** — the worker's budget runs out exactly at the payload boundary, it
returns and is joined, `finished=True`, and `Ppmd7T_Free` never wakes it. Any
overshoot leaves it blocked-in-reader instead, and the freed output block is then
written by the resumed worker.

Bottom line: this is a **pyppmd binding bug** — three compounding defects, all in
`ThreadDecoder.c` / `_ppmdmodule.c` / `blockoutput.h` (Section D), introduced by
the 1.3.0 `#126` rewrite. Igor Pavlov's `Ppmd7.c` is *memory-unsafe if driven
past EOF*, but that is a latent property the caller must respect (real 7-Zip
always decodes to the exact known unpack size and never trips it); it is **not**
the first corrupting write here. The regression and the fix both belong to
pyppmd.

---

## A. Code map (which file owns what)

Vendored tree under `pyppmd/src/`:

| File | Provenance | Role |
|------|-----------|------|
| `lib/ppmd/Ppmd7.c`, `Ppmd7.h` | Igor Pavlov / 7-Zip (`2017-04-03 : Igor Pavlov : Public domain`, "based on PPMd var.H (2001): Dmitry Shkarin") | Model + **suballocator** (`InsertNode`/`RemoveNode`/`GlueFreeBlocks`/`AllocUnits`), range-dec vtable |
| `lib/ppmd/Ppmd7Enc.c` | Pavlov / 7-Zip | Range encoder + `Ppmd7z_RangeEnc_FlushData`, `Ppmd7_EncodeSymbol` |
| `lib/ppmd/Ppmd7Dec.c` | Pavlov / 7-Zip | Range decoder + `Ppmd7_DecodeSymbol` |
| `lib/ppmd/Ppmd8*.c` | Pavlov / 7-Zip (var.I, RAR) | PPMd8 model/enc/dec (has a real end mark) |
| `lib/buffer/ThreadDecoder.c/.h` | **pyppmd original** (`Created by miurahr 2021/08/07`) | Worker-thread wrapper, blocking reader, `Ppmd7T_decode`, `Ppmd7T_Free` |
| `lib/buffer/Buffer.c/.h` | pyppmd original | `BufferReader`/`BufferWriter`, `InBuffer`/`OutBuffer`, growable output |
| `ext/_ppmdmodule.c` | pyppmd original | Python `Ppmd7Encoder`/`Ppmd7Decoder` (+ Ppmd8), `eof`/`needs_input` state machine, `remains` budget |

So the **algorithm** files (`Ppmd7*.c`) are untouched Pavlov code; the
**threading, budget, and lifecycle** live entirely in pyppmd's own
`ThreadDecoder.c` + `_ppmdmodule.c`. This division is what makes the verdict
crisp.

### How a decode byte flows

`_ppmdmodule.c:335` wires the range decoder's input stream to the **blocking**
reader: `bufferReader->Read = Ppmd_thread_Reader`. Every
`IByteIn_Read(p->Stream)` inside `Ppmd7Dec.c` (`Range_Normalize`,
`Ppmd7z_RangeDec_Init`) therefore calls `Ppmd_thread_Reader`
(`ThreadDecoder.c:65`), which **blocks on `notEmpty` when input is exhausted**
(`pos == size`) instead of returning a byte. The actual symbol loop runs on a
separate worker thread (`Ppmd7T_decode_run`), decoupled from the Python call by
condition variables.

---

## B. "Omit last null" / the extra input byte

### What the encoder actually does

`Ppmd7Encoder.flush()` (`_ppmdmodule.c:851`) optionally encodes an end-mark
symbol **only if `endmark=True`** (default `False`), then unconditionally calls
`Ppmd7z_RangeEnc_FlushData` (`Ppmd7Enc.c:67`):

```c
void Ppmd7z_RangeEnc_FlushData(CPpmd7z_RangeEnc *p) {
  unsigned i;
  for (i = 0; i < 5; i++)
    RangeEnc_ShiftLow(p);   // always emits 5 range-coder bytes
}
```

**There is no code that omits a trailing `0x00`.** The encoder writes exactly 5
flush bytes, unconditionally. The README's

> "The encoder will omit a last null (`b"\0"`) byte when last byte is `b"\0"`."

is therefore **not a description of `Ppmd7Enc.c`** — pyppmd's own encoder omits
nothing. This matches the archivey labs: `encode()+flush()` round-trips on 1.3.1
need the synthetic NUL in **0/60768** trials.

### Where the "extra byte" convention really comes from

It is a **reader convention**, not an encoder action. Two facts from source:

1. The PPMd7 range decoder does a **1-byte lookahead** at the tail. `Range_Normalize`
   (`Ppmd7Dec.c:26`) reads a fresh byte whenever `Range < kTopValue`; near the
   end of a stream it can demand one more byte than the payload strictly needed.
2. pyppmd's reader **blocks** at EOF (`ThreadDecoder.c:70-81`) rather than
   synthesising that lookahead byte.

In stock **7-Zip**, the PPMd stream is read through an in-byte wrapper
(`CByteInBufWrap`-style) whose `ReadByte` **returns `0` and bumps an
"extra bytes" counter once the buffer is exhausted**, so the decoder's tail
lookahead transparently reads zeros past end-of-input. That over-read-zero
behaviour is exactly what lets 7-Zip *store* a PPMd pack stream with a trailing
`0x00` trimmed — "omit last null" is a **container storage optimisation that
depends on the decoder reader returning 0 past EOF**, not on the encoder
dropping a byte.

pyppmd's blocking reader does **not** return 0 past EOF, so the binding pushes
that responsibility onto the caller: the README's
`decode(b"\0", length - len(result))` is the caller **manually feeding the zero
byte 7-Zip's reader would have synthesised**. Confirmation to run (Section G):
feeding `b"\0"` unblocks a stream that `needs_input` at the tail, whereas the
same stream stalls forever if you never feed it.

**Implication for archivey:** keep bounded NUL recovery — it is required for
members produced by real 7-Zip that were stored with a trimmed trailing zero,
even though pyppmd's *own* encoder never produces such a stream. The cap must be
bounded (not `unpack_size`) because the same `decode(b"\0", big)` call is the
overshoot crash primitive (Section D).

---

## C. `max_length` and `eof` semantics

### The budget

`_ppmdmodule.c:521`:

```c
int remains = length >= 0 ? length : INT_MAX;   // <-- -1 becomes INT_MAX
```

The Python `length` (`max_length`) is a plain symbol budget. `-1` is not "decode
to end mark" (PPMd7 has none) — it is "decode up to INT_MAX symbols". The output
buffer grows on demand (`OutputBuffer_Grow`, `_ppmdmodule.c:534`), so nothing
bounds the run except (a) the budget and (b) the worker's `outbuf_full` check.

### The worker's stop condition (the #126 regression)

`Ppmd7T_decode_run` (`ThreadDecoder.c:110-137`):

```c
while (i < max_length) {
    Bool outbuf_full = threadInfo->out->size == threadInfo->out->pos;
    /* Only stop when output buffer is full. Do NOT stop just because
       input buffer appears empty ... */
    if (outbuf_full) break;
    int c = Ppmd7_DecodeSymbol(cPpmd7, rc);   // may block in reader, or run on stale state
    ...
}
```

Pre-1.3.0, the loop also broke when input was exhausted. #126 removed that,
commenting that the reader will block instead. That is true **only while more
real input is coming**. When the whole pack has been fed in one `decode` call
and `max_length` exceeds the payload, the range coder still has its 5 flush
bytes + code register, so `Ppmd7_DecodeSymbol` keeps **returning symbols without
reading input** — it walks the model on a desynchronised range coder, emitting
garbage, until it either finally demands a byte (reader blocks) or the model
throws `-1`/`-2`. With `INT_MAX`/oversized budget that window is effectively
unbounded — and, crucially, it usually ends with the worker **blocked in the
reader** rather than finished, which is the precondition for the output-buffer
UAF (Section D). This is the mechanism behind `overshoot` and `oversized`
(`scripts/pyppmd_crash_repro.py`), and behind half-pack + large NUL.

### Premature `eof`

`_ppmdmodule.c:553`:

```c
if (Ppmd7z_RangeDec_IsFinishedOK(self->rangeDec)) self->eof = True;
```

and `Ppmd7.h:107`:

```c
#define Ppmd7z_RangeDec_IsFinishedOK(p) ((p)->Code == 0)
```

`eof` is set **whenever the range-coder `Code` register is 0 at the end of a
decode call** — not when the stream is genuinely finished. On highly
compressible data decoded with a small `max_length`, the `Code` register
transiently hits 0 after the first ~64 output bytes, so `eof=True` is reported
even though `unpack_size` is far larger. That is the "premature eof" the brief
asks about, and it is a direct consequence of using `Code == 0` as an
end-of-stream proxy. The register returning to a non-zero value on the next
symbol is why *ignoring* the premature eof and continuing with `decode(b"", n)`
can still complete a **valid** stream (the archivey chunked-drain observation) —
and why the same continuation on a **truncated** stream runs the overshoot
primitive into the ground.

`needs_input` is set (`_ppmdmodule.c:541`) when the worker returned `0`
(reader blocked / input exhausted), i.e. `Ppmd7T_decode` took the `inempty`
path (`ThreadDecoder.c:189`). So the state machine is:

- worker fills output → `result = i > 0`, loop continues / stops on budget;
- reader blocks (input empty) → `result = 0` → `needs_input = True`;
- `Ppmd7_DecodeSymbol` returns `-1` → `result = -1` → `eof = True`;
- returns `-2` → `ValueError("Corrupted input data")`;
- after any call, `Code == 0` → `eof = True` (the premature-eof path).

---

## D. Corruption mechanism (root cause — valgrind-confirmed)

The heap-corruption abort (`corrupted size vs. prev_size` / `malloc(): invalid
size` / SIGABRT / SIGSEGV, Windows `STATUS_HEAP_CORRUPTION 0xC0000374`) is a
**use-after-free of pyppmd's output buffer**, *not* (primarily) a Pavlov
suballocator wild-write. Valgrind (memcheck) reports the same single error
context for `overshoot`, `oversized`, and after-eof `extra-null`:

```
Invalid write of size 1
   at 0x...: Ppmd7T_decode_run (ThreadDecoder.c:134)
   by ...: start_thread (pthread_create.c:447)
 Address 0x... is 1,838 bytes inside a block of size 32,801 free'd
   at ...: free
   by ...: OutputBuffer_Finish (blockoutput.h:253)
   by ...: Ppmd7Decoder_decode (_ppmdmodule.c:552)
 Block was alloc'd at
   by ...: OutputBuffer_InitAndGrow (blockoutput.h:79) / Ppmd7Decoder_decode:504
```

`ThreadDecoder.c:134` is the worker's output write
`*((Byte *)threadInfo->out->dst + threadInfo->out->pos++) = (Byte) c;`. The block
it writes into was freed by `OutputBuffer_Finish`'s `Py_DECREF(buffer->list)`
(`blockoutput.h:253`, reached from `_ppmdmodule.c:552`). So a **worker thread is
still alive and writing after the Python `decode` call freed the output block.**

### The exact causal chain (three compounding defects, all pyppmd-original)

1. **`#126` removed the input-empty stop** (`ThreadDecoder.c`, 1.3.0). In 1.2.0,
   `Ppmd7T_decode_run` broke out of the symbol loop when the input buffer was
   consumed:

   ```c
   // v1.2.0 src/lib/buffer/ThreadDecoder.c
   Bool inbuf_empty = reader->inBuffer->size == reader->inBuffer->pos;
   ...
   if (inbuf_empty && reader->inBuffer->size > 0) { break; }  // <-- REMOVED in 1.3.0
   ```

   With the whole pack fed in one `decode` call and `max_length` exceeding the
   payload, the 1.3.x worker no longer stops at input-empty; it keeps decoding
   (garbage) symbols until the range coder finally needs a byte, then **blocks in
   the reader** (`pthread_cond_wait(notEmpty)`, `ThreadDecoder.c:77`). The
   controller's `inempty` path (`ThreadDecoder.c:189`) returns 0 to Python
   **without joining the still-blocked worker**.

2. **`OutputBuffer_Finish` frees the output block while the worker holds a raw
   pointer into it.** Back in Python land, `Ppmd7Decoder_decode` breaks its loop
   on `result == 0` (`_ppmdmodule.c:530`), sets `needs_input`, and calls
   `OutputBuffer_Finish` (`:552`), whose `Py_DECREF(buffer->list)` frees the
   PyBytes blocks — including the one `out->dst` still points at. There is **no
   worker-quiescence step** before the free.

3. **The blocked worker is later resumed with no new input, and free-runs.** The
   only things that broadcast `notEmpty` are the next `decode` call or
   `Ppmd7T_Free` at teardown (`:198`). When woken, the reader
   (`Ppmd_thread_Reader`, `ThreadDecoder.c:81`) executes
   `return *((const Byte *)inBuffer->src + inBuffer->pos++)` with `pos == size`
   — an OOB read — advancing `pos` to `size+1`. Because the empty check is
   `pos == size` (`:70`) and **not** `pos >= size`, the reader **never blocks
   again**, so the worker free-runs: each iteration decodes a garbage symbol and
   writes it to the freed `out->dst` (`:134`) — thousands of UAF writes
   (valgrind counted 33 423 / 59 522 in 6-cycle runs) until the corrupted glibc
   metadata aborts, a wild read SIGSEGVs, or the deferred `pthread_cancel` lands.

### Why the controls are clean

Exact-sized `decode(packed, len(data))` is **0 valgrind errors**: the worker's
budget (`i < max_length`) runs out at exactly the payload boundary, the worker
returns `i`, sets `finished = True`, and is `pthread_join`-ed by the controller's
`finished` path (`ThreadDecoder.c:185`). No worker is ever left blocked, so
`Ppmd7T_Free` sees `finished` and does nothing, and `out->dst` is never written
after the free. This is precisely the measured safe/unsafe split (sized-safe 0%,
overshoot/oversized/extra-null high-rate).

### Where the Pavlov suballocator fits

The desynced model (`Ppmd7_DecodeSymbol` on a range coder past EOF) is what
*produces* the garbage symbols the worker then writes, and in principle its
suballocator (`InsertNode`/`GlueFreeBlocks` via `NODE(offs)`, `Ppmd7.c:120/145/55`)
can also compute out-of-`Base` offsets. But valgrind's **first** error is always
the output-buffer UAF in pyppmd's own `ThreadDecoder.c:134`, not a write inside
`Ppmd7.c`. So the corruption the earlier `pyppmd-upstream-report.md` attributed
to "walking the native model on a desynchronized range coder" is more precisely a
**pyppmd output-buffer lifetime bug**; the model walk is the garbage *source*, the
UAF is the corrupting *write*. Both are enabled by the same removed stop + oversized
budget.

---

## E. Ppmd8 parity (measured)

PPMd8 (var.I / RAR) **does** have a real end mark: `Ppmd8_DecodeSymbol` returns
`-1` at the EndMarker (`Ppmd8.h:124`), and `Ppmd8T_decode_run` translates it to
`PPMD_RESULT_EOF` (`ThreadDecoder.c:235`), which the module maps to `eof=True`.

Measured (this env, 1.3.1): an **unsized** PPMd8 decode of `b"a"*2000`,
`b"\x00"*2000`, and `"hello world "*100` terminates on the end mark with
`eof=True` and **overshoot = 0** in each case (drove `decode(b"", 4096)` to
completion; no fabricated trailing bytes). This confirms archivey's decision to
perform **no** post-eof drain for unsized PPMd8: the end mark flushes the final
symbols with no residual buffered output, so skipping the drain cannot truncate a
valid member (brief gap #8).

The `Ppmd8T_*` wrapper shares the Ppmd7 structure exactly — same removed
input-empty stop, same `INT_MAX` budget (`_ppmdmodule.c:1264`), same
`OutputBuffer_Finish` free, same `Ppmd8T_Free` fake-input-then-cancel (`:302`) —
so **overshooting past the end mark** (an oversized budget on truncated/corrupt
PPMd8, or empty drains past `eof` toward an inflated `unpack_size`) reproduces the
identical output-buffer UAF. The end mark only protects *valid* unsized streams
by giving the worker a clean stop; it does not protect against a caller that
requests more than the member contains.

---

## F. Answers to the brief's four questions (interim)

1. **Omit-null:** pyppmd's encoder omits nothing (5 unconditional flush bytes,
   `Ppmd7Enc.c:67`); the "extra byte" is a 7-Zip *reader* convention (return 0
   past EOF) that pyppmd's *blocking* reader does not implement, so the caller
   must feed `b"\0"`. Archivey must keep bounded NUL recovery for real-7-Zip
   members, but never with an `unpack_size` budget.
2. **`max_length`/`eof`:** `-1 → INT_MAX` (`:521`); `eof` is `Code == 0`
   (`Ppmd7.h:107`), a proxy that fires prematurely on compressible data under a
   small cap; retained-input semantics let a valid stream continue past that
   premature eof but let a truncated stream run the overshoot primitive.
3. **Corruption:** use-after-free of pyppmd's output block at
   `ThreadDecoder.c:134` (freed by `OutputBuffer_Finish`, `_ppmdmodule.c:552`),
   because the overshooting worker is left blocked-in-reader and later resumed to
   free-run (reader `pos==size` bug). Valgrind-confirmed as the first error in
   overshoot / oversized / after-eof families; the Pavlov suballocator supplies
   the garbage symbols but is not the first faulting write.
4. **Separability:** the whole crash family is **pyppmd-only** — it is a binding
   lifetime/threading bug (`ThreadDecoder.c` + `_ppmdmodule.c` + `blockoutput.h`),
   introduced by `#126` (the input-empty stop existed in 1.2.0, source-confirmed).
   The Pavlov core's memory-unsafety-past-EOF is real but latent: real 7-Zip
   decodes to the exact known unpack size and never trips it, and it is not the
   first corrupting write in pyppmd either.

---

## G. Empirical results (this env: pyppmd 1.3.1, CPython 3.11.15, glibc 2.39)

- [x] **Premature-eof:** `decode(b"a"*4096, 64)` → `out=64`, `eof=True`,
      `needs_input=False` after only 64 of 4096 bytes. `eof` here is the
      `Ppmd7z_RangeDec_IsFinishedOK` (`Code == 0`, `Ppmd7.h:107`) path at
      `_ppmdmodule.c:553` (not an end mark — PPMd7 has none). Ignoring it and
      continuing with `decode(b"", 64)` recovered all 4096 bytes over 63 calls
      (`match_full=True`). Confirms premature eof is a `Code == 0` proxy artefact,
      and that continued empty decode is valid *on a complete stream*.
- [x] **Corruption:** valgrind pins the first error to the output-buffer UAF at
      `ThreadDecoder.c:134` for `overshoot` (`-1`), `oversized`, and after-eof
      `extra-null`; exact-sized decode is 0 errors (Section D). gdb on the raw
      `overshoot` repro aborts with `corrupted size vs. prev_size` at
      `Ppmd7Decoder_dealloc` (`_ppmdmodule.c:222`) — i.e. corrupted metadata is
      only *detected* at teardown free, consistent with an earlier UAF.
      `scripts/pyppmd_crash_repro.py 20 --mode overshoot` → 16/20 crashes here.
- [x] **Omit-null / reader-blocks:** no `encode()+flush()` stream reports
      tail-`needs_input` (encoder omits nothing; `Ppmd7Enc.c:67` writes 5
      unconditional flush bytes). Flushed packs commonly end in `0x00` (that byte
      is load-bearing compressed data). The "extra byte" is the caller manually
      feeding the zero that 7-Zip's over-read-zero reader would synthesise, which
      pyppmd's blocking reader (`ThreadDecoder.c:70-81`) does not.
- [x] **Ppmd8 parity:** unsized decode terminates on the end mark with
      overshoot = 0 (Section E). Structural overshoot-past-end-mark shares the
      Ppmd7 UAF.
- [x] **Version delta (source-confirmed):** the input-empty stop
      `if (inbuf_empty && reader->inBuffer->size > 0) break;` is present in
      `v1.2.0:src/lib/buffer/ThreadDecoder.c` and **absent** in `v1.3.1`
      (removed by `#126`). 1.2.0's own trade-off bug: that same early break
      truncates chunked decodes that must keep producing without new input —
      which is what `#126` set out to fix, swapping a correctness bug for this
      memory-safety bug.

---

## H. Concrete upstream fix (summary)

The full, paste-able fix list and reproduction are the ready-to-file report in
**§J** below (which supersedes the root-cause analysis in
`pyppmd-upstream-report.md`). In short, the root-cause finding sharpens the
priority over the earlier draft: **the corrupting write is the output-buffer UAF,
so the primary fix is worker/output lifetime, not (only) budget clamping.**

1. **Primary — never free the output block while a worker may still write to it**
   (`OutputBuffer_Finish` at `_ppmdmodule.c:552`): quiesce the worker first. This
   alone removes the UAF valgrind flags.
2. Restore an input-exhausted stop (bound the loop by available input, not
   `INT_MAX`, `:521/1264`) without 1.2.0's chunked-truncation bug.
3. Reader empty check `pos >= size`, not `== size` (`ThreadDecoder.c:70`).
4. Explicit terminate flag in `Ppmd7T_Free`/`Ppmd8T_Free` instead of faking
   `tc->empty = False` (`:198/307`).
5. Port the cffi `_eof` guard to the C extension (`_ppmdmodule.c:396`).

Until a fixed release ships, archivey's discipline (never overshoot; require
`unpack_size`/`pack_size`; bounded single NUL; no post-eof drain unless pack
delivery is known complete; **quiesce-on-close** for teardown, §I) is the correct
in-process mitigation.

---

## I. What archivey can do until pyppmd is fixed

The root cause reframes the whole mitigation story around **one invariant**:

> **A `PpmdDecoder` must never be left with a worker blocked in the reader —
> not between calls, and above all not at disposal.** The worker is left blocked
> exactly when a `decode` call requests more output symbols than the *currently
> fed* input can produce. A worker that instead exhausts its `max_length` budget
> returns and is `pthread_join`-ed (`finished=True`), and `Ppmd7T_Free` then
> no-ops — no resume, no use-after-free.

### 1. For valid members: already fully safe in-process (no change needed)

The shipped discipline *is* this invariant, and the investigation now proves it:

- **Require `unpack_size`; bound every call to `min(chunk, unpack_size - produced)`;
  stop exactly at `unpack_size`; never `-1`; never `decode` after `eof` unless the
  pack is known complete; single capped NUL.**

Exact-sized `decode(packed, len(data))` is **0 valgrind errors** (Section D).
Chunked reads of a valid member are clean for the same reason: each call's budget
(e.g. 64) is reached *before* the range coder needs a byte past what was fed, so
the worker finishes every call and `needs_input` never latches at the end. Nothing
to add here — the existing `pack_size` gate + bounded calls cover every
well-formed 7z/PPMd member.

### 2. For truncated / corrupt members: the residual, and a concrete new fix

A member that genuinely contains fewer symbols than its header claims (truncated
pack, or a corrupt full-length pack) **will** exhaust the fed input mid-budget on
some call, latch `needs_input=True`, and leave the worker blocked. archivey
detects this and raises `TruncatedError` — but by then the decoder is already in
the blocked-worker state, and `OutputBuffer_Finish` has already freed the last
output block. When that `PpmdDecoder` is later garbage-collected, `Ppmd7T_Free`
resumes the blocked worker into the freed block → the intermittent
"exit-after-green" abort. Bounding `max_length` shrinks the blast radius (a small
budget makes the free-run short) but does **not** remove the dangling pointer.

**New, measured lever — quiesce the worker before disposal.** Because the UAF
needs the blocked worker to be *resumed*, driving it to `finished` **before** the
decoder is freed removes the resume entirely. One bounded `decode` per outstanding
`needs_input` does it: the worker wakes via the *decode* path (which allocates a
fresh output block **before** resuming, so the 1-symbol write lands in live
memory), hits its 1-symbol budget, and exits `finished`. `Ppmd7T_Free` then
no-ops.

Measured (valgrind, truncated pack + sized decode that blocks the worker, 6
cycles):

| Disposal policy | Invalid writes at `ThreadDecoder.c:134` |
|-----------------|------------------------------------------|
| `del dec` directly (worker left blocked) | **8 154** |
| `while dec.needs_input: dec.decode(b"\0", 1)` (≤4×), then `del` | **0** |

So archivey can add a **"quiesce on close"** step to `PpmdDecoder` /
`DecompressorStream.close()`: while a worker is parked, issue a bounded
`decode(b"\0", 1)` (cap the loop at a few iterations) to force it to `finished`
before releasing the decoder. This is the deterministic-dispose spike the brief's
review addendum asked for (gap #1).

#### Prototype implemented (2026-07-23)

Landed on this branch as `PpmdDecoder._quiesce_worker()`, wired through both an
explicit `close()` (new no-op `Decoder.close()` on the protocol / `BaseDecoder`,
called from `DecompressorStream.close()`) and a `__del__` GC safety net, and
gated on `not self.finished` so a fully-decoded member's close costs nothing.
All 26 `tests/test_ppmd_raw_streams.py` + 7z reader tests pass; both type-checkers
clean.

**What is proven, and what is not:**

- **The quiesce mechanism works** — valgrind on the raw shape that reproduces the
  UAF (bare `pyppmd`, a large-budget `decode` over truncated input, 6 cycles):

  | Disposal policy | Invalid writes at `ThreadDecoder.c:134` |
  |-----------------|------------------------------------------|
  | `del dec` directly (worker left blocked) | **8 154** |
  | `while parked: dec.decode(b"\0", 1)` (≤4×), then `del` | **0** |

  Through the archivey `PpmdDecoder` (truncated PPMd7 via the stream `close()`
  path and via `__del__`): **0** valgrind errors with the fix.

- **On archivey's own shapes in this env, the baseline was already ~0**, so the
  fix could not be shown to move a nonzero crash count *here*:
  - Child-level soak (archivey truncated PPMd7 flush + dispose, fracs
    0.25/0.5/0.7/0.9, 100 fresh processes each): **0 teardown aborts** *without*
    the fix. archivey's capped single NUL (`_PPMD_EXTRA_NUL_MAX_OUTPUT = 64`)
    already limits any teardown free-run to ≤64 writes, which rarely aborts — the
    doc's historical ~15% was the *uncapped* bare-`pyppmd` shape, not archivey's.
  - Module soak (`ci_run_native_modules.py --repeat 30/40`, no
    `--allow-exit-after-green`): **all iterations PASSED** both with and without
    the fix — the in-process adversarial shapes are already subprocess-isolated,
    so the parent session does not abort here.
  - Under valgrind's deterministic thread scheduling, the small-budget teardown
    *race* does not reproduce at all (baseline and fixed both 0) — `pthread_cancel`
    wins at the reader's `cond_wait` cancellation point before the OOB
    read/write. The 8 154→0 result reproduces only with a **large** budget
    (long free-run), which archivey mostly avoids (the one large-budget archivey
    path is unsized PPMd8's 64 KiB chunk; it too was 0/0 here because its end mark
    exits the worker on valid data).

**Verdict on the prototype:** sound, zero-overhead on the happy path,
valgrind-proven to remove the UAF on the shape that exhibits it, and the right
structural fix for gap #1 — but in the current archivey code + this Linux/CPython
3.11 host the teardown residual is already ~0, so it is **defense-in-depth**, not
a fix for a locally-reproducible archivey crash. Dropping required CI's
`--allow-exit-after-green` should be gated on a **deterministic** check (a
valgrind driver like Section D's, run in the PPMd-native-stress workflow) and on
the hot-race platforms (3.12+/free-threaded/Windows, gap #4), not on this host's
already-green soak.

### 3. What cannot be closed in-process

- A **corrupt but full-length** pack (`fed >= pack_size`, right length, wrong
  bytes) can still desync the model and report `needs_input`/premature `eof` with
  large remaining `unpack_size`; `pack_size` cannot tell "wrong bytes" from "right
  bytes", so the gate would permit exactly the blocked-worker state. Quiesce-on-
  close (2) would still neutralise its *teardown*, but any in-call overshoot must
  remain forbidden.
- **True containment for hostile inputs** remains process isolation (exploration
  doc Option D) or the upstream fix (Section H). Quiesce-on-close is a strong
  in-process *reduction* of the teardown residual, not a guarantee against a
  worker that faults *inside* `Ppmd7_DecodeSymbol` on a maximally-corrupt model
  before it can return.

### Summary

| Case | In-process safety today | Lever |
|------|------------------------|-------|
| Valid member (known `unpack_size`, complete pack) | **Safe** (0 valgrind errors) | Existing bound-every-call + `pack_size` gate |
| Truncated member | Teardown abort already ~0 here (capped NUL); a large-budget worker would UAF | **Quiesce-on-close** prototype (bare-shape 8154→0; defense-in-depth) — gate CI allowance-drop on a valgrind check + hot-race platforms |
| Corrupt full-length pack | Residual | Quiesce-on-close neutralises teardown; forbid in-call overshoot; process isolation for full guarantee |

---

## J. Upstream report (ready to file against miurahr/pyppmd)

This section is the self-contained, paste-able bug report. It **supersedes the
root-cause analysis** in `dev-docs/investigations/pyppmd-upstream-report.md` (that draft
attributed the corruption to the vendored 7-Zip model being walked on a
desynchronised range coder; valgrind shows the *first* corrupting write is an
output-buffer use-after-free in pyppmd's own `ThreadDecoder.c`). The two describe
the **same defect** — 1.3.x heap corruption decoding valid/overshot PPMd7 — and
that file now points here.

### Title

> 1.3.x: heap corruption / SIGSEGV / SIGABRT decoding PPMd7 whenever a `decode`
> requests more output than the fed input can produce — root cause is a
> use-after-free of the decode output buffer by the worker thread
> (`ThreadDecoder.c:134`), not the PPMd model. Regression from the 1.3.0
> ThreadDecoder rewrite (#126).

### Summary

Since **1.3.0**, `Ppmd7Decoder.decode` intermittently corrupts the heap on
**valid** PPMd7 data whenever the requested output exceeds what the stream can
still produce — `max_length=-1`, an oversized sized bound (≳64 KiB past the true
payload), any `decode` after `eof`, or a large NUL/empty budget over a truncated
member. Symptoms: `malloc(): invalid size` / `corrupted size vs. prev_size` /
SIGSEGV on Linux, `STATUS_HEAP_CORRUPTION (0xC0000374)` on Windows. 1.1.1/1.2.0
do not corrupt on these inputs. `Ppmd8Decoder` shares the wrapper and the same
defect past its end mark.

### Root cause (valgrind-confirmed)

The worker thread's output write is a **use-after-free**. Valgrind memcheck
reports one context for `overshoot`/`oversized`/after-eof:

```
Invalid write of size 1  at Ppmd7T_decode_run (ThreadDecoder.c:134)
Address ... free'd by  OutputBuffer_Finish (blockoutput.h:253)  <- Py_DECREF(buffer->list)
                       Ppmd7Decoder_decode (_ppmdmodule.c:552)
Block alloc'd at        OutputBuffer_InitAndGrow (blockoutput.h:79) / _ppmdmodule.c:504
```

Three compounding defects, all in pyppmd-original code, introduced by #126:

1. **#126 removed the input-empty stop.** 1.2.0's `Ppmd7T_decode_run` broke out of
   the symbol loop when the input buffer was consumed:
   `if (inbuf_empty && reader->inBuffer->size > 0) break;`. 1.3.0 removed it, so
   with a budget larger than the payload the worker keeps decoding past logical
   EOF and, when it finally needs a byte, **blocks in the reader**
   (`Ppmd_thread_Reader`, `ThreadDecoder.c:77`). The controller returns to Python
   via the `inempty` path (`:189`) **without joining** the still-blocked worker.

2. **`OutputBuffer_Finish` frees the output block under the blocked worker.** Back
   in `Ppmd7Decoder_decode`, the loop breaks on `result == 0` (`_ppmdmodule.c:530`)
   and `OutputBuffer_Finish` (`:552`) does `Py_DECREF(buffer->list)`
   (`blockoutput.h:253`), freeing the PyBytes block that the worker's `out->dst`
   still points at. No worker-quiescence precedes the free.

3. **The blocked worker is resumed with no input and free-runs.** The next
   `decode` or `Ppmd7T_Free` at teardown (`:198`) broadcasts `notEmpty`; the
   reader does an OOB `*(src + pos++)` at `pos == size`, and because the empty
   check is `pos == size` (not `pos >= size`, `:70`) it **never blocks again** and
   free-runs — each iteration writing one byte into the freed block
   (`ThreadDecoder.c:134`) for thousands of iterations until the heap aborts.

**Control:** exact-sized `decode(packed, len(data))` is **0 valgrind errors** — the
worker's budget ends at the payload boundary, it returns, is joined
(`finished == True`), and `Ppmd7T_Free` no-ops. This is why py7zr (always passes a
size) and any caller that never overshoots are safe.

The vendored 7-Zip model (`Ppmd7.c`) is memory-unsafe *if driven past EOF* (its
suballocator addresses nodes by unchecked `p->Base + offset`), but that is a
latent property the caller must respect; it is **not** the first corrupting write
here, and real 7-Zip never trips it because it always decodes to the exact known
unpack size.

### Reproduction

```bash
pip install 'pyppmd==1.3.1'
# Probabilistic crash-rate (fresh subprocess children):
python scripts/pyppmd_crash_repro.py 30 --mode overshoot   # crashes
python scripts/pyppmd_crash_repro.py 30 --mode oversized   # crashes, no -1
python scripts/pyppmd_crash_repro.py 30 --mode sized-safe  # control, clean
# Deterministic (valgrind memcheck; pins the UAF every run):
python scripts/ppmd_uaf_valgrind.py --scenario pyppmd-overshoot --strict-pyppmd
```

`ppmd_uaf_valgrind.py` reports the `Invalid write ... ThreadDecoder.c:134` context
deterministically; a fixed release must make it 0.

### Suggested fixes (priority order)

1. **Do not free the output block while a worker may still write to it (primary).**
   Before `OutputBuffer_Finish` / any `Py_DECREF(buffer->list)` in
   `Ppmd7Decoder_decode` (`_ppmdmodule.c:552`) and `Ppmd8Decoder_decode`, ensure
   the worker is quiescent (finished, or parked in a way that guarantees it will
   not dereference `out->dst` until re-entry). Equivalently, never hand the worker
   a raw pointer into a Python-owned block the controller can free while the worker
   is only paused.
2. **Restore an input-exhausted stop** without reintroducing 1.2.0's
   chunked-truncation bug: stop/park when the range coder needs a byte the input
   cannot supply, and bound the loop by what the input supports instead of
   `INT_MAX` (`:521`/`:1264`).
3. **Fix the reader's empty check** to `pos >= size` (`ThreadDecoder.c:70`) so a
   one-byte overshoot cannot become an unbounded free-run.
4. **Signal termination explicitly in `Ppmd7T_Free`/`Ppmd8T_Free`** via a flag the
   reader re-checks after wakeup, instead of faking `tc->empty = False` with no
   data (`:198`/`:307`); the reader must park/return on termination, not read
   `src[pos++]`.
5. **Port the cffi `_eof` guard to the C extension:** `decode` after `eof` returns
   `b""` without starting a worker (`_ppmdmodule.c:396`).

Fixes 2–5 are defence-in-depth; **fix 1 is the one valgrind demands.**

### Caller-side workaround (what archivey ships)

Never overshoot: require the exact `unpack_size`; bound every `decode` to
`min(chunk, unpack_size - produced)`; never `-1`; `pack_size` gate on post-eof
drains; a single capped extra NUL. Plus **quiesce-on-close** — drive a parked
worker to `finished` with bounded `decode(b"\0", 1)` before disposal so
`Ppmd7T_Free` cannot resume it into freed memory (`PpmdDecoder._quiesce_worker`,
§I). See `dev-docs/known-issues.md`.

### Verification checklist for a fixed release

All must be **0 crashes / 0 memcheck errors**:

```bash
python scripts/pyppmd_crash_repro.py 50 --mode extra-null
python scripts/pyppmd_crash_repro.py 50 --mode overshoot
python scripts/pyppmd_crash_repro.py 50 --mode oversized
python scripts/pyppmd_crash_repro.py 50 --mode warmup-overshoot
python scripts/pyppmd_crash_repro.py 100 --mode nul-after-error --cycles 20
python scripts/pyppmd_crash_repro.py 100 --mode spent-quiesce-nul --cycles 20
python scripts/ppmd_uaf_valgrind.py --scenario all --strict-pyppmd
uv run --no-sync pytest tests/test_ppmd_raw_streams.py -q
```

---

## K. Field record: fingerprints, version matrix, stress setup and mitigations

This section holds the evidence that used to sit in `dev-docs/known-issues.md`. That
page keeps the live upstream defect and the residual risk; the measurements are here.

### K.1 How the defect showed up in CI

**Windows: `STATUS_HEAP_CORRUPTION` on fresh PPMd children.** On `windows-latest` the
suite intermittently aborted during
`tests/test_sevenzip_reader.py::test_py7zr_codec_fixtures_roundtrip` with
`Windows fatal exception: code 0xc0000374`. Re-runs of identical commits often passed.
Early reports named Windows/py3.14; isolation pinned the same abort on Windows/py3.11
(`pyppmd==1.3.1` win_amd64), and py3.14 could pass on the commit where py3.11 failed.
Per-label subprocess isolation and a dedicated stress run produced:

| Field | Value |
|-------|--------|
| Label / filters | `ppmd` / `("PPMD",)` |
| Exit | `0xC0000374` (`STATUS_HEAP_CORRUPTION`) |
| Library | `pyppmd` 1.3.1 |
| First pin phase | `read_member:nested/beta.bin:start` (after `alpha.txt` OK) |
| Stress pin (50×) | 2/50 on py3.11 at `read_member:alpha.txt:start`; 0/50 on py3.14 that run |
| Stack | `_open_member` → `skip_forward` / decode → `pyppmd` |

Fresh PPMd-only subprocesses were enough; prior pytest cases were not required. The
fixture was a py7zr-built solid PPMd archive of plain members (`b"alpha\n" * 100`,
`bytes(range(64)) * 16`).

**Linux: SIGSEGV or `malloc(): invalid size` after other-codec warmup.** Stress on Linux
reproduced a flaky native abort when other 7z codecs ran in the same process before PPMd
(the `warmup_codecs` scenario):

| Observation | Detail |
|-------------|--------|
| Rate | about 10/30 children in one local soak; also seen on a single first run |
| Signals | `SIGSEGV` (−11) and `SIGABRT` (−6) with `malloc(): invalid size (unsorted)` |
| Typical phase | PPMd read after LZMA2/Deflate/Bzip2 warmup (`read_member:…:start` or stream open) |
| `fresh_baseline` alone | 0/20 crashes in the same soak |
| Raw `pyppmd` encode/decode alone | 0/40 subprocesses |
| Raw archivey `PpmdDecompressorStream` alone | clean in short soaks |
| Warmup without PPMd (LZMA2/Deflate/Bzip2 only) | 0/30 crashes |
| Same warmup, then PPMd | 10/30 crashes |

So the Linux abort is PPMd-related: the warmup alone does not fire it. The warmup only
shifts allocator layout; the crash reproduces with no archivey imports (§D).

### K.2 Version matrix and the `pyppmd>=1.3.1` floor

The same Linux `warmup_codecs` stress, with archivey's PPMd adapter forced back to
unbounded `max_length=-1`, across published versions, 40 children each:

| pyppmd | native crashes | other failures | passes |
|--------|----------------|----------------|--------|
| 1.1.1 | 0/40 | 27 (CRC mismatch on solid 2nd member) | 13 |
| 1.2.0 | 0/40 | 27 (same CRC pattern) | 13 |
| 1.3.1 | 12/40 (`SIGSEGV`/`SIGABRT`) | 0 | 28 |

`pyppmd==1.3.0` had no installable artifact on the test platform; 1.3.1 (2025-11-27) is
the first 1.3.x wheel that ran. The abort reproduces on 1.3.1 and not on 1.1.1 or 1.2.0
under the same unbounded path, which matches the `#126` regression window (§C). Older
versions return wrong bytes instead: their worker stopped at input-empty, which prevented
the runaway but cut symbols short at chunk boundaries (§G). With decodes bounded by
`unpack_size`, the same soak was 0/80 on 1.3.1.

The `[recommended]` extra requires `pyppmd>=1.3.1` (the comment in `pyproject.toml`
points here). Older is worse on every axis: 1.1.x and 1.2.0 silently return wrong bytes
on chunked bounded decodes, `py7zr` 1.1 and later hard-require `pyppmd>=1.3.1` (a conflict
with the test oracle and any 7z-writing extra), and 1.3.1 is the first line with CPython
3.14 wheels. With the floor raised, the 1.1.x premature-eof recovery pumps were removed
from `PpmdDecoder.flush`.

### K.3 Crash shapes and the exact-bound rule

`scripts/pyppmd_crash_repro.py` depends only on `pyppmd` and the stdlib:

| mode | what | crash rate (5 cycles per child, 1.3.1) |
|------|------|------|
| `extra-null` | sized to eof, then `decode(b"\0", -1)` | about 40% (up to 30/30 seen) |
| `overshoot` | `decode(packed, -1)` only | 15 to 25% (19/30 seen) |
| `sized-safe` / `pre-eof-null` / `skip-after-eof` | controls | 0% |
| `underfed-sized` / `hostile-tail` | adversarial-shape controls (truncation, garbage tail) | 0% |

```bash
pip install 'pyppmd==1.3.1'
python scripts/pyppmd_crash_repro.py 30 --mode extra-null
python scripts/pyppmd_crash_repro.py 30 --mode overshoot
python scripts/pyppmd_crash_repro.py 30 --mode sized-safe
uv run --no-sync python scripts/ppmd_native_stress.py 30 --scenarios warmup_codecs
uv run --no-sync pytest -m ppmd_native_stress -k warmup --timeout=600 -o addopts=
```

"Bounded" is not enough; the bound must be exact. A/B soaks of the `oversized` mode: a
sized request 65 536 bytes over the true remaining output crashed 13/20 and 10/20 in two
soaks; 64 or 4096 bytes over, 0/20 each; large multi-chunk members with the exact bound,
0/20.

Those soaks free the decoder without a quiesce. A sized over-request leaves the worker
waiting for input once it runs past what the range coder's tail lookahead can satisfy
(+64 and +4096 over did not, +65536 over did), and freeing the decoder in that state is
the §D teardown use-after-free. Re-measured on 2026-10-20 (pyppmd 1.3.1, CPython
3.11.17): the same bare `oversized` shape with a single-symbol NUL before the free
crashed 0/40 across payload kinds, and 8/20 without it. Through archivey, crafted 7z and
ZIP members whose header overstates `unpack_size` by 64 KiB, 1 MiB or 15 MiB (header CRCs
valid, so the decoder is reached) gave 0 crashes in 860 fresh children and 0 valgrind
errors on 12 shapes. On those members the worker blocked on input a few hundred to a few
thousand symbols past the true end. What remains is in K.4.

Hence the decoder contract: unsized PPMd7 is refused at construction (no end mark,
no declared size, so no safe request size; the 7z header always gives the folder size),
and unsized PPMd8 decodes in bounded 64 KiB requests in a drain loop, never `-1`, since its
end mark stops the worker on valid data. The adversarial shapes a damaged archive can
force (truncation, early close mid-member, an inflated declared size with a garbage tail)
are pinned in `tests/test_ppmd_raw_streams.py` and as soak modes in the repro script, all
0-crash on 1.3.1 with bounding in place.

### K.4 Random input: decode after an early end

Random bytes, which is what a wrong 7z AES key hands the PPMd coder and what a hostile
archive can hand it directly, crash pyppmd by a second route. A PPMd7 stream whose first
byte is not 0 fails the range decoder's init, and pyppmd returns `NULL` without setting an
exception (`SystemError`, mapped to `CorruptionError`; it also leaks a buffer export per
call). The crash is the other 1 in 256: with a zero first byte the model decodes garbage
until it returns its end result after a few hundred symbols, pyppmd raises `eof` and
returns short, and the caller feeds it the rest of the member. The next `decode` starts a
new worker thread on a finished model, and within one or two calls the process segfaults
in `Ppmd7_DecodeSymbol` (gdb: `ThreadDecoder.c:124`). Deterministic: 64 KiB feeds of
`random.Random(3011).randbytes(256 * 1024)` with a 512 KiB request crash on the third call.
PPMd8 (ZIP method 98) crashes the same way, and pyppmd 1.2.0 crashes too, so no version pin
avoids it.

A caller cannot just stop at "short and `eof`". pyppmd also raises `eof` when the range
coder's `Code` is 0 and never clears it, and that happens on valid streams: at a feed
boundary inside a run of zero bytes in the compressed data (a 7z of a file with 2 MB of
zeros raised it on half its 64-byte feed boundaries), and one byte before the end of most
7-Zip-written streams. `needs_input` reads the same in both cases. A first fix that stopped
there broke those valid files.

The shipped fix hands pyppmd the whole member in its first `decode`, so any short return
is the end; members past `DecoderLimits.max_ppmd_in_process_input` (16 MiB) decode in a
child process. Before it, 10 of 10 hostile runs crashed; after it, 0 crashes in 1200
hostile members across both paths, and 111 valid 7-Zip-written members byte-exact on both
paths (`tests/test_ppmd_crash_isolation.py`).

The teardown NUL is the one call archivey still makes after a short return at `eof`
(measured 2026-10-20). On a spent payload (K.5) `_quiesce_worker` still sends
`decode(b"\0", 1)`, up to `_PPMD_QUIESCE_MAX_CALLS` times, because pyppmd's flags do not
say whether the worker waits for input (where the NUL is needed) or the model has ended
(where the NUL is a decode after the end). A spy on archivey's native calls saw that NUL
sent at `eof` on 183 of 200 hostile 7z members and on 20 of 20 overstated text members,
up to four calls each. In isolation it measured clean, 100/100 children with 20 members
each:

```bash
python scripts/pyppmd_crash_repro.py 100 --mode spent-quiesce-nul --cycles 20
```

The same NULs sent after a `decode` that raised `ValueError` do crash: 59/100 children
for PPMd8 and 5/100 for PPMd7.

```bash
python scripts/pyppmd_crash_repro.py 100 --mode nul-after-error --cycles 20
PPMD_REPRO_VARIANT=7 python scripts/pyppmd_crash_repro.py 100 --mode nul-after-error --cycles 20
```

archivey does not make that call. After the error pyppmd reports `eof=True` and
`needs_input=False`, so `_quiesce_worker` returns before decoding (a non-forwarding spy:
370 errored 7z and ZIP members, 0 calls after the error). No crash is confirmed on the
in-process path; the teardown NUL at `eof` stays a candidate because it is a decode after
the model's end. Candidate fixes are tracked internally.

The same spent-payload state reached password iteration. 7z AES has no password check
value, so confirmation decodes the folder, and on some wrong keys the garbage stops PPMd
short of the declared size at native `eof` with the whole pack fed; the next empty drain
raised `MemoryError`, which is not an `ArchiveyError`, so the candidate loop died before
the right password. On the 194-byte fixture now pinned in
`test_aes_ppmd_wrong_key_moves_on_to_the_next_password`, a sweep of `wrong0`..`wrong2999`
over the old code gave `EncryptionError` 2998 times and `MemoryError` twice (`wrong856`,
`wrong2552`). The spent-payload stop below removed it.

### K.5 Exit-after-green: the in-process mitigations

Lab notes and the pre-mitigation symptom are in
[`ppmd-exit-after-green-exploration.md`](ppmd-exit-after-green-exploration.md); the root
cause is §D and the quiesce measurement §I. What `PpmdDecoder`
(`src/archivey/internal/streams/decompress.py`) does:

- Caps extra-NUL recovery output at `_PPMD_EXTRA_NUL_MAX_OUTPUT` (64) in `flush` and in
  empty-`feed` NUL injection, with at most one synthetic NUL. The uncapped shape,
  `decode(b"\0", remaining)` on a truncated mid-stream member, crashed 85/100 bare-pyppmd
  children; capped at 64, 0/100. Happy-path tests alone: 0/40.
- Runs post-eof empty drains only when `fed_compressed >= pack_size` and a container
  `unpack_size` bounds them. Unknown or short `pack_size` and unsized decodes get the one
  capped NUL only.
- Requires `pack_size` for PPMd7. Without it a premature native `eof` is
  indistinguishable from truncation, and draining to finish the tail raised `MemoryError`
  on 1.3.x in 36/36 cuts at 50 to 99% of the pack, so the decoder would have to choose
  between truncating a valid member and a crash.
- Plumbs `pack_size` through the 7z pipeline. A standalone PPMd folder reads it from the
  sized pack slice; an encrypted one is fed from an AES stream of unknown length, so
  `sevenzip_pipeline.plan_folder` sets `_CodecStage.pack_size` from the preceding coder's
  output size (`test_encrypted_ppmd_chunked_reads_roundtrip`).
- Gives unsized PPMd8 no post-eof drain: its end mark ends valid decodes, and a drain with
  no `unpack_size` clamp only fabricated trailing bytes (+3 on an all-zero payload). Sized
  PPMd8 keeps the drain.
- Quiesces a parked worker before dispose (`_quiesce_worker`, from `close()` and
  `__del__`) with bounded `decode(b"\0", 1)` until it exits on budget, so `Ppmd7T_Free`
  becomes a no-op. `scripts/ppmd_uaf_valgrind.py` reports 0 memcheck errors on the archivey
  scenarios and still reports the UAF on the bare-pyppmd overshoot reproducer.
- Stops at a spent payload (`_note_decoded`): a sized `decode` that returns short, at
  native `eof`, with every compressed byte fed, ends decoding, and `flush` reports
  `TruncatedError`. Another `decode` would resume a worker parked on empty input, which
  reads past the input buffer and surfaces as a bare `MemoryError`. Reached from a 7z
  folder that overstates `unpack_size` and from a wrong AES key (K.4). `_quiesce_worker`
  still sends its NUL in that state: without it valgrind shows the Free-time invalid
  write, and a later decoder in the same process starts from corrupted state.
- Caps each request at a C `int` (`_PPMD_MAX_REQUEST`): pyppmd parses `length` as one,
  and a larger value raised `OverflowError` reading a member over 2 GiB.

| Soak | Overshoot (large NUL) | Free-race residual |
|------|----------------------|--------------------|
| Bare half-pack + NUL(rem) | about 85/100 → 0/100 with cap 64 | n/a |
| Adversarial tests in subprocess | Contained | Child may still SIGSEGV after `ok` |
| Parent `test_ppmd_raw_streams` session | Soft-pass via `--allow-exit-after-green` | Intermittent exit-after-green possible |
| `ppmd_uaf_valgrind.py` (deterministic) | archivey scenarios 0 errors | quiesce-on-close: 0 errors with the fix; bare overshoot still reproduces |

### K.6 CI coverage

In the required matrix, the 7z PPMd roundtrip runs on every platform with decodes bounded
by the folder unpack size; other Windows codec labels keep per-label subprocess isolation;
default pytest runs `-m 'not ppmd_native_stress'`; `tests/test_ppmd_raw_streams.py` covers
raw PPMd with no 7z container. In-process PPMd7 create/destroy loops and
`test_encrypted_ppmd_chunked_reads_roundtrip` stay skipped on Windows, where the stress
workflow covers them.

The non-blocking **PPMd native stress** workflow
(`.github/workflows/ppmd-native-stress.yml`) runs weekly and on a PR that touches the PPMd
code, its tests or its scripts (the `paths:` list in the workflow), on
`windows-latest` and `ubuntu-latest` × Python 3.11 and 3.14: `scripts/ppmd_native_stress.py`
plus `pytest -m ppmd_native_stress`, a `--repeat 20` soak of `tests/test_ppmd_raw_streams.py`
through `scripts/ci_run_native_modules.py` that hard-fails on an exit-after-green abort,
and on Linux the valgrind gate `scripts/ppmd_uaf_valgrind.py`. It exits non-zero when any
child crashes and must not become a required check. Default scenarios go from the minimal
surface up:

| Scenario | Surface | Notes |
|----------|---------|--------|
| `raw_pyppmd7` / `raw_pyppmd8` | bare `pyppmd` only | No archivey, no 7z |
| `raw_archivey_ppmd7` / `raw_archivey_ppmd8` | `PpmdDecompressorStream` / `open_codec_stream` | No 7z container |
| `fresh_baseline` | py7zr PPMd 7z + archivey read | The original CI fixture |
| `warmup_codecs` | LZMA2→Deflate→Bzip2 then PPMd | The Linux repro (K.1) |
| `same_process` / `fresh_varied` | optional | Reuse and payload-shape axes |

```bash
uv sync --group dev --extra all
uv run --no-sync python scripts/ppmd_native_stress.py
uv run --no-sync python scripts/ppmd_native_stress.py --scenarios raw_pyppmd7 raw_archivey_ppmd7
ARCHIVEY_PPMD_STRESS_ITERS=30 uv run --no-sync python scripts/ppmd_native_stress.py --scenarios warmup_codecs
```
