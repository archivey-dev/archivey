# Design — full-count reads for non-seekable sources

## Context

`ensure_full_count_reads` (`streamtools/binaryio.py`) is the one boundary every archive
source crosses. Its job is narrow: turn the `io.RawIOBase` *up-to-n* `read(n)` contract
into a full-count one, so a header parser that pulls a fixed-size structure with a single
`read(n)` cannot mistake a legal short return for EOF. That failure mode is not
hypothetical — it is what reported healthy archives as corrupt and produced the archived
`short-read-source-contract` change.

The function opts out for non-seekable sources. The opt-out predates the measurement work,
and its stated justification was wrong in every revision of the docstring up to and
including `main` at `0f691dc`: it claimed that buffering a non-seekable source would make
it look seekable.

That much is already corrected. #329 (Parcel C, merged as `0ed80b7`) rewrote the
docstring to name the real obstacle — `BufferedReader` reads *ahead*, and from a pipe that
over-read is unrecoverable — to record both corrections explicitly, to inventory the three
downstream layers the guarantee currently leans on, and to point at this change by name.
So this change inherits an accurate problem statement and owes the tree the *fix*, not the
diagnosis. See §Decisions.

## Decisions

### D1 — A wrapper, not an error

Refusing a short-returning non-seekable source is not available: specs require
non-seekable streaming. `format-single-file-compressors` §Requires seek says every
supported single-file codec "SHALL stream from non-seekable sources", and
`testing-contract`'s non-seekable matrix requires `.tar.gz` through a non-seekable double
to iterate and read (the spec calls it `FakeNonSeekable`; the class in `tests/` is
`NonSeekableBytesIO` — see the `testing-contract` delta, which retires the stale name). A source cannot be refused for exercising a contract `io.RawIOBase`
explicitly permits and the specs explicitly require.

### D2 — The wrapper needs no buffer, and that is the whole point

"Returns the full count" and "consumes no more than asked" look like they trade off.
They only do so for `io.BufferedReader`, which reads *ahead*: ask it for 20 bytes and it
pulls 8 KiB from the raw. On a seekable source that over-read is recoverable; on a pipe
it is not, and a `_NonClosingBufferedReader` that later detaches strands whatever it
pulled.

Gathering the count without read-ahead is already implemented in this module as
`read_exact`: each pass asks for exactly `n - len(gathered)`, so the total consumed is
exactly `n` (or everything up to EOF). The wrapper is that function behind a stream:

```python
class FullCountStream(ReadOnlyIOStream):
    """Make a short-returning inner full-count without reading ahead."""
    def read(self, n: int = -1, /) -> bytes:
        if n < 0:
            out = bytearray()
            while chunk := self._inner.read(-1):  # loop: do not trust readall()
                out.extend(chunk)
            return bytes(out)
        data = self._inner.read(n)
        if len(data) == n:
            return data                          # the common case: no copy
        return data + read_exact(self._inner, n - len(data))
```

Two details in that sketch are deliberate, and both were review findings.

`read_exact` allocates a `bytearray`, `extend`s it and returns `bytes(data)`, so it copies
every byte twice even when the first `read` satisfies the ask. At this boundary that is
every byte of every member on the non-seekable path, not just headers — so the full-count
call keeps a single-read fast path and only falls back to `read_exact` for the bytes still
missing. The fallback is what makes it *exact*; the fast path is what makes it free when
the source is well-behaved.

`read(-1)` loops anyway, even though it looks like it need not. `io.RawIOBase.read(-1)`
dispatches to `readall()`, which is defined to drain to EOF, so an inner that does not
override `read` has no legal short form there — which is why `ShortReadBytesIO` carves
`read(-1)` out of its cap (`streams_util.py`: *"read(-1) means everything up to EOF; it has
no legal short form"*). But an inner that *does* override `read` can return short on `-1`,
and "the inner will behave" is the exact assumption this change exists to delete. Trusting
`readall()` here would be the same shape of luck as trusting `tarfile._Stream`, one layer
down. The loop costs one extra `read` returning `b""` on a well-behaved source.

Zero buffered bytes, nothing to strand on close, `seekable()` inherited `False` from
`ReadOnlyIOStream`.

`ensure_full_count_reads` returns a `FullCountStream` unchanged, making the whole function
idempotent (the seekable branch already was — see D5). Callers can therefore apply it
defensively without checking, which is what lets `PeekableStream` own its own precondition.

**Maintainer decision (davitf, #330 review session, [packet 3](https://github.com/archivey-dev/archivey/pull/330#pullrequestreview-5184461333)):
the zero-read-ahead promise is boundary-only, and `DecompressorStream`'s buffering of a pipe
is accepted.** Stated as an absolute, "no `BufferedReader` on a non-seekable source" is a rule
the tree already breaks: `decompressor_stream.py:269` puts a `_NonClosingBufferedReader` on a
non-seekable source on every compressed streaming open, and `tar_reader.py:333` does the same
one layer up. Measured: a `read(20)` through that stack takes 8192 bytes from the raw, against
exactly 20 through the boundary alone.

The distinction that actually holds is **ownership**:

- Read-ahead is **safe** where one layer consumes the source to EOF and nobody else will
  read it. The decompressor owns its input to the end, so the bytes in its buffer are bytes
  it was going to read anyway; stranding them on close costs nothing because there is no
  later reader to strand them from.
- Read-ahead is **unsafe** at a boundary that hands the source *between* layers — detection
  to backend, or one wrapper to the next. `ensure_full_count_reads` is that boundary by
  definition, and `_NonClosingBufferedReader.detach()` on close is what makes an over-read
  there unrecoverable.

So D2's rejection of `BufferedReader` stands for this function and does not indict
`DecompressorStream`. Writing the reason down is the point: without it, the next reader finds
D2 and `decompressor_stream.py:269` contradicting each other, has to guess which is wrong, and
"a `BufferedReader` is fine on pipes, we already do it" is the available wrong answer — the
same shape of mistake that kept this function's docstring wrong through three revisions. This reframes the seekable branch too: `BufferedReader` is correct
there *because* read-ahead is recoverable by seeking and because it collapses the
parsers' tiny reads (the archived measurement: a 1000-member RAR listing went from 2007
reads to 7). Neither benefit applies to a pipe; neither is needed there.

### D3 — `read_exact`, not a single forwarded `read`

`slice.py` documents two gather policies (ADR 0014) and the difference is what a short
return *means*. At the source boundary the inner is a raw byte source, not a decoder with
a deferred truncation error to preserve, so a short means "ask again" — `read_exact`.
That matches what `BufferedReader` gives the seekable branch, which keeps the two halves
of `ensure_full_count_reads` behaviourally identical. Forwarding a single `inner.read(n)`
— what every *other* bounded read in the stream layer does, because those inners are
already fill-or-EOF — would stop on the first short and reintroduce the exact bug this
boundary exists to prevent.

This is the one place in the library that gathers at a public `read(n)`, and the reason is
that it is the only one whose inner is not full-count already. (Originally written against
`read_full_count`; that helper turned out to be a single `stream.read(n)` behind a loop
that could not iterate, and was removed — the policy contrast above is unchanged, only
the name of the thing being contrasted.)

### D4 — This is not the buffering ADR 0010 forbids

ADR 0010 (`no-silent-buffer-nonseekable`) and `testing-contract`'s "MUST never implicitly
buffer the non-seekable source **to make it seekable**" are one rule about two things:
don't fake seekability, and don't materialize a pipe into memory or a temp file. ADR
0010's Context is explicit — *"buffers a pipe into memory or a temp file to 'make ZIP
work'"*.

`FullCountStream` holds zero bytes, reports `seekable()` as `False`, and changes nothing
about random access: `streaming=False` over a non-seekable source still fails fast at
open. Conflating "don't buffer a non-seekable source" with "don't fix short reads on a
non-seekable source" is the error that kept producing wrong docstrings; the two are
independent and only one is a rule.

### D5 — What this does and does not simplify in `PeekableStream`

`PeekableStream` does two jobs: pushback for `peek` (detection needs it — the peeked
prefix is replayed to the backend), and full-count gathering in `_fill_to`. Only the
second is redundant once the inner is full-count:

```python
# before: loops because the underlying stream may return short
while len(self._buffer) < n:
    chunk = self._underlying.read(n - len(self._buffer))
    if not chunk: break
    self._buffer.extend(chunk)
```

Over a full-count inner that is one `read`. Roughly four lines. The class is **not**
deletable and the wrapper is not a replacement for it — this is about one class owning
the guarantee instead of three mechanisms covering three paths.

Composition order is `PeekableStream(FullCountStream(raw))`: the peek buffer sits above
the guarantee, so replayed prefix bytes and pass-through reads are both full-count.

**Maintainer decision (davitf, #330 review session, [packet 1](https://github.com/archivey-dev/archivey/pull/330#pullrequestreview-5184461333)):
`PeekableStream.__init__` calls `ensure_full_count_reads` on its own inner, and
`ensure_full_count_reads` is made idempotent so no caller has to check.** Collapsing
`_fill_to` turns "my inner is full-count" from an observation into a precondition, and it
was not satisfied everywhere: `core.py:592` (`open_stream`, non-seekable) hands
`PeekableStream` the raw caller stream, and `open_stream` never calls `resolve_source`.
Measured on `main` with `_fill_to` collapsed to a single `read` over a `max_chunk=1`
non-seekable source — gzip, bzip2 and xz all raise `FormatDetectionError` on the detected
path, while the explicit-`format=` path is rescued by `ensure_bufferedio` inside
`DecompressorStream`. A healthy archive from a pipe, reported as undetectable, by the change
meant to close that class of bug.

The class that needs the guarantee asks for it, so no construction site can get it wrong —
including the ~20 in `tests/` that build `PeekableStream` directly over a bare double. The
idempotence is what makes this free rather than a double wrap:

- `ensure_full_count_reads(FullCountStream(...))` returns it unchanged, so the
  `open_archive` site — already downstream of `resolve_source` — gains nothing to unwind.
- The seekable branch is **already** idempotent: `ensure_bufferedio` opens with
  `if isinstance(obj, io.BufferedIOBase): return obj`. Adding the `FullCountStream`
  short-circuit makes the whole function idempotent, which is worth stating as a property
  rather than leaving as two coincidences.

**`core.py` therefore needs no edit**, which is the substantive reason to prefer this over
fixing `core.py:592` alone: the fix lives where the requirement lives, and the next
`PeekableStream(...)` call site inherits it instead of re-opening the bug.

This is **not** the fourth rejected alternative below. That one routes every non-seekable
source *through* `PeekableStream` at the boundary, paying a pushback buffer on paths that
never peek and moving the guarantee up into `streams/`. Here the guarantee stays in
`streamtools`; `PeekableStream` merely calls the boundary function on the way in.

### D8 — The wrapper stays transparent to the metadata probes

**Maintainer decision (davitf, #330 review session, [packet 2](https://github.com/archivey-dev/archivey/pull/330#pullrequestreview-5184461333)):
forward the metadata on the wrapper.** `FullCountStream` sits at the one boundary every
source crosses, so an opaque wrapper blinds the duck-typed probes. Measured with the D2
sketch over a stream carrying `name` and `size`:

```
raw source                     : source_name='/tmp/pipe-ish.tar'  source_byte_size=4096
FullCountStream, unforwarded   : source_name=None                 source_byte_size=None
PeekableStream(FullCountStream): PeekableStream.name -> AttributeError
```

The third line is D5's doing: `PeekableStream.name` resolves through
`source_name(self._underlying)`, so wrapping its inner propagates the opacity onto the
detection path as well. Consequences traced: `ResolvedSource.archive_name` becomes `None`
for every non-seekable stream source (`volumes.py` `_resolve_single`, feeding error messages
and diagnostics), and `source_byte_size` returns `None` into `base_reader.py`
`compressed_source_size` — a **public** cost signal — and into the ratio guard, which then
installs a `CountingReader` instead. Correctness survives; honest cost signals is a VISION
claim, and it does not.

**A non-seekable source does carry a name — that is the ordinary case, not a corner one.**
The obvious objection to forwarding metadata is that pipes have no metadata to forward. A
real FIFO says otherwise, and it is how a caller would most plainly hand archivey a
non-seekable source:

```
open("/tmp/myfifo.tar", "rb")  ->  BufferedReader
  is_seekable()      False          <- takes the non-seekable branch
  .name              '/tmp/myfifo.tar'
  source_name()      '/tmp/myfifo.tar'
```

**And the seekable branch already preserves it.** `io.BufferedReader.name` forwards to
`raw.name` at C level, so `ensure_full_count_reads`' seekable half keeps the name for free
(measured: `source_name` through a `_NonClosingBufferedReader` returns the path). An opaque
`FullCountStream` would therefore make the two halves of one function disagree about the same
source — the exact asymmetry `_under_buffer` was written to remove for `size`. Forwarding
`name` is what keeps the branches consistent; it is not a new courtesy.

Two mechanisms, because neither covers the other:

- **`name`: forward via `source_name`.** Peeling does not reach it — `source_name` has no
  `peel_for_source_size` path — and this is the shape both siblings in the package already
  use (`BinaryIOWrapper.name` and `PeekableStream.name` both resolve through `source_name`
  and re-raise `AttributeError` when the inner has no name, which keeps `hasattr` false per
  `ReadOnlyIOStream.name`). This is the half that pays for itself.
- **`size` / `try_get_size`: set `peel_for_source_size = True`.** One line, and the existing
  opt-in for "a pass-through wrapper whose cheap size *is* the inner's" — documented on
  `DelegatingStream`, set by `CountingReader`, and read by `source_byte_size` via `getattr`,
  so a `ReadOnlyIOStream` subclass can opt in too. `FullCountStream` is exactly that: it
  changes *when* bytes arrive, never how many exist.

  Its motivation is narrower than `name`'s, and worth stating so nobody over-reads the
  scenario row. A FIFO reports `None` either way — `source_byte_size`'s metadata probe
  requires an `io.FileIO` over a *regular* file and runs only on a seekable source. The case
  that benefits is a source carrying an explicit integer `size`, the fsspec convention that
  probe 2 documents: an object-store or HTTP body opened non-seekably with a known length.
- **`fileno` is deliberately *not* forwarded.** The reviewer's packet listed it; nothing reads
  it on a non-seekable source. The only two `fileno()` calls in `src/` are a seekable path
  handle in `detection_workspace.py` and `source_byte_size`'s metadata probe, which is
  seekable-gated *and* requires `io.FileIO` over a regular file. Neither sibling wrapper
  forwards it either. Adding it would be speculative surface on the boundary class.

Verified together: `source_byte_size` 4096, `source_name` and `PeekableStream.name` both
`/tmp/pipe-ish.tar`, `seekable()` still `False`, and `tell()` still raising
`io.UnsupportedOperation` — which D7 depends on for the multi-volume refusal.

**`tell()` deliberately keeps raising.** It is not metadata: answering it would claim a
position the wrapper does not track, and D7's `ConcatenatedFile` refusal is triggered by it
raising. No live break from leaving it: `ConcatenatedFile.__init__` already catches
`io.UnsupportedOperation`, and `DecompressorStream._ensure_index_built`'s `tell()` calls sit
behind `self._inner.seekable()`.

**Out of scope, noted so it is not chased.** `source_byte_size(PeekableStream(...))` is
`None` both before and after this change — `PeekableStream` sets no `peel_for_source_size`
and exposes no `size`. That is pre-existing and independent of this wrapper.

### D6 — Cost

One extra Python-level call per read on the non-seekable path, where nothing stood before.
For a well-behaved source the fast path returns the inner's own `bytes` object with no
gather loop entered and no copy made; only a genuinely short source pays the `read_exact`
fallback, and it pays one copy of the short prefix, not of the whole read.
Nothing on the seekable path changes, so the `VISION.md` budget paths (path and seekable
stream sources) are untouched.

## Rejected alternatives

| Alternative | Why not |
| --- | --- |
| Raise `UnsupportedFeatureError` for short-returning non-seekable sources | Contradicts specs that require non-seekable streaming (D1); also undetectable at wrap time — shortness is only observable mid-read |
| Wrap non-seekable sources in `BufferedReader` too | Unrecoverable over-consumption at a boundary that hands the source between layers, and `_NonClosingBufferedReader.close()` detaches, stranding the read-ahead. Not a blanket ban on buffering a pipe — `DecompressorStream` does that deliberately and safely, because it consumes its input to EOF and owns it (D2, ownership rule) |
| Leave it and document the gap | What ships today. The guarantee then depends on `tarfile._Stream` internals for one live path, in a package documented as dependency-free and liftable |
| Fold the guarantee into `PeekableStream` and always wrap non-seekable sources in that | Ties a detection concern to a source-boundary one, puts the boundary's guarantee in `streams/` above `streamtools/`, and pays a pushback buffer on paths that never peek |

### D7 — Multi-volume: non-seekable volume items stay refused

This was filed as an open question. It is answerable from `volumes.py` today, and the
answer removes work rather than adding it.

`ConcatenatedFile.__init__` probes every item with `stream.tell()` then
`stream.seek(0, os.SEEK_END)`, catches `(OSError, AttributeError, io.UnsupportedOperation)`
and raises:

```python
raise StreamNotSeekableError("all volume streams must be seekable") from exc
```

So a non-seekable volume item never reaches a `read` — it is refused at construction, with
the same error type a non-seekable *single* source gets when it asks for random access.
`ConcatenatedFile.seekable()` returns `True` unconditionally, which is consistent: the
class only ever holds seekable items.

The refusal still fires after this change. `FullCountStream.tell()` raises
`io.UnsupportedOperation` (inherited from `ReadOnlyIOStream`, measured), and that is
already in the caught tuple — so wrapping the item changes which call raises, not whether.

The second half of the question resolves too, and is moot. `ConcatenatedFile.read`'s
`while n > 0 and self._pos < self._size` loop re-asks the current volume and breaks only on
an empty return, so it is `read_exact`-shaped in D3's taxonomy. It never matters: every
item that reaches it is seekable and has therefore already been wrapped in
`io.BufferedReader` by the per-item `ensure_full_count_reads` in `_coerce_path_or_stream`.

**Consequence for the plan.** Do not add a streaming multi-volume path in this change.
Task 4.3 asserts the refusal survives, not that a new case works.
