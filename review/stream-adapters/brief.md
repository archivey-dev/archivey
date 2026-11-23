# Stream adapter architecture review

[PR #1728](https://github.com/archivey-dev/archivey/pull/1728) made pipe mode
explicit. Its review exposed a recurring problem. Several wrappers assemble the same
read operation from two helpers, and source constructors repeat how to prepare a pipe.
Put source policy in `ArchiveSource`. Give wrappers one shared operation for each
common read contract.

This assessment uses the implementation merged in `272e584c`. The proposed changes
are internal refactors that preserve the public read, error, and ownership contracts.

## What ArchiveSource would gain

**One place to prepare a stream for pipe mode.** The caller-stream branch in
`resolve_source` and the fsspec decompressor constructor each check seekability,
create a `PipeView`, and record that the original stream could seek. The order
matters. Measuring a seekable stream first can seek to EOF or decode ahead to learn
its size. The constructor should enforce the order for every caller.

One possible shape is an internal `ArchiveSource.for_stream(stream, *, pipe=False)`
entry point. With pipe mode enabled, it would choose the forward-only view before
collecting size or seek-cost information. It would keep the name hint and the state
that selects the retry advice. The fsspec decompressor constructor could call it and
then attach the handles it owns and the remote origin. Source resolution would still
select paths, streams, and volume sets. [Source resolution](../../src/archivey/internal/volumes.py)
· [Source constructors](../../src/archivey/internal/source.py)

Keep the path and range-backed conversions inside `ArchiveSource` too. They can
continue to use `read_as_pipe`, which keeps remote change detection and per-request
progress attached. A known size can still appear in progress reports without
becoming a size that bounds pipe reads. Closing an owned view must close its source.
Closing a borrowed view must leave the caller's object open.

**A smaller private view.** `ReadOnlyIOStream` already fills buffers through the
subclass's `read()`. `PipeView` also supplies a native `readinto()` fast path.
During review, an instrumented override saw zero calls in four public opens:
ZIP from `BytesIO` and TAR.GZ from `BytesIO`, a path, and fsspec. A direct buffer
fill via the inherited implementation returned the expected bytes and left the
borrowed stream open. Remove the override unless a measured use needs it. The view
then needs to forward reads, expose the name hint, and implement its close policy.
[Read-only base](../../src/archivey/internal/streams/streamtools/base.py)
· [Pipe view](../../src/archivey/internal/source.py)

**Keep the input-specific fill policy at the boundary.** `ArchiveSource.readinto()`
knows the remaining length, the replay prefix, the source position, and the progress
reporter. It also knows when a caller's zero-byte fill needs a follow-up read and when
to avoid the PyPy `readinto()` path. These checks belong with the source. The generic
byte operations can support them without taking on source state.
[Source fill policy](../../src/archivey/internal/source.py)

## What to share in streamtools

### Native buffer fill with a read fallback

Add an internal operation such as `readinto_or_read(stream, buffer)`. It should use
`try_readinto()` and fall back to `readinto_via_read()` when native fill is missing or
unsupported. A valid zero result stays zero. A native or fallback read that stalls
raises `BlockingIOError`. A legal short fill remains short. The existing precondition
still applies. A stream that refuses native fill must do so before consuming bytes.
[Read primitives](../../src/archivey/internal/streams/streamtools/binaryio.py)

Start with `LockedStream`. The helper would run while its lock is held and read
directly from its inner stream on fallback. Calling the wrapper's `read()` there can
reacquire a non-reentrant lock. Keep the lower-level probe for callers that need
different fallback receivers or accounting. The counting wrappers and 7z size guard
fall back through their own `read()`, which already counts or checks the bytes.
Review those paths before moving any accounting into a common step.
[Locked stream](../../src/archivey/internal/streams/streamtools/locked.py)
· [Counting wrappers](../../src/archivey/internal/streams/counting.py)
· [7z size guard](../../src/archivey/internal/backends/sevenzip_pipeline.py)

### Gather up to a requested size

The plugin adapter and makeself each implement `_read_up_to()`. The shared
`streamtools.read_exact()` already gathers short reads until it has enough bytes or
reaches EOF. Give it a name or guide entry that makes the short-at-EOF contract
visible. `ReaderSource.read_exact()` has a stronger contract and raises
`TruncatedError` on short input. Keep the distinction visible to parser authors.
[Plugin adapter](../../src/archivey/internal/format_adapter.py)
· [Makeself](../../src/archivey/internal/backends/makeself_reader.py)
· [Parser source contract](../../src/archivey/formats.py)

Use the shared gatherer for equivalent bounded reads, with the wrapper that owns
accounting as the receiver. `_GatheringReader` also repeats the positive-size path.
Benchmark sharing that path before changing it. Preserve its bounded requests when
draining to EOF and the common fast path that returns a full first chunk without
copying. The gatherer remains useful above `ArchiveSource` because a decoder or a
plugin can return short reads of its own.
[Gather implementation](../../src/archivey/internal/streams/streamtools/binaryio.py)
· [Source gatherer](../../src/archivey/internal/source.py)

### Discard a known byte count

TAR and the plugin adapter each implement a bounded read-and-discard loop.
`skip_forward()` already reports each chunk as it arrives. Use that contract where
it matches, so callers can preserve their current position when the next read fails.
Preserve each caller's chunk size and truncation message. Let decoder exceptions
propagate. TAR can discard decoded bytes, so its offsets belong to the parser. A
drain that checks a digest or tests for surplus decoded bytes keeps those checks
with the caller.
[Shared skip](../../src/archivey/internal/streams/streamtools/solid.py)
· [TAR discard](../../src/archivey/internal/backends/tar_parser.py)
· [Plugin skip](../../src/archivey/internal/format_adapter.py)

## How contributors find the right operation

The package root tells contributors to import there. It exports `readinto_via_read`
while two central read primitives, `read_blocking` and `try_readinto`, live only in
`binaryio.py`. Put the usual operations at that import boundary. Keep the probe
available for specialist callers. Add a short chooser to the stream guide.

| Need | Operation |
| --- | --- |
| One read, with a stall reported as an error | `read_blocking()` |
| Wait for some bytes, then return without gathering to N | `read_arrived()` |
| Up to N bytes, gathering short reads until EOF | Shared gather operation |
| Exactly N bytes, with an archive truncation error on EOF | Parser source's `read_exact()` |
| Fill an existing buffer with a native fast path and a read fallback | `readinto_or_read()` |
| Discard N bytes in bounded requests | `skip_forward()` |

Keep `ReadOnlyIOStream` as the base for wrappers with a custom `read()`.
`DelegatingStream` can keep its owning, seek-forwarding contract. Adding borrowing
and forward-only flags there would spread source policy into a base used by readers,
decoders, and measurement wrappers.
[Package entry point](../../src/archivey/internal/streams/streamtools/__init__.py)
· [Stream guide](../../dev-docs/guide/06-streams-and-codecs.md)
· [Ownership rules](../../dev-docs/topics/stream-ownership.md)

## Suggested implementation order

1. Move pre-measurement pipe preparation behind the source constructor. Remove the
   redundant view override after checking local, borrowed, and remote input paths.
2. Add the shared buffer-fill operation and use it in the simple forwarding callers.
   Cover unavailable native fill, zero, short fills, stalls, and lock scope.
3. Migrate the matching gather and discard loops. Measure small reads and large
   reads before changing the hot source path. Check that a partial skip preserves
   position and propagates the decoder's original error.
4. Publish the chooser with the shared operations so contributors can find it while
   writing a new wrapper.
