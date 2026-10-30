# Stream-wrapper ownership

Who calls `close()` on the stream underneath a wrapper. Not file-mode bits, not
archive member Unix uid/gid.

## 1. The rule

**A wrapper borrows unless its type says otherwise.** Silence on a view or a
decoder means "do not close the inner." Silence on a `DelegatingStream` means
"do close the inner." The keyword for the exception is `owns_inner`.

| Type | Default | Opt-in |
| --- | --- | --- |
| `SlicingStream` | borrow | `owns_inner=True` (4 production sites) |
| `SharedView` | borrow, hardcoded | none — Parcel B split this class so `lock=` could not switch modes |
| `DecompressorStream` | borrow | `owns_inner=True` on later staged BCJ filters (first-stage Copy+BCJ / BCJ-alone borrows the pack view) |
| `DelegatingStream` | **own** | none; `_SUBCLASS_CLOSES_INNER` is *who* closes, not *whether* |
| `AesDecryptStream` | borrow | `owns_inner=True` — 7z AES-CBC pull stream; default matches other transform wrappers. Production 7z borrows the pack `SharedView`. |
| `_HeaderDecryptStream` | borrow, hardcoded | none — RAR header cursor must not close the archive; ciphertext `tell`, not a member stream |
| `WinZipAesDecryptStream` | **own**, hardcoded | none — ZIP AE-x payload slice has no borrow caller; CTR+HMAC, not CBC |
| `ArchiveSource` | borrow the caller's object; own what it opened or built | none — how it was built decides: `for_path` owns its lazy handle, `for_stream` borrows (and detaches, never closes, a buffer it put in front), `for_volumes` owns the join, which borrows its caller-stream parts |
| `SharedSource` | borrow, always | none — the reader's `ArchiveSource` owns what is underneath |
| TAR `_owned_stream`, RAR `_owned_concat` | what the reader built itself | not a wrapper flag; see §4 |

The public contract is the borrow default: archivey never closes a
caller-supplied `BinaryIO` (`openspec/specs/archive-reading/spec.md`). Views and
decoders sit on those handles, so they borrow. `DelegatingStream` is a 1:1
stand-in in a close chain, so it owns.

The defaults alone do not deliver that contract: they say what each *wrapper*
does, and a caller's object that reaches a backend unwrapped is one owning wrapper
away from being closed. The source boundary (`internal/source.py`) therefore hands
every backend an `ArchiveSource`, never the caller's stream, so no keyword anywhere
above it has to be right for the contract to hold. The reader owns that source and
closes it after its own teardown (`BaseArchiveReader._maybe_teardown`); if a backend
constructor raises first, `open_archive` closes it. `open_stream` builds one too: the
`ArchiveStream` it returns closes the source when it is closed (`on_close`), and a
refusal before that point closes it on the way out.

`AesDecryptStream` is a `ReadOnlyIOStream`, so it is absent from the
`DelegatingStream` inventory and from the leak oracle's pinned population
(it holds no OS handle). `owns_inner` defaults to borrow, matching
`DecompressorStream`. Nothing in the 7z pipeline closes it on the common
`[AES, LZMA]` shape except GC: stdlib `LZMAFile` does not close a passed-in
fileobj, and `_execute_stage` forwards `owns_inner` only to `_FilterStage`
(`[AES, BCJ]`, or a Delta with no LZMA). RAR headers use `_HeaderDecryptStream` (borrow, ciphertext
`tell` as archive offset) and ZIP uses `WinZipAesDecryptStream` (hardcoded
own, CTR). Two CBC streams share `DecryptStage`; WinZip AES shares only the
availability check. What still blocks folding the RAR header stream in is
the walk's `tell()` polymorphism and an unbounded mid-file handle, not a
flag `AesDecryptStream` is missing.

## 2. Why `DelegatingStream` still owns

Flipping it to borrow was the tempting unification: then swapping
`DelegatingStream` for `SlicingStream` could not leak. The leak oracle already
catches that swap (`tests/leak_oracle.py` pins `owns_inner=True` slices and
live children). The remaining risk is the other direction.

Every production subclass is classified by the close-inventory test
(`test_delegating_stream_close_inventory`), and most ride the owning default with no
keyword. Counting wrappers (`CountingReader`, `OutputCountingStream`,
`SeekCountingStream`) are spliced mid-chain, and their inner must therefore be a wrapper
rather than the caller's own object.

That inner is never the caller's own object, because every source crosses the
boundary before any backend sees it, and what comes out is an `ArchiveSource`. Closing
it never closes the caller's stream, so the owning default has nothing of the caller's
to reach.

| Class | Close must reach |
| --- | --- |
| `LockedStream` | tar `extractfile` / the stream a plugin's `open_member` returned |
| `_GzipTruncationCheckStream` | the rapidgzip accelerator |
| `OutputCountingStream` | mid-chain; inner is already a non-closing wrapper (see above) |
| `SeekCountingStream` | mid-chain; inner is already a non-closing wrapper (see above) |
| `CountingReader` | mid-chain; inner is already a non-closing wrapper (see above) |
| `_StdlibOnAcceleratorError` | the rapidgzip accelerator, or the stdlib decoder it switched to |
| `_Bzip2EmptyStreamCheck` | the rapidgzip bzip2 decoder, or the `bz2` engine it retargeted to |
| `_UnconfirmedZipCryptoStream` | the decoded ZipCrypto member and its CRC verifier |
| `UnverifiedPasswordReadWatch` | the decoded encrypted member (zip and 7z) |

The other three own too, but close themselves and tell the base to skip the second call:

| Class | Why `_SUBCLASS_CLOSES_INNER = True` |
| --- | --- |
| `ProcessOutputStream` (`_UnrarOwnedStream`, `UnarOutputStream`) | close the pipe, then reap the process, then mark closed |

The ones that ride the default would need `owns_inner=True` after a flip. A missed one
leaks a handle the oracle does not pin: default `DelegatingStream` constructors wrap
`BytesIO` by the thousand and are excluded on purpose. The oracle catching the
#336 shape is not a reason to create a new silent-miss on `LockedStream`.

A per-class opt-out (`_OWNS_INNER = False`) existed while the boundary's borrow
wrapper was a `DelegatingStream`. It went with that wrapper: `ArchiveSource` borrows by
being its own class, and a flag with no production user is one more thing the
inventory would have to explain. A future wrapper that must not close what it wraps
should likewise not be a `DelegatingStream`.

`subclass_closes_inner` is kept, not folded into `owns_inner`. Both values own;
the flag is the close *mechanism*. Eliminating it would double-close the
accelerator / unrar pipe, or force a new oracle key that is easy to forget.
`_replace_inner` honours the flag the same way: it closes the inner it swaps out
unless the subclass closes that one itself. Such a subclass captures `self._inner`
before the call, because `_replace_inner` does not return the old inner.

## 3. What is left of mandatory-explicit keywords

Not much. The unusual direction is already spelled at the call site
(`owns_inner=True` on the four owning slices; later staged BCJ filters derive
`owns_inner=(stage_index > 0)` in `open_folder_pipeline`, and only that
branch reads the flag). Making `owns_inner` required on every
`SlicingStream` would add `False` noise to the borrow sites the type
already describes. pyrefly/ty catching a missing kwarg converts "forgot to
think" into "typed `False` without thinking"; the oracle now fails the leak
instead.

A new `DelegatingStream` subclass is forced to pick a close contract by
the close-inventory test, which asserts the class-level
`_SUBCLASS_CLOSES_INNER` flag (same idiom as the resume-offset inventory)
and rejects a production `__init__` that still passes the kwarg. That is
per-class, which is the right grain for this type. The constructor kwarg
remains for ad-hoc construction in tests; that path is not inventory-checked.

Named constructors (`SlicingStream.owning()`) were the Parcel B analogue.
Rejected: `owns_inner` only changes `close()`, it does not switch I/O contracts
the way `lock=None` used to. A second class for that is `SharedView` already.

## 4. Reader-level flags, left alone

The flags that recorded "did this reader open a Path" (`SharedSource._owns_handle`,
ZIP/ISO `_owned_fp`, the source half of TAR's `_owned_stream`) are gone: the
`ArchiveSource` opens the handle and the reader closes the source. Two reader-level
fields remain, each for something the reader built itself rather than a source it
was handed. TAR's `_owned_stream` is the decompressor over a compressed tar. RAR's
`_owned_concat` joins siblings discovered from volume 1's path: the boundary hands
RAR that path (unrar walks the set itself and needs the files on disk), and RAR's
in-process reader builds its own join from it. They are not wrapper kwargs, and
renaming them to `owns_inner` would collide with the wrapper vocabulary for no
call-site gain.

`ConcatenatedFile` is the same split: Path volumes are owned, caller streams are
borrowed. Path parts are sized with `os.stat()` and opened on the first read
that needs that part, into an LRU of three handles so a caller that
alternates across a volume boundary (two `SharedView`s under
`concurrent_operations=True`) does not open-and-close on every read. Three is
the fd budget, not a working-set size: a fourth live Path volume evicts on
every miss, so those reads pay `open()`+`close()` again. A 100-part set still
reads; growing the cache to the volume count would hold one descriptor per
part. `close()` releases every cached Path handle and is safe when none are
open. A missing or unstatable file fails at construction with the
`OSError` from `stat()` itself (`FileNotFoundError`, `PermissionError`), as a
single path does; a numbering gap among paths that exist is `TruncatedError`
from the numbered sequence check. A permission error on `open()` surfaces on
the first read of that part as that `OSError`. Running out of descriptors
(`EMFILE` / `ENFILE`) at either point raises `ResourceUnavailableError` with
the `OSError` as its cause. Opening every Path at construction just to fail-fast would put
the descriptors back. Volume bytes are sampled at read time, not pinned by a
construction-time fd: replacing a part after construction is visible on the
next open of that part. A borrowed `BinaryIO` volume is re-seeked before every
read. A Path handle is seeked when the cursor lands on it — from a seek, from
a sequential advance into a cached volume, or on first open.

`readinto_passthrough` and `peel_for_source_size` share the same
class-flag-plus-constructor-override pattern as `_SUBCLASS_CLOSES_INNER`.
Neither is ownership.

## 5. Leak oracle

`SlicingStream` is keyed on the **kwarg** `owns_inner`. `DelegatingStream` is
keyed on the resolved `_subclass_closes_inner` instance flag — the class-level
`_SUBCLASS_CLOSES_INNER` default, or a constructor kwarg that overrides it.
An `ArchiveSource` is not pinned: it is neither a `SlicingStream` nor a
`DelegatingStream`, and what it owns is closed by the reader's teardown, which the
tests check directly.
Renaming those without updating `tests/leak_oracle.py` pins nothing, and the
tests being edited are the ones that would have caught it.

Confirm the gate still fires: delete `owns_inner=True` at
`src/archivey/internal/backends/rar_reader.py` (`_bounded_member_pipe`) and run
`pytest tests/test_rar_reader.py -q --no-cov`. Expect the two
`assert inner.closed` unit tests plus the oracle's live-`unrar` errors. Restore
before committing.

## 6. Verify

```bash
uv run --no-sync pytest tests/test_stream_bases.py tests/test_slice.py \
    tests/test_source_ownership.py tests/test_archive_source.py \
    tests/test_leak_oracle.py tests/test_codecs.py tests/test_rar_reader.py \
    tests/test_volumes.py tests/test_sevenzip_reader.py::test_first_stage_bcj_does_not_close_pack_source \
    tests/test_sevenzip_reader.py::test_copy_bcj_folder_roundtrip -q --no-cov
```
