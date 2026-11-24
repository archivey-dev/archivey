## ADDED Requirements

### Requirement: archivey-codecs holds only codecs that archivey also has in Python

The `archivey-codecs` distribution SHALL contain only codecs, filters and checksums for
which archivey ships a pure-Python version that stays the reference. It SHALL NOT
contain archive parsers, archive types, I/O, or policy, and SHALL NOT depend on any
package other than its build-time binding layer. It SHALL NOT import archivey.

#### Scenario: package contents

| Case | Expected |
| --- | --- |
| `import archivey_codecs` with archivey absent | Succeeds; every kernel usable |
| A kernel with no archivey Python twin | Not added |
| A wrapper of zlib, bz2 or LZMA | Not added |

### Requirement: Hash objects follow hashlib

Each hash SHALL be a type, named in CamelCase (`Crc16Arc`), whose constructor takes
optional initial data and whose objects have `update(data)`, `digest()`, `hexdigest()`,
`copy()`, `name`, `digest_size` and `block_size`, with the meaning `hashlib` gives them.
Each CRC SHALL also have a separate function `name(data, value=0) -> int` in snake case,
like `zlib.crc32`, and both SHALL be named after its CRC catalogue entry. A CRC's
`digest()` SHALL be big-endian. `update()` SHALL release the GIL only for immutable
`bytes` input above a documented size; a mutable buffer SHALL be copied first or read
with the GIL held.

#### Scenario: hash interface

| Case | Expected |
| --- | --- |
| `h = Crc16Arc(); h.update(a); h.update(b)` | `h.digest()` equals `Crc16Arc(a + b).digest()` |
| `h.copy()` then more `update()` on the copy | The original's digest is unchanged |
| `crc16_arc(b, crc16_arc(a))` | Equals `crc16_arc(a + b)` |
| `Crc16Arc(a).digest()` | `crc16_arc(a).to_bytes(2, "big")` |

### Requirement: Streaming objects and block functions have fixed shapes

Each streaming object SHALL have one of three shapes. A decompressor (LZX, LZW) SHALL
have `decompress(data, max_length=-1) -> bytes` and the attributes `eof`, `needs_input`
and `unused_data`, with the meaning `lzma.LZMADecompressor` gives them, and SHALL
return at most `max_length` bytes when it is not negative. The LZX decompressor SHALL
take the declared output size (`output_size=` or `set_output_size(n)` before the last
frame ends), SHALL decode whole frames of 32 KiB with only the last one shorter,
whatever `max_length` is, and SHALL set `eof` when `total_out` reaches it. LZX and LZW
SHALL have `flush(max_length=-1)`, which marks the end of input and returns the
remaining output; before it, input that ends inside a frame or code only means more
input is needed. LZX's `flush()` SHALL finish the last frame with the Python twin's zero
padding and SHALL raise `TruncatedDataError` when the frame still cannot finish. LZW's
`flush()` SHALL then set `eof` and `truncation` (`None` or a message), and SHALL NOT
raise for a truncation it can only suspect, so the bytes before it are kept. The pull
decoder (BCJ2) SHALL take the declared output size as the required `out_size`, SHALL
read from its four input streams with `read(n)` and SHALL have
`read(max_length=-1) -> bytes` and `eof`, returning at most `max_length` bytes when it
is not negative and setting `eof` after exactly `out_size` bytes. An input that ends
before then SHALL raise `TruncatedDataError`, and bytes left in `main`, `call` or `jump`
after the last output byte SHALL raise `CorruptDataError`. A length-keeping transform
(the ARM64 and RISC-V filters with `decode(data)` and `flush()`, ZipCrypto with
`decrypt(data)`) SHALL return at most the input given plus the bytes it held back from
the previous call, and `flush()` SHALL return the held-back bytes. A block function
whose output size is known (LZO, later LZFSE) SHALL be `decompress(block, *, out_size)`
and SHALL never allocate more than `out_size` bytes; LZO SHALL also take `max_size=` in
its place, for a container that records only the most a block may decode to (SquashFS),
returning the block's output and never allocating more than `max_size` bytes. Every
allocation SHALL be bounded by a constructor argument, `max_length`, the input length,
`out_size` or `max_size`.

#### Scenario: decoder interface

| Case | Expected |
| --- | --- |
| `decompress(data, max_length=10)` on a stream with more output | At most 10 bytes; `needs_input` is false |
| The stream's end reached | `eof` true; bytes after it in `unused_data` |
| A CAB with Intel E8 translation and a short last frame, read with `max_length=1` | Same bytes as one `decompress()` call and as the Python twin; `eof` false until the last byte is returned |
| LZX last frame split across two `decompress()` calls | After the first, `needs_input` true and no error; after the second and `flush()`, the frame as the twin decodes it |
| LZX input that stops at that same split, then `flush()` | The twin's output and its terminal error (`TruncatedDataError`) |
| LZX with no output size (incomplete block table), `flush()` inside a frame | `TruncatedDataError`, as the twin |
| LZW `decompress(b"")` before the source ends | Buffered output only; `eof` false |
| LZW `flush()` after a clean stream | The rest of the output; `eof` true; `truncation` is `None` |
| LZW `flush()` with padding still owed | The bytes before the cut; `truncation` names the owed padding; no exception |
| BCJ2 `read(10)` with more output | At most 10 bytes; `eof` false |
| BCJ2 after `out_size` bytes, all inputs used | `read()` returns `b""`; `eof` true |
| BCJ2 whose `main` ends before `out_size` bytes | `TruncatedDataError` naming `main` |
| BCJ2 with bytes left in `call` after the last output byte | `CorruptDataError` |
| ARM64 `decode()` on 6 bytes, then `flush()` | `decode()` returns 4 bytes and holds 2; `flush()` returns the 2 unchanged |
| ZipCrypto `decrypt(data)` | Exactly `len(data)` bytes |
| `lzo1x.decompress(block, out_size=n)` whose output is shorter or longer than `n` | `CorruptDataError`; never more than `n` bytes allocated |
| `lzo1x.decompress(block, max_size=n)` whose output is longer than `n` | `CorruptDataError`; never more than `n` bytes allocated |
| Corrupt input | `CorruptDataError`, a `CodecError` and `ValueError` |
| Input ends inside the stream | `TruncatedDataError` |
| A parameter the kernel does not support | `UnsupportedDataError` |
| Two threads call one object at once | One raises `RuntimeError`; the object's state is intact |
| A `bytearray` input that another thread writes during the call | The kernel reads a consistent copy, or holds the GIL; never reads memory being written |
| Another mutable buffer (`array.array`, `mmap`, a write through a second `memoryview`) written during the call | The caller's to prevent, as with CPython's own `zlib` and `hashlib`: such an exporter has no lock to take. The kernel still reads only its own copy |

### Requirement: Streaming decoder state can be copied and saved

Each streaming object SHALL have `copy()`, `getstate() -> bytes` and a class method
`from_state(state)`, except BCJ2, which SHALL have no `copy()` (two copies would share
its four read cursors) and SHALL be restored with
`from_state(state, main, call, jump, rc)`, each new stream placed at its saved count,
and SHALL count its input and output: a decompressor and a filter have `total_in` (input
bytes consumed) and `total_out` (output bytes returned to the caller, not decoded output
still held); BCJ2 has `total_in` as a tuple of four counts, one per input stream, and
`total_out`; ZipCrypto has `total_in` only, since its output length equals its input
length. `getstate()` SHALL hold everything the object consumed, including bits of a
partly read byte, a filter's held-back bytes and decoded output not yet returned,
and SHALL NOT hold input that the object holds but has not used. An object made by
`from_state` and fed each input from its `total_in` offset SHALL produce exactly the
output a straight decode produces from offset `total_out` (for ZipCrypto, from offset
`total_in`). `from_state` SHALL refuse a state written by another kernel or another
revision with `UnsupportedDataError`. A decoder that holds a decode error (LZW, LZX,
BCJ2) SHALL refuse `getstate()` with `ValueError`: while it holds the error, every later
decoding call raises it, and it has no state to resume from. (An LZX `set_output_size()`
that gives back the input the error was met in drops it.) Block functions have no state;
a seek point is the block's offset.

#### Scenario: resume from a saved state

| Case | Expected |
| --- | --- |
| Save at any call boundary before a decode error, resume from `total_in` | Output equals the straight decode from `total_out`, byte for byte, errors included |
| LZW, LZX or BCJ2 `getstate()` after a decode error | `ValueError`; every later decoding call raises the same error while the decoder holds it |
| LZX without an output size, saved after it read input past the stream, then a late `set_output_size()` | The original gives that input back and drops an error met in it, unless it has already dropped that input from its buffer; the restored decoder keeps it consumed and keeps the error |
| BCJ2 saved mid-stream, restored with four new streams each at its own `total_in` | Output equals the straight decode from `total_out` |
| BCJ2 restored twice from one state, with independent streams, reads interleaved past their buffers | Both produce the straight decode; neither affects the other |
| `bcj2.Decompressor.copy` | Does not exist |
| An LZX decoder saved after returning 1 byte of a 12-byte last frame | `total_out` counts that 1 byte; the restored decoder returns the other 11, then `eof` |
| LZX or LZW saved during a capped `flush()` | The restored decoder has not been flushed: given the input from `total_in` and then `flush()`, it returns the rest of the output and ends as the original does |
| LZX at `eof` with bytes after the stream | `total_in` stops where the stream does (an odd uncompressed block's pad byte in, words fetched ahead out); `unused_data` holds the rest |
| An ARM64 filter saved with 2 bytes held back | The resumed filter returns those 2 bytes first; output equals the straight decode |
| ZipCrypto saved after `n` bytes | `getstate()` holds the three 32-bit keys after the kernel name and revision; decrypting from offset `n` equals the straight decrypt |
| `copy()` then decode on both | Both produce the same output; neither affects the other |
| A state from LZW revision 1 given to revision 2 | `UnsupportedDataError` |
| A state from the LZX kernel given to `lzw.Decompressor.from_state` | `UnsupportedDataError` |
| A state with a valid header and damaged contents (window too large, table index out of range, cut off) | `CorruptDataError`; no allocation beyond the kernel's largest window |
| `from_state` | The counters equal the saved values |

### Requirement: KERNELS reports a revision per kernel

`archivey_codecs.KERNELS` SHALL map each kernel's name to an integer revision. A
release that changes a kernel's observable behaviour (output bytes, error kind or
message, reported state such as seek points) SHALL raise that kernel's revision. A
release SHALL NOT remove a kernel or lower a revision before 1.0, nor within a major
version after it. A raised revision SHALL keep the kernel's call signature, attribute
names and error classes; a change to any of them SHALL use a new `KERNELS` key.

#### Scenario: revisions

| Case | Expected |
| --- | --- |
| A release adds a kernel | New key; other revisions unchanged |
| A fix changes the LZW error message | `KERNELS["lzw"]` goes up |
| A change to the saved-state layout | That kernel's revision goes up |
| A new required constructor argument for LZX | A new key (for example `"lzx2"`); `"lzx"` stays |
| A refactor with identical behaviour | No revision changes |

### Requirement: archivey-codecs is versioned and released on its own

The package SHALL carry its own semantic version, single-sourced in `Cargo.toml`, and
its own changelog. A release SHALL come from a `codecs-vX.Y.Z` tag that matches that
version, and SHALL publish abi3 wheels for CPython 3.11 and later on manylinux and
musllinux (x86_64, aarch64), macOS (arm64, x86_64) and Windows (x86_64, arm64),
per-version free-threaded wheels on the same platforms from CPython 3.13t on, and an
sdist. Every wheel SHALL pass the package's API and parity tests on its platform before
upload.

#### Scenario: release

| Case | Expected |
| --- | --- |
| Tag `codecs-v0.2.0` with `Cargo.toml` at 0.2.0 | Wheels built, tested, uploaded |
| Tag and `Cargo.toml` disagree | The workflow fails before upload |
| Tag `v0.6.0` (an archivey release) | The codecs workflow does not run |
