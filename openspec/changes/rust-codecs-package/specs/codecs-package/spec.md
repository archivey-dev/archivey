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

Each hash SHALL be a type whose constructor takes optional initial data and whose
objects have `update(data)`, `digest()`, `hexdigest()`, `copy()`, `name`,
`digest_size` and `block_size`, with the meaning `hashlib` gives them. Each CRC SHALL
also have a function form `name(data, value=0) -> int`, like `zlib.crc32`, and SHALL be
named after its CRC catalogue entry. A CRC's `digest()` SHALL be big-endian. `update()`
SHALL release the GIL for inputs above a documented size.

#### Scenario: hash interface

| Case | Expected |
| --- | --- |
| `h = crc16_arc.new(); h.update(a); h.update(b)` | `h.digest()` equals `crc16_arc.new(a + b).digest()` |
| `h.copy()` then more `update()` on the copy | The original's digest is unchanged |
| `crc16_arc(b, crc16_arc(a))` | Equals `crc16_arc(a + b)` |
| `crc16_arc.new()` fed `a`, `digest()` | `crc16_arc(a).to_bytes(2, "big")` |

### Requirement: Streaming decoders follow lzma.LZMADecompressor

Each streaming decoder SHALL have `decompress(data, max_length=-1) -> bytes` and the
attributes `eof`, `needs_input` and `unused_data`, with the meaning
`lzma.LZMADecompressor` gives them. A call SHALL return at most `max_length` bytes when
it is not negative. A block decoder whose output size is known SHALL have
`decompress(data, *, out_size)` that never allocates more than `out_size` bytes. Every
allocation SHALL be bounded by a constructor argument, `max_length` or `out_size`.

#### Scenario: decoder interface

| Case | Expected |
| --- | --- |
| `decompress(data, max_length=10)` on a stream with more output | At most 10 bytes; `needs_input` is false |
| The stream's end reached | `eof` true; bytes after it in `unused_data` |
| Corrupt input | `CorruptDataError`, a `CodecError` and `ValueError` |
| Input ends inside the stream | `TruncatedDataError` |
| A parameter the kernel does not support | `UnsupportedDataError` |
| Two threads call one object at once | One raises `RuntimeError`; the object's state is intact |

### Requirement: Streaming decoder state can be copied and saved

Each streaming decoder SHALL have `copy()`, `getstate() -> bytes`, a class method
`from_state(state)`, and the counters `total_in` (input bytes consumed) and `total_out`
(output bytes produced). `getstate()` SHALL hold everything the decoder consumed,
including bits of a partly read byte, and SHALL NOT hold input the decoder holds but
has not used. A decoder made by `from_state` and fed the input from offset `total_in`
SHALL produce exactly the output a straight decode produces from offset `total_out`.
`from_state` SHALL refuse a state written by another kernel or another revision with
`UnsupportedDataError`. One-shot block decoders have no state.

#### Scenario: resume from a saved state

| Case | Expected |
| --- | --- |
| Save at any call boundary, resume from `total_in` | Output equals the straight decode from `total_out`, byte for byte, errors included |
| `copy()` then decode on both | Both produce the same output; neither affects the other |
| A state from LZW revision 1 given to revision 2 | `UnsupportedDataError` |
| A state from the LZX kernel given to `lzw.Decompressor.from_state` | `UnsupportedDataError` |

### Requirement: KERNELS reports a revision per kernel

`archivey_codecs.KERNELS` SHALL map each kernel's name to an integer revision. A
release that changes a kernel's observable behaviour (output bytes, error kind or
message, reported state such as seek points) SHALL raise that kernel's revision. A
release SHALL NOT remove a kernel or lower a revision within a major version.

#### Scenario: revisions

| Case | Expected |
| --- | --- |
| A release adds a kernel | New key; other revisions unchanged |
| A fix changes the LZW error message | `KERNELS["lzw"]` goes up |
| A change to the saved-state layout | That kernel's revision goes up |
| A refactor with identical behaviour | No revision changes |

### Requirement: archivey-codecs is versioned and released on its own

The package SHALL carry its own semantic version, single-sourced in `Cargo.toml`, and
its own changelog. A release SHALL come from a `codecs-vX.Y.Z` tag that matches that
version, and SHALL publish abi3 wheels for CPython 3.11 and later on manylinux and
musllinux (x86_64, aarch64), macOS (arm64, x86_64) and Windows (x86_64, arm64),
per-version free-threaded wheels on the same platforms, and an sdist. Every wheel SHALL
pass the package's API and parity tests on its platform before upload.

#### Scenario: release

| Case | Expected |
| --- | --- |
| Tag `codecs-v0.2.0` with `Cargo.toml` at 0.2.0 | Wheels built, tested, uploaded |
| Tag and `Cargo.toml` disagree | The workflow fails before upload |
| Tag `v0.6.0` (an archivey release) | The codecs workflow does not run |
