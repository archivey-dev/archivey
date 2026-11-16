# cramjam and unpackio as codec or format backends

**Recommendation — cramjam 2.14.0:** keep the existing backends. Its common Python
interface is convenient for whole buffers, but does not supply archivey's resumable,
output-bounded decoder contract. Two raw-DEFLATE mutations return bytes where archivey
refuses the data. Wrapping a whole decode and slicing its result would retain the memory
problem and would miss that leniency. A narrow follow-up is worthwhile: a `.sz` Snappy
plugin with Python framing and bounded native chunk decoding. That adds a missing format
without replacing a working backend. It needs its own producer corpus, resource tests,
and error translation before integration. Neither throughput alone nor the shared API
justifies a general cramjam dependency.

**Recommendation — unpackio 0.1.1:** do not integrate its current format readers or
standalone stream API. Python bindings already exist. The release is an unpack-only
format library, with full-input retention and buffered archive payloads behind bounded
output callbacks. That conflicts with archivey's Python-parser boundary and incremental
read contract. Measured acceptance differences include truncated `.Z`, damaged ZIP and
7z headers, and Debian/Zstandard data whose checksum archivey rejects. The last group
includes changed member bytes. Its checked Rust PPMd7, Deflate64, ARJ and filter code is
worth studying as a possible upstream codec-only API, but that would require new native
interfaces and another evaluation. It is not a drop-in acceleration option today.

## Evidence and scope

Measured on 2026-11-16 against archivey `main` at
`205bed416e359ab96b3c17eb9b2067b7389f3211`, CPython 3.11.18, Linux x86-64, glibc 2.41.
The container exposes three CPUs and a two-CPU quota. The measured candidates are PyPI
wheels, cramjam 2.14.0 with `backend == "c"`, and unpackio 0.1.1. This investigation
changes no library code, dependencies, or changelog.

The code and saved observations are in
[`scripts/investigations/codec_libraries/`](../../scripts/investigations/codec_libraries/).
**Measured** means an installed-wheel experiment here. **Read** means source, package
metadata, or upstream documentation. No Windows, macOS, PyPy, sdist-build or exhaustive
security-audit result is claimed. A separate Linux CPython 3.14t import probe is
recorded below. Unpackio's current GitHub `main` describes 0.2.0, including additional
ZIP methods. Those claims are not measurements of 0.1.1.

Both candidates receive the same deterministic payload generator, mutation rules,
acceptance/output oracle, timeout, resource ceiling, small/large sizes and timing
method. The available APIs determine which layer can be compared: cramjam supplies
codecs; unpackio supplies streams and containers. Missing APIs are reported, not
simulated as native streaming. This follows the earlier [libarchive
evaluation](libarchive-accelerator.md): compare damaged input as well as speed, save
differences, and distinguish a fallback-repairable refusal from silent acceptance. A
passing sample does not establish parity for all possible inputs.

### Reproduce

From the repository root, install the ordinary development dependencies first:

```sh
uv sync --group dev --extra all
uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
  scripts/investigations/codec_libraries/differential.py --output work/codec-diff
uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
  scripts/investigations/codec_libraries/bench.py --output work/codec-bench
uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
  scripts/investigations/codec_libraries/probes.py --output work/codec-probes
uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
  scripts/investigations/codec_libraries/replay.py --all
uv run python scripts/investigations/codec_libraries/metadata.py \
  --output work/codec-metadata
```

Use Linux for the resource and RSS measurements. Keep `CRAMJAM_BACKEND` unset or set to
`c`; the separately distributed pure-Rust variant is not the measured wheel. The scripts
need the development dependencies for producers and archivey's existing optional
backends. They make no filesystem extraction decisions. They never give native code an
immutable Python `bytes` object as writable output. Differential exit zero means the
experiment completed, not that the candidate passed parity. Replay exit zero means the
saved outcomes repeated.

## archivey's existing boundaries

**Read:** `internal/streams/codecs/registry.py` owns the `StreamCodec` instances.
`resolve_codec` chooses the implementation and translator. `open_codec_stream` wraps
reads and translates failures. `FramedDecoder` owns per-stream EOF, truncation, further
members, padding, and trailing-data behavior. Container readers compose these streams;
they do not bypass the layer to call a codec package directly.

The public extension API is `archivey.formats.CodecHandler`, `CodecCall`, and
`register_codec`. `decompressor(call)` returns an object with
`decompress(data, max_length)`, `eof`, `needs_input`, and `unused_data`. The optional
`end_input()` supports a final drain after input ends. Output held by `max_length` must
keep EOF false. A decoder must distinguish waiting for input from buffered output.
`CodecCall` supplies size, properties, `DecoderLimits`, and a detection probe bound.
Registration adds a new stream identity; it cannot overwrite a built-in codec.

Formats use `IndexedFormatHandler.open(ReaderSource, ReaderContext)` returning an
`IndexedReader`, or `SequentialFormatHandler.open_sequential(context)` returning a
`SequentialReader`. The former implements `iter_members` and `open_member`, returning
`MemberRecord` and `MemberData`. The latter implements `walk`, yielding `MemberSpan`.
`ReaderContext` owns name decoding, normalization, metadata charges, diagnostics and
nested decompression. A replacement format handler uses `FormatPolicy(replace=...)`.
An interface that can be adapted mechanically is not automatically a policy-compliant
backend.

### Existing codecs

**Read:** this inventory covers openable codecs plus format-local decoders and filters.
“Core” means no third-party Python package. C libraries behind Python's stdlib are still
native code.

| Codec / variant | Current implementation | Optional dependency |
| --- | --- | --- |
| gzip, zlib, raw DEFLATE | stdlib `zlib`, archivey framing/resume | `rapidgzip` acceleration |
| bzip2, concatenated streams | stdlib `bz2`, archivey block/framing logic | `rapidgzip` acceleration |
| XZ, LZMA Alone, raw LZMA1/LZMA2 | stdlib `lzma`; native Python XZ structure | none |
| lzip | Python framing over raw stdlib LZMA1 | none |
| Zstandard frames, skippable/concatenated | `compression.zstd` on 3.14+, else backport | `backports.zstd` below 3.14 |
| LZ4 modern/legacy frames | `lz4.frame` / `lz4.block`, Python framing | `lz4` |
| mozlz4, size-prefixed raw LZ4 | Python envelope over `lz4.block` | `lz4` |
| Brotli | bounded `brotli.Decompressor.process` | `brotli>=1.2.1` |
| PPMd7 var.H / PPMd8 | `pyppmd`, isolated decoder machinery | `pyppmd>=1.3.1,<2` |
| Deflate64 | `inflate64`, bounded adapter | `inflate64` |
| Unix compress `.Z` | archivey Python LZW | none |
| LZO1X / lzop | Python decoder/framing, optional native kernel | `python-lzo` |
| bzip3 | `bz3`, normally in a child | separate `[bzip3]` extra |
| ZIP Shrink / Reduce factors 1–4 / Implode | archivey Python | none |
| ZIP DCL Implode | archivey Python | none |
| uuencode, begin-base64, bare Base64 | archivey parser plus stdlib text codecs | none |
| CAB MSZIP / LZX | zlib plus Python MSZIP / Python LZX | none |
| LHA LZH/ARJ 1–3, LArc, ARJ 4 | archivey Python engines | none |
| Delta, BCJ x86/ARM/Thumb/PPC/SPARC/IA64 | stdlib raw LZMA filter chains | none |
| BCJ2, ARM64, RISC-V | archivey Python filters | none |
| Stored data, sparse expansion, ZipCrypto | archivey Python / stdlib | none |
| 7z/RAR/ZIP AES, related KDF/authentication | `cryptography` blocks plus stdlib hashes | `cryptography` |

`[recommended]` contains pyppmd, inflate64, backports.zstd where needed, Brotli, LZ4,
cryptography, pycdlib, and tqdm. `[seekable]` contains rapidgzip. `[all]` combines those
two extras. `[free-threaded]` is a measured subset of optional packages, with version
markers. `[bzip3]` is separate and is not in `[all]`. Python-lzo is an optional detected
kernel, not an extra dependency. `OptionalLibrary` and the dependency exclusion policy
must continue to describe whichever implementation is active.

### Existing formats

**Read:** ZIP/ZIP64 and SFX, TAR (V7/ustar/GNU/pax and sparse forms), 7z including
solid, SFX, split byte volumes and supported encryption, RAR3/RAR5 metadata, ISO9660,
CPIO (binary both byte orders/odc/newc/crc), ar (including long names), Debian packages,
RPM, makeself, SquashFS 4, CAB, XAR, LHA, ARJ, directory, and raw single compressed
files. Sequential containers also compose with the registered outer stream formats.

All these container parsers are archivey's Python, except ISO's optional `pycdlib`
reader. RAR member data uses external `unrar` or a probed supported `unar`, while
archivey parses names and headers. ZIP and TAR no longer use stdlib `zipfile`/`tarfile`
readers (ADRs 0020/0021). Member codecs use the table above. CAB reads stored/MSZIP/LZX,
not Quantum or cabinet sets. LHA reads header levels 0–3; stored
`-lh0-`/`-lz4-`/`-pm0-`, `-lh1-`, `-lh4-` through `-lh7-`, `-lhx-`, `-lk7-`, `-lzs-`,
and `-lz5-`. ARJ reads methods 0–4, not garbled or split-member data. DMG is detected
and explicitly refused, not supported for reading. Snappy `.sz` is absent.

| Format | Current format backend | Optional component |
| --- | --- | --- |
| ZIP / ZIP64 / SFX | Python ZIP parser and codec layer | member codecs / AES above |
| TAR / GNU / pax / sparse | Python TAR parser and codec layer | outer codecs above |
| 7z / solid / split / SFX | Python header/coder-graph parser | member codecs / AES above |
| RAR3 / RAR5 | Python metadata, external member decoder | `unrar` or supported `unar`; AES headers |
| ISO / Rock Ridge / Joliet / zisofs | `pycdlib`, Python sector/CUE adapters | `pycdlib`; no UDF reader |
| CPIO / ar / Debian / RPM | Python parsers, codec layer | compressed-payload codecs above |
| makeself | Python script envelope, nested TAR readers | compressed-payload codecs above |
| SquashFS 4 | Python index, gzip/LZMA/XZ/LZO/LZ4/Zstd blocks | LZ4/Zstd; optional python-lzo |
| CAB | Python cabinet, stored/MSZIP/LZX folder engines | none |
| XAR | Python XML/heap parser, zlib/bzip2/LZMA/XZ | none |
| LHA | Python level 0–3 headers and LZH/LArc engines | none |
| ARJ | Python headers and methods 0–4 | none |
| Directory | Python filesystem walk | none |
| Raw compressed file | Python single-file reader, registered stream codec | codec-specific above |

### Constraints on either integration

**Read:** [design rules](../design-rules.md), [code map](../code-map.md), and
[decision log](../decisions/index.md):

- DR-1/DR-5: a full read must not silently return wrong/incomplete bytes. Backend choice
  must preserve bytes and error types. DR-5a records narrow malformed-input exceptions;
  none authorizes these candidates' divergences or weakens the no-wrong-bytes rule.
- DR-9a and `DecoderLimits.max_decoder_memory`: check attacker-declared dictionaries,
  windows, blocks and output work before allocation. Slicing a completed decode is not
  an output cap. Detection probes need the same protection.
- DR-20: Python owns container/header parsing. Native codecs with known crashes run in a
  child or are designed around. Rust bindings do not prove transitive C code safe.
- ADRs 0001/0002/0020/0021 defend native Python container parsing; ADR 0010 forbids
  silent spooling of a nonseekable input to manufacture random access. ADR 0011 keeps
  the core free of third-party dependencies.
- ADR 0008 prevents loading the conflicting rapidgzip/indexed_bzip2 implementations
  together. It is not a blanket ban on every other optional codec.
- ADR 0009 selects stdlib/backports Zstandard; ADR 0014 makes a completed read the
  integrity boundary. Callback completion and final CRC checks must not be lost.
- ADRs 0003/0007/0013 preserve capability declarations, mutable late metadata, names and
  link policy. A candidate's “safe path” flag cannot replace archivey's policies.
- ADR 0022 records PPMd isolation, with implementation pending in that ADR. A safe-Rust
  candidate does not by itself authorize reversing this choice.

## cramjam

### Scope and implementation

**Read:** [repository](https://github.com/milesgranger/cramjam), [PyPI
2.14.0](https://pypi.org/project/cramjam/2.14.0/), shipped Cargo.lock and Rust source.
The PyPI project URL names `milesgranger/pyrus-cramjam`; the supplied `cramjam`
repository is accessible and contains the Python binding. The Rust layer is
[`libcramjam`](https://crates.io/crates/libcramjam), locked at 0.9.1 in this release.
The current crates.io version is newer; it was not substituted into the wheel tests.

There are compression stream envelopes, not named-member archive containers. No ZIP,
TAR, 7z, RAR, paths, links, passwords, or multi-volume API exists. File/Buffer support
is I/O convenience, not an archive parser.

| Shipped codec / variants | Underlying implementation in locked default build |
| --- | --- |
| gzip, zlib wrapper, raw DEFLATE | `flate2 1.1.10`, default `miniz_oxide 0.9.1` |
| bzip2 | `bzip2 0.5.2`, `bzip2-sys 0.1.13+1.0.8`, libbzip2 1.0.8 |
| Brotli | Rust `brotli 8.0.4`, `brotli-decompressor 5.0.3` |
| Snappy framed and raw | Rust `snap 1.1.1` |
| LZ4 frame; block with/without stored size | `lz4 1.28.1`, `lz4-sys 1.11.1+lz4-1.10.0` |
| XZ and LZMA Alone decode | `xz2 0.1.7`, `lzma-sys 0.1.20`, vendored liblzma 5.2.5 |
| Raw LZMA1/LZMA2 and filter chains | exposed for compression; no raw Python decode parameters |
| XZ filters | LZMA1/2, x86, ARM, Thumb, PPC, SPARC, IA64 declared in API |
| Zstandard frames | `zstd 0.13.3`, `zstd-safe 7.3.0`, `zstd-sys 2.1.0+zstd.1.5.7` |
| Experimental Blosc2, igzip/ideflate/izlib | not enabled in measured wheels |

The experimental lock entries are `blosc2-rs`/`blosc2-sys 0.4.0+2.15.2` and
`isal-rs`/`isal-sys 0.5.3+496255c`; they are not additional default codecs.
`cramjam-pure-rust` is a separate distribution, selected at import by
`CRAMJAM_BACKEND=pure-rust`. Its implementations need independent parity and performance
results. An environment-selected backend also needs a pinned, tested policy in archivey.
The source tests note that the default vendored liblzma build omits some declared BCJ
encoders. A declared filter is not evidence that every wheel handles that filter.

### Python API and failure behavior

**Measured and read:** `compress`/`decompress` return a buffer object. `_into`
operations write to a caller buffer or file. The generic `output_len` argument
initializes a Vec; it is not a maximum. All nine ordinary codec families returned the
full 2,048 bytes with `output_len=8`, and the bomb probes request 128 bytes from a 16
MiB result. A fixed writable bytearray bounds writes: overflow raises
`DecompressionError`, but there is no resumable state or consumed-input count for
continuing the decode.

`Compressor` is stateful. The generic `Decompressor` instead keeps an output Vec and
calls a fresh `libcramjam::<codec>::decompress` for each supplied input. `flush` empties
that Vec, and `finish` consumes it. Both do not finalize an incremental codec state. All
nine codec modules and the separate LZMA Alone profile failed on a half-stream followed
by its remainder, usually on the first half. These methods cannot implement archivey's
pull decoder by renaming their methods. Splitting the compressed bytes on arbitrary I/O
boundaries changes behavior.

One-shot malformed input generally raises `cramjam.DecompressionError` with a string.
The generic `Decompressor` path exposes `OSError` from Rust I/O errors. Neither exposes
a structured truncated/corrupt/checksum taxonomy. `eof`, `needs_input`, `unused_data`,
per-call output limits and decoder-memory limits are absent. A wrapper cannot map every
`OSError` to archive damage because genuine file I/O errors must remain I/O errors.
It would need tightly scoped codec-only calls and a supported error protocol.

The measured checksum probes refuse bad gzip CRC, zlib Adler-32, bzip2 combined CRC, XZ
block check, LZ4 content check, Zstandard content check and Snappy chunk CRC-32C.
Checksum detection alone does not prove strict grammar validation: raw DEFLATE has no
checksum, and its two lenient mutations below pass. The differential data separately
records every prefix and mutation result. Concatenated gzip/XZ/Zstd/LZ4 worked on the
small corpus. A crafted legacy LZ4 frame decoded in archivey and unpackio but was
refused by cramjam (`ERROR_frameType_unknown`). LZMA Alone concatenation was refused
where archivey continued it. Trailing junk and zero padding are stricter in several
cramjam decoders than archivey's framing policy. Without consumed-input/unused-data
information, repairing those boundaries requires Python framing or a new binding.

### Fit by codec

The categories are **a** replace, **b** accelerator, **c** new capability, **d** no fit
through the released API. A conditional opportunity is not an integration
recommendation. The speed column is measured archivey time / candidate time: above 1
favors the candidate.

| Codec / format | Current archivey | Candidate | Fit | Safety | 4 KiB / 8 MiB |
| --- | --- | --- | --- | --- | --- |
| gzip | zlib | flate2/miniz | d | trailer/padding differ | 20.20x / 1.14x |
| zlib | zlib | flate2/miniz | d | sample agrees; API lacks bounds | 8.16x / 1.26x |
| raw DEFLATE | zlib | flate2/miniz | d | 2 invalid-distance accepts | 9.57x / 0.97x |
| bzip2 | bz2 | libbzip2 | d | trailer/padding differ | 7.60x / 1.06x |
| XZ | lzma + Python XZ | liblzma | d | trailing-data refusal differs | 12.11x / 0.39x |
| LZMA Alone | lzma | liblzma | d | concatenation/padding differ | 10.29x / 0.44x |
| Zstd frames | stdlib/backport | libzstd | d | trailer/padding differ | 7.05x / 1.39x |
| LZ4 modern frames | lz4 + Python framing | liblz4 | d | trailer/padding differ | 5.21x / 1.18x |
| LZ4 legacy frames | lz4.block + framing | frame API refuses | d | valid legacy frame refused | n/m |
| LZ4 blocks / mozlz4 | lz4.block | liblz4 block API | b conditional | 2 short accepts; length guard needed | 0.65x / 0.75x |
| Brotli | brotli | Rust brotli | d | sample agrees; no resumable cap | 4.99x / 0.66x |
| Snappy framed / raw | absent | Rust snap | c conditional | roundtrip/checksum only; no oracle | n/m / n/m |
| raw LZMA / filters | lzma / Python filters | no Python raw decode | d | unavailable API | n/m |
| Blosc2 / ISA-L variants | absent / zlib | experimental build features | d | not shipped/measured | n/m |

No existing overlapping codec earns category a. For category b, a new resumable native
API and parity proof are prerequisites, so the released whole-buffer API remains d.
The raw LZ4 length mismatch can be repaired by comparing returned length with the
validated header, as mozlz4 already does; that does not fix raw-DEFLATE leniency or add
incremental decoding to the other modules.

### What a `.sz` wrapper would need

**Design sketch, not implemented:** define a `PluginStream` and `CodecHandler` with
Snappy's `ff 06 00 00 73 4e 61 50 70 59` stream identifier. Its decompressor would:

1. Parse framing in Python, retain a bounded incomplete header/chunk, and skip optional
   chunks incrementally. Refuse unknown mandatory chunk kinds and incomplete chunks.
2. Bound each data chunk to Snappy's 64 KiB decoded limit before a native call. Validate
   raw Snappy's size varint before allocation. Do not trust a 24-bit chunk length as an
   output bound.
3. Use a fixed output buffer with framed checksum verification, or bounded raw decode
   plus masked CRC-32C verification. Preserve stream identifiers, skippable chunks and
   empty streams according to the format specification.
4. Keep at most one decoded chunk, return at most `max_length`, and expose the required
   EOF/input state. `end_input` rejects a partial header or payload; a clean chunk
   boundary is a valid end because Snappy framing has no mandatory final marker.
5. Translate known codec failures and retain archivey's framing/diagnostic policy.
   Validate compressor output against an independent Snappy producer/decoder corpus.

This is a small framing implementation plus tests, not a thin alias around
`snappy.Decompressor`. The present Snappy roundtrip/checksum probes do not constitute
that corpus. Raw Snappy alone adds no identifiable common archive format.

## unpackio

### Discovery and supported formats

**Read:** [repository](https://github.com/bwhitn/unpackio), [PyPI
0.1.1](https://pypi.org/project/unpackio/0.1.1/), and the [crates.io
lookup](https://crates.io/crates/unpackio). The crates.io API returned **404** on the
measurement date. The shipped Rust core and Python binding both declare
`publish = false`; this is source in a Cargo workspace, not an installable published
Rust crate under that name. Documentation links to docs.rs do not establish a published
crate. The Python package is real: `unpackio._native`, PyO3 0.29.0, with typed wrappers
in `python/unpackio` and a `cp39-abi3` extension.

| 0.1.1 reader | Variants and limits read from shipped source |
| --- | --- |
| 7z | Copy, LZMA1/2, Deflate/64, bzip2, PPMd7-H, Brotli, LZ4, Zstd |
| 7z filters | Delta, BCJ x86, BCJ2, PPC, ARM, Thumb, ARM64, SPARC, IA64, RISC-V, Swap2/4 |
| 7z structure | plain/encoded/encrypted headers, solid folders, SFX, sequential `.001` volumes |
| ZIP | ordinary/ZIP64/SFX; Store 0, Deflate 8, Deflate64 9, bzip2 12, LZMA 14, Zstd 20/93 |
| ZIP encryption | ZipCrypto; WinZip AES AE-1/AE-2, 128/192/256 bits |
| RPM | lead/header/index; raw, gzip, bzip2, XZ, LZMA Alone, Zstd CPIO payloads |
| CPIO | newc, crc-newc, odc, little-/big-endian historical binary |
| Debian | System V ar 2.0; control/data tar, V7/ustar/GNU long names and links/pax |
| Debian compression | control: none/gzip/XZ/Zstd; data also bzip2/LZMA Alone |
| ARJ | single-volume methods 0–4; empty no-data 8/9; bounded SFX |
| Standalone streams | modern/legacy LZ4, Zstd, skippable and concatenated frames; Unix `.Z` 9–16 bits |

There is no general TAR or ar reader API, Snappy, lzip, lzop/LZO, bzip3, RAR, ISO,
SquashFS, CAB, XAR, LHA reader, Base64, or uuencode API. An internal LH6 decoder used
for ARJ does not imply LHA container support. ZIP XZ and PPMd are explicitly unsupported
in 0.1.1, as are split/spanned ZIP, strong encryption and encrypted central directories.
ARJ garbled entries can be listed but not decoded; split volumes and security envelopes
are unsupported. External LZ4/Zstd dictionaries are unsupported. 7z AES is AES-256-CBC,
with per-session passwords and KDF bounds. That does not add encrypted ZIP headers.

**Read, unmeasured:** current upstream `COMPATIBILITY.md` describes ZIP methods 95
(XZ), 96 (a restricted WinZip JPEG profile), 97 (restricted WavPack), and 98 (PPMd-I).
That is a possible future capability benefit, not support in the wheel evaluated here.
It still does not expose independent incremental codec bindings.

### Implementation inventory

**Read:** exact versions below come from the shipped binding's Cargo.lock and manifests.
“Local” identifies source compiled into unpackio 0.1.1 rather than a separately linked
crate. The adapters and integrity logic around a crate matter as much as that crate.

| Codec / function | Implementation and version |
| --- | --- |
| raw Deflate; gzip envelopes in packages | `miniz_oxide 0.8.9`; local gzip parser/checks |
| Deflate64 | local checked decoder, Apache Commons Compress adaptation |
| LZMA1/LZMA2 in 7z and ZIP | local safe Rust, adaptation of ulikunitz/xz 0.5.15 |
| XZ / legacy package LZMA paths | `lzma-rust2 0.16.4`, local structural checks |
| bzip2 | `bzip2-rs 0.1.2` |
| Brotli | `brotli-decompressor 5.0.3` |
| LZ4 block/frame/legacy | `lz4_flex 0.13.1`, local framing/checks |
| Zstandard | `ruzstd 0.8.1`, distinct standalone and container adapters |
| PPMd7-H | local checked Rust adaptation of stangelandcl/ppmd 0.1.1 |
| Unix `.Z` LZW | local NetBSD zopen.c adaptation |
| ARJ 1–3 | `delharc 0.6.1` LH6 kernel plus local adaptation |
| ARJ 4 | local checked unarj-rs 0.2.1 adaptation |
| BCJ/BCJ2/Delta/Swap2/Swap4 | local code; bodgit/sevenzip and XZ filter references |
| ZipCrypto | local code |
| AES / modes | `aes 0.9.1`, `cbc 0.2.1`, `ctr 0.10.1` |
| KDF and hashes | `pbkdf2 0.13.0`, `hmac 0.13.0`, `sha1/sha2 0.11.0` |
| ZIP record access | `rawzip 0.4.4` plus local validation |
| checksums / secret erasure | `twox-hash 2.1.2`, `crc32fast 1.5.0`, `zeroize 1.9.0` |

### API, names, integrity and memory

**Measured and read:** `open_bytes`/`open_path` are 7z-specific, with separate
`open_zip_*`, `open_rpm_*`, `open_cpio_*`, `open_deb_*`, `open_arj_*` and
`open_stream_*` functions. Entries have stable indices and raw metadata.
`extract_entry_to` writes to a caller-selected writer. `stream_entry` and stream
`stream(callback)` supply bounded output chunks. Their callbacks must return `None` or
a bool, not the integer returned by `BytesIO.write`. Cancellation is explicit.
`extract_entries_to` supports begin/write/finish callbacks, including a natural-order
solid pass. It does not create filesystem names.

This is push output over complete input, not `decompress(data, max_length)`. A callback
can cancel, but cannot suspend a live decoder and resume it on a later pull.
`open_path` reads input into owned memory too; it is not a seek/read callback into an
archivey source. 7z decodes a complete folder before delivering its member bytes, ZIP
buffers decoded entries, RPM retains decoded CPIO, and Debian retains both decoded tar
images. These allocations are capped by configured totals, but are proportional to
archive/folder/member size, not a fixed streaming working set. A small output callback
does not bound the allocation before that callback.

`Limits` has header/file/folder/coder/stream/frame/name/input/output/dictionary/KDF/
recursion/SFX bounds, plus work budgets and cancellation. Default input allowance is
64 GiB, total decoded output 8 GiB, entry output 2 GiB and dictionary 256 MiB. Those
are resource caps, not suitable implicit values for archivey's detection or pull-read
buffers. Mapping `max_dictionary_bytes` alone does not cap the buffered folder/member
allocation against `max_decoder_memory`.

The hostile-name ZIP probe preserved `/absolute`, `../escape`, nested traversal,
Windows drive paths and symlink bytes. Unsafe paths are classified separately.
The symlink name `link` can be safe while its stored target is `../../escape`.
A wrapper must retain raw names, encoding choice, duplicate ordering, archivey's
normalization and link rules, and Debian's `DEBIAN/` projection. Unpackio's path check
is not archivey's portable-name/collision policy and must not decide extraction.

Read errors are structured `UnpackioError` subclasses: `FormatError`, `ChecksumError`,
`UnsupportedMethodError`, `UnsupportedFeatureError`, `LimitExceededError`,
`MissingVolumeError`, `PasswordRequiredError`, `WrongPasswordOrCorruptError`,
`CancelledError`, `ArchiveIoError`, and `InternalError`. Checksum errors retain scope
and, where applicable, member/frame index. `FormatError` covers both malformed and
truncated data, with a detail string; there is no dedicated truncation subclass.
A wrapper could map checksums to the appropriate archivey checksum error, limits to
`ResourceLimitError`, and missing features to `UnsupportedFeatureError`. It cannot
reliably recover archivey's full truncation taxonomy by parsing arbitrary strings.
Genuine callback/I/O failures must keep their identity.

The source catches Rust unwinds at binding/codec boundaries and forbids unsafe code in
its own core. Dependencies and PyO3 still contain native/unsafe implementation code.
No crash occurred in the bounded mutation sample. This does not prove crash immunity or
settle archivey's process-isolation policy. Password buffers are zeroized on the Rust
side; Python's supplied strings/bytes cannot be erased by that mechanism.

### Fit by format or codec

| Codec / format | Current archivey | Candidate | Fit | Safety | 4 KiB / 8 MiB |
| --- | --- | --- | --- | --- | --- |
| Zstd streams | stdlib/backport + framing | ruzstd + strict stream checks | d | padding/trailer differences | 12.81x / 0.87x |
| LZ4 modern/legacy streams | lz4 + framing | lz4_flex + framing | d | modern sample strict; legacy works | 16.84x / 2.06x |
| Unix .Z | Python LZW | local Rust LZW | d | 50 truncated accepts | 3.16x / 2.14x |
| ZIP Store | Python ZIP / stored | Rust ZIP / Copy | d | trailer/central-header differences | 43.64x / 0.24x |
| ZIP Deflate | Python ZIP / zlib | Rust ZIP / miniz | d | local/central disagreement | 16.24x / 0.41x |
| ZIP bzip2 | Python ZIP / bz2 | Rust ZIP / bzip2-rs | d | local/central disagreement | 11.32x / 1.18x |
| ZIP LZMA | Python ZIP / lzma | Rust ZIP / local LZMA | d | 1 damaged offset accepted | 11.12x / 0.21x |
| 7z LZMA2 | Python 7z / lzma | Rust 7z / local LZMA2 | d | small sample agrees | 18.89x / 0.23x |
| 7z Copy | Python 7z / stored | Rust 7z / Copy | d | small sample agrees | 29.91x / 0.28x |
| 7z LZMA1 | Python 7z / lzma | Rust 7z / local LZMA | d | 1 damaged header accepted | 20.72x / 0.22x |
| 7z Deflate | Python 7z / zlib | Rust 7z / miniz | d | small sample agrees | 33.66x / 0.46x |
| 7z bzip2 | Python 7z / bz2 | Rust 7z / bzip2-rs | d | small sample agrees | 17.28x / 0.95x |
| 7z PPMd7 | Python 7z / pyppmd child | Rust 7z / local PPMd | b conditional | valid large input refused | 1.61x / refused |
| 7z Brotli | Python 7z / brotli | Rust 7z / brotli-decompressor | d | valid input refused | refused / refused |
| 7z Zstd | Python 7z / stdlib/backport | Rust 7z / ruzstd | d | small sample agrees | 36.13x / 0.29x |
| Swap2 / Swap4 filters | absent | local Rust, private | c conditional | not measured; Python implementation may suffice | n/m |
| Deflate64 / AES / filters | inflate64 / crypto / Python | local Rust / RustCrypto | b conditional | raw kernels private; mostly read only | fixture table / n/m |
| RPM / Debian / CPIO | Python parsers + codec layer | native format APIs | d | links/order, CRC, package checksum gaps | fixture table / n/m |
| ARJ 0–4 | Python parsers and codecs | local Rust + delharc | b kernel only | sample agrees; native parser not fit | fixture table / n/m |
| ZIP XZ/JPEG/WavPack/PPMd | existing XZ/PPMd; no JPEG/WavPack | unreleased main only | c conditional | 0.1.1 has no support; unmeasured | fixture table / n/m |

### What wrapping would take

**Design sketch, not implemented:** a format adapter could store an unpackio index as
the `MemberRecord` locator and turn writer/callback output into `MemberData`. It would
still need name/time/metadata normalization, links, shared-source lifetime, per-open
password handling, diagnostics, listing/memory charges, seek costs and exact exception
translation. Bridging push output to a pull `BinaryIO` needs a worker with bounded IPC
and cancellation, or a new suspend/resume API. Buffering the whole result into BytesIO
is not an acceptable bridge. A child contains crashes; it does not remove full-input
or folder buffering and does not repair silent decoding differences.

A codec adapter would be preferable, but the 0.1.1 raw `decode` module is private; its
`unstable-internals` feature is a regression/fuzz interface, not a stable decoder API.
Publishing a crate alone would not expose those kernels. Upstream would need a public
bounded-input/output decoder with consumed-input counts, exact EOS, EOF/unused-data,
resource preflight and structured truncated/checksum errors, then a PyO3 binding.
The wrapper would keep Python headers and plug into `StreamCodec` internally. An
existing built-in cannot be replaced by registering another `CodecHandler` under its
name. Repackaging raw bytes into synthetic 7z/ZIP would add a native parser and buffer
copies, reproducing the rejected libarchive approach with different plumbing.

## Differential safety results

**Measured:** `differential.py` tests a valid 2 KiB payload per generated case, every
strict compressed prefix when input is at most 512 bytes, otherwise 64 evenly spaced
cuts plus endpoints, 64 seeded single-bit flips, trailing junk, zero padding,
concatenation, and skippable frames where applicable. It also runs every supported
fixture family selected by `fixture_cases`: RPM payload compressors, Debian compressors,
CPIO variants, ARJ methods 1–4 and three RISC-V 7z fixtures. Each family runs in a child
with a 60-second timeout, 45 CPU seconds and 1 GiB address-space ceiling. No worker
crash or timeout was observed. Resource failures remain failures, not proof of
corruption.

Archivey's codec baseline disables accelerators and decoder policy limits. Candidate
limits are raised above these small samples; no comparison intentionally disables a
checksum or accepts a partial read. All regular/hardlink data is read to EOF.
The container adapter concatenates payloads in native entry order. This exposes link
projection differences, but does not compare full metadata, duplicate-name resolution,
or extraction policy. Those remain required before any integration. A matching payload
hash does not prove matching metadata or exception type.

| Candidate | Same bytes | Both refuse | Only archivey accepts | Only candidate accepts | Different bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| cramjam | 260 | 3,460 | 12 | 4 | 0 |
| unpackio | 363 | 7,662 | 96 | 108 | 161 |

The 161 two-sided byte differences are 91 RPM, 67 newc and three Debian cases. They
include valid inputs: the minimal adapters do not reconstruct hardlink data, and newc
also has a different native entry order. They are **wrapper/format-model differences**,
not 161 independent codec corruptions. Conversely, candidate-only acceptance on damaged
Debian/Zstandard includes changed file content and is an integrity defect for the
proposed backend. The categories must not be combined into a generic “corruption rate”.
Snappy has no archivey baseline; roundtrip and checksum probes are kept separate.
The raw-LZ4 comparison uses the `lz4.block` primitive used by mozlz4, without its outer
header/length checks, and is identified as such.

### Every difference is saved

[`results/differences.zip`](../../scripts/investigations/codec_libraries/results/differences.zip)
holds one original `.bin` per observed difference, plus `differences.json` with the
library, mutation, both acceptance decisions, output length/SHA-256 or exception class
and message. It includes the stricter-refusal direction too. `replay.py --all` reads
these entries directly without filesystem extraction. The standalone
[`repros/`](../../scripts/investigations/codec_libraries/repros/) contains small
examples and the explicit checksum probes. Fixture-derived inputs retain the origin in
their family name; originals and their provenance live in `tests/fixtures/`.

| Break family | Cases | Repro / implication |
| --- | ---: | --- |
| cramjam raw DEFLATE | 2 | `cramjam-deflate-flip-18-12.bin`, `flip-46-23.bin`; invalid distance accepted |
| cramjam size-prefixed LZ4 block | 2 | cuts 35 and 299; 29/1,126 bytes returned against declared 2,048 |
| unpackio `.Z` | 50 | `unpackio-unix_compress-cut-10.bin` and saved cuts; incomplete LZW tail accepted |
| unpackio ZIP-LZMA archive | 1 | `unpackio-zip_lzma-flip-20-444.bin`; central-directory offset damage accepted |
| unpackio 7z-LZMA archive | 1 | saved `7z_lzma-flip-17-452.bin`; archivey's LZMA header decode refuses |
| unpackio Debian/Zstandard | 56 | `unpackio-deb_hello-zstd-flip-0-2292.bin` and saved flips; checksum not enforced |
| unpackio hardlink/order projection | 161 | RPM/newc/Debian inputs; native bytes need archivey reconstruction |

For raw DEFLATE, archivey reports “invalid distance too far back”; cramjam returns
2,069 or 2,055 bytes for the two damaged 2,048-byte originals. A caller's later CRC may
catch this in ZIP, but there need not be a CRC in every raw-codec use. A fallback only
on candidate failure cannot catch a successful bad decode. Running Python again on
every successful decode would remove most reason to accelerate it.

For `.Z`, archivey raises `TruncatedError` for nonzero leftover bits after the last
complete LZW code. Unpackio returns a prefix with no error. Its checksum-free format
cannot let an outer wrapper infer the lost bytes. This repeats the class of failure
that ruled out libarchive for `.Z`.

For Debian, unpackio 0.1.1's package path calls `decode_zstd`, which drives ruzstd
through `decode_reader` without comparing calculated and stored frame checksums.
Its standalone stream path explicitly compares them. The targeted bad-checksum
standalone probe is refused by both libraries, while the package mutations can change
member bytes without raising. Existing package-level digests may catch some RPM damage,
but do not repair the common payload decoder for Debian or a forged container digest.
This is a layer-specific result, not a claim that ruzstd never supports checksums.

The remaining stricter cases include trailer/padding/concatenation policy, ZIP
local/central disagreements, a valid uncompressed RPM fixture refused as gzip, valid
CPIO CRC symlink data refused, and valid py7zr Brotli data refused in 7z. Retrying the
current backend can repair many refusals. It cannot repair candidate success on damage.
Even when both refuse, native error classes differ; the report does not count a
shared “refuse” decision as an error-taxonomy pass.

## Cross-reading the libraries' own tests

**Measured after reading the released test sources:** `upstream_corpus.py` executes
unpackio 0.1.1's complete Python binding suite and captures each byte/path input before
its native open. It keeps the original assertions, callbacks, passwords and limits
for that suite. All **23 tests pass**, with no skips. Captured inputs are deduplicated,
then fully read independently through archivey and unpackio, without the individual
test's cancellation or deliberately low resource limits. This separates an API-limit
test from the archive's validity. Whole output hashes and acceptance are compared;
this is not a full comparison of every metadata field.

For cramjam, the script reads all seven committed integration files from
`tests/test_integration.py`, including the independent-producer fixture corpus. It also
uses `sample` and the compress/flush/finish sequence from
`tests/test_streaming_semantics.py` for all seven tested streaming compressors.
The file named `plaintext.txt.lzma` contains XZ magic; it must be read as XZ, exactly as
upstream's `xz` auto-decoder does. Treating that filename as LZMA Alone would be a
harness error, not an archivey defect. Cramjam's full Hypothesis/numpy suite and
unpackio's Rust test binaries were not executed. Four shipped Rust ARJ reference
archives are cross-read as bytes, and all four agree.

| Source corpus | Cases | Same bytes | Both refuse | Only candidate accepts |
| --- | ---: | ---: | ---: | ---: |
| cramjam integration and completed flush streams | 14 | 13 | 0 | 1 |
| unpackio captured binding inputs and Rust ARJ fixtures | 51 | 35 | 14 | 2 |

The complete outcomes and test-method origins are in `results/upstream-corpus.json`.
`results/upstream-corpus.zip` holds all 65 exact input files plus triage controls, the
upstream unittest log and the relevant upstream license notices. Three individual
differences are also in `repros/upstream-*`. The only differences in this corpus are:

- **Snappy:** archivey has no decoder. This confirms the proposed `.sz` follow-up with
  an upstream integration fixture, rather than just a self-roundtrip.
- **Mixed CPIO record formats:** unpackio's own `cpio_archive()` puts a CRC-newc record
  before ordinary newc records in one archive. Archivey refuses the change at byte 132.
  GNU cpio 2.15 also refuses it, reporting premature EOF after the first entry, both
  before and after padding the archive to 512 bytes. A uniform-newc control reads in
  both archivey and GNU cpio. The upstream test's acceptance does not establish that
  archivey should support this mixture. Retain the refusal under DR-6.
- **Synthetic RPM:** unpackio's `rpm_archive()` declares the literal compressor `none`.
  Archivey recognizes uncompressed RPM using absent/`identity`/`ufdio` tags. This is not
  evidence that uncompressed RPM is missing. Changing the synthetic tag to `identity`
  exposes another mismatch: the fixture supplies three file modes but no on-disk file
  list archivey recognizes. It uses extension tag 5000, while rpm's header defines
  `OLDFILENAMES=1027` or the normal 1116/1117/1118 directory/basename arrays. Unpackio
  then refuses `identity`, so neither adapter can turn this constructor into a shared
  positive oracle by changing one tag. Do not loosen header validation from this
  fixture. Revisit a literal `none` alias only with a real-producer RPM and rpm-tool
  evidence; it is not an established archivey defect here.

The CPIO tool/version/command and captured failure are in `results/gnu-cpio.json`. The
RPM distinction is **read evidence** from [rpm's tag
definitions](https://github.com/rpm-software-management/rpm/blob/master/include/rpm/rpmtag.h)
(read blob `89b0e69ed2db34e6bbe1fcf35bb9374c050e2c74`) and archivey's existing
compressor/file-list checks. No literal-`none` real-producer interoperability claim is
made. These source fixtures found no confirmed new archivey defect. They reinforce the
Snappy opportunity and the need to keep validity checks independent of a candidate's
tests. This investigation records support/fix decisions; it does not change `src/`.

## Memory and performance

**Measured:** the tables use the median of five complete, byte-checked decodes.
Generated inputs are 4 KiB and 8 MiB. Large input mixes repeated text with fresh seeded
binary blocks, so its compressed bytes cross 64 KiB boundaries. Small input repeats one
mixed block. This is one compressibility profile, not a workload distribution. Timings
ran after the full test suite finished. Imports and payload creation are outside timing;
Python result copies, parsing and integrity checks are included. No disk I/O is timed.
The source/version snapshot is `results/environment.json`.

“Streaming” below means 64 KiB input chunks for cramjam, 64 KiB output reads for
archivey, and native callbacks for unpackio. Unpackio still receives complete input.
The container baseline opens random access in both columns; bounded output reads do not
claim forward-only source support. Refused calls have no speed ratio. Small compressed
inputs often fit in one call and therefore hide cramjam's missing incremental state.
`probes.py` also tests each stream split in half, independent of its compressed size.

| Library / codec | Small ratio | Large ratio | Large archivey MB/s | Large candidate MB/s | Large streaming ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| cramjam gzip | 20.20x | 1.14x | 987.5 | 1129.2 | refused |
| cramjam zlib | 8.16x | 1.26x | 911.1 | 1143.8 | refused |
| cramjam deflate | 9.57x | 0.97x | 1246.3 | 1204.0 | refused |
| cramjam bzip2 | 7.60x | 1.06x | 47.3 | 50.1 | refused |
| cramjam xz | 12.11x | 0.39x | 197.4 | 77.8 | refused |
| cramjam lzma_alone | 10.29x | 0.44x | 185.7 | 81.9 | refused |
| cramjam zstd | 7.05x | 1.39x | 4592.5 | 6376.2 | refused |
| cramjam lz4 | 5.21x | 1.18x | 1360.9 | 1609.3 | refused |
| cramjam brotli | 4.99x | 0.66x | 1337.8 | 884.6 | refused |
| cramjam snappy | n/m | n/m | — | 3728.3 | refused |
| cramjam snappy_raw | n/m | n/m | — | 8570.8 | n/m |
| cramjam lz4_block | 0.65x | 0.75x | 15782.0 | 11914.2 | 0.83x |
| unpackio zstd | 12.81x | 0.87x | 3490.7 | 3036.5 | 0.89x |
| unpackio lz4 | 16.84x | 2.06x | 1174.8 | 2417.7 | 2.21x |
| unpackio unix_compress | 3.16x | 2.14x | 18.2 | 39.0 | 2.56x |
| unpackio zip_stored | 43.64x | 0.24x | 1563.7 | 379.1 | 0.12x |
| unpackio zip_deflate | 16.24x | 0.41x | 803.3 | 328.7 | 0.42x |
| unpackio zip_bzip2 | 11.32x | 1.18x | 42.8 | 50.5 | 1.18x |
| unpackio zip_lzma | 11.12x | 0.21x | 204.0 | 42.1 | 0.26x |
| unpackio 7z | 18.89x | 0.23x | 180.8 | 41.9 | 0.23x |
| unpackio 7z_copy | 29.91x | 0.28x | 1535.6 | 429.2 | 0.23x |
| unpackio 7z_lzma | 20.72x | 0.22x | 203.7 | 45.1 | 0.22x |
| unpackio 7z_deflate | 33.66x | 0.46x | 655.1 | 302.5 | 0.45x |
| unpackio 7z_bzip2 | 17.28x | 0.95x | 45.4 | 43.1 | 1.11x |
| unpackio 7z_ppmd | 1.61x | refused | 9.0 | — | refused |
| unpackio 7z_brotli | refused | refused | 802.7 | — | refused |
| unpackio 7z_zstd | 36.13x | 0.29x | 1497.0 | 432.2 | 0.30x |

Ratios above 1 favor the candidate. `n/m` means no baseline, and “refused” includes
unsupported incremental APIs. Raw Snappy and raw LZ4 have no incremental binding in this
adapter; their repeated one-shot timing is not evidence of streaming support.

The large 7z/PPMd input passes archivey but unpackio raises
`FormatError: PPMd SEE summary overflows`. Both whole-result and callback calls fail.
Its small fixture passes. Thus even the attractive small-member child-startup saving
needs a valid-data fix upstream before a PPMd kernel integration. The deterministic
`7z_ppmd` producer and payload generator reproduce this case. A smaller 256 KiB input
reproduces the same refusal in `repros/ppmd-valid-refused.7z`. Official 7-Zip 26.05
decodes it with exit 0 and exactly the expected 262,144 bytes and SHA-256, as archivey
does. The oracle was built with the repository script at
`b88c6bc09339de32f7d18bbab900686b244f42ba`; `results/ppmd-oracle.json` and
`probes.py --sevenzip <7zz>` record the comparison. Valid py7zr Brotli archives are also
refused.

Real-producer fixture timings below read **regular-member payloads only**, with byte
comparison. The differential tests separately include hardlink reads. This avoids
reporting a speedup for omitting hardlink reconstruction. CPIO binary/odc still have
payload-model differences and receive no ratio. Their fixture input sizes range from
about 6 KiB to 36 KiB; ARJ expands to about 53 KiB. No large RPM/Debian/CPIO/ARJ
producer benchmark is claimed. Native format parsing contributes to these ratios, which
are not raw-codec speedups or permission to replace Python parsers.

| unpackio fixture | Archivey MB/s | Candidate MB/s | Whole-result ratio | Callback ratio |
| --- | ---: | ---: | ---: | ---: |
| rpm_payload-bzip2 | 14.4 | 63.7 | 4.42x | 3.99x |
| rpm_payload-gzip | 21.3 | 199.2 | 9.35x | 8.73x |
| rpm_payload-lzma | 12.0 | 36.3 | 3.01x | 6.29x |
| rpm_payload-none | 14.7 | — | refused | refused |
| rpm_payload-xz | 15.2 | 56.4 | 3.71x | 4.05x |
| rpm_payload-zstd | 22.1 | 189.3 | 8.58x | 9.25x |
| deb_hello-gzip | 1.2 | 46.6 | 40.04x | 44.82x |
| deb_hello-xz | 1.1 | 11.5 | 10.14x | 12.29x |
| deb_hello-zstd | 1.2 | 70.4 | 58.19x | 51.32x |
| cpio_gnu-bin | 46.4 | — | differs | differs |
| cpio_gnu-crc | 34.5 | — | refused | refused |
| cpio_gnu-newc | 50.2 | 2458.0 | 49.01x | 17.51x |
| cpio_gnu-odc | 33.8 | — | differs | differs |
| arj_method1 | 8.7 | 80.0 | 9.20x | 14.18x |
| arj_method2 | 18.8 | 109.9 | 5.85x | 9.27x |
| arj_method3 | 12.1 | 114.2 | 9.41x | 11.49x |
| arj_method4 | 12.4 | 144.3 | 11.65x | 10.16x |
| 7z_riscv_lzma2 | 24.8 | 32.4 | 1.31x | 1.21x |
| 7z_riscv_offset_lzma2 | 24.2 | 31.8 | 1.31x | 1.21x |
| 7z_riscv_special_lzma2 | 3.7 | 14.6 | 3.91x | 4.02x |

Fresh-process import latency, median of nine, excludes interpreter startup and uses warm
filesystem caches. Wheel sizes are PyPI's compressed x86-64 Linux download bytes.

| Library | Import ms | Wheel bytes |
| --- | ---: | ---: |
| archivey | 164.17 | not a candidate wheel |
| cramjam | 1.02 | 1,961,119 |
| unpackio | 0.75 | 1,009,675 |

### Output bounds and peak resident memory

**Measured:** fresh child processes decode 16 MiB of zeros from compressed files.
The baseline requests 128 output bytes, then drains in 64 KiB reads. Cramjam's ordinary
call requests `output_len=128`; it returns all 16 MiB. Separate `_into` children receive
a fixed 128-byte bytearray and fail when it fills. That bounds writes before a full
result is produced, but discards progress and cannot implement a resumable `max_length`.
Unpackio is tested with both a 128-byte total/entry output cap and default limits.

The table reports Linux `/proc/self/status` VmHWM observations in MiB, including imports
and allocator overhead. `getrusage` can inherit a pre-exec high-water mark from the
parent and is deliberately not used for this table. These are measured process peaks,
not allocations attributed to one function. The benchmark parent and any decoder child
are not combined into a process-tree total. Bzip2's native block working memory can be
large even when archivey returns only 128 output bytes.

| Codec | Archivey peak MiB | cramjam full-call peak MiB | cramjam fixed-buffer peak MiB |
| --- | ---: | ---: | ---: |
| gzip | 47.5 | 66.2 | 50.5 |
| zlib | 47.3 | 66.4 | 49.4 |
| deflate | 47.3 | 66.4 | 49.8 |
| bzip2 | 65.2 | 67.2 | 51.4 |
| xz | 55.2 | 74.2 | 50.7 |
| lzma_alone | 55.5 | 74.1 | 50.4 |
| zstd | 49.9 | 69.2 | 50.8 |
| lz4 | 47.9 | 66.5 | 49.7 |
| brotli | 52.1 | 70.0 | 54.4 |

With a 128-byte output cap, unpackio refuses the LZ4/Zstd streams and ZIP/7z archives
before delivering a callback. `.Z` refuses during bounded decode. Default-limit tests
cancel at the first callback; cancellation is correctly reported, but ZIP and 7z have
already allocated the decoded payload. Callback chunk size alone is not a memory cap.

| unpackio default-limit first callback | Bytes delivered | RSS increase before callback, MiB |
| --- | ---: | ---: |
| zstd | 4096 | 4.7 |
| lz4 | 4096 | 0.6 |
| unix_compress | 1 | 0.6 |
| zip_deflate | 4096 | 16.5 |
| 7z | 8192 | 16.5 |

Standalone unpackio streams can decode incrementally to a sink once input is retained;
the archive surfaces buffer payloads. Archivey cannot turn a 128-byte *total* output cap
into a 128-byte *per-call* output cap by repeatedly reopening the same archive. Input
retention, allocation preflight, exact error behavior and restart/seek support still
need their own wrapper contracts.


## Packaging, licenses and maintenance

**Read from PyPI, source and public issues.** The complete artifact matrix, file hashes,
upload dates and metadata are saved in
[`results/packaging.json`](../../scripts/investigations/codec_libraries/results/packaging.json).
The sdist SHA-256 and selected lockfile paths are in
[`results/sources.json`](../../scripts/investigations/codec_libraries/results/sources.json).
An sdist lockfile is source evidence for the release build, not a reverse-engineered
proof of every object linked into every published wheel.

| Property | cramjam 2.14.0 | unpackio 0.1.1 |
| --- | --- | --- |
| Python floor | >=3.11 | >=3.9 |
| Extension ABI | per interpreter/version, not abi3 | `cp39-abi3` |
| CPython wheels | 3.11–3.15, including 3.14t/3.15t | abi3 floor 3.9; upstream tested 3.12–3.14 |
| PyPy | PyPy 3.11 wheels (`pypy311_pp73`) | no PyPy wheels |
| Free-threaded | 3.14t import keeps GIL disabled on measured Linux wheel | no free-threaded wheel tags; abi3 is not a free-threaded guarantee |
| Linux | glibc x86-64/aarch64/i686/armv7/ppc64le/s390x/riscv64 | glibc x86-64/aarch64, manylinux2014 |
| musl | x86-64/aarch64/i686/armv7 wheels | no musllinux wheels |
| macOS | x86-64, ARM64, universal2 | x86-64, ARM64 |
| Windows | x86-64, ARM64, x86 | x86-64, ARM64 |
| Other | two Emscripten/Pyodide artifacts | no additional platform wheels |
| sdist | Rust >=1.85, Cargo, maturin; C toolchain for bundled C codecs | Rust >=1.85, Cargo, pinned maturin 1.13.3 |
| Python runtime dependencies | none in base; separate pure-Rust extra | none |
| Release history | published since 2020; 2.12 Aug, 2.13 Sep, 2.14 Oct 2026 | 0.1.0 July 22 and 0.1.1 July 23, 2026 |

The cramjam matrix has 126 wheels plus an sdist; unpackio has six wheels plus an sdist.
The PyPy tags, architecture exclusions and platform floors are authoritative in the
saved filenames; a platform family row does not promise every interpreter/arch pairing.
ABI3 reduces unpackio's wheel count but does not establish support for PyPy or GIL-free
CPython. Both detach the interpreter for native work and reattach for Python callbacks;
that is separate from whether importing the extension enables the GIL on a free-threaded
build. A Linux CPython 3.14.10t import of cramjam 2.14.0 kept
`sys._is_gil_enabled()` false before and after import. The reproducible
`runtime_probe.py` result is saved in `results/free-threaded-import.json`. This tests
import behavior only, not concurrent decoding. Unpackio was not runtime-tested on a
free-threaded interpreter.

### License inventory

Both projects are MIT. Unpackio's NOTICE additionally identifies adapted BSD-3-Clause
bodgit/sevenzip, ulikunitz/xz and NetBSD zopen code, MIT PPMd and rpmfile tables,
Apache-2.0 Deflate64/unarj adaptation, and 0BSD XZ filter descriptions. Its ARJ-4 source
metadata/license discrepancy is handled conservatively as Apache-2.0 in its NOTICE.
RustCrypto and codec dependencies are permissively licensed, but redistribution must
preserve the relevant notices. Its source forbids linking libarchive/7-Zip as fallback.

Cramjam's default native bundles include LZ4 1.10.0 (BSD-2-Clause library), libbzip2
1.0.8 (bzip2 license), liblzma 5.2.5 (public-domain library code in this source
release), and Zstandard 1.5.7 (BSD-3-Clause or GPL-2.0 option). The xz source archive
also contains GPL/LGPL tools and documentation; that is not a claim those tools are
linked into the wheel. The flate2/miniz and Rust Snappy/Brotli portions carry their own
permissive notices. Optional ISA-L uses BSD-3-Clause; optional Blosc2 has additional
bundled-code notices and is outside the measured default build. The wheel itself is not
proof that all bundled-source license texts are present or complete.

[`results/lockfile-licenses.json`](../../scripts/investigations/codec_libraries/results/lockfile-licenses.json)
records **every registry package in both shipped lockfiles**, exact version and registry
license declaration: 126 cramjam entries and 54 unpackio entries, with no lookup
failure. It deliberately includes build/test/disabled-feature/platform-only packages,
not just linked runtime objects. For example, cramjam's build tooling includes MPL-2.0
`cbindgen`; the lockfiles also contain Unicode-3.0 and LLVM-exception expressions.
Inspect which features ship before redistributing or replacing dependencies. This is a
reproducible inventory, not legal advice or a completed binary license audit.

### Maintenance and security evidence

Cramjam names Miles Granger as author/maintainer and has a multi-year release history.
Unpackio is maintained in bwhitn's repository; its Python metadata has an empty authors
list, its classifier is Pre-Alpha, and only two released versions exist. Current
unreleased main is active, but does not inherit the released wheel's measurements.
A single umbrella package can reduce Python dependency names while increasing the
codec versions and wheel matrix that one project must maintain. It does not remove
transitive Rust/C dependencies or the need to update vulnerable bundles.

Public open-issue searches for security, crashes, corruption and CVEs found cramjam
[#201](https://github.com/milesgranger/cramjam/issues/201), a report of flaky possible
data corruption in distribution tests, and
[#259](https://github.com/milesgranger/cramjam/issues/259), compressor lifecycle
behavior. The latter explicitly says it has no security impact. No matching open
unpackio issue was returned. This is a public search result, not proof that either
dependency graph has no vulnerability. No upstream issue was filed by this
investigation. Cramjam's C-backed codecs remain subject to the native-isolation
assessment; unpackio's safe local code reduces some risks but cannot substitute for a
damaged-input parity proof.

## Other benefits, costs and ranked follow-ups

1. **Retain current backends and use these repros as integration gates.** The silent
   DEFLATE, `.Z` and package-Zstd cases block a general accelerator. Tightening error
   mapping alone cannot fix them. Draft focused upstream reports with the saved inputs;
   the maintainer files upstream reports under the repository policy.
2. **Evaluate a bounded `.sz` plugin using cramjam's Snappy chunk primitive.** This is
   the clearest new capability. Add independent producer fixtures, framed/raw checksum
   and prefix tests, skippable/mandatory chunk cases, concatenation and bomb preflight.
   Compare a direct Snappy binding too; an umbrella dependency is a cost for one codec.
3. **Ask unpackio upstream for stable raw codec interfaces.** Prioritize PPMd7,
   Deflate64, ARJ-4/LH6 and selected Python filters. Require bounded incremental I/O,
   structured errors and per-codec memory preflight. Benchmark kernels separately from
   full-folder copies and the existing child startup cost. Do not fork a container
   reader merely to reach a decoder.
4. **Re-evaluate a released unpackio 0.2.x on its own artifacts.** ZIP JPEG/WavPack may
   add uncommon methods archivey lacks. Keep Python headers and evaluate codec-only
   access, license provenance, positive producer coverage and strict malformed input.
   Unreleased support tables are not a reason to weaken DR-20.
5. **Keep the upstream corpus as a support/refusal check.** Retain mixed-CPIO and
   malformed/incomplete RPM refusal unless producer/tool evidence changes the result.
   The valid large PPMd refusal also needs an upstream fix before a kernel experiment.
6. **Measure alternative runtimes only for a concrete integration.** Cramjam's PyPy and
   free-threaded wheels are a packaging benefit; no PyPy speedup is measured here.
   Include process startup, small-member latency, seek/restart costs and wheel gaps.

Cramjam could supply compression if archive writing returns to scope, but archivey's
current read-only API does not need a compressor and unpackio intentionally has none.
Neither package adds the missing LZX/Quantum/LZO/bzip3 breadth that could justify an
umbrella dependency for archivey's pure-Python slow paths. Unpackio's solid-folder batch
API and cancellation/work budgets are useful design references even without integration.
Neither provides archivey's restart-point/seek-index behavior through the released
Python decoder interfaces. Fewer import names and faster valid decodes do not outweigh
changed acceptance, output, errors, or memory behavior.

## Repository validation

`./scripts/check.sh --fix` passes formatting, lint, both type checkers, script tests
(524 pass, one skip), API surface, documentation and the repository's OpenSpec static
checks. After installing the missing OpenSpec 1.4.1 CLI in the workspace, its
`validate --all` reports 21 failed items, mostly requirement text lacking SHALL/MUST.
The same failed items and issue details occur on the untouched base commit; no specs
are changed here. `review_prep.py` reports no stale references or over-wide prose.

`./scripts/test.sh -n 4` completes with 23,307 passes, 2,650 skips and 11 failures.
A focused run of those 11 node IDs on a detached clean base reproduces ten failures:
filesystem-mode expectations and rapidgzip child reuse/peak-reset tests. The remaining
failure is a native PPMd pytest-worker crash in the full run; that test passes in the
focused base run. This is not a claim that the full suite passed. The full run lacked
RAR/7-Zip system tools and optional external corpora; 7zz was built later for the
independent PPMd oracle. The three dependency configurations were not rerun because no
shipped code or dependencies change. The pinned investigation environment and the
results above do not test a proposed production wrapper.

All 381 mutation differences replay unchanged. The complete unpackio Python binding
suite passes all 23 tests, and its captured inputs plus the cramjam/Rust fixtures give
65 cross-reads. `results/validation.json` records the gate results and the unchanged
OpenSpec failures. No library fix or new backend is included in this PR.
