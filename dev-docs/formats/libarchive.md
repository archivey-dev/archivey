# archivey-libarchive

Current maintainer truth for `packages/archivey-libarchive`, the separate distribution that
reads formats through the system libarchive. Today it registers one format, LHA. It is the
first package built on `archivey.formats` from outside `src/archivey`, so it uses only the
public plugin API.

## At a glance

| | |
| --- | --- |
| Distribution | `archivey-libarchive`, import name `archivey_libarchive`, version in lockstep with archivey and pinned to it with `==` |
| Registers | `LHA` (`.lzh`, `.lha`; magic: the method id, such as `-lh5-`, at offset 2) via `archivey_libarchive.register()` |
| Library | The system libarchive, 3.6 or later, through the package's own ctypes bindings (`_libarchive.py`). `LIBARCHIVE` names another file. Not bundled |
| Process | A child process per walk (`_worker.py`), unless `process_isolation` is `NONE` |
| Reader | `SequentialReader` with `MemberSpan.data`: one forward pass, `is_solid=True`, so an out-of-order read walks again |
| Checks | libarchive's per-member CRC-16 (`checked=True`); no `hashes` |
| Errors | Mapped from libarchive's message: "truncated" → `TruncatedError`, "unsupported" → `UnsupportedFeatureError`, `ENOMEM` → `ResourceUnavailableError`, anything else → `CorruptionError` |
| Tests | `packages/archivey-libarchive/tests`, in their own pytest run (registration is process-wide); CI runs them on the Linux `[all]` legs, and `scripts/test.sh` after the main suite |

## Decisions (davi, 2026-11-06/07)

- A separate package, not in archivey: it needs a C library the user installs, and it
  reads with weaker guarantees than archivey's own readers.
- Own ctypes bindings, not `libarchive-c`: `libarchive-c` logs `ARCHIVE_WARN` and carries on,
  which is how libarchive reports a CRC mismatch, and it decodes names through the wide-char
  call, which fails on names that are not UTF-8.
- libarchive runs in a child process.
- System libarchive only for now. Bundled wheels, falling back to libarchive when a native
  reader refuses a file, and libarchive as a RAR backend come later.
- Only formats archivey has no reader for. RPM, deb, CAB and XAR have native readers, so the
  plugin registers none of them.

## The child process

`_client.ChildSession` starts `python -I -c` with the package's directory on `sys.path`
and imports `archivey_libarchive._worker`, which imports only the standard library (the
package's `__init__` loads its archivey names lazily for that reason). The two sides speak
`_protocol.py`: a tag byte, a 4-byte length and a payload, with JSON for headers and errors
and raw bytes for data. Nothing is unpickled, so a child that a crafted archive takes over
can send only bytes the parent checks: message size (1 MiB plus a little), tags, JSON shape,
no more data than asked for, and input requests of at most 64 KiB (`Session.CHUNK`), so it
cannot make the parent buffer the source.

The read is lockstep. The parent sends a request; while serving it the child may send `N`
(need input), and the parent answers with the next bytes from the `ForwardStream`. So no
thread reads the source behind archivey's back, and a pipe works.

A child that ends by a signal raises `CorruptionError`, except SIGKILL (most often the
out-of-memory killer), which raises `ResourceUnavailableError`, as for archivey's own decoder
children. One that cannot start raises `ResourceUnavailableError` naming
`ProcessIsolation.NONE`. A child is not reused: each walk starts one, about 45 ms on one Linux machine
(start-up, import, open, first header, quit).

## Not shipped

- **WARC.** libarchive 3.7.2 appends four NUL bytes to every record's data (`bsdtar -xO` shows
  them), and a record read only to its listed size leaves the next one misread. archivey
  would refuse every record as longer than its size.
- **`DecoderLimits`** do not reach inside libarchive. The child has no memory limit of its
  own yet.
- **Release and publish.** `scripts/release/release.py` and `publish.yml` do not bump or
  upload the package yet; the first upload needs a PyPI pending publisher for the new name.
  The user docs (`docs/`) do not mention it until it is on PyPI.

## What libarchive converts or makes up

libarchive hands over an LHA entry already interpreted. The session (`_libarchive.py`,
the same code in the child and in-process) keeps the last 256 KiB of input it fed
libarchive and reads the header's own bytes back at `archive_read_header_position` (or at
the first method id after it, past junk), to undo three of those interpretations.

- **Names and the locale.** libarchive turns names into wide characters through the C
  library's locale, so under `LC_ALL=C` a CP932 name fails. Each call into libarchive runs
  with a UTF-8 `LC_CTYPE` set for its thread only (`uselocale`, `C.UTF-8` or the first
  UTF-8 locale found), which leaves an in-process caller's locale alone, and names are
  read through the `*_utf8` getters.
- **`encoding=`.** Without it, libarchive reads a level-0/1 name as UTF-8 when it is valid
  and as CP932 otherwise; a name that is neither fails the header with no message (the
  reader says `encoding=` is needed). With it, the session sets libarchive's `hdrcharset`
  to that charset, and libarchive then decodes every such name with it, valid UTF-8 too.
  The reader encodes each name back with `encoding=` to recover the stored bytes, so
  `ReaderContext.decode_name` applies the rule of every format: valid UTF-8 wins.
  Names whose charset the header itself records (UTF-16, a code page) do not take
  `hdrcharset`; encoding those back gives bytes in `encoding=`, not the stored ones, as
  `raw_name`. A charset libarchive's iconv lacks is `UnsupportedFeatureError` at open.
- **Times.** Levels 0 and 1 store a DOS local time, which libarchive turns into a
  timestamp with `mktime` in the host's time zone. When libarchive's time equals `mktime`
  of the header's DOS fields in the same process (no Unix or Windows time replaced it), the
  reader reports the DOS fields as a naive datetime, as ZIP does; otherwise the time is
  UTC.
- **Mode and owner.** When a header stores no Unix mode, libarchive makes one up (0777 for
  a directory, 0666 otherwise, without write bits for the DOS read-only attribute), and uid
  and gid 0 when it stores no owner. The session walks the header's extended records as
  libarchive does (level 0: LHa for UNIX's 12-byte `U` extension; levels 1-3: records
  `0x50`, `0x51`, `0x7F`, `0xFF`) and the reader reports `None` for what is not stored.


## Verify

- `packages/archivey-libarchive/tests/test_lha.py`: libarchive's own LHA test archives
  (header levels 0 to 3, `-lh5-`, `-lh6-`, `-lh7-`, CP932 and UTF-16 names, trailing junk)
  under every isolation mode, a stored archive built in the test, a flipped byte failing the
  CRC, truncation, a pipe, `.lzh.gz`, children that crash, are killed, break the protocol,
  ask for too much input or cannot start, and a missing libarchive. Names under
  `LC_ALL=C`, a Latin-1 name with and without `encoding=`, a DOS time under three time
  zones, and mode and owner stored or made up.
