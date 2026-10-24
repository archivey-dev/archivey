# Security

Archivey treats everything in an archive as untrusted: names, link targets, sizes and the
compressed data itself. Whatever an archive contains, extraction writes only inside the
destination folder, the limits cap how much an extraction writes and how much memory a decoder
may ask for, and damaged data raises an `ArchiveyError`. This page covers what archivey assumes
about everything else, and where those guarantees stop.

## What archivey relies on

Archivey checks each path in the destination right before writing to it, so a folder that another
program swaps for a link between two files is caught. A program that swaps a folder at exactly the
right moment could still redirect a write outside the destination, so the guarantee holds fully only
for a folder that untrusted programs can't write to.

If the archive changes while it's open, reads may fail or return a mix of old and new data, but the
guarantees at the top of this page still hold.

A folder opened as a source gets extra checks, because its entries can be replaced by other kinds of
file. A read never follows a link out of the folder or hangs on a pipe put in a file's place, and a
file that was replaced or changed size since the listing is refused. On a filesystem that doesn't
report file identities, such as some network and FUSE mounts, a file replaced by another of the same
size isn't caught, and the replacement can be a hard link to a file elsewhere on that filesystem.
Everywhere else, the most you get is content written after the folder was listed.

Archivey also trusts the optional packages and programs it uses, such as `unrar` for RAR data, not
to be malicious. It doesn't count on them to handle every input: when one fails, you get an
`ArchiveyError` like any other damaged data, except in the cases below.

## Where the guarantees stop

- **A crash in native code can take your process with it.** Decoders written in C, such as the
  standard library's zlib, bz2 and lzma, run inside your process. Archivey runs the decoders known
  to crash in a child process: rapidgzip, and pyppmd for every member compressed with PPMd, a
  method some 7z and ZIP archives use. A crash nobody has found yet in another decoder would still
  abort yours, unless you [run every decoder in a child process](#decoders-in-a-child-process).

    ??? note "Why every PPMd member?"
        pyppmd, the PPMd decoder, can crash when it's asked to keep decoding after a damaged
        stream has ended early, and a wrong password or a crafted member gets it there. Archivey
        stops asking once it sees the end, but stopping a decoder that might still be waiting for
        input takes one more call, and that call can crash it too, on members of any size. In a
        child process the crash becomes a `CorruptionError` for that member. Archivey reuses the
        processes, so each PPMd member costs about 1.4 to 2 ms more than decoding in your
        process. A solid PPMd folder is decoded as one, so it pays that once, plus about 0.1
        to 0.35 ms for each 4 KiB member read from it.

- **Running out of memory raises `MemoryError`, not an `ArchiveyError`,** so it's never mistaken for
  a damaged archive. `DecoderLimits` caps the memory an archive can ask one decoder for, 2 GiB by
  default. Everything else needs memory on top of that: the rest of your program, archivey itself,
  other archives open at the same time, and other members read at once, each with its own decoder.
  If memory is tight, such as in a container or on a server that opens many archives, a lower limit
  makes an archive that asks for too much raise `ResourceLimitError` instead.
- **Nothing limits how long an operation takes.** The limits cap bytes, entries and
  password-hashing work, not time. Raising an exception from `on_progress` stops an extraction, but
  the callback only runs between chunks of written data, so a decompressor that's slow to produce
  the next chunk can't be interrupted. If you need a hard time limit, run archivey in a process you
  can stop. Archivey's exceptions can be pickled, so an error raised in that process comes back
  with its details. For a scan that has to return data, such as member names or hashes, [Stop a
  scan that takes too long](recipes.md#stop-a-scan-that-takes-too-long) runs it in a worker
  process. When only the outcome matters, the simplest way is the command line in a subprocess with
  a timeout:

    ```python
    import subprocess
    import sys

    try:
        subprocess.run(
            [sys.executable, "-m", "archivey", "extract", "archive.7z", "-d", "out"],
            check=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        ...  # the subprocess was killed; "out" may hold some of the files
    except subprocess.CalledProcessError:
        ...  # archivey refused the archive or stopped part-way; it said why on stderr
    ```
- **Reading a member has no size limit.** `read()` returns the whole decompressed member as bytes in
  memory. A stream from `open()` decodes only as much as you ask for, so `stream.read(n)` holds
  about `n` bytes however large the member is, but a `stream.read()` with no size returns the rest
  of the member. `DecoderLimits` is the main limit that applies to a read. It caps the decoder's own
  memory, so the data you read takes additional memory on top. `ExtractionLimits` doesn't apply,
  because it covers only what `extract_all` writes to disk. A RAR archive opened from a file object
  rather than a path is copied to a temporary file the first time a member needs `unrar` or `unar`.
  `spool_limits.max_bytes` caps that copy, along with the few other temporary files archivey makes
  for RAR archives, listed in the table below. When the archive records a member's size in
  `member.size`, archivey never decodes more than that, and a member holding more raises
  `CorruptionError`.
- **A pass that reads members as it goes checks the listing limits as it goes.** On a TAR,
  `stream_members()` yields members up to the limit and then raises, and `extract_all` leaves the
  files it wrote before then on disk. 7z, RAR and ISO archives check the limits before they give you
  any member, with or without `streaming=True`. A ZIP read from a file checks the member count its
  end record declares before any member, and the rest as it reads its index, so an index holding
  more members than its end record says gives you members up to the limit before the error, as a TAR
  does. A ZIP read from a pipe is checked like a TAR as its members arrive, and again on its index
  at the end.
- **A ZIP extracted from a pipe is checked on what it stages before its index arrives.** The pass
  writes each member's data into a private `.archivey-tmp-` folder in the destination, and only the
  index at the end says which members the extraction keeps. The extraction limits count what's
  staged while it's there, so a member that's then not extracted, one your `filter` drops
  included, can still stop the extraction under `max_entries` or `max_extracted_bytes`, where the
  same archive read from a file completes. The name checks and `abort_on` run on each member's
  name as the pass meets it, so a hostile archive is refused before the rest of it is decoded, and
  the extraction can stop for a member the index would have left out. A run that stops before the
  index leaves nothing of its own in the destination.
- **Limits apply to each archive separately.** A small archive can hold archives that each expand
  up to the limit, and those can hold more, so the total grows with every level you extract. Be
  careful if you extract archives found inside other archives.
- **Accelerators are on by default for seekable streams.** If you open an archive with
  `seekable_members=True` and the `seekable` extra is installed, archivey reads bzip2 data of 1 MiB
  or more compressed, and DEFLATE data of 16 MiB or more, through rapidgzip. DEFLATE is the
  compression in gzip files and in most ZIP members. rapidgzip marks places in the stream it can
  restart from as it reads, so a seek jumps to the nearest one instead of decompressing from the
  start. rapidgzip can crash on some damaged data, so it runs in a separate process, for bzip2 too,
  and if it crashes, the standard library's decoder takes over and reports what it finds. To avoid
  it, pass
  `config=archivey.ArchiveyConfig(use_rapidgzip=archivey.AcceleratorMode.OFF,
  use_indexed_bzip2=archivey.AcceleratorMode.OFF)`.

    ??? note "Why a separate process, and why those sizes?"
        The crashes seen so far are in rapidgzip's DEFLATE decoder. Its bzip2 decoder hasn't been
        seen to crash, but it runs in a separate process too as a precaution, since it's part of the
        same library. Archivey's fuzz tests run both and compare their output with the standard
        decoders. Starting that process takes about 45 ms; on Linux, later members of the same archive file reuse it and skip that cost. On a full read, rapidgzip saves about 3.4
        ms per MB of compressed DEFLATE data, so it pays for itself from about 13 MB, and 16 MiB
        keeps it safely past that point. The standard library decodes bzip2 much more slowly, so
        there the process pays for itself between about 0.6 and 2 MiB, depending on how many cores
        you have, and 1 MiB sits between the two.

- **After a seek, a crafted `.xz` or `.lz` file can return different data at a position you've
  already read.** A seek restarts at the block the file's own index names, and a crafted index can
  name the wrong one, so reading again after a seek back can give different bytes from the first
  read, with no error.

    ??? note "Why trust the index?"
        Where a block really ends is known only by decompressing it, and not having to decompress is
        why the index exists. Checking the index first would make every seek decompress from the
        start, on every honest file too.

- **On Windows, a folder source is less protected.** Windows can't open a path without following
  links, so a subfolder swapped for a link during the listing can list files from outside the
  folder. Reading a file still checks it's the one listed where the filesystem reports file
  identities. Where it doesn't, only the last part of the path is checked, after the file is opened,
  so a folder above it swapped for a link can serve a same-size file from outside.

## Decoders in a child process

`ArchiveyConfig(process_isolation=...)` says which decoders run in a child process, where a crash
costs only the member being read:

- **`ProcessIsolation.KNOWN_CRASHES`**, the default, isolates the decoders that have crashed on
  some input: rapidgzip and pyppmd. The decoders it leaves in your process cost nothing extra;
  each PPMd member, or each solid PPMd folder, costs about 1.4 to 2 ms more, and each 4 KiB
  member read from a solid PPMd folder about 0.1 to 0.35 ms, with the copying of larger members
  on top ([why every PPMd member](#where-the-guarantees-stop)). Where no child process can start, such as in a frozen
  application, a PPMd member raises `ResourceUnavailableError`, and rapidgzip gives way to the standard
  library's decoder with one warning.
- **`ProcessIsolation.NATIVE_DECODERS`** also isolates zlib, bz2, lzma, zstd, lz4, brotli and
  inflate64 (Deflate64), detection's trial decodes included. Reads take longer. Measured on one
  Linux machine, a single stream took about 1.05 to 1.5 times as long for bzip2, 1.1 to 1.6 times
  for xz, 1.4 to 2 times for gzip and deflate, and 2 to 6 times for zstd, mostly copying data
  between processes. Each member with a decoder of its own also costs about 0.6 to 1 ms (1.4 to
  2 ms for PPMd), which is most of the cost for an archive of many small members; a solid 7z
  folder is one decoder, plus about 0.1 to 0.3 ms for each 4 KiB member read from it, with the
  copying of larger members on top. Each process
  holds about 9 MB while it waits to be reused. Where no child process can start, reading raises
  `ResourceUnavailableError`; nothing is decoded in your process instead.
  [`scripts/bench_process_isolation.py`](https://github.com/archivey-dev/archivey/blob/main/scripts/bench_process_isolation.py)
  in the repository measures these costs on your machine.
- **`ProcessIsolation.NONE`** decodes everything in your process. It's for trusted files, tests,
  and places that can't start processes. A damaged or crafted PPMd member can crash your process,
  and rapidgzip isn't used.

pyppmd bundles a copy of 7-Zip's PPMd code from before the fix for
[CVE-2023-31102](https://nvd.nist.gov/vuln/detail/CVE-2023-31102), an integer underflow and
invalid read, so it may still have that bug. Under the default, a crash or a wild read there costs
that member, not your process, though a crafted member may still decode to wrong data.

AES decryption and checksums always run in your process. A child that crashes raises
`CorruptionError`, and one killed from outside raises `ResourceUnavailableError` (SIGKILL, most
often the out-of-memory killer) or `ReadError`. No setting limits how long a decoder takes; for that, see
the time-limit recipe [above](#where-the-guarantees-stop).

??? note "Why are processes reused, and what if a member damages one?"
    Starting a process costs 12 to 18 ms, which on an archive of thousands of small members
    would be minutes, so a process that finished a member cleanly decodes the next one. One that
    reported an error, or a PPMd member that ended early, isn't reused. A crash in a reused process
    isn't blamed on the member being read, since an earlier member may have caused it: that member
    is decoded again in a new process, and only a crash there counts. A process decodes at most 64
    members before it's replaced.

## Hardening

RAR data is decompressed by an external program found on your `PATH`: `unrar` or `rar`, or `unar`
when neither is installed. Like the optional packages, it's [trusted not to be
malicious](#what-archivey-relies-on), and archivey checks only that it runs and that archivey works
with its version, which can be several years old. Older versions can have security bugs that later
ones fixed, so an up-to-date version is safer. `unar` receives the password on its command line,
where other users on the same machine can see it while it runs. If you set
`rar_decompressor=RarDecompressor.UNRAR` in `ArchiveyConfig`, archivey never runs `unar`. With
`RarDecompressor.NONE` it runs no external program at all, so stored RAR members still read
(archivey decrypts an encrypted one itself if `cryptography` is installed, and raises
`PackageNotInstalledError` if it isn't), and the rest raise `UnsupportedFeatureError`.

The same goes for the optional packages. The `[recommended]` extra sets minimum versions,
such as brotli 1.2.1 for a decoder buffer overflow that version fixed, but archivey uses a package
that's already installed whatever its version. If one came from somewhere else, such as a system
package, upgrade it, for example with `pip install -U brotli`.

Every limit has a default that lets large legitimate archives through. A higher limit lets a
malicious archive use more memory, disk space or processing time before it's stopped, so if you know
what your archives look like, lower the limits to fit them. They're set in `ArchiveyConfig`, and
`extract_all` also takes `limits=` for one call.
[`scripts/measure_limit_costs.py`](https://github.com/archivey-dev/archivey/blob/main/scripts/measure_limit_costs.py)
in the repository measures what each limit costs in time and memory on your machine.

- **`extraction_limits.max_extracted_bytes`**, default 2 GiB, caps the bytes one extraction writes.
  It costs disk space, plus 5-10 ms per MiB written, 10-20 s at the default.
- **`extraction_limits.max_entries`**, default 262,144, caps the members one extraction writes. It
  costs about 0.6 ms per file written, under 3 minutes at the default.
- **`extraction_limits.max_ratio`**, default 1000, caps how much a member, or the whole archive,
  expands. It's checked as data is written, and for a member whose size and compressed size the
  archive records, before any of it is written. Outputs under 5 MiB, or 256 MiB for a whole archive
  read from a pipe, aren't checked. It has no cost of its own.
- **`listing_limits.max_members`**, default 262,144, caps the members an archive can list. It costs
  about 25-50 µs and 1.5 KiB of memory per member, under 15 s and 384 MiB at the default.
- **`listing_limits.max_metadata_bytes`**, default 64 MiB, caps the text kept for names, comments
  and link targets. A ZIP read from a pipe also keeps up to this much of its small members' data, in
  case they are links, on top of the text. It costs about 1.7 MiB of memory per MiB counted, 110 MiB
  at the default, and up to 64 MiB more for a ZIP read from a pipe.
- **`decoder_limits.max_decoder_memory`**, default 2 GiB, caps the memory an archive can ask a
  decoder for, and the memory of rapidgzip's process for gzip, zlib and DEFLATE. It costs the memory
  itself.
- **`decoder_limits.max_key_derivation_rounds`**, default 2^25, caps the password-hashing work per
  open archive. It costs 0.2-0.7 µs per round, 7-25 s at the default.
- **`decoder_limits.max_ppmd_held_input`**, default 16 MiB, caps the largest PPMd member
  that's held and handed to the decoder whole. A larger one is fed in pieces, where pyppmd can't
  tell a corrupt member that ended from one waiting for more input, the case that can crash it
  and that `process_isolation` keeps in a child process. It costs up to twice the limit in memory
  while a PPMd member decodes, 32 MiB at the default.
- **`spool_limits.max_bytes`**, default 1 GiB, caps the temporary disk space for RAR archives.
  `unrar` and `unar` need the archive as a file, so a RAR opened from a file object is copied, and
  so are volumes archivey can't link into its temporary folder and, for `unar`, an archive with data
  before it. A pass over a solid RAR also keeps the members that later file copies repeat. It costs
  the disk space itself.

The costs were measured on one 2.8 GHz core.

??? note "Why 2^25 rounds?"
    An archive made by the usual tools costs, per password, 2^19 rounds for 7z, 2^18 for RAR3 (a
    fixed cost the archive does not choose), and 2^16 to 2^17 for RAR5. RAR5 asks for 2^15, and
    archivey runs that derivation two or three times: once for the password check, and once each
    for the key checksums are verified with and the key archivey decrypts with, when it needs
    them. A crafted 7z or RAR5 archive can ask for up to 2^24 rounds and repeat that work for each
    member. Two such 7z members use the whole default and a third is refused; one such RAR5
    member already goes over it. Each password you try costs the same work again.

Going over a limit raises `ResourceLimitError`.

For archives from strangers, the default `policy="strict"` refuses or rewrites every kind of unsafe
member archivey knows of. The [policy
table](extracting.md#what-each-policy-does-with-unusual-members) on the Extracting page shows what
each policy does. Untrusted archives should be extracted into an empty folder that nothing else
uses, so you can check what came out before moving it anywhere else.

## Known attacks on other archive tools

Archivey's test suite replays published vulnerabilities of other archive readers that could also
apply to it: path traversal, link and hard link escapes, header parsing bugs, decompression bombs,
structures built to make a reader hang, member names that drive the terminal, and permissions that
leave extracted files writable by others. They come from GNU tar, libarchive, Info-ZIP, 7-Zip,
unrar and WinRAR, py7zr, rarfile, Apache Commons Compress, and Python's `tarfile` and `zipfile`.
Each test builds the archive the advisory describes and checks that archivey refuses it, keeps it
inside the destination, ends it with a typed error rather than a hang, or reads it as the format
defines without allocating more than the archive's size pays for. The decompression libraries
archivey calls have published bugs too: in brotli, zlib, CPython's decompressors and pyppmd. Those
bugs are the libraries' to fix, so the tests for them check archivey's side: how much output one
call may produce, that a decoder that failed is not called again, which decoders run in a child
process, and that archivey's own CRC-32 combining ends for any length. Each test names the advisory
it replays:

- [`tests/test_cve_regressions.py`](https://github.com/archivey-dev/archivey/blob/main/tests/test_cve_regressions.py)
- [`tests/test_cve_regressions_7z_rar.py`](https://github.com/archivey-dev/archivey/blob/main/tests/test_cve_regressions_7z_rar.py)
- [`tests/test_cve_regressions_libarchive.py`](https://github.com/archivey-dev/archivey/blob/main/tests/test_cve_regressions_libarchive.py)
- [`tests/test_cve_regressions_codecs.py`](https://github.com/archivey-dev/archivey/blob/main/tests/test_cve_regressions_codecs.py)
- [`tests/test_cve_parsing.py`](https://github.com/archivey-dev/archivey/blob/main/tests/test_cve_parsing.py)

## Reporting a vulnerability

Please report security problems privately through
[GitHub's private vulnerability reporting](https://github.com/archivey-dev/archivey/security/advisories/new),
not in a public issue. [SECURITY.md](https://github.com/archivey-dev/archivey/blob/main/SECURITY.md) says
what's in scope and what happens after you report. The limits on this page are known and accepted.
If you find one that does more harm than this page describes, please report it.
