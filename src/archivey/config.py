"""Public configuration types for archivey."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar

from archivey.detection_cost import (
    BALANCED_BUDGET,
    DetectionBudget,
    DetectionBudgetPreset,
)
from archivey.diagnostics import DiagnosticPolicy, OnDiagnostic
from archivey.exceptions import ArchiveyUsageError
from archivey.internal.arg_checks import (
    check_callable,
    check_encoding,
    check_instance,
    check_limit,
    check_limit_fields,
)
from archivey.internal.enum_args import coerce_enum
from archivey.types import ArchiveMember


class AcceleratorMode(Enum):
    """Whether to use an optional accelerator that gives seekable streams over a codec."""

    AUTO = "auto"
    """Use it only when seekable streams were asked for (``seekable_members=True`` on
    ``open_archive``, ``seekable=True`` on ``open_stream``), its package is installed,
    and the compressed input is known to be large enough to pay for it:
    :data:`RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE` for gzip, zlib and raw deflate, and
    :data:`INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE` for bzip2. An input of unknown size
    counts as large enough. For gzip, zlib and raw deflate the decompressed size must
    also be known, so that a truncated stream cannot be read short without an error.
    Otherwise the standard library decodes the stream."""
    ON = "on"
    """Always use it. Raises :class:`~archivey.PackageNotInstalledError` when its
    package is not installed."""
    OFF = "off"
    """Never use it. The standard library decodes the stream."""

    def enabled_for(
        self,
        *,
        seekable: bool,
        available: bool,
        input_size: int | None = None,
        min_size: int | None = None,
    ) -> bool:
        """Resolve the tri-state to "use the accelerator?".

        ``ON`` always returns ``True`` (the caller checks availability and raises
        ``PackageNotInstalledError`` if the package is missing — the user asked for it
        explicitly; ``min_size`` is ignored). ``AUTO`` enables it only when
        seekability is declared and the package is available, so a missing package
        falls back silently. When ``min_size`` is set and ``input_size`` is known and
        strictly below that threshold, ``AUTO`` also falls back (tiny members do not
        repay per-stream accelerator setup). Unknown ``input_size`` keeps the
        pre-threshold AUTO behaviour.
        """
        if self is AcceleratorMode.OFF:
            return False
        if self is AcceleratorMode.ON:
            return True
        # AUTO: only pay for seek machinery when the caller asked for seekable streams.
        if not (available and seekable):
            return False
        return not (
            min_size is not None and input_size is not None and input_size < min_size
        )


class ProcessIsolation(Enum):
    """Which native decoders run in a child process, where a crash on hostile input
    costs the member being read instead of the caller's process.

    A decoder in a child process whose process crashes raises
    :class:`~archivey.CorruptionError`; one killed from outside raises
    :class:`~archivey.ResourceUnavailableError` (SIGKILL, most often the out-of-memory killer)
    or :class:`~archivey.ReadError`. Checksums and AES decryption always run in the
    caller's process, and no setting bounds how long a decoder takes.
    """

    KNOWN_CRASHES = "known_crashes"
    """The default: only the decoders seen to crash on some input run in a child
    process: rapidgzip (``use_rapidgzip``, ``use_indexed_bzip2``) and pyppmd (every PPMd
    member). Every other decoder runs in the caller's process. Processes are reused for
    later decoders. Measured on one Linux machine (``scripts/bench_process_isolation.py``),
    each PPMd decoder costs about 1.4 to 2 ms more than in-process: a non-solid 7z of
    1024 PPMd members of 4 KiB took about twice as long. A ZIP member or a non-solid 7z
    member has a decoder of its own. A solid PPMd folder is one decoder for all its
    members: it pays that once, and about 0.1 to 0.35 ms for each 4 KiB member read from
    it; the decoded bytes cross between processes on top of that, at the copying cost
    ``NATIVE_DECODERS`` gives for single streams.
    Where no child process can be started, a PPMd member raises
    :class:`~archivey.ResourceUnavailableError` and rapidgzip under ``AUTO`` falls back to the
    standard library."""
    NATIVE_DECODERS = "native_decoders"
    """Every native decoder runs in a child process: zlib, bz2, lzma, zstd, lz4, brotli,
    inflate64, pyppmd and rapidgzip, including the trial decodes format detection runs.

    Each open decoder has a process of its own, and processes are reused for later
    decoders. Measured on one Linux machine (``scripts/bench_process_isolation.py``), a
    single stream (1 to 64 MiB for gzip and zstd, 1 to 16 MiB for bzip2 and xz) took
    about 1.05 to 1.5 times as long for bzip2, 1.1 to 1.6 times for xz, 1.4 to 2 times
    for gzip and deflate, and 2 to 6 times for zstd, mostly copying data between
    processes. Each decoder also costs about 0.6 to 1 ms (ZIP deflate and non-solid 7z
    LZMA2 members), and a PPMd decoder about 1.4 to 2 ms, as under ``KNOWN_CRASHES``; an
    archive of many small members pays mostly that. A solid 7z folder is one decoder,
    plus about 0.1 to 0.3 ms for each 4 KiB member read from it, with the copying of
    larger members on top. An idle process holds about 9 MB. Where no child process can
    be started (a frozen application, archivey imported from a zip, a refused spawn),
    opening a decoder raises :class:`~archivey.ResourceUnavailableError`; nothing is decoded
    in the caller's process."""
    NONE = "none"
    """No child process at all: every decoder runs in the caller's process.

    Not recommended for archives you do not trust: rapidgzip and pyppmd are isolated by
    default because they crash the process on some input, and here a crash takes the
    caller with it. It suits trusted files where speed matters, tests, and environments
    that cannot start processes. PPMd members decode in-process at any size, and
    rapidgzip is not used: ``use_rapidgzip`` and ``use_indexed_bzip2`` under ``AUTO`` use
    the standard library, and ``ON`` is refused with
    :class:`~archivey.ArchiveyUsageError` when the config is built."""


class RarDecompressor(Enum):
    """Which external program decompresses RAR member data.

    The native parser lists a RAR archive without either program, except for a
    compressed RAR 1.5-4 comment, which the selected program decodes (without it the
    comment is ``None``). Otherwise one of them is needed only to read a compressed
    member, or an encrypted one archivey does not decrypt itself. Stored members are read
    directly; a stored, encrypted member in one part is decrypted by archivey (AES, RAR
    2.9 and later) when ``cryptography`` is installed, and by the program otherwise.

    With ``UNRAR`` or ``UNAR``, archivey never changes from one program to the other.
    """

    UNRAR = "unrar"
    """RARLAB ``unrar`` 6.0 or later (or the RARLAB ``rar`` writer). It reads every RAR
    archive, including encrypted ones."""
    UNAR = "unar"
    """``unar`` 1.10 or later, from The Unarchiver's XADMaster library. It is free
    software, and ``brew install unar`` installs it on macOS.

    It is not a full substitute: archivey refuses, before ``unar`` runs, every read that
    ``unar`` is known to get wrong. A password is passed on ``unar``'s command line,
    where other local users can see it while it runs. Selecting ``UNAR`` when ``unar``
    is not installed raises :class:`~archivey.PackageNotInstalledError`, even when
    ``unrar`` is available."""
    AUTO = "auto"
    """The default: ``unrar`` when a usable one is on ``PATH``, otherwise ``unar``.

    The choice is made once per opened archive, when it is opened, and holds for every
    read of it: a read that ``unar`` refuses is not retried with ``unrar``. One exception
    goes the other way: a member whose name ``unrar`` cannot be given, or whose glob name
    also matches earlier members (``rar_allow_glob_member_concatenation``), is read with
    ``unar`` when an accepted one is installed, because ``unar`` selects members by
    index. That applies only to a read that needs no password, from a file with nothing
    before the RAR (so ``unar`` gets no password and no copy), and to a member ``unar``
    reads correctly; otherwise the ``unrar`` refusal stands.

    With neither installed, a read raises :class:`~archivey.PackageNotInstalledError`
    naming ``unrar``. On a machine with ``unar`` and no RARLAB program, a password is
    passed on ``unar``'s command line; select ``UNRAR`` to rule that out."""
    NONE = "none"
    """No program at all, for a caller who does not want ``unrar`` or ``unar`` run on
    its archives.

    Opening and listing work as with the others, and so does reading a stored
    (uncompressed) member that is not encrypted, also when it is split across volumes or
    sits in a solid archive, and one that is encrypted, in one part, with
    ``cryptography`` installed. A compressed member, an encrypted one split across
    volumes, or a split one with a volume missing, raises
    :class:`~archivey.UnsupportedFeatureError` before anything runs. A stored, encrypted
    member in one part raises :class:`~archivey.PackageNotInstalledError` naming
    ``cryptography`` when that package is missing. A compressed RAR 1.5-4 comment is
    ``None``. The ``format_availability()`` query takes no config and still runs the
    ``unrar`` identification probe; pass it ``check_programs=False`` to avoid that."""


# Minimum known compressed input size (bytes) before ``use_rapidgzip`` AUTO selects
# rapidgzip for a DEFLATE-family stream (gzip / zlib / raw deflate). ``ON`` ignores
# this; unknown size keeps pre-threshold AUTO.
#
# rapidgzip runs in a child process, so each accelerated stream pays about 45 ms to
# start the child and open the stream, and a full read then saves about 3.4 ms per MB
# of compressed input against the stdlib (``scripts/bench_rapidgzip_child.py``). So the
# child breaks even near 13 MB compressed, and below that the stdlib is faster; 16 MiB
# keeps AUTO on the side where rapidgzip pays for itself. A caller that seeks backward
# a lot gains from rapidgzip's index sooner, and can set ``ON``. See the
# rapidgzip-deflate-child-process design note.
RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE: int = 16 * 1024 * 1024

# Minimum known compressed input size (bytes) before ``use_indexed_bzip2`` AUTO selects
# rapidgzip's bzip2 decoder. ``ON`` ignores this; unknown size keeps pre-threshold AUTO.
#
# The bzip2 decoder runs in a child process too, so each accelerated stream pays about
# 45 ms to start the child. The standard library decodes bzip2 slowly, so the child pays
# for itself much sooner than for DEFLATE: a full read broke even near 0.6 MiB
# compressed with 4 cores, and near 2 MiB with one (``scripts/bench_bzip2_child.py``).
# 1 MiB sits between the two. A caller that seeks backward a lot gains from the index
# sooner, and can set ``ON``.
INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE: int = 1024 * 1024


# How many decompressed bytes a backward seek must re-decode before
# STREAM_REWIND_REDECOMPRESSES reports it: target offset minus the nearest preceding
# seek point, measured at seek time.
#
# ABSOLUTE, NOT RELATIVE, and the counterexample is why. A relative rule ("you re-decoded
# more than the distance you jumped") sounds like it captures disproportionate work, but
# on a 1 GB single-block .xz, seeking from the end back to 900 MB re-decodes 900 MB while
# jumping only ~100 MB — a 0.11x ratio, under any sane relative threshold. Relative goes
# quietest exactly where the absolute cost is highest. The caller cares about wall time,
# which tracks bytes re-decoded.
#
# Below about a megabyte of re-decoding, the work is not worth a caller's attention.
REWIND_REDECODE_WARN_BYTES: int = 1 * 1024 * 1024


@dataclass(frozen=True)
class ExtractionLimits:
    """Decompression-bomb limits for extraction.

    Applied by :meth:`~archivey.ForwardArchiveReader.extract_all`.

    ``None`` on a guard field disables that guard. :attr:`UNLIMITED` sets the three
    guard fields to ``None``; :attr:`ratio_activation_threshold` and
    :attr:`live_ratio_activation_threshold` are parameters of the ratio guard rather than
    guards of their own, and are moot once ``max_ratio`` is ``None``.
    """

    max_extracted_bytes: int | None = 2 * 2**30
    """Most bytes one extraction may write in total, across every member. 2 GiB.

    Bytes copied rather than decoded count too: a hard link written as a copy because
    it crosses a device boundary or goes past the filesystem's link-count limit. Only
    the link-count copies also count toward the archive-wide ``max_ratio``, so this is
    the one guard that bounds a cross-device copy.
    Crossing it stops the whole extraction, even under ``on_error="continue"``.
    """

    max_ratio: float | None = 1000.0
    """Largest decompressed-to-compressed ratio allowed. ``1000.0``.

    Checked per member (a member over it fails on its own, and ``on_error="continue"``
    moves on) and across the archive (which stops the extraction). The per-member check
    needs the member's compressed size; where the format or access mode does not give
    one, only the archive-wide check applies. Neither check starts before
    :attr:`ratio_activation_threshold` bytes of output, and the archive-wide check on a
    source of unknown size, such as a pipe, not before
    :attr:`live_ratio_activation_threshold`. The archive-wide check also
    counts the copies written when a file runs out of hard-link slots (1024 names on
    NTFS), since the archive's declared link count drives them.

    A member's output never passes the size the archive records for it. Where both
    sizes are recorded, a member over the per-member ratio is refused before any of it
    is written.
    """

    ratio_activation_threshold: int = 5 * 2**20
    """Output bytes before :attr:`max_ratio` is checked. 5 MiB.

    Small members compress extremely well without being bombs, so the ratio is only
    judged once a member (or the archive, for the archive-wide check) has produced this
    much. The archive-wide check on a source of unknown size, such as a pipe, waits for
    :attr:`live_ratio_activation_threshold` as well. It cannot be ``None``; set
    :attr:`max_ratio` to ``None`` to turn the ratio guard off.
    """

    max_entries: int | None = 262_144
    """Most entries one extraction may create: files, directories and links.

    Crossing it stops the whole extraction, even under ``on_error="continue"``.

    It also bounds, separately, how many times one extraction rechecks a symlink
    because a later member changed a path the link resolves through. Only a hostile
    archive comes near it, and crossing it stops the extraction the same way. ``None``
    removes both bounds, so a hostile archive can then make the rechecks take time
    quadratic in its size.
    """

    live_ratio_activation_threshold: int = 256 * 2**20
    """Output bytes before the archive-wide ratio is checked on a source of unknown size. 256 MiB.

    When the archive's size is not known up front, as for a ``.tar.gz`` read from a
    pipe, the archive-wide check divides the output by the compressed bytes read so
    far. An honest archive whose data starts with a long blank run, such as a disk
    image, looks like a bomb until the data after that run arrives: blank data
    compresses past 1000:1. The same archive read from a file passes, because there
    the check divides by the whole file. So from such a source the archive-wide check
    waits for this much output, and a blank start shorter than this passes as it does
    from a file. Past it, the check still divides by the bytes read so far, so a longer
    blank start can still be refused; once a pipe has been read to its end, the two
    checks agree. A bomb read this way can write this much before the check stops it;
    :attr:`max_extracted_bytes` still bounds the total.
    Lower it to stop such a bomb sooner; raise it for piped archives with longer blank
    starts. A value below :attr:`ratio_activation_threshold` has no effect. It cannot be
    ``None``; set :attr:`max_ratio` to ``None`` to turn the ratio guard off.
    """

    UNLIMITED: ClassVar[ExtractionLimits]

    def __post_init__(self) -> None:
        # allow_none and allow_float come from the field annotations.
        check_limit_fields(self, cls="ExtractionLimits")


ExtractionLimits.UNLIMITED = ExtractionLimits(
    max_extracted_bytes=None,
    max_ratio=None,
    max_entries=None,
)


@dataclass(frozen=True)
class ListingLimits:
    """Caps on the member listing a reader builds and keeps.

    Applied from the reader's open :attr:`ArchiveyConfig.listing_limits` for its lifetime.
    ``None`` on a field disables that guard. :attr:`UNLIMITED` disables both.
    Every call that lists members enforces them, in both access modes: ``members()``,
    ``members_report()``, ``stream_members()``, ``for member in reader`` and
    ``extract_all``. Each raises :class:`~archivey.exceptions.ResourceLimitError` at
    the member that crosses a cap.
    ZIP, 7z, RAR and ISO apply ``max_members`` at parse (ZIP at open, or as it reads
    the directory when the end record understates the count), 7z and RAR weigh the
    names and comments their headers hold against ``max_metadata_bytes`` (RAR's
    compressed RAR 1.5-4 comments by declared or packed size, whichever is larger,
    before decoding them), and ISO the directory records, path tables and UDF
    descriptors ``pycdlib`` parses, so ``open_archive`` raises. A ZIP read from a
    stream that cannot seek has no directory to read at open: its pass charges
    ``max_members`` on each local header as it yields the member, and again on the
    directory's entries after the last member, and weighs the directory's text
    against ``max_metadata_bytes`` as it arrives. A ZIP file whose end record sits
    behind more than 64 KiB of trailing bytes is walked the same way at open, which
    charges ``max_members`` on each local header.
    ISO also counts each path-table entry against ``max_members`` (a table of more than
    ``max_members + 1`` entries is refused): every entry is a directory, which is a
    member anyway, so real images never notice. ISO counts the UDF tree ``pycdlib``
    parses against ``max_members`` too, one per UDF name, although ``members()`` does
    not list UDF: an image whose UDF tree has more names than its ISO 9660 tree can be
    refused for the UDF tree. ISO counts members per tree but weighs bytes as one sum
    for the whole image, every tree together.
    TAR refuses, in every mode, an extended header (PAX or GNU long name) that declares
    more than is left of ``max_metadata_bytes``, before reading it.
    """

    max_members: int | None = 262_144
    """Most members a listing may hold.

    Each listed member costs about 1.5 KiB of memory (measured by
    ``scripts/measure_limit_costs.py``), so the default allows about 384 MiB at open on
    7z, RAR and ISO, where a tiny compressed header can declare that many members (ZIP
    checks the count too, but its directory costs about 46 bytes per entry). A
    current Linux kernel source tree has about 90 000 files, a third of the default;
    raise this for archives with more members, and lower it when opening untrusted
    archives on a server with less memory to spare.
    """

    max_metadata_bytes: int | None = 64 * 2**20
    """Most bytes of text a listing may retain across its members. 64 MiB.

    Counts member names (and raw names), comments, link targets, owner and group names
    and the string or bytes values in ``extra``, plus the keys of a dict nested in it
    (such as TAR's PAX keywords), plus the archive comment. The top-level ``extra``
    keys are fixed per format and do not count. Non-ASCII text counts four bytes per
    character, so it is an upper bound rather than an exact size. A TAR sparse member's
    map, which the listing keeps to read the member, counts 24 bytes per entry, and
    each ZIP extra field kept in ``extra["zip.extra_fields"]`` counts 72 bytes plus its
    data.

    A ZIP read from a stream that cannot seek also keeps the data of each member
    short enough to be a symlink until its directory says which members are links.
    That data does not count here; the pass holds at most this many bytes of it,
    dropping the longest first. A link whose data was dropped is listed without its
    target and reports ``SYMLINK_TARGET_UNAVAILABLE``.
    """

    UNLIMITED: ClassVar[ListingLimits]

    def __post_init__(self) -> None:
        check_limit_fields(self, cls="ListingLimits")


ListingLimits.UNLIMITED = ListingLimits(
    max_members=None,
    max_metadata_bytes=None,
)


@dataclass(frozen=True)
class DecoderLimits:
    """Caps on what a decoder may allocate or compute because the *archive* said to.

    Several codecs size their working memory from a number in the archive's own
    header rather than from anything the caller chose: 7z PPMd var.H carries a
    32-bit window size, ZIP method 98 an 8-bit megabyte count, LZMA a 32-bit
    dictionary size. Those numbers are attacker-chosen, they are read before a
    single byte of member data is, and the allocation that follows is not
    proportional to the archive's size — a 153-byte 7z can ask for 4 GiB.

    **What is capped today:** both PPMd paths, and the LZMA dictionary size
    wherever an archive declares one — 7z LZMA and LZMA2, ZIP method 14, each xz
    block, ``.lzma`` and each lzip member — and the window each zstd frame declares,
    on ``.zst``, ZIP method 93 and 7z. RAR's dictionary is checked too, before
    ``unrar`` or ``unar`` is started, at what that program allocates for it. ``unar``
    writes to the whole declared dictionary, so the declared size counts. ``unrar``
    writes to it only as output is produced, so the declared size counts only up
    to the unpacked bytes the read decodes: the member's own size, or in a solid
    archive the members up to and including it. The two decoders that allocate what
    the header says, pyppmd and liblzma, differ. A refused allocation inside pyppmd
    takes its process down (a child process unless ``process_isolation`` is ``NONE``).
    liblzma does raise ``MemoryError`` when it cannot reserve the dictionary, but a
    reservation that succeeds is its real cost: the dictionary fills as output is
    written, so a 151 KB stream declaring 4 GiB held 1.1 GiB resident after
    producing 1 GiB, where the same stream declaring 1 MiB held 59 MB. The
    dictionary bounds how much of the output the decoder keeps, and the archive
    picks it.

    ``max_decoder_memory`` also caps the rapidgzip accelerator for gzip, zlib and raw
    DEFLATE, though no archive declares a size there. rapidgzip keeps whole decoded
    chunks in memory, so a 1 MB gzip file of zeros made it hold close to 1 GiB. Its
    child process is stopped when its memory grows past the cap, and the standard
    library reads the rest of the stream, so the result does not change; only the
    speed does. The child checks every millisecond and again before it answers each
    read, so the peak can pass the cap by what the decoder allocates between two
    checks: measured, about 17 MB on four cores. On a busy machine the timed check can
    wait for a processor, and then the check before the next read stops it. Where the
    platform does not report a process's peak memory, the child is not capped.

    The same shape holds for key derivation, which costs time rather than memory:
    RAR5 and 7z headers say how many hashing rounds turn a password into a key,
    and :attr:`max_key_derivation_rounds` caps their total over one open archive.

    This is not an :class:`ExtractionLimits` field, and the difference is not
    cosmetic. The bomb guards there measure *output*: they count bytes as an
    extraction produces them and stop when the total or the ratio says the
    archive is lying about its size. A decoder's working memory is neither
    output nor proportional to it, it is claimed up front, and it is claimed on
    ``open()`` and ``read()`` as much as on ``extract_all()`` — paths
    ``ExtractionLimits`` does not cover at all.

    Applied from the reader's open :attr:`ArchiveyConfig.decoder_limits` for its
    lifetime, as :class:`ListingLimits` is: the codec-layer view is built once
    when the reader is.

    ``None`` on a field disables that guard. :attr:`UNLIMITED` disables every one.

    Where an archive declares the size, exceeding a guard raises
    :class:`~archivey.exceptions.ResourceLimitError` *before* the allocation,
    which is the only place it can be raised in this process: the process has no
    recourse once the request is in the allocator's hands. The rapidgzip child is
    the exception: nothing declares its size, so its memory is measured after the
    allocation, in its own process, and going over the cap raises nothing to the
    caller. The child is stopped and the standard library continues the stream.

    **Detection is not capped.** Formats without magic (``.lzma``, and the
    compressed tar inside ``.tar.xz`` and its siblings) are recognised by
    decoding a small sample, and that sample is decoded with no decoder limit,
    because a capped probe would report a different format for a caller who
    passed :attr:`UNLIMITED`. It does not need one: a probe builds its LZMA
    decoder with only the dictionary its sample needs (4 to 64 KiB, whatever the
    header declares), which decodes the sample to the same bytes, and lowers
    zstd's window limit to libzstd's default 128 MiB, treating a frame over it
    as unrecognised. The open that follows detection is capped as described
    here.

    Under a memory cap (a container limit, ``RLIMIT_AS``, a small machine) a
    refused native allocation does not always surface as ``MemoryError`` —
    pyppmd 1.3.1 dies on ``double free or corruption`` and takes the
    interpreter with it, so no ``try``/``except`` around the decode can contain
    it.
    """

    max_decoder_memory: int | None = 2 * 2**30
    """Largest archive-declared working set a single decoder may allocate. 2 GiB.

    A 7z folder runs all its decoders at once (the stages of a coder chain, and a BCJ2
    folder's ``main``, ``call`` and ``jump`` branches), so when it has more than one,
    their LZMA dictionaries, PPMd memory sizes and zstd windows count together against
    it. A zstd window counts as the first frame declares it, when the zstd coder reads a
    packed stream directly.

    That number is a policy choice, not a limit of the format, so here
    is what it was chosen against. Measured on 7-Zip 23.01, a writer
    declares whatever ``-m0=PPMd:mem=…`` asked for, reduced for a small
    member to 16× its size rounded up to a power of two (floor 64 KiB).
    Its presets never ask for much: plain ``-m0=PPMd`` declares 16 MiB
    and ``-mx9`` 256 MiB, whatever the input. Reaching 2 GiB therefore
    takes an explicit ``mem=2g``, which cannot go above it at any member
    size; only ``mem=3g`` and ``mem=4g`` do. The field itself is
    32 bits, so a header may declare just under 4 GiB — and a 153-byte
    archive may declare it, which is the case the cap is really for,
    since asking costs an attacker nothing and it is read before any
    member data is.

    2 GiB is the last round value below that 32-bit ceiling, matching
    :attr:`ExtractionLimits.max_extracted_bytes`. It admits every
    archive 7-Zip's own presets write, by a factor of eight, and admits
    a deliberate ``mem=2g`` as well; it refuses the top of the field.
    Reading archives written with ``mem=3g`` or above means raising it
    or passing :attr:`UNLIMITED`.

    The LZMA dictionary sits further under it. xz Utils refuses to
    write a dictionary over 1.5 GiB, and its ``-9`` preset writes
    64 MiB whatever the input. 7-Zip 23.01 shrinks the dictionary it
    declares to about the member's size (4 KiB for a 25-byte member,
    7 MiB for 6.7 MB, 96 MiB for 100 MB, all asked for with
    ``-md=1536m``), so declaring more than 2 GiB takes a member over
    2 GiB *and* an explicit ``-md`` above 2g. lzip's field cannot say
    more than 512 MiB. The same number serves both codecs because it
    answers the same question, and xz and ``.lzma`` are checked through
    liblzma's own memory limit, which also counts about 64 KiB of the
    decoder's overhead; a 128 KiB allowance keeps a dictionary exactly
    at the cap readable there as on every other path.

    What the default is *not* is a promise about the machine. The cap
    bounds what an archive may ask for; whether an allocation succeeds
    is a property of the host, and the two are independent. A process
    with less headroom than the cap — a container under a memory limit,
    a small VM — gets nothing from the default: a declaration below
    2 GiB passes the guard, and the allocation that follows is the one
    that fails, which is the unsurvivable case described above. Such a
    process should set the cap under its own headroom, anchored on the
    limit it runs with rather than on anything 7-Zip writes. Code that
    opens files it did not choose — an upload endpoint, a mail scanner —
    wants the same move for a different reason: 256 MiB still takes
    everything the PPMd and LZMA presets produce."""

    max_key_derivation_rounds: int | None = 2**25
    """Total rounds of password-to-key derivation one open archive may run.
    ``2**25``.

    RAR5 and 7z let the archive choose how expensive a key is to derive:
    RAR5's ``kdf_count`` asks for ``2**kdf_count`` PBKDF2-HMAC-SHA256
    rounds, 7z's ``NumCyclesPower`` for ``2**cycles`` SHA-256 rounds, each
    up to ``2**24`` (a few seconds). Each derivation is capped already;
    this caps the sum. RAR5 salts each encryption record and 7z each
    folder, so an archive can make every member cost a fresh derivation,
    and a candidate password list multiplies that again. The work runs
    inside ``hashlib`` with the GIL released and cannot be interrupted,
    so what the caller sees is a process that stops responding.

    Rounds are counted as the archive declares them, per derivation that
    actually runs. A key the reader already derived for the same
    password and salt comes from its cache and costs nothing, and real
    writers reuse one salt across an archive (rar 7.00 writes one per
    archiving run, 7-Zip 23.01 writes none), so an ordinary archive
    spends one or two derivations whatever its size. Every candidate
    password that is tried counts, right or wrong. The RAR3 scheme,
    whose cost is fixed at ``2**18`` SHA-1 rounds, counts at that
    number; ZIP AES (a fixed 1000 rounds) is not counted.

    RAR5 charges one derivation per output it needs from a password:
    the PswCheck (``2**kdf_count + 32`` rounds), the checksum HashKey
    (``+ 16``) and, when archivey decrypts a stored member or the
    headers itself, the AES key (``+ 0``). A RAR5 read through
    ``unrar`` costs two derivations per password, a stored member three.

    ``2**25`` is about ten seconds of hashing: two 7z derivations at
    the ``2**24`` maximum, but not one maximum-cost RAR5 member, which
    needs two or three; 64 passwords at 7-Zip's ``2**19``; about 500 at
    rar's ``2**15``. Exceeding it raises
    :class:`~archivey.exceptions.ResourceLimitError` before the
    derivation that would cross it starts. Code that opens archives it
    did not choose may want ``2**24``, which still admits every
    archive the usual tools write."""

    max_ppmd_held_input: int | None = 16 * 2**20
    """Largest PPMd member, in compressed bytes, held and handed to the decoder whole.
    16 MiB.

    The decoder is pyppmd, in a child process unless ``process_isolation`` is
    ``ProcessIsolation.NONE``. Fed whole, it is asked little after a corrupt member
    ends early, the state in which it can crash. Fed in pieces, it cannot tell a
    corrupt stream that ended from a valid one waiting for input. Holding costs memory
    in this process: the held input, and about as much again while it is copied. A
    larger member, and a ZIP member read from a stream that cannot seek with its sizes
    stored after its data, is fed in pieces. ``None`` holds every member whose size is
    known, at a memory cost that grows with the member."""

    UNLIMITED: ClassVar[DecoderLimits]

    def __post_init__(self) -> None:
        check_limit_fields(self, cls="DecoderLimits")


DecoderLimits.UNLIMITED = DecoderLimits(
    max_decoder_memory=None,
    max_key_derivation_rounds=None,
    max_ppmd_held_input=None,
)


@dataclass(frozen=True)
class SpoolLimits:
    """Caps on what a reader writes to temporary storage, mostly copies of its source.

    Some reads need the archive as a file on disk even when the caller passed a stream.
    Today that is RAR: ``unrar`` and ``unar``, the programs that decode member data, take
    a filesystem path, so a RAR opened from a ``BytesIO`` or another file object is
    copied to a temporary file (a volume set, to a temporary directory) the first time a
    member has to go through one of them. The copy is of the whole archive, and it is
    removed when the reader closes.

    A source opened from a path is read in place and not copied, with two exceptions
    that are bounded here too. A RAR with a prefix before it (an SFX stub, say) read
    with ``rar_decompressor='unar'`` is copied from where the RAR starts. And files
    that must be linked into a temporary directory, which ``unar`` always reads from
    and ``unrar`` needs for an explicit list of volumes it would not find by name, are
    copied there when the system can make neither a symlink nor a hard link.

    Applied from the reader's open :attr:`ArchiveyConfig.spool_limits` for its lifetime.
    ``None`` on a field disables that guard. :attr:`UNLIMITED` disables it.
    """

    max_bytes: int | None = 2**30
    """Most bytes one reader may write to temporary storage. 1 GiB.

    That is the copy of its source, and the sources a solid RAR pass keeps for file
    copies. A volume set counts as one copy: the limit applies to the total across its
    volumes. When the size is known before the copy starts, an
    archive over the limit raises :class:`~archivey.exceptions.ResourceLimitError`
    before anything is written. Otherwise the copy stops before it passes the limit.
    Either way the partial copy is removed, and the error names this field. The limit
    holds for the reader, not per attempt: once a copy is refused, later reads that
    need it are refused without copying again.

    ``0`` refuses every copy: a stream source then reads only the members archivey can
    read without ``unrar``, such as stored, unencrypted RAR members. The copy goes
    to the platform temporary directory (``tempfile.gettempdir()``); where that is
    memory-backed, such as ``tmpfs``, this limit is a memory limit.

    The same allowance holds the sources of RAR5 file copies (``rar -oi``) in a solid
    pass (``stream_members``, extraction): the pass keeps each source as it decodes
    it, up to 8 MiB in memory and the rest in a temporary file within this limit, so
    a copy does not decode the solid stream again. That file counts only from the
    source's first decoded byte, after any copy of the archive the pass needs, until
    the pass ends and deletes it. Unlike a copy's bytes, which keep counting after the
    copy is removed, the kept file's bytes then stop counting. A source the limit has
    no room for is not kept, and its copies decode it again from the archive; that is
    never refused.
    """

    UNLIMITED: ClassVar[SpoolLimits]

    def __post_init__(self) -> None:
        check_limit_fields(self, cls="SpoolLimits")


SpoolLimits.UNLIMITED = SpoolLimits(max_bytes=None)


@dataclass(frozen=True)
class ArchiveyConfig:
    """Library tuning knobs passed as ``config=`` to :func:`open_archive`,
    :func:`open_stream` and :func:`detect_format`.

    Per-call operationals (``format``, ``streaming``, ``password``, extraction's
    ``members``/``filter``/``policy``/…) stay keyword arguments — not fields here.
    """

    use_rapidgzip: AcceleratorMode = AcceleratorMode.AUTO
    """Whether to use the ``rapidgzip`` accelerator for gzip, zlib and raw deflate.

    It gives seekable member streams over those codecs. Under ``AUTO`` it is used only
    when the compressed input is known to be at least
    ``RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE`` bytes (or its size is unknown) and the
    decompressed size can be verified, so a truncated stream cannot be swallowed
    silently.

    rapidgzip runs in a child Python process, because it aborts the process on a stream
    that ends early; starting one costs about 45 ms, which is why the ``AUTO`` threshold
    is 16 MiB. Each open stream has a child of its own. On Linux, the members of one
    archive file on disk reuse children: a member whose stream closed without an error
    hands its child to the next one, which skips the start. A reused child counts what
    earlier members left in its memory against ``max_decoder_memory``, so one that kept
    more than a quarter of the cap is not reused. Those children end when the archive
    closes. Where no child can be started (a frozen application, archivey imported from
    a zip, or a spawn or temporary file the operating system refuses), ``AUTO`` uses the
    standard library, logging one warning per process on the ``archivey.streams``
    logger, and ``ON`` raises :class:`~archivey.exceptions.ResourceUnavailableError`.
    ``OFF`` never starts a child.
    """

    use_indexed_bzip2: AcceleratorMode = AcceleratorMode.AUTO
    """Whether to use rapidgzip's bundled bzip2 backend for random access into bzip2.

    Under ``AUTO`` it is used only when the compressed input is known to be at least
    ``INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE`` bytes (or its size is unknown). Like the
    gzip decoder, it runs in a child Python process, one per open stream, reused the same
    way (see ``use_rapidgzip``). No crash has been seen in it; it is isolated as a
    precaution, because it comes from the same library as the gzip decoder, which does
    crash on some input. Where no child can be started, ``AUTO`` uses the standard
    library, logging one warning per process on the ``archivey.streams`` logger, and
    ``ON`` raises :class:`~archivey.exceptions.ResourceUnavailableError`.
    """

    process_isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES
    """Which native decoders run in a child process. See :class:`ProcessIsolation`.

    Accepts the member or its name (``"known_crashes"``, ``"native_decoders"``,
    ``"none"``).
    """

    zip_unflagged_fallback_encoding: str = "cp437"
    """Encoding for a ZIP member name that is neither flagged nor valid UTF-8.

    A name stored without the UTF-8 flag is tried as UTF-8 first; this encoding is used
    when those bytes are not valid UTF-8. The default is cp437, as the ZIP specification
    (APPNOTE) says. Set a local code page (for example ``"cp1252"`` or ``"shift_jis"``)
    for archives known to come from one. An explicit ``encoding=`` on
    :func:`~archivey.open_archive` replaces this fallback for that archive; a name
    whose bytes are valid UTF-8 is still decoded as UTF-8.
    """

    rar_allow_glob_member_concatenation: bool = False
    """Read a RAR member whose stored name contains ``*`` or ``?`` even when that name
    also matches other members.

    ``unrar`` selects members by an include mask, so such a name can match other
    members as well. Names like this are almost always constructed, so the read is
    refused by default. On a nonsolid archive the extra decode is also unbounded and not
    reported (:class:`ExtractionLimits` does not cover ``open()`` or ``read()``); on a
    solid archive those bytes are already inside ``AccessCost.SOLID``. Set ``True`` to
    read it anyway. A glob name that matches no other member is unaffected either way.
    Under ``rar_decompressor=AUTO``, an installed ``unar`` reads such a member by index
    instead of the refusal (see :class:`RarDecompressor`), so this flag matters only
    when ``unrar`` must read it.
    """

    rar_decompressor: RarDecompressor = RarDecompressor.AUTO
    """Which external program decompresses RAR member data. See :class:`RarDecompressor`.

    Accepts the member or its name (``"unrar"``, ``"unar"``, ``"auto"``, ``"none"``). The
    listing does not depend on it, except that the selected program decodes compressed
    RAR 1.5-4 comments.
    """

    read_link_targets: bool = True
    """Whether the reader reads a symlink's target when the format stores it as member
    data (ZIP, 7z, RAR3/4) rather than in the header.

    ``True``: listing and a finished ``stream_members()`` pass read every such target,
    selected or not, so the report matches random access. On ZIP and 7z that can
    decompress data nobody selected and consult the password provider. ``False``: the
    reader reads none of them on its own; ``extract_all`` reads the targets of links its
    selector and filter accept, and ``open()`` reads the target of a link it follows.
    Fixed for the reader's lifetime.
    """

    extraction_limits: ExtractionLimits = ExtractionLimits()
    """Decompression-bomb guards for extraction. See :class:`ExtractionLimits`."""

    listing_limits: ListingLimits = ListingLimits()
    """Caps on the size of a member listing. See :class:`ListingLimits`."""

    decoder_limits: DecoderLimits = DecoderLimits()
    """Caps on what the archive may make a decoder allocate or compute.

    See :class:`DecoderLimits`.
    """

    spool_limits: SpoolLimits = SpoolLimits()
    """Caps on what a reader writes to temporary storage. See :class:`SpoolLimits`."""

    detection_budget: DetectionBudget = BALANCED_BUDGET
    """Upper bounds on what format detection may read and decode.

    Used by :func:`~archivey.open_archive` and :func:`~archivey.detect_format` alike.
    The default, ``BALANCED``, covers every format archivey reads at the offset it
    specifies, a self-extracting archive within 2 MiB of the start, and the content
    probes. ``FAST_BUDGET`` and ``THOROUGH_BUDGET`` in ``archivey.detection_cost``
    are the other presets; to change a single limit, ``dataclasses.replace`` one.
    """

    always_probe_content: bool = False
    """Whether detection tries every content probe, whatever the source is named.

    LZMA Alone, zlib and Brotli have no magic that detection can trust, so only a
    content probe (a trial decode of the first bytes) recognises them. Arbitrary binary
    files sometimes pass a probe, so by default :func:`~archivey.open_archive` and
    :func:`~archivey.detect_format` run a probe only when the source's name ends in one
    of that format's extensions: ``.lzma`` or ``.tlz`` for LZMA Alone, ``.zz`` or
    ``.zlib`` for zlib, ``.br`` or ``.brotli`` for Brotli, and the ``.tar.`` form of
    each except ``.tlz``. An extensionless raw stream of these formats is then refused
    with :class:`~archivey.FormatDetectionError`. If you read such sources, set this to
    ``True``, pass ``format=``, or use :func:`~archivey.open_stream`, which always tries
    every probe because its caller already says the source is a compressed stream.
    """

    diagnostic_policy: DiagnosticPolicy = field(default_factory=DiagnosticPolicy)
    """Whether each diagnostic code is ignored, collected or raised.

    See :class:`~archivey.DiagnosticPolicy`.
    """

    max_retained_diagnostic_references: int = 256
    """How many references to diagnostics the library keeps per collector.

    Each diagnostic retained in the summary takes a slot, and each one attached to a
    member takes another. Counts stay exact past the cap. A random-access member walk
    also keeps, until it ends, a record that a walk started over after a failure
    replays: the codes of the diagnostics emitted for the members it has built, and the
    full diagnostics only for the member being typed. That record takes no slot.
    """

    on_diagnostic: OnDiagnostic | None = None
    """A callback called with each diagnostic the policy collects or raises, as it is
    emitted, or ``None``."""

    def __post_init__(self) -> None:
        """Check the fields at construction, and convert the two that hold enums.

        A config field is read wherever it is needed, which is never where it was
        written: ``ArchiveyConfig(extraction_limits="none")`` builds fine and then
        fails part-way through an extraction as ``AttributeError: 'str' object has no
        attribute 'max_extracted_bytes'`` — a private attribute name, and no mention of
        the argument the caller actually got wrong. Checking ``config=`` at the entry
        points does not reach this: the object passed there *is* an ``ArchiveyConfig``,
        and the wrong type is one field in.

        The two accelerator fields are **converted** rather than only checked, because
        their consumers test them with ``is`` (:meth:`AcceleratorMode.enabled_for`): a
        string that survived construction would not be refused on use, it would read as
        "neither ON nor OFF" and silently take the AUTO path. Converting here means the
        field always holds a member, and a bad spelling names itself at the call site
        that wrote it rather than during some later stream open.

        They stay annotated ``AcceleratorMode`` rather than ``AcceleratorMode | str``
        because that is what they hold once constructed, and it keeps every consumer
        honest. A string is still accepted at construction — a type checker flags it,
        which is the right answer for a typed caller who has the enum imported anyway,
        and an untyped script gets the conversion.

        That conversion goes through ``object.__setattr__`` because the dataclass is
        frozen and it *rewrites* the field rather than only inspecting it. The checks
        above reject without writing, so they need no such thing.
        """
        # The checks below run in this order, not field order: with several bad
        # fields, the first check that fails is the error the caller sees.
        instance_fields: tuple[tuple[str, type], ...] = (
            ("extraction_limits", ExtractionLimits),
            ("listing_limits", ListingLimits),
            ("decoder_limits", DecoderLimits),
            ("spool_limits", SpoolLimits),
            ("diagnostic_policy", DiagnosticPolicy),
        )
        for field_name, expected in instance_fields:
            check_instance(
                getattr(self, field_name),
                expected,
                call=f"ArchiveyConfig({field_name}=…)",
                allow_none=False,
            )
        if not isinstance(self.detection_budget, DetectionBudget):
            # A preset member, or its name, is converted here so the field always
            # holds the budget detection reads. The annotation stays the budget alone,
            # as it does for ``use_rapidgzip`` below: it is read by every consumer of
            # the attribute, not only by the constructor's callers, and after
            # construction it always holds a ``DetectionBudget``.
            # ``tests/test_enum_arguments.py`` records the exemption.
            preset = coerce_enum(
                self.detection_budget,
                DetectionBudgetPreset,
                call="ArchiveyConfig()",
                param="detection_budget=",
                also_accepts="DetectionBudget",
            )
            object.__setattr__(
                self, "detection_budget", DetectionBudget.for_preset(preset)
            )
        # Guard switches: a string such as "false" is truthy, so it would silently
        # turn a refusal off. Only a real bool is accepted.
        for field_name in (
            "rar_allow_glob_member_concatenation",
            "read_link_targets",
            "always_probe_content",
        ):
            check_instance(
                getattr(self, field_name),
                bool,
                call=f"ArchiveyConfig({field_name}=…)",
                allow_none=False,
            )
        check_callable(self.on_diagnostic, call="ArchiveyConfig(on_diagnostic=…)")
        check_encoding(
            self.zip_unflagged_fallback_encoding,
            call="ArchiveyConfig(zip_unflagged_fallback_encoding=…)",
            allow_none=False,
        )
        check_limit(
            self.max_retained_diagnostic_references,
            cls="ArchiveyConfig",
            field_name="max_retained_diagnostic_references",
            allow_none=False,
        )
        # These two are coerced at a public boundary with no ``Literal`` alias beside
        # them (as are ``ArchiveFormat``'s two fields), and that is deliberate: the
        # annotation is read by every consumer of the attribute, not only by the
        # constructor's callers, and after construction the field always holds a
        # member. ``tests/test_enum_arguments.py``
        # records the exemption so the gap is not "fixed" back into a union.
        for field_name in ("use_rapidgzip", "use_indexed_bzip2"):
            object.__setattr__(
                self,
                field_name,
                coerce_enum(
                    getattr(self, field_name),
                    AcceleratorMode,
                    call="ArchiveyConfig()",
                    param=f"{field_name}=",
                ),
            )
        object.__setattr__(
            self,
            "rar_decompressor",
            coerce_enum(
                self.rar_decompressor,
                RarDecompressor,
                call="ArchiveyConfig()",
                param="rar_decompressor=",
            ),
        )
        object.__setattr__(
            self,
            "process_isolation",
            coerce_enum(
                self.process_isolation,
                ProcessIsolation,
                call="ArchiveyConfig()",
                param="process_isolation=",
            ),
        )
        if self.process_isolation is ProcessIsolation.NONE:
            for field_name in ("use_rapidgzip", "use_indexed_bzip2"):
                if getattr(self, field_name) is AcceleratorMode.ON:
                    raise ArchiveyUsageError(
                        f"ArchiveyConfig({field_name}=ON) cannot be combined with "
                        "process_isolation=NONE: rapidgzip runs only in a child "
                        "process. Use AUTO or OFF, or another process_isolation."
                    )


DEFAULT_ARCHIVEY_CONFIG = ArchiveyConfig()
"""The configuration used when a call is given no ``config=``: ``ArchiveyConfig()``."""


@dataclass(frozen=True)
class PasswordRequest:
    """Context passed to a :data:`PasswordProvider` when a password is needed."""

    member: ArchiveMember | None
    """The member being decrypted, or ``None`` for archive-level (header) decryption."""

    attempt: int
    """1 on the first ask for this unit; increments on every later ask for it.

    Each ask follows a failure: either the previous answer failed to decrypt the unit,
    or it was a password that had already failed for this unit (a known-good password
    from an earlier unit, a listed candidate) and was skipped without a second try.
    A repeated answer is never decrypted twice. Asking stops when the provider returns
    ``None``, or after three answers in a row that it had already given for this unit;
    one or two repeats in a row do not stop it, so a person at a prompt who types the
    same password again is asked again. A provider walking a stored list should skip
    duplicates in it: three equal entries in a row end the asking.
    """


PasswordProvider = Callable[[PasswordRequest], str | bytes | None]
"""Callable consulted when static password candidates fail for an encrypted unit."""

PasswordInput = str | bytes | Sequence[str | bytes] | PasswordProvider | None
"""Accepted ``password=`` shapes: one value, an ordered candidate list, a provider, or None."""
