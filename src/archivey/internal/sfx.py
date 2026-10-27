"""Self-extracting (SFX) stubs: the shared scan bound, the forward scan, and the cue.

A self-extracting archive is an executable stub with a real archive appended, so the
archive magic sits at some offset ``N > 0`` rather than at byte zero. Four places have
to agree on how far forward to look for it:

* :func:`archivey.internal.detection.detect_format` — the SFX scan that turns an
  executable-shaped prefix into ``(format, payload_offset)``;
* ``rar_parser._find_sfx_header`` — the RAR parser's own scan, which is what makes
  forced ``format=RAR`` work on an SFX file;
* ``sevenzip_parser.find_signature_offset`` — the 7z equivalent;
* ``zip_local_walk.LocalHeaderWalk`` — the forward ZIP walk's scan for its first local
  header, for a ZIP read from a stream it cannot seek.

They share :data:`SFX_MAX` rather than each carrying a bound of its own: separate
limits drift, and a stub the RAR parser accepts but the detector does not would be a
file that opens under ``format=RAR`` and fails under auto-detect. Raising the bound is
one edit here for all four.

Two scan entry points, because the callers differ in what they may do to the source.
A parser owns its handle and reads forward (:func:`scan_for_magic`); the detector must
not consume anything, so it works from growing peeks (:func:`iter_magic_in_prefix`).
Both keep the window bounded and neither buffers the whole of it. Both can skip a
decoy: the iterating path yields every structural match so the detector's caller can
reject it, and :func:`scan_for_magic` takes an optional :class:`HitValidator` so the
parser path returns the earliest *valid* match, falling back to the earliest identified
candidate when none validate.

:func:`executable_cue` is a **cost gate, not a correctness gate**. Its purpose is to
avoid reading up to :data:`SFX_MAX` from every source a caller opens — not to keep
false matches out. Hit validators (ZIP local-header sanity, 7z StartHeaderCRC, RAR
main-header CRC) are what reject a decoy. Widening the cue is therefore a cost
decision: ``MZ``, ELF, a ``#!`` shebang, or a Mach-O header that parses. The gate is
deliberately two-tiered — see :class:`ExecutableCue`.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Container, Iterator, Sequence, Set as AbstractSet
from enum import Enum
from typing import BinaryIO, Generic, NamedTuple, Protocol, TypeVar

from archivey.internal.streams.streamtools import source_byte_size

_T = TypeVar("_T")

# How far past the start of a source the archive magic may sit before we stop looking.
# 2 MiB comfortably covers real stubs (a `rar a -sfx` ELF stub is ~250 KB, and Windows
# installer stubs are of the same order) while keeping a miss cheap and bounded.
SFX_MAX = 2 * 1024 * 1024

# Rejected-candidate cap per format, shared by both SFX scans: :func:`scan_for_magic`
# when a validator is passed, and the detector's scan over :func:`iter_magic_in_prefix`.
# A 2 MiB window of planted 6-byte decoys is otherwise an unbounded validation loop,
# and each RAR decoy can make its validator read and CRC up to 64 KiB. This is
# structural, not a ``ListingLimits`` / ``DetectionBudget`` knob: a real SFX stub does
# not carry hundreds of format magics, and the native parsers that call this have no
# detection budget. Each parser scans for one format, so the detector counts each
# format's rejections apart (:class:`HitSelector`) and caps only the formats whose
# parser scans (``ReadBackend.SFX_PARSER_SCANS``: RAR and 7z). Decoys of one format
# do not spend another's allowance, and a ZIP is never capped: its seekable reader
# finds the end of central directory from the tail and runs no scan, and the forward
# walk's scan (``zip_local_walk``) is bounded by the window alone, its validator
# reading only the header and computing no CRC. So a file of decoys means the same
# thing to detection as to a forced ``format=``. 256 is
# a starting value; raise it here if a real archive needs more.
MAX_VALIDATED_CANDIDATES = 256

# How far past its candidate origin a hit validator may read. The scan window bounds
# where a magic may *start*; a candidate that starts inside it is judged on its whole
# header, even when that header crosses the window end. It must cover every
# validator's largest peek: a ZIP local header with maximal name and extra on a source
# of unknown length (30 + 2 * 65 535 bytes), and a RAR main header at its 64 KiB cap;
# 7z reads 32 bytes. The detector extends each validator's view past ``scan_limit`` by
# this much or by ``max_scan_bytes``, whichever is smaller
# (``detection.validator_allowance``), so the budget field still bounds the tier's
# reads. Under the presets that is this constant.
VALIDATOR_PEEK_MAX = 132 * 1024

# Read granularity for the forward scan. Large enough that a full 2 MiB window is 32
# reads, small enough that a match near the front stops early.
_SCAN_CHUNK = 65536

# Peek sizes the non-consuming scan steps through. With a monotone prefix workspace each
# step reads only the delta, so a full miss costs **1×** the window in unique I/O.
# Geometric growth is about stopping early on a hit. A stub whose magic is at 250 KB —
# the size `rar a -sfx` produces — is found on the third peek.
#
# The pre-workspace loop re-requested from byte 0 each step, so a miss billed
# 64 + 256 + 1024 + 2048 KiB = 3392 KiB for a 2048 KiB window — **1.66×**, not
# "a little over 2×". That 1.66× figure is what the tiering argument was counted
# against; I/O is 1× now, and the gap versus a tail probe is still large either way.
_PEEK_STEPS = (1 << 16, 1 << 18, 1 << 20)

_MZ = b"MZ"
_ELF = b"\x7fELF"
_PE = b"PE\x00\x00"
# Offset of the PE header pointer (``e_lfanew``) in the DOS header, and the smallest
# value it can legally hold — the PE header cannot overlap the DOS header itself.
_E_LFANEW_OFFSET = 0x3C
_DOS_HEADER_SIZE = 0x40


def candidate_origin_for_hit(hit_offset: int, needle_offset: int) -> int | None:
    """Convert a needle hit at ``hit_offset`` to a candidate origin.

    Returns ``None`` when the computed origin would be negative (not a candidate).
    Kept beside :class:`ScanNeedle` / :class:`MagicHit` so backend parsers that import
    this module do not transitively pull in the detection workspace.
    """
    origin = hit_offset - needle_offset
    return origin if origin >= 0 else None


class HitOutcome(Enum):
    """Result of a format-owned scan-hit validator.

    ``NOT_THIS_FORMAT`` — identity never held (decoy magic, unparseable header).
    ``VALID`` — identity and cheap structure both hold.
    ``VALID_SHORT`` — identity and structure hold, but the archive declares an end
    before the source ends, which a decoy can do and a payload appended last does
    not. A scan keeps the first one as a fallback and looks on for a ``VALID`` hit;
    only a validator that knows where its format ends (7z) returns it, and only when
    ``remaining`` is known. Trailing bytes are legitimate (SFX configuration, a
    signature), so it is never a reject.
    ``DAMAGED`` — identity holds, structure does not (a 7z whose ``StartHeaderCRC``
    fails, or whose declared end overruns the source). A validated
    :func:`scan_for_magic` skips both non-``VALID`` grades while looking for a
    later ``VALID`` hit, then falls back to the first of them if none validate
    (so a damaged payload still reaches the parser). :func:`iter_magic_in_prefix`
    yields every structural match and lets the caller grade it. A later policy
    may treat ``DAMAGED`` as a still-identified candidate without changing this
    enum.
    """

    NOT_THIS_FORMAT = "not_this_format"
    VALID = "valid"
    VALID_SHORT = "valid_short"
    DAMAGED = "damaged"


class HitValidator(Protocol):
    """Format-owned SFX scan check: candidate-relative view plus known remaining.

    ``remaining`` is provable bytes from the *candidate origin* to source EOF
    (``workspace.remaining_known() - candidate_origin``), or ``None`` when the
    source length is unknown. It is a length, not a peek budget — do not confuse
    it with ``scan_limit``. The scan always passes it; ``None`` is a value, not
    an omitted argument.

    ``peek_more(n)`` returns fewer than ``n`` bytes when the source ends, or
    when the detector's budget clamps the view. :func:`scan_for_magic` reads the
    source forward until it holds ``n`` bytes past the candidate; the detector's
    SFX scan hands out a
    :meth:`~archivey.internal.detection_workspace.PrefixWorkspace.candidate_view`
    that reaches ``validator_allowance(budget)`` past ``scan_limit``:
    :data:`VALIDATOR_PEEK_MAX` under the presets, so a candidate near the end of
    the window is judged on the same bytes as one inside it. Under a smaller
    ``max_scan_bytes`` the view can clamp first; the workspace notes the clamp
    and the scan records ``sfx_scan`` as cut short. Either way a short peek means
    the header was not checked, so the candidate is not this format. A validator
    must not read more than :data:`VALIDATOR_PEEK_MAX`.
    """

    def __call__(
        self,
        peek_more: Callable[[int], bytes],
        remaining: int | None,
    ) -> HitOutcome: ...


class ExecutableCue(Enum):
    """How strongly a source's leading bytes say "this is a prefix worth scanning".

    The cue is a **cost gate**: it decides whether to spend the ``SFX_MAX`` window,
    not whether a hit is trustworthy. Hit validators decide that.

    ``STRONG`` means structurally confirmed — a DOS header whose ``e_lfanew`` actually
    points at a ``PE\\0\\0`` signature, an ELF identification block whose class, data
    encoding and version fields are all valid, or a Mach-O header whose ``cputype`` /
    ``filetype`` (thin) or fat arch table parse. Arbitrary data reaches this by accident
    with vanishing probability. A strong cue with no archive needle suppresses content
    probes.

    ``WEAK`` is the two- or four-byte prefix alone (``MZ``, ``\\x7fELF``, or ``#!``).
    It is enough to justify *looking* for an appended archive, but not enough to
    overrule a content probe: ``MZ`` is two bytes, and a genuine Brotli stream that
    happens to start with them must still be detectable (``format-detection``:
    "Executable-looking prefixes must not silently become a wrong stream format" is
    outcome-shaped, not "disable Brotli on ``MZ``").

    Mach-O is the exception: its magic raises **no** cue until the header parses,
    because ``ca fe ba be`` is also the Java class-file magic and a weak cue would
    still put every ``.class`` file through the scan.
    """

    NONE = "none"
    WEAK = "weak"
    STRONG = "strong"


class ScanNeedle(NamedTuple):
    """A magic needle plus the offset at which it sits *within its candidate*.

    TAR's ``ustar`` sits at candidate offset 257, so a hit at absolute ``H`` denotes a
    candidate origin of ``H - 257``. A gzip or ZIP local-header needle begins at
    candidate offset zero.
    """

    magic: bytes
    offset: int = 0


class MagicHit(NamedTuple):
    """A scan hit expressed as a candidate origin, not a raw needle position."""

    candidate_origin: int
    needle: bytes
    needle_offset: int


class ScanMiss(Enum):
    """Why :func:`scan_for_magic` returned no :class:`MagicHit`.

    ``NO_MATCH`` — no needle in the window.
    ``CAPPED`` — :data:`MAX_VALIDATED_CANDIDATES` rejections of one format, none
    ``VALID`` or ``VALID_SHORT``. ``CAPPED`` discards the damaged fallback on purpose: 256
    rejections is evidence that none of them is the payload, so the scan returns no
    origin rather than the first decoy. A ``VALID_SHORT`` hit is not a rejection
    (its header checked out), so the cap returns it rather than a miss. An uncapped
    window of rejected candidates is not a miss: those become the fallback origin
    (earliest identified), so the parser can name the damage.
    """

    NO_MATCH = "no_match"
    CAPPED = "capped"


class MagicScan(NamedTuple):
    """Outcome of :func:`scan_for_magic`.

    ``hit`` is, in order of preference: the earliest ``VALID`` candidate; the
    earliest ``VALID_SHORT`` one; the earliest identified but rejected one. ``None``
    only when there was nothing to fall back to: no needle, or the
    rejected-candidate cap fired with no ``VALID_SHORT`` hit in hand.

    ``miss`` is set iff ``hit`` is ``None``.
    """

    hit: MagicHit | None
    miss: ScanMiss | None
    rejected_count: int


def describe_scan_miss(scan: MagicScan, *, limit: int) -> str:
    """One clause for why a validated scan returned no hit.

    Callers prefix this with their format name. ``limit`` is the scan bound they
    passed, so the message names the window the caller actually used.
    """
    if scan.miss is ScanMiss.CAPPED:
        return (
            f"stopped after {MAX_VALIDATED_CANDIDATES} rejected candidates "
            f"within the {limit}-byte self-extracting scan window"
        )
    return f"no signature within the {limit}-byte self-extracting scan window"


class HitSelector(Generic[_T]):
    """The SFX hit-selection rule both scans share, fed one graded hit at a time.

    The earliest ``VALID`` hit wins. Failing that, the first ``VALID_SHORT`` hit;
    failing that, with ``keep_damaged``, the first other hit, so a damaged payload
    still reaches the parser. A later ``VALID`` hit displaces the short one only
    when its ``key`` (the format) matches: the preference for a hit that ends at the
    end of the source is a tie-break among candidates of one format, and never
    reorders formats. Every other hit, a second short one included, is a rejection.

    Rejections are counted per ``key``, so each format gets ``cap`` of them, as each
    parser's own one-format scan does. ``cap_keys`` names the keys the cap applies
    to; ``None`` applies it to every key. Once a key reaches ``cap`` it is capped: the
    caller stops validating that key's candidates (:meth:`is_capped`), and
    :meth:`offer` ignores them. :meth:`result` then gives a ``VALID`` or short hit
    if one is held (a ``VALID_SHORT`` hit is structurally valid, not a rejection, so
    the cap does not discard it), and otherwise :attr:`ScanMiss.CAPPED`. Either way
    :attr:`capped` stays true, because the candidates the cap skipped were never
    judged.
    """

    def __init__(
        self,
        *,
        keep_damaged: bool,
        cap: int | None,
        cap_keys: Container[object] | None = None,
    ) -> None:
        self._keep_damaged = keep_damaged
        self._cap = cap
        self._cap_keys = cap_keys
        self._chosen: _T | None = None
        self._short: tuple[object, _T] | None = None
        self._fallback: _T | None = None
        self._rejected_by_key: dict[object, int] = {}
        self._capped_keys: set[object] = set()
        self.rejected = 0

    @property
    def capped(self) -> bool:
        """Whether any key reached the cap, so some candidates were never judged."""
        return bool(self._capped_keys)

    def is_capped(self, key: object) -> bool:
        """Whether ``key`` reached the cap; its later candidates are not judged."""
        return key in self._capped_keys

    def offer(self, key: object, hit: _T, outcome: HitOutcome) -> bool:
        """Grade ``hit``; ``True`` means a ``VALID`` hit decided the scan.

        A hit for a capped key is ignored. A caller that must stop once a key is
        capped checks :meth:`is_capped` itself.
        """
        if key in self._capped_keys:
            return False
        if outcome is HitOutcome.VALID:
            short = self._short
            self._chosen = short[1] if short is not None and short[0] != key else hit
            return True
        if outcome is HitOutcome.VALID_SHORT and self._short is None:
            self._short = (key, hit)
            return False
        if self._keep_damaged and self._fallback is None:
            self._fallback = hit
        self.rejected += 1
        count = self._rejected_by_key.get(key, 0) + 1
        self._rejected_by_key[key] = count
        if (
            self._cap is not None
            and count >= self._cap
            and (self._cap_keys is None or key in self._cap_keys)
        ):
            self._capped_keys.add(key)
        return False

    def result(self) -> tuple[_T | None, ScanMiss | None]:
        """The selected hit, or ``None`` and why there is none."""
        if self._chosen is not None:
            return self._chosen, None
        if self._short is not None:
            return self._short[1], None
        if self._capped_keys:
            return None, ScanMiss.CAPPED
        if self._fallback is not None:
            return self._fallback, None
        return None, ScanMiss.NO_MATCH


def executable_cue(prefix: bytes) -> ExecutableCue:
    """Classify ``prefix`` as :class:`ExecutableCue`.

    Reads only ``prefix`` — the bytes detection already peeked — so a source whose
    leading bytes are not prefix-shaped costs a handful of byte comparisons, and
    nothing here ever reaches back to the source for more.

    That bounds how strong ``STRONG`` can get: a DOS header whose ``e_lfanew`` points
    past the end of ``prefix`` grades ``WEAK``, because the ``PE\\0\\0`` it promises is not
    in hand to confirm. Exceeding what this prefix can confirm is "cannot confirm
    cheaply", never "not an executable". Real PE files put the header within a few
    hundred bytes, so this costs nothing in practice; when it does bite, the result is
    the ordinary weak-cue path (scan, then probes on a miss), never a wrong answer.
    """
    if prefix.startswith(_MZ):
        return ExecutableCue.STRONG if _is_pe(prefix) else ExecutableCue.WEAK
    if prefix.startswith(_ELF):
        return ExecutableCue.STRONG if _is_elf(prefix) else ExecutableCue.WEAK
    if prefix.startswith(b"#!"):
        return ExecutableCue.WEAK
    if _is_macho(prefix):
        return ExecutableCue.STRONG
    return ExecutableCue.NONE


def _is_pe(prefix: bytes) -> bool:
    """Whether a ``MZ`` prefix carries a DOS header pointing at a real PE signature.

    No upper bound on ``e_lfanew`` turns a large pointer into "not an executable":
    if the PE signature is not in this prefix, the cue stays ``WEAK``. Alignment is
    not required — a valid image may be unaligned.
    """
    if len(prefix) < _E_LFANEW_OFFSET + 4:
        return False
    (e_lfanew,) = struct.unpack_from("<I", prefix, _E_LFANEW_OFFSET)
    if not _DOS_HEADER_SIZE <= e_lfanew <= len(prefix) - len(_PE):
        return False
    return prefix[e_lfanew : e_lfanew + len(_PE)] == _PE


def _is_elf(prefix: bytes) -> bool:
    """Whether an ``\\x7fELF`` prefix carries a valid identification block.

    ``EI_CLASS`` (32/64-bit), ``EI_DATA`` (endianness) and ``EI_VERSION`` are the three
    ident fields with a closed set of legal values.
    """
    if len(prefix) < 7:
        return False
    return prefix[4] in (1, 2) and prefix[5] in (1, 2) and prefix[6] == 1


# Mach-O magics as they appear on disk. Thin ones are unique; fat ``ca fe ba be`` is
# also the Java class-file magic, which is why Mach-O raises no cue until the header
# parses — a weak match would still enroll every ``.class`` file in the scan.
_MACHO_THIN = {
    b"\xce\xfa\xed\xfe": ("<", False),  # 32-bit LE
    b"\xfe\xed\xfa\xce": (">", False),  # 32-bit BE
    b"\xcf\xfa\xed\xfe": ("<", True),  # 64-bit LE
    b"\xfe\xed\xfa\xcf": (">", True),  # 64-bit BE
}
_MACHO_FAT = {
    b"\xca\xfe\xba\xbe": (">", False),  # fat 32-bit offsets, BE
    b"\xbe\xba\xfe\xca": ("<", False),  # fat 32-bit offsets, LE
    b"\xca\xfe\xba\xbf": (">", True),  # fat 64-bit offsets, BE
    b"\xbf\xba\xfe\xca": ("<", True),  # fat 64-bit offsets, LE
}
# mach/machine.h CPU_TYPE_* values, unpacked in the file's endianness.
_MACHO_CPU_TYPES = frozenset(
    {
        1,  # VAX
        6,  # MC680x0
        7,  # X86 / I386
        0x01000007,  # X86_64
        8,  # MIPS
        10,  # MC98000
        11,  # HPPA
        12,  # ARM
        0x0100000C,  # ARM64
        0x0200000C,  # ARM64_32
        13,  # MC88000
        14,  # SPARC
        15,  # I860
        18,  # POWERPC
        0x01000012,  # POWERPC64
    }
)
# loader.h MH_* filetypes; 1–16 leaves a little room past MH_FILESET without
# accepting a zeroed or class-file field.
_MACHO_FILETYPES = range(1, 17)
_MACHO_FAT_ARCH_MAX = 16


def _is_macho(prefix: bytes) -> bool:
    """Whether ``prefix`` is a Mach-O header that parses (thin or fat).

    Magic alone is not enough — ``ca fe ba be`` is the Java class-file magic too.
    """
    if len(prefix) < 4:
        return False
    key = bytes(prefix[:4])
    thin = _MACHO_THIN.get(key)
    if thin is not None:
        return _thin_macho_parses(prefix, thin[0], thin[1])
    fat = _MACHO_FAT.get(key)
    if fat is not None:
        return _fat_macho_parses(prefix, fat[0], fat[1])
    return False


def _thin_macho_parses(prefix: bytes, endian: str, is_64: bool) -> bool:
    size = 32 if is_64 else 28
    if len(prefix) < size:
        return False
    cputype, _cpusubtype, filetype = struct.unpack_from(endian + "iiI", prefix, 4)
    return cputype in _MACHO_CPU_TYPES and filetype in _MACHO_FILETYPES


def _fat_macho_parses(prefix: bytes, endian: str, is_64: bool) -> bool:
    if len(prefix) < 8:
        return False
    (nfat_arch,) = struct.unpack_from(endian + "I", prefix, 4)
    if not 1 <= nfat_arch <= _MACHO_FAT_ARCH_MAX:
        return False
    arch_size = 32 if is_64 else 20
    table_end = 8 + nfat_arch * arch_size
    if len(prefix) < table_end:
        return False
    # fat_arch: cputype, cpusubtype, offset, size, align. fat_arch_64 widens offset
    # and size to 64 bits and appends a reserved word; the field order is the same.
    arch_fmt = endian + ("iiQQII" if is_64 else "iiIII")
    for i in range(nfat_arch):
        fields = struct.unpack_from(arch_fmt, prefix, 8 + i * arch_size)
        cputype, _cpusubtype, offset, size, align = fields[:5]
        if (
            cputype not in _MACHO_CPU_TYPES
            or size == 0
            or offset < table_end
            or align >= 32
        ):
            return False
    return True


def _normalize_needles(
    needles: Sequence[bytes | ScanNeedle],
) -> tuple[ScanNeedle, ...]:
    out: list[ScanNeedle] = []
    for n in needles:
        if isinstance(n, ScanNeedle):
            out.append(n)
        else:
            out.append(ScanNeedle(n, 0))
    return tuple(out)


class _EarliestFinder:
    """Earliest needle occurrence at or after a rising ``start``, in linear time.

    Each needle's next match is remembered, so a later :meth:`find` searches only
    past it instead of re-running ``bytes.find`` from ``start`` for every needle.
    Re-searching from each candidate made a scan packed with one needle's decoys
    quadratic whenever another needle was absent (each miss re-read to the end):
    about 75 s for 1 MiB of back-to-back RAR5 ids. Tracking positions returns the
    same hits in the same order; ties still go to the needle listed first.

    ``data`` may grow between calls (the validated scan's window is extended by
    validator peeks) but must not otherwise change. ``start`` must not decrease.

    ``searched`` is how far a previous pass already covered. A shorter
    needle that fitted entirely in that prefix must not be re-found in the overlap
    kept for a longer sibling (RAR5's 8 bytes vs RAR4's 7, or ZIP's 4).

    ``dropped`` holds magics no longer searched for; it may grow between calls. A
    dropped needle is not searched again, so a window carpeted with its decoys costs
    only the other needles' ``bytes.find``.
    """

    def __init__(
        self,
        data: bytes | bytearray,
        needles: Sequence[ScanNeedle],
        *,
        searched: int = 0,
        dropped: Container[bytes] = frozenset(),
    ) -> None:
        self._data = data
        self._needles = needles
        self._dropped = dropped
        # Per needle: the lowest index it may match at (the ``searched`` skip).
        self._floors = [max(0, searched - (len(n.magic) - 1)) for n in needles]
        # Per needle: its next match (``-1`` for none), and ``len(data)`` when that
        # was computed. A ``-1`` goes stale only when ``data`` grows.
        self._next = [-1] * len(needles)
        self._scanned_len = [-1] * len(needles)
        self._last_start = 0

    def find(self, start: int = 0) -> tuple[int, ScanNeedle] | None:
        assert start >= self._last_start, "_EarliestFinder.find: start went back"
        self._last_start = start
        data = self._data
        size = len(data)
        best: tuple[int, ScanNeedle] | None = None
        dropped = self._dropped
        for i, needle in enumerate(self._needles):
            if needle.magic in dropped:
                continue
            found = self._next[i]
            scanned_len = self._scanned_len[i]
            if scanned_len < 0 or (found >= 0 and found < start):
                # Never searched, or the remembered match is behind ``start``.
                found = data.find(needle.magic, max(start, self._floors[i]))
                self._next[i], self._scanned_len[i] = found, size
            elif found < 0 and scanned_len != size:
                # No match in the old bytes; search only what was appended, less
                # the needle's length so a match straddling the old end is found.
                resume = max(
                    start, self._floors[i], scanned_len - (len(needle.magic) - 1)
                )
                found = data.find(needle.magic, resume)
                self._next[i], self._scanned_len[i] = found, size
            if found >= 0 and (best is None or found < best[0]):
                best = (found, needle)
        return best


def _remaining_from_origin(
    scan_start: int | None, origin: int, total: int | None
) -> int | None:
    """Provable bytes from ``origin`` (relative to the scan start) to source EOF.

    ``None`` when the start position or the total size is unknown. ``total`` is
    the scan-start size probe — callers compute it once, because it cannot
    change during a forward scan.
    """
    if scan_start is None or total is None:
        return None
    remaining = total - scan_start - origin
    return remaining if remaining >= 0 else None


def _scan_start_position(source: BinaryIO) -> int | None:
    try:
        return source.tell()
    except (OSError, ValueError):
        # Closed file: ValueError. Pipe/FIFO: OSError. io.UnsupportedOperation
        # subclasses both, so it does not need its own arm.
        return None


def scan_for_magic(
    source: BinaryIO,
    needles: Sequence[bytes | ScanNeedle],
    *,
    limit: int = SFX_MAX,
    validator: HitValidator | None = None,
) -> MagicScan:
    """The earliest ``needles`` match within ``limit`` bytes, as a :class:`MagicScan`.

    The scan starts at ``source``'s **current position** and the returned candidate
    origin is relative to it. A needle counts as found only when it lies wholly inside
    the first ``limit`` bytes, so the bound is a promise about the whole magic and not
    just its first byte. A hit whose computed candidate origin would be negative is
    discarded and the scan continues.

    ``validator``, when given, is the same :class:`HitValidator` shape the detector
    uses: a candidate-relative ``peek_more(n)`` plus known remaining from that origin.
    Candidates are chosen by :class:`HitSelector` with the damaged fallback kept and
    :data:`MAX_VALIDATED_CANDIDATES` as the rejection cap. Each caller passes the
    needles of one format (the 7z and RAR parsers). With no validator the first
    structural match wins and there is no cap.

    ``peek_more`` is served from the scan window and may pull extra bytes *forward*
    if the header extends past what has been read. It does not seek back. The source
    does not have to be seekable. A non-zero :class:`ScanNeedle` offset together with
    a validator is an error — the origin can sit behind the overlap trim, and a short
    peek would silently mis-grade it. ``remaining`` is filled from a size probe taken
    once at scan start when both ``tell()`` and the total size are known, otherwise
    ``None``.

    ``source`` is left wherever the scan stopped reading — callers reposition it from
    the returned origin. Overlapping needles are resolved by earliest start, not by
    needle order, so a caller can pass several magics (RAR4's and RAR5's ids, say) and
    get the one that actually comes first in the file.
    """
    normalized = _normalize_needles(needles)
    if not normalized:
        return MagicScan(None, ScanMiss.NO_MATCH, 0)
    if validator is not None and any(needle.offset != 0 for needle in normalized):
        raise ValueError(
            "scan_for_magic(validator=...) requires offset-0 needles; "
            "a non-zero ScanNeedle.offset leaves the origin behind the window"
        )
    # Bytes carried between chunks so a magic straddling a chunk boundary still matches.
    overlap = max(len(needle.magic) for needle in normalized) - 1

    window = bytearray()
    # Offset (from the scan start) of window[0], so a hit inside the window maps back.
    window_start = 0
    consumed = 0
    search_from = 0
    # Window-relative end of the previous pass. The skip is per needle: a shorter
    # needle wholly inside the retained overlap is not re-found after the trim.
    # A *longer* sibling that was not fully inside the previous window is still
    # searched, so the same candidate origin can be validated twice — once via
    # the short needle, once via the long. Unreachable for the needle sets in
    # the tree today (7z is one needle; RAR5/RAR4 differ at byte 6).
    # ``_EarliestFinder(..., searched=)`` is the same skip ``iter_magic_in_prefix``
    # already uses.
    searched = 0
    selector: HitSelector[MagicHit] = HitSelector(
        keep_damaged=True, cap=MAX_VALIDATED_CANDIDATES
    )
    scan_start = _scan_start_position(source) if validator is not None else None
    # One probe: the total cannot change during a forward scan, and repeating it
    # inside the candidate loop is 256 metadata reads (or 512 seeks on an
    # unflushed r+b handle) for a capped scan.
    total = source_byte_size(source) if scan_start is not None else None

    def peek_more(n: int, *, origin: int) -> bytes:
        nonlocal consumed
        if n <= 0:
            return b""
        origin_in_window = origin - window_start
        if origin_in_window < 0:
            return b""
        need = origin_in_window + n
        while len(window) < need:
            chunk = source.read(min(_SCAN_CHUNK, need - len(window)))
            if not chunk:
                break
            window.extend(chunk)
            consumed += len(chunk)
        return bytes(window[origin_in_window : origin_in_window + n])

    def bind_view(bound_origin: int) -> Callable[[int], bytes]:
        def view(n: int) -> bytes:
            return peek_more(n, origin=bound_origin)

        return view

    def finish() -> MagicScan:
        return MagicScan(*selector.result(), selector.rejected)

    while consumed < limit:
        chunk = source.read(min(_SCAN_CHUNK, limit - consumed))
        if not chunk:
            break
        consumed += len(chunk)
        window.extend(chunk)

        # Rebuilt per chunk: the finder's remembered positions are window-relative,
        # and the trim below shifts them. Validator peeks inside the loop only append.
        finder = _EarliestFinder(window, normalized, searched=searched)
        while True:
            hit = finder.find(search_from)
            if hit is None:
                break
            index, needle = hit
            abs_pos = window_start + index
            if abs_pos + len(needle.magic) > limit:
                # This needle does not fit. A later shorter one still might
                # (needles of different lengths), so skip rather than stop.
                # Reached only when a validator peek has already pulled the
                # window past ``limit``; the main read loop never stores those
                # bytes. Two needles matching at the *same* index are a
                # different case: ``_EarliestFinder`` returns one of them and
                # ``search_from = index + 1`` skips the other even if the
                # shorter would have fitted. Unreachable for (RAR5, RAR4):
                # byte 6 differs, so they cannot match at one index.
                search_from = index + 1
                continue
            origin = candidate_origin_for_hit(abs_pos, needle.offset)
            if origin is None:
                # Negative origin — not a candidate; resume just past this decoy.
                search_from = index + 1
                continue
            found = MagicHit(origin, needle.magic, needle.offset)
            if validator is None:
                return MagicScan(found, None, 0)
            remaining = _remaining_from_origin(scan_start, origin, total)
            # One key for every hit: each caller passes the needles of one format,
            # so a later VALID hit always displaces a held short one, and the cap
            # counts that one format's rejections.
            if (
                selector.offer(None, found, validator(bind_view(origin), remaining))
                or selector.capped
            ):
                return finish()
            search_from = index + 1

        search_from = 0
        if len(window) > overlap:
            window_start += len(window) - overlap
            del window[: len(window) - overlap]
        searched = len(window)

    return finish()


def iter_magic_in_prefix(
    peek_more: Callable[[int], bytes],
    needles: Sequence[bytes | ScanNeedle],
    *,
    limit: int = SFX_MAX,
    dropped: AbstractSet[bytes] = frozenset(),
) -> Iterator[MagicHit]:
    """Yield every in-window ``needles`` match, earliest first, as :class:`MagicHit`.

    Callers skip decoys (a candidate that fails its format-owned validator) and
    keep iterating. A caller that stops looking for a magic adds it to ``dropped``
    between yields; its later matches are not searched for, and once every needle is
    dropped the iteration ends without reading further. A negative candidate origin
    is discarded rather than yielded.
    Each match is yielded once: a shorter needle that sat wholly inside the previous
    peek is not re-emitted when the next step rewinds by the longest needle's overlap.
    ``peek_more(n)`` returns the source's first ``n`` bytes without consuming them
    (idempotent, growing supersets — a
    :class:`~archivey.internal.detection_workspace.PrefixWorkspace` view).
    """
    normalized = _normalize_needles(needles)
    if not normalized:
        return
    searched = 0

    magics = {needle.magic for needle in normalized}
    for step in (*_PEEK_STEPS, limit):
        if step <= searched:
            continue
        # The detector never gets here today: it drops only capped formats' magics
        # (RAR, 7z), and ZIP's is never capped, so it stays searched.
        if magics <= dropped:
            return
        data = peek_more(min(step, limit))
        search_from = 0
        finder = _EarliestFinder(data, normalized, searched=searched, dropped=dropped)
        while True:
            hit = finder.find(search_from)
            if hit is None:
                break
            index, needle = hit
            origin = candidate_origin_for_hit(index, needle.offset)
            if origin is not None:
                yield MagicHit(origin, needle.magic, needle.offset)
            search_from = index + 1
        if len(data) < step:
            return  # the source ended inside this peek; nothing more to search
        searched = len(data)
