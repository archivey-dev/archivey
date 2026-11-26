"""Salvage mode's header search for RAR (``open_archive(salvage=True)``).

The shared search driver (:mod:`archivey.internal.salvage`) asks a format for a
``find_header(window, start, stop)`` that is pure on bytes. This module holds RAR's two:

- :class:`Rar5Finder` finds a RAR5 header that passes its CRC-32.
- :class:`Rar3Finder` finds a RAR 1.5-4 ``FILE`` or ``SUB`` header (and ``MAIN`` at a
  lost start) that passes its CRC16.

Before a CRC is hashed, each finder checks only what the walk in
:mod:`~archivey.internal.backends.rar_parser` would also reject: a header the finder
drops is one the walk would not list. Neither puts a condition on the header flags
or on a field value the walk lists (method, dictionary size, host OS), because a
filter there drops real headers: the last FILE header of every volume but the last
has the split-after flag ``0x10`` set. Values are compared as the walk decodes them,
so a vint with a non-minimal encoding passes wherever the walk reads it.

A RAR5 header can be 2 MiB long. Hashing such a candidate at each byte would make the
work grow with what crafted bytes declare, not with the input, so the CRC of a
candidate longer than :data:`_DIRECT_CRC_MAX` comes from prefix CRCs of the window
(:class:`_WindowCrc`): each byte of a window is hashed once for the prefixes, and a
candidate costs at most two short hashes and a few table lookups.

:func:`is_rar5_qo_copy` tells a FILE header copy in a quick-open service header's
data from a member's header: the copy passes its CRC, but its data is not after it.
"""

from __future__ import annotations

import re
import struct
import zlib
from collections.abc import Callable

from archivey.exceptions import CorruptionError
from archivey.internal.backends.rar_parser import (
    _RAR3_FILE,
    _RAR3_FILE_EXTTIME,
    _RAR3_FILE_LARGE,
    _RAR3_FILE_SALT,
    _RAR3_MAIN,
    _RAR3_SUB,
    _RAR5_ENCRYPTION,
    _RAR5_ENDARC,
    _RAR5_FILE,
    _RAR5_MAIN,
    _RAR5_SERVICE,
    _parse_rar3_file_header,
    load_vint,
    rar3_main_crc_end,
)
from archivey.internal.salvage import HeaderSearch

# The longest header each finder reads from a candidate position: the CRC, a size
# vint of at most 3 bytes and the size it holds (RAR5); ``HEAD_SIZE``, a u16 (RAR
# 1.5-4). The driver's windows overlap by this much, less one byte.
RAR5_MAX_HEADER_SPAN = 4 + 3 + (1 << 21)
RAR3_MAX_HEADER_SPAN = 0xFFFF

# A candidate up to this long has its CRC hashed directly; a longer one gets it from
# the window's prefix CRCs.
_DIRECT_CRC_MAX = 4096

# The fixed part of a RAR 1.5-4 FILE or SUB header: the 7-byte block header, then
# PACK_SIZE, UNP_SIZE, HOST_OS, FILE_CRC, FTIME, UNP_VER, METHOD, NAME_SIZE, ATTR.
_RAR3_FILE_FIXED = 32
_S_RAR3_BLOCK = struct.Struct("<HBHH")
_S_U16 = struct.Struct("<H")
_S_U32 = struct.Struct("<L")

# Positions whose bytes can start a RAR5 header: four CRC bytes, a size vint of 1 to
# 3 bytes, then a type vint whose value is 1 to 5 (in any encoding the walk decodes:
# the value's low bits, then continuation bytes that add nothing).
_RAR5_CANDIDATE = re.compile(
    rb"(?=[\x00-\xff]{4}"
    rb"(?:[\x03-\x7f]|[\x80-\xff][\x00-\x7f]|[\x80-\xff]{2}[\x00-\x7f])"
    rb"(?:[\x01-\x05]|[\x81-\x85]\x80{0,8}\x00))",
    re.DOTALL,
)
# Positions whose third byte is a RAR 1.5-4 FILE or SUB type, and with MAIN too.
_RAR3_CANDIDATE = re.compile(rb"(?=[\x00-\xff]{2}[\x74\x7a])", re.DOTALL)
_RAR3_CANDIDATE_OR_MAIN = re.compile(rb"(?=[\x00-\xff]{2}[\x73\x74\x7a])", re.DOTALL)


# ---------------------------------------------------------------------------
# CRC-32 of a slice from the window's prefix CRCs
# ---------------------------------------------------------------------------

# zlib's CRC-32 satisfies crc(A + B) = shift(crc(A), len(B)) ^ crc(B), where
# shift(c, n) advances the register through n zero bytes. shift is linear over
# GF(2), so it is a 32x32 bit matrix; the one for n = 2**k bytes is kept as four
# 256-entry tables, one per byte of the register, and shift(c, n) applies the
# tables of the bits set in n. 23 levels cover a RAR5 header (2 MiB + 7 bytes).
_SHIFT_LEVELS = 23
# Built on first use and published whole, as one tuple: readers on other threads see
# either no tables or every level, never a list still growing.
_shift_tables: tuple[tuple[list[int], ...], ...] = ()


def _tables_from_basis(basis: list[int]) -> tuple[list[int], ...]:
    """The four byte tables of the linear map whose image of bit ``i`` is
    ``basis[i]``."""
    tables = []
    for byte in range(4):
        table = [0] * 256
        images = basis[8 * byte : 8 * byte + 8]
        for value in range(1, 256):
            low = value & -value
            table[value] = table[value ^ low] ^ images[low.bit_length() - 1]
        tables.append(table)
    return tuple(tables)


def _apply(tables: tuple[list[int], ...], value: int) -> int:
    t0, t1, t2, t3 = tables
    return (
        t0[value & 0xFF]
        ^ t1[(value >> 8) & 0xFF]
        ^ t2[(value >> 16) & 0xFF]
        ^ t3[value >> 24]
    )


def _shift_table_levels() -> tuple[tuple[list[int], ...], ...]:
    """Every level of the shift tables, built on first use. Two threads that both
    build them get equal tables; whichever is published last stays."""
    global _shift_tables
    tables = _shift_tables
    if tables:
        return tables
    zero = zlib.crc32(b"\0")
    # One zero byte, from zlib itself: crc32(b"\0", c) ^ crc32(b"\0", 0).
    basis = [zlib.crc32(b"\0", 1 << bit) ^ zero for bit in range(32)]
    levels = []
    for _ in range(_SHIFT_LEVELS):
        level = _tables_from_basis(basis)
        levels.append(level)
        # Twice the bytes: the map applied to itself.
        basis = [_apply(level, image) for image in basis]
    tables = _shift_tables = tuple(levels)
    return tables


def _shift(crc: int, length: int) -> int:
    """``crc`` advanced through ``length`` zero bytes."""
    tables = _shift_table_levels()
    level = 0
    while length:
        if length & 1:
            crc = _apply(tables[level], crc)
        length >>= 1
        level += 1
    return crc


def crc32_from_prefixes(prefix_a: int, prefix_b: int, length: int) -> int:
    """The CRC-32 of ``x[a:b]`` from ``crc32(x[:a])``, ``crc32(x[:b])`` and
    ``b - a``."""
    return prefix_b ^ _shift(prefix_a, length)


class _WindowCrc:
    """CRC-32 of slices of one window, the long ones from prefix CRCs.

    The prefix CRC at every :data:`_STRIDE`-th byte is computed the first time a
    long slice needs one, in one pass, so each byte of the window is hashed once
    for them; a prefix CRC at any other point then hashes fewer than
    :data:`_STRIDE` bytes more.
    """

    _STRIDE = 256

    def __init__(self) -> None:
        self._window: bytes | None = None
        self._points: list[int] = []

    def crc(self, window: bytes, start: int, stop: int) -> int:
        if stop - start <= _DIRECT_CRC_MAX:
            return zlib.crc32(memoryview(window)[start:stop])
        return crc32_from_prefixes(
            self._prefix(window, start), self._prefix(window, stop), stop - start
        )

    def _prefix(self, window: bytes, at: int) -> int:
        if window is not self._window:
            self._window = window
            self._points = [0]
        points = self._points
        stride = self._STRIDE
        view = memoryview(window)
        index = at // stride
        while len(points) <= index:
            here = (len(points) - 1) * stride
            points.append(zlib.crc32(view[here : here + stride], points[-1]))
        base = index * stride
        return zlib.crc32(view[base:at], points[index])


# ---------------------------------------------------------------------------
# RAR5
# ---------------------------------------------------------------------------


def _vint_in(window: bytes, pos: int, end: int) -> tuple[int, int] | None:
    """A vint at ``pos`` that ends at or before ``end``; ``None`` otherwise."""
    try:
        value, after = load_vint(window, pos)
    except CorruptionError:
        return None
    if after > end:
        return None
    return value, after


def rar5_header_end(window: bytes, pos: int) -> int | None:
    """Where the RAR5 header at ``pos`` ends in ``window``, when every check before
    its CRC passes (checks 1 to 5 of ``openspec/changes/salvage-rar-search``
    design §3); ``None`` otherwise.

    The size vint is 1 to 3 bytes (the RAR5 note caps a header at 2 MiB) and at least 3,
    the smallest header. The type is one the note defines. The extra area, when the
    flags declare one, is smaller than the whole header (CRC and size vint included), as
    ``unrar`` and the walk require. The type's own fields fit in the header; no field
    value is checked.
    """
    n = len(window)
    q = pos + 4
    if q >= n:
        return None
    b0 = window[q]
    if b0 < 0x80:
        size = b0
        q += 1
    else:
        if q + 1 >= n:
            return None
        b1 = window[q + 1]
        if b1 < 0x80:
            size = (b0 & 0x7F) | (b1 << 7)
            q += 2
        else:
            if q + 2 >= n:
                return None
            b2 = window[q + 2]
            if b2 >= 0x80:
                return None
            size = (b0 & 0x7F) | ((b1 & 0x7F) << 7) | (b2 << 14)
            q += 3
    if size < 3:
        return None
    end = q + size
    if end > n:
        return None
    field = _vint_in(window, q, end)
    if field is None:
        return None
    block_type, q = field
    if not _RAR5_MAIN <= block_type <= _RAR5_ENDARC:
        return None
    field = _vint_in(window, q, end)
    if field is None:
        return None
    flags, q = field
    if flags & 0x01:
        field = _vint_in(window, q, end)
        if field is None:
            return None
        extra_size, q = field
        # ``unrar`` 7.00 reports "Corrupt header" for ``ExtraSize >= HeadSize``,
        # and ``HeadSize`` counts the whole header, its CRC and size vint
        # included; so does the walk (``_walk_rar5_file_extras``). Comparing with
        # the body length ``size`` instead would drop a header the walk lists.
        if extra_size >= end - pos:
            return None
    if flags & 0x02:
        field = _vint_in(window, q, end)
        if field is None:
            return None
        q = field[1]
    if not _rar5_fields_fit(window, q, end, block_type):
        return None
    return end


def _rar5_fields_fit(window: bytes, q: int, end: int, block_type: int) -> bool:
    """Whether the fields of a header of ``block_type`` from ``q`` fit before
    ``end``."""
    if block_type in (_RAR5_FILE, _RAR5_SERVICE):
        field = _vint_in(window, q, end)  # file flags
        if field is None:
            return False
        file_flags, q = field
        for _ in range(2):  # unpacked size, attributes
            field = _vint_in(window, q, end)
            if field is None:
                return False
            q = field[1]
        if file_flags & 0x02:  # modification time
            q += 4
        if file_flags & 0x04:  # data CRC
            q += 4
        for _ in range(2):  # compression information, host OS
            field = _vint_in(window, q, end)
            if field is None:
                return False
            q = field[1]
        field = _vint_in(window, q, end)
        if field is None:
            return False
        name_size, q = field
        return name_size >= 1 and q + name_size <= end
    if block_type == _RAR5_MAIN:
        field = _vint_in(window, q, end)
        if field is None:
            return False
        archive_flags, q = field
        if archive_flags & 0x02:  # volume number
            return _vint_in(window, q, end) is not None
        return True
    if block_type == _RAR5_ENDARC:
        return _vint_in(window, q, end) is not None
    assert block_type == _RAR5_ENCRYPTION
    field = _vint_in(window, q, end)  # version
    if field is None:
        return False
    field = _vint_in(window, field[1], end)
    if field is None:
        return False
    enc_flags, q = field
    q += 1 + 16  # KDF count, salt
    if enc_flags & 0x01:  # password check value
        q += 12
    return q <= end


class Rar5Finder:
    """``find_header`` for RAR5: the first position at or after ``start`` where a
    header passes :func:`rar5_header_end` and its CRC-32."""

    def __init__(self) -> None:
        self._crc = _WindowCrc()

    def __call__(self, window: bytes, start: int, stop: int) -> int | None:
        return self.find(window, start, stop)

    def find(self, window: bytes, start: int, stop: int | None) -> int | None:
        """As a call, looking only at positions before ``stop`` when it is given."""
        crc = self._crc
        for match in _RAR5_CANDIDATE.finditer(window, start):
            pos = match.start()
            if stop is not None and pos >= stop:
                return None
            end = rar5_header_end(window, pos)
            if end is None:
                continue
            stored = _S_U32.unpack_from(window, pos)[0]
            if crc.crc(window, pos + 4, end) == stored:
                return pos
        return None


def rar5_search() -> HeaderSearch:
    return HeaderSearch(Rar5Finder(), step=1, max_header_size=RAR5_MAX_HEADER_SPAN)


# The bytes a quick-open cache record holds before the header it copies: its CRC-32,
# then four vints (the record size, its flags, the offset and the copy's size).
_QO_RECORD_PREFIX_MAX = 4 + 4 * 10


def is_rar5_qo_copy(read_at: Callable[[int, int], bytes], header_at: int) -> bool:
    """Whether the RAR5 header at ``header_at`` is the copy a quick-open cache record
    holds, and not a member's own header.

    A ``QO`` service header's data is a run of cache records: CRC-32, the record
    size vint, then the record (flags, offset and size vints, and the header bytes
    it copies, last). The copy passes its own CRC, but its member's data is
    elsewhere. It is a copy when a record starts within the
    :data:`_QO_RECORD_PREFIX_MAX` bytes before it, ends where the header ends, says
    its copy is this long, and passes its own CRC-32.
    """
    head = read_at(header_at, 7)
    length = _rar5_header_length(head) if len(head) == 7 else None
    if length is None:
        return False
    header_end = header_at + length
    lead = min(header_at, _QO_RECORD_PREFIX_MAX)
    data = read_at(header_at - lead, lead + header_end - header_at)
    if len(data) != lead + header_end - header_at:
        return False
    header_size = header_end - header_at
    for back in range(5, lead + 1):
        rec = lead - back
        try:
            body_size, body = load_vint(data, rec + 4)
            if body + body_size != len(data):
                continue
            _flags, q = load_vint(data, body)
            _offset, q = load_vint(data, q)
            copy_size, q = load_vint(data, q)
        except CorruptionError:
            continue
        if q != lead or copy_size != header_size:
            continue
        stored = _S_U32.unpack_from(data, rec)[0]
        if zlib.crc32(memoryview(data)[rec + 4 :]) == stored:
            return True
    return False


# ---------------------------------------------------------------------------
# RAR 1.5-4
# ---------------------------------------------------------------------------


def rar3_header_check(
    window: bytes, pos: int, *, with_main: bool, crc: _WindowCrc | None = None
) -> bool:
    """Whether a RAR 1.5-4 ``FILE`` or ``SUB`` header (or, ``with_main``, a ``MAIN``
    header) at ``pos`` passes the checks of design §4 and its CRC16."""
    n = len(window)
    if pos + 7 > n:
        return False
    head_crc, block_type, flags, head_size = _S_RAR3_BLOCK.unpack_from(window, pos)
    end = pos + head_size
    if end > n:
        return False
    hash_slice = crc.crc if crc is not None else _direct_crc
    if block_type == _RAR3_MAIN:
        if not with_main:
            return False
        main_end = rar3_main_crc_end(flags)
        if head_size < main_end:
            return False
        return hash_slice(window, pos + 2, pos + main_end) & 0xFFFF == head_crc
    if block_type not in (_RAR3_FILE, _RAR3_SUB) or head_size < _RAR3_FILE_FIXED:
        return False
    name_size = _S_U16.unpack_from(window, pos + 26)[0]
    fixed_end = (
        _RAR3_FILE_FIXED
        + name_size
        + (8 if flags & _RAR3_FILE_LARGE else 0)
        + (8 if flags & _RAR3_FILE_SALT else 0)
    )
    if name_size < 1 or head_size < fixed_end:
        return False
    is_service = block_type == _RAR3_SUB
    if is_service:
        crc_end = head_size
    elif flags & _RAR3_FILE_EXTTIME:
        # Where the extended times end, read from their flag word alone: the
        # name is not decoded before the CRC16 passes, so a candidate costs the
        # bytes it spans (hashed once, ``_WindowCrc``) and not a parse of them.
        crc_end = _rar3_ext_time_end(window, pos + fixed_end, end) - pos
    else:
        crc_end = fixed_end
    if hash_slice(window, pos + 2, pos + crc_end) & 0xFFFF != head_crc:
        return False
    try:
        _member, parsed_end = _parse_rar3_file_header(
            window[pos:end],
            7,
            flags=flags,
            header_offset=0,
            header_size=head_size,
            data_offset=head_size,
            volume_index=0,
            is_service=is_service,
        )
    except CorruptionError:
        return False
    return parsed_end == crc_end


def _rar3_ext_time_end(window: bytes, at: int, end: int) -> int:
    """Where a RAR 1.5-4 ``EXTTIME`` block that starts at ``at`` ends, in a header
    that ends at ``end``. It walks the block as ``_parse_rar3_ext_time`` does: a flag
    word, then per time (mtime, ctime, atime, arctime) a DOS word unless it is the
    mtime, and up to 3 bytes of fraction."""
    if at + 2 > end:
        return at
    flags = _S_U16.unpack_from(window, at)[0]
    at += 2
    for shift in (12, 8, 4, 0):
        slot = flags >> shift
        if not slot & 8:
            continue
        if shift != 12:
            if at + 4 > end:
                continue
            at += 4
        at = min(at + (slot & 3), end)
    return at


def _direct_crc(window: bytes, start: int, stop: int) -> int:
    return zlib.crc32(memoryview(window)[start:stop])


class Rar3Finder:
    """``find_header`` for RAR 1.5-4: the first position at or after ``start`` where
    :func:`rar3_header_check` passes. ``with_main`` adds the ``MAIN`` type, looked
    for only at a lost start."""

    def __init__(self, *, with_main: bool = False) -> None:
        self._with_main = with_main
        self._pattern = _RAR3_CANDIDATE_OR_MAIN if with_main else _RAR3_CANDIDATE
        self._crc = _WindowCrc()

    def __call__(self, window: bytes, start: int, stop: int) -> int | None:
        return self.find(window, start, stop)

    def find(self, window: bytes, start: int, stop: int | None) -> int | None:
        for match in self._pattern.finditer(window, start):
            pos = match.start()
            if stop is not None and pos >= stop:
                return None
            if rar3_header_check(window, pos, with_main=self._with_main, crc=self._crc):
                return pos
        return None


def rar3_search() -> HeaderSearch:
    return HeaderSearch(Rar3Finder(), step=1, max_header_size=RAR3_MAX_HEADER_SPAN)


class LostStartFinder:
    """``find_header`` for a lost start, when the version is not known: the first
    position where a RAR5 header or a RAR 1.5-4 ``FILE``, ``SUB`` or ``MAIN`` header
    passes. The walk tells which one it is again from the bytes there."""

    def __init__(self) -> None:
        self._rar5 = Rar5Finder()
        self._rar3 = Rar3Finder(with_main=True)

    def __call__(self, window: bytes, start: int, stop: int) -> int | None:
        found = self._rar5.find(window, start, stop)
        older = self._rar3.find(window, start, stop if found is None else found)
        return older if older is not None else found


def lost_start_search() -> HeaderSearch:
    return HeaderSearch(LostStartFinder(), step=1, max_header_size=RAR5_MAX_HEADER_SPAN)


def _rar5_header_length(head: bytes) -> int | None:
    """The whole length of the RAR5 header ``head`` starts (at least 7 bytes of it),
    from its size vint; ``None`` when the vint is not 1 to 3 bytes."""
    size = 0
    for index in range(3):
        byte = head[4 + index]
        size |= (byte & 0x7F) << (7 * index)
        if byte < 0x80:
            return 4 + index + 1 + size
    return None


def classify_header(read_at: Callable[[int, int], bytes], offset: int) -> int | None:
    """Which version's header passes at ``offset``: 5, 4, or ``None``. RAR5 is asked
    first, as :class:`LostStartFinder` takes a RAR5 header where both pass at one
    position."""
    head = read_at(offset, 7)
    if len(head) < 7:
        return None
    length = _rar5_header_length(head)
    if length is not None:
        data = read_at(offset, length)
        if Rar5Finder().find(data, 0, 1) == 0:
            return 5
    rar3 = read_at(offset, max(7, _S_U16.unpack_from(head, 5)[0]))
    if rar3_header_check(rar3, 0, with_main=True):
        return 4
    return None
