"""Test-only encoders for ZIP Shrink (method 1) and Implode (method 6), and a ZIP writer.

No current tool writes either method, so the tests build their own. The encoders are
checked against Info-ZIP ``unzip`` where it is installed (``test_zip_legacy_methods``),
so they stand for a real writer, not for archivey's reading of APPNOTE.

``shrink`` widens its codes only when a code needs it, and clears when the table is
full. It keeps the table as a decoder does, a parent pointer per slot, so after a clear
frees the code just sent, the next entry's parent is that freed slot, whatever takes the
slot over later (7-Zip's "orphan"). ``implode`` is a greedy LZ77 with Huffman code lengths,
which are valid Shannon-Fano lengths.
"""

from __future__ import annotations

import heapq
import struct
import zlib
from dataclasses import dataclass, field


class BitWriter:
    """An LSB-first bit stream, as both methods write it."""

    def __init__(self) -> None:
        self._out = bytearray()
        self._acc = 0
        self._n = 0

    def write(self, value: int, n: int) -> None:
        self._acc |= value << self._n
        self._n += n
        while self._n >= 8:
            self._out.append(self._acc & 0xFF)
            self._acc >>= 8
            self._n -= 8

    def write_msb_first(self, code: int, n: int) -> None:
        for i in reversed(range(n)):
            self.write((code >> i) & 1, 1)

    def getvalue(self) -> bytes:
        tail = bytes([self._acc]) if self._n else b""
        return bytes(self._out) + tail


@dataclass
class ShrinkStats:
    max_width: int = 9
    partial_clears: int = 0
    orphans: int = 0
    full_table_codes: int = 0


_TABLE = 8192


def shrink(data: bytes, *, clear: bool = True) -> tuple[bytes, ShrinkStats]:
    """Shrink ``data``; ``clear=False`` never clears, so the table stays full."""
    stats = ShrinkStats()
    out = BitWriter()
    if not data:
        return b"", stats
    width = 9
    prefix = [-1] * _TABLE
    used = [True] * 257 + [False] * (_TABLE - 257)
    code_of: dict[tuple[int, int], int] = {}
    key_of: dict[int, tuple[int, int]] = {}
    free = 257

    def lowest_free() -> int:
        nonlocal free
        while free < _TABLE and used[free]:
            free += 1
        return free

    def add(code: int, char: int) -> None:
        slot = lowest_free()
        if slot >= _TABLE:
            stats.full_table_codes += 1
            return
        used[slot] = True
        prefix[slot] = code
        code_of[(code, char)] = slot
        key_of[slot] = (code, char)

    def emit(code: int) -> None:
        nonlocal width
        while code >= 1 << width:
            out.write(256, width)
            out.write(1, width)
            width += 1
            stats.max_width = width
        out.write(code, width)

    def partial_clear() -> None:
        nonlocal free
        out.write(256, width)
        out.write(2, width)
        stats.partial_clears += 1
        parent = [False] * _TABLE
        for slot in range(257, _TABLE):
            if used[slot]:
                parent[prefix[slot]] = True
        for slot in range(257, _TABLE):
            if not parent[slot] and used[slot]:
                used[slot] = False
                prefix[slot] = -1
                del code_of[key_of.pop(slot)]
        free = 257

    cur = data[0]
    for char in data[1:]:
        nxt = code_of.get((cur, char))
        if nxt is not None:
            cur = nxt
            continue
        emit(cur)
        if clear and lowest_free() >= _TABLE:
            partial_clear()
            if cur > 256 and not used[cur]:
                stats.orphans += 1
        add(cur, char)
        cur = char
    emit(cur)
    return out.getvalue(), stats


def _huffman_lengths(freqs: list[int], limit: int = 16) -> list[int]:
    """Huffman code lengths for ``freqs`` (every one above zero), at most ``limit``."""
    shift = 0
    while True:
        weights = [max(1, f >> shift) for f in freqs]
        heap: list[tuple[int, int, list[int]]] = [
            (w, i, [i]) for i, w in enumerate(weights)
        ]
        heapq.heapify(heap)
        lengths = [0] * len(freqs)
        tie = len(freqs)
        while len(heap) > 1:
            w1, _, s1 = heapq.heappop(heap)
            w2, _, s2 = heapq.heappop(heap)
            for i in s1 + s2:
                lengths[i] += 1
            heapq.heappush(heap, (w1 + w2, tie, s1 + s2))
            tie += 1
        if max(lengths) <= limit:
            return lengths
        shift += 1


def _shannon_fano_codes(lengths: list[int]) -> list[int]:
    """The code of each value (its top ``length`` bits of 16), as APPNOTE 5.3.6 assigns
    them: lengths ascending, the longest first from zero."""
    order = sorted(range(len(lengths)), key=lambda v: lengths[v])
    codes = [0] * len(lengths)
    code = step = last = 0
    for value in reversed(order):
        code += step
        if lengths[value] != last:
            last = lengths[value]
            step = 1 << (16 - last)
        codes[value] = code >> (16 - lengths[value])
    return codes


def _write_tree(out: BitWriter, lengths: list[int]) -> None:
    runs: list[int] = []
    i = 0
    while i < len(lengths):
        run = 1
        while run < 16 and i + run < len(lengths) and lengths[i + run] == lengths[i]:
            run += 1
        runs.append(((run - 1) << 4) | (lengths[i] - 1))
        i += run
    out.write(len(runs) - 1, 8)
    for byte in runs:
        out.write(byte, 8)


@dataclass
class ImplodeStats:
    matches: int = 0
    long_lengths: int = 0
    before_start: int = 0
    tokens: list = field(default_factory=list, repr=False)


def implode(
    data: bytes, *, large_window: bool, literal_tree: bool, zeros_before: bool = True
) -> tuple[bytes, ImplodeStats]:
    """Implode ``data``. ``zeros_before``: a match may reach before the start of the
    output, where a decoder reads zeros (Info-ZIP does)."""
    stats = ImplodeStats()
    low_bits = 7 if large_window else 6
    window = 1 << (low_bits + 6)
    min_match = 3 if literal_tree else 2
    max_match = min_match + 63 + 255
    padded = bytes(window) + data if zeros_before else data
    base = window if zeros_before else 0
    chains: dict[bytes, list[int]] = {}
    tokens: list[tuple[int, int] | int] = []
    i = base
    end = len(padded)
    if zeros_before:
        for j in range(base - min_match + 1, base):
            chains.setdefault(padded[j : j + min_match], []).append(j)
    while i < end:
        best_len = 0
        best_dist = 0
        key = padded[i : i + min_match]
        if len(key) == min_match:
            for j in reversed(chains.get(key, [])[-64:]):
                if i - j > window:
                    break
                length = 0
                while (
                    length < max_match
                    and i + length < end
                    and padded[j + length] == padded[i + length]
                ):
                    length += 1
                if length > best_len:
                    best_len, best_dist = length, i - j
        if best_len >= min_match:
            tokens.append((best_dist, best_len))
            stats.matches += 1
            if best_len - min_match >= 63:
                stats.long_lengths += 1
            if i - best_dist < base:
                stats.before_start += 1
            step = best_len
        else:
            tokens.append(padded[i])
            step = 1
        for j in range(i, min(i + step, end)):
            chains.setdefault(padded[j : j + min_match], []).append(j)
        i += step

    lit_freq = [1] * 256
    len_freq = [1] * 64
    dist_freq = [1] * 64
    for token in tokens:
        if isinstance(token, int):
            lit_freq[token] += 1
        else:
            dist, length = token
            dist_freq[(dist - 1) >> low_bits] += 1
            len_freq[min(length - min_match, 63)] += 1
    out = BitWriter()
    lit_lengths = _huffman_lengths(lit_freq)
    len_lengths = _huffman_lengths(len_freq)
    dist_lengths = _huffman_lengths(dist_freq)
    if literal_tree:
        _write_tree(out, lit_lengths)
    _write_tree(out, len_lengths)
    _write_tree(out, dist_lengths)
    lit_codes = _shannon_fano_codes(lit_lengths)
    len_codes = _shannon_fano_codes(len_lengths)
    dist_codes = _shannon_fano_codes(dist_lengths)
    for token in tokens:
        if isinstance(token, int):
            out.write(1, 1)
            if literal_tree:
                out.write_msb_first(lit_codes[token], lit_lengths[token])
            else:
                out.write(token, 8)
        else:
            dist, length = token
            out.write(0, 1)
            out.write((dist - 1) & ((1 << low_bits) - 1), low_bits)
            high = (dist - 1) >> low_bits
            out.write_msb_first(dist_codes[high], dist_lengths[high])
            sym = min(length - min_match, 63)
            out.write_msb_first(len_codes[sym], len_lengths[sym])
            if sym == 63:
                out.write(length - min_match - 63, 8)
    stats.tokens = tokens
    return out.getvalue(), stats


@dataclass
class LegacyEntry:
    name: str
    data: bytes
    method: int
    compressed: bytes
    flags: int = 0


def shrink_entry(name: str, data: bytes) -> LegacyEntry:
    return LegacyEntry(name, data, 1, shrink(data)[0])


def implode_entry(
    name: str, data: bytes, *, large_window: bool, literal_tree: bool
) -> LegacyEntry:
    compressed, _ = implode(data, large_window=large_window, literal_tree=literal_tree)
    flags = (0x2 if large_window else 0) | (0x4 if literal_tree else 0)
    return LegacyEntry(name, data, 6, compressed, flags)


def _header_fields(method: int, flags: int, sizes: tuple[int, int, int]) -> bytes:
    """Version needed (1.0), flags, method, DOS time and date, CRC-32 and sizes."""
    return struct.pack("<HHHHHIII", 10, flags, method, 0, 0x21, *sizes)


def build_zip(entries: list[LegacyEntry], *, descriptor: bool = False) -> bytes:
    """A plain ZIP of ``entries``, sizes in the local headers, as PKZIP 1.x wrote one.

    ``descriptor``: the local headers leave the CRC-32 and sizes zero (bit 3), and a
    data descriptor after each member's data holds them, as later writers stream one.
    """
    body = bytearray()
    central = bytearray()
    for entry in entries:
        name = entry.name.encode()
        crc = zlib.crc32(entry.data)
        offset = len(body)
        flags = entry.flags | (0x8 if descriptor else 0)

        sizes = (crc, len(entry.compressed), len(entry.data))
        local = _header_fields(entry.method, flags, (0, 0, 0) if descriptor else sizes)
        central_fields = _header_fields(entry.method, flags, sizes)
        body += (
            b"PK\x03\x04"
            + local
            + struct.pack("<HH", len(name), 0)
            + name
            + entry.compressed
        )
        if descriptor:
            body += b"PK\x07\x08" + struct.pack("<III", *sizes)
        central += (
            b"PK\x01\x02"
            + struct.pack("<H", 10)
            + central_fields
            + struct.pack("<HH", len(name), 0)
            + struct.pack("<HHHII", 0, 0, 0, 0, offset)
            + name
        )
    eocd = b"PK\x05\x06" + struct.pack(
        "<HHHHIIH", 0, 0, len(entries), len(entries), len(central), len(body), 0
    )
    return bytes(body + central + eocd)


def unshrink_reference(data: bytes, size: int) -> bytes:
    """A plain Shrink decoder to check ``ShrinkDecompressor`` against: every code
    walks its parents, slots come from a scan for the lowest free one, and a partial
    clear scans the table. Same semantics as the decoder (7-Zip's); raises
    ``ValueError`` where it raises ``CorruptionError``, and returns what it decoded
    when the input runs out.
    """
    parent = [-1] * _TABLE
    suffix = bytearray(_TABLE)
    used = [True] * 257 + [False] * (_TABLE - 257)
    out = bytearray()
    bits = nbits = pos = 0
    width = 9
    prev = -1
    prev_first = 0
    low = 257  # no free slot below it

    def read() -> int | None:
        nonlocal bits, nbits, pos
        while nbits < width:
            if pos == len(data):
                return None
            bits |= data[pos] << nbits
            pos += 1
            nbits += 8
        code = bits & ((1 << width) - 1)
        bits >>= width
        nbits -= width
        return code

    while len(out) < size:
        code = read()
        if code is None:
            break
        if code == 256:
            if prev < 0:
                raise ValueError("control code first")
            sub = read()
            if sub is None:
                break
            if sub == 1 and width < 13:
                width += 1
            elif sub == 2:
                # A used slot's pointer counts even to a free parent (an orphan's).
                pointed = [False] * _TABLE
                for slot in range(257, _TABLE):
                    if used[slot]:
                        pointed[parent[slot]] = True
                for slot in range(257, _TABLE):
                    if used[slot] and not pointed[slot]:
                        used[slot] = False
                low = 257
            else:
                raise ValueError("bad control code")
            continue
        new = -1
        if prev >= 0:
            while low < _TABLE and used[low]:
                low += 1
            if low == _TABLE:
                raise ValueError("table full")
            new = low
            used[new] = True
            parent[new] = prev
            suffix[new] = prev_first
        elif code > 255:
            raise ValueError("undefined code first")
        if not used[code]:
            raise ValueError("free code")
        entry = bytearray()
        walk = code
        while walk > 255:
            if not used[walk] or len(entry) >= _TABLE:
                raise ValueError("free code or loop")
            entry.append(suffix[walk])
            walk = parent[walk]
        entry.append(walk)
        entry.reverse()
        if new >= 0:
            suffix[new] = entry[0]
        prev = code
        prev_first = entry[0]
        out += entry
    return bytes(out)


# --- Reduce (methods 2 to 5) and DCL Implode (method 10) ---

_ESCAPE = 0x90


@dataclass
class ReduceStats:
    copies: int = 0
    long_copies: int = 0
    escaped_literals: int = 0
    far_copies: int = 0
    before_start: int = 0
    follower_sizes: set[int] = field(default_factory=set)


def _longest_match(
    data: bytes, pos: int, max_distance: int, max_length: int, *, start: int = 0
) -> tuple[int, int]:
    """The longest earlier copy of ``data[pos:]``: (length, distance). A distance past
    ``start`` reaches before the output, which reads zeros (``before_start`` copies)."""
    best_length = 0
    best_distance = 0
    limit = min(max_length, len(data) - pos)
    for distance in range(1, max_distance + 1):
        length = 0
        while length < limit:
            source = pos - distance + length
            byte = data[source] if source >= start else 0
            if byte != data[pos + length]:
                break
            length += 1
        if length > best_length:
            best_length, best_distance = length, distance
            if length == limit:
                break
    return best_length, best_distance


def reduce(
    data: bytes,
    *,
    factor: int,
    max_distance: int | None = None,
    zeros_before: bool = True,
) -> tuple[bytes, ReduceStats]:
    """Reduce ``data`` with compression factor 1 to 4: a greedy LZ77 behind the 0x90
    escape, then follower sets of each byte's most common next bytes.

    ``max_distance`` bounds the copy search, which is slow; the format allows up to
    ``256 << factor``. ``zeros_before`` lets copies reach before the start, as the
    zeros a decoder reads there.
    """
    stats = ReduceStats()
    length_bits = 8 - factor
    length_mask = (1 << length_bits) - 1
    format_distance = 256 << factor
    search = min(max_distance or format_distance, format_distance)
    max_length = length_mask + 255 + 3
    escaped = bytearray()
    pos = 0
    while pos < len(data):
        length, distance = _longest_match(
            data, pos, min(search, pos + (search if zeros_before else 0)), max_length
        )
        # A copy whose first byte would be zero (length 3, distance 256 or less) reads
        # as an escaped literal, so it cannot be written.
        if length == 3 and distance <= 256:
            length = 0
        if length >= 3:
            stats.copies += 1
            stats.far_copies += distance > 256
            stats.before_start += distance > pos
            extra = length - 3
            high = (distance - 1) >> 8
            first = (high << length_bits) | min(extra, length_mask)
            escaped += bytes([_ESCAPE, first])
            if extra >= length_mask:
                stats.long_copies += 1
                escaped.append(extra - length_mask)
            escaped.append((distance - 1) & 0xFF)
            pos += length
            continue
        byte = data[pos]
        if byte == _ESCAPE:
            stats.escaped_literals += 1
            escaped += bytes([_ESCAPE, 0])
        else:
            escaped.append(byte)
        pos += 1

    pairs: dict[int, dict[int, int]] = {}
    last = 0
    for byte in escaped:
        counts = pairs.setdefault(last, {})
        counts[byte] = counts.get(byte, 0) + 1
        last = byte
    followers: dict[int, list[int]] = {}
    for byte, counts in pairs.items():
        ranked = sorted(counts, key=lambda b: (-counts[b], b))
        # Vary the set sizes, so every index width is used: byte b keeps up to
        # (b % 32) + 1 followers.
        followers[byte] = ranked[: (byte % 32) + 1]
        stats.follower_sizes.add(len(followers[byte]))

    out = BitWriter()
    for byte in range(255, -1, -1):
        chosen = followers.get(byte, [])
        out.write(len(chosen), 6)
        for member in chosen:
            out.write(member, 8)
    last = 0
    for byte in escaped:
        chosen = followers.get(last, [])
        if not chosen:
            out.write(byte, 8)
        elif byte in chosen:
            out.write(0, 1)
            bits = max(1, (len(chosen) - 1).bit_length())
            out.write(chosen.index(byte), bits)
        else:
            out.write(1, 1)
            out.write(byte, 8)
        last = byte
    return out.getvalue(), stats


def reduce_entry(name: str, data: bytes, *, factor: int) -> LegacyEntry:
    return LegacyEntry(
        name, data, 1 + factor, reduce(data, factor=factor, max_distance=300)[0]
    )


@dataclass
class DclStats:
    copies: int = 0
    two_byte_copies: int = 0
    longest: int = 0


def _dcl_codes(packed: bytes) -> list[tuple[int, int]]:
    """Each symbol's (code, length), from ``blast.c``'s run-length table."""
    lengths: list[int] = []
    for byte in packed:
        lengths.extend([byte & 0x0F] * ((byte >> 4) + 1))
    codes = [(0, 0)] * len(lengths)
    code = 0
    for length in range(1, max(lengths) + 1):
        for symbol, symbol_length in enumerate(lengths):
            if symbol_length == length:
                codes[symbol] = (code, length)
                code += 1
        code <<= 1
    return codes


# The tables of zlib's contrib/blast/blast.c (Mark Adler, zlib license).
_DCL_LITERALS = _dcl_codes(
    bytes.fromhex(
        "0b7c08071c07bc0d4c040a080c0a0c0a08170809070607080706370817180c0b"
        "07090b0c060716050718060b09060716070b26070908190b080b090c080c0526"
        "0526050b07050615060a350807180a1b2cfdfdfdfcfcfc0d0c2d0c2d0c3d0c2d"
        "2cad"
    )
)
_DCL_LENGTHS = _dcl_codes(bytes([2, 35, 36, 53, 38, 23]))
_DCL_DISTANCES = _dcl_codes(bytes([2, 20, 53, 230, 247, 151, 248]))
_DCL_BASE = (3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264)
_DCL_EXTRA = (0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8)


def _write_dcl_code(out: BitWriter, code: tuple[int, int]) -> None:
    value, length = code
    out.write_msb_first(value ^ ((1 << length) - 1), length)


def _write_dcl_length(out: BitWriter, length: int) -> None:
    for symbol in range(15, -1, -1):
        base = _DCL_BASE[symbol]
        if base <= length < base + (1 << _DCL_EXTRA[symbol]):
            _write_dcl_code(out, _DCL_LENGTHS[symbol])
            out.write(length - base, _DCL_EXTRA[symbol])
            return
    raise AssertionError(length)


def dcl_implode(
    data: bytes, *, coded: bool, window_bits: int, max_distance: int = 300
) -> tuple[bytes, DclStats]:
    """A DCL Implode stream: a greedy LZ77 over the format's fixed codes, raw or coded
    literals, a 1, 2 or 4 KiB window (``window_bits`` 4 to 6), then the end code."""
    stats = DclStats()
    out = BitWriter()
    out.write(int(coded), 8)
    out.write(window_bits, 8)
    window = 64 << window_bits
    pos = 0
    while pos < len(data):
        length, distance = _longest_match(
            data, pos, min(max_distance, window, pos), 518
        )
        if length == 2 and distance > 256:
            length = 0
        if length >= 2:
            stats.copies += 1
            stats.two_byte_copies += length == 2
            stats.longest = max(stats.longest, length)
            out.write(1, 1)
            _write_dcl_length(out, length)
            low_bits = 2 if length == 2 else window_bits
            _write_dcl_code(out, _DCL_DISTANCES[(distance - 1) >> low_bits])
            out.write((distance - 1) & ((1 << low_bits) - 1), low_bits)
            pos += length
            continue
        out.write(0, 1)
        if coded:
            _write_dcl_code(out, _DCL_LITERALS[data[pos]])
        else:
            out.write(data[pos], 8)
        pos += 1
    out.write(1, 1)
    _write_dcl_length(out, 519)
    return out.getvalue(), stats


def dcl_implode_entry(
    name: str, data: bytes, *, coded: bool, window_bits: int
) -> LegacyEntry:
    compressed, _ = dcl_implode(data, coded=coded, window_bits=window_bits)
    return LegacyEntry(name, data, 10, compressed)
