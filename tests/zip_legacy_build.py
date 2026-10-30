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
    """A plain Shrink decoder to check ``ShrinkDecoder`` against: every code walks its
    parents, slots come from a scan for the lowest free one, and a partial clear scans
    the table. Same semantics as the decoder (7-Zip's); raises ``ValueError`` where it
    raises ``CorruptionError``, and returns what it decoded when the input runs out.
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
