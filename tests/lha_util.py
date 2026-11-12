"""Write LHA archives for tests: headers of every level, and an ``-lh5-`` to ``-lh7-``
encoder.

No Linux tool here writes LHA (lhasa, Debian's ``lha``, only extracts), so the tests
build their archives with this module. The encoder is greedy and plain: hashed match
search, one block per 65 535 commands or fewer, canonical Huffman codes of at most 16
bits. lhasa reads what it writes (``test_lha.py`` checks that whenever lhasa is
installed), so the decoder is not checked only against its own reading.
"""

from __future__ import annotations

import heapq
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field

_CRC16_TABLE: list[int] = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xA001 if _c & 1 else _c >> 1
    _CRC16_TABLE.append(_c)


def crc16(data: bytes) -> int:
    """CRC-16/ARC, as LHA checks data and headers."""
    crc = 0
    for byte in data:
        crc = (crc >> 8) ^ _CRC16_TABLE[(crc ^ byte) & 0xFF]
    return crc


# ── Bits and Huffman codes ──────────────────────────────────────────────────────────


class BitWriter:
    """Bits, most significant first."""

    def __init__(self) -> None:
        self._out = bytearray()
        self._acc = 0
        self._n = 0

    def write(self, value: int, bits: int) -> None:
        if bits == 0:
            return
        assert 0 <= value < 1 << bits, (value, bits)
        self._acc = self._acc << bits | value
        self._n += bits
        while self._n >= 8:
            self._n -= 8
            self._out.append((self._acc >> self._n) & 0xFF)
        self._acc &= (1 << self._n) - 1

    def getvalue(self) -> bytes:
        tail = bytes([(self._acc << (8 - self._n)) & 0xFF]) if self._n else b""
        return bytes(self._out) + tail


def code_lengths(freqs: list[int], limit: int = 16) -> list[int]:
    """Huffman code lengths for ``freqs``, none over ``limit``; 0 for an unused
    symbol. Needs at least two used symbols."""
    freqs = list(freqs)
    while True:
        heap = [(f, i, (i,)) for i, f in enumerate(freqs) if f]
        assert len(heap) >= 2
        heapq.heapify(heap)
        lengths = [0] * len(freqs)
        tie = len(freqs)
        while len(heap) > 1:
            f1, _, a = heapq.heappop(heap)
            f2, _, b = heapq.heappop(heap)
            for s in a + b:
                lengths[s] += 1
            heapq.heappush(heap, (f1 + f2, tie, a + b))
            tie += 1
        if max(lengths) <= limit:
            return lengths
        freqs = [(f + 1) // 2 if f else 0 for f in freqs]


def canonical_codes(lengths: list[int]) -> list[int]:
    """The canonical code of each symbol: by length, then by symbol."""
    codes = [0] * len(lengths)
    code = 0
    for length in range(1, 17):
        for symbol, n in enumerate(lengths):
            if n == length:
                codes[symbol] = code
                code += 1
        code <<= 1
    return codes


@dataclass
class Code:
    """A code for one table: ``single`` set when one symbol needs no bits."""

    lengths: list[int]
    codes: list[int] = field(default_factory=list)
    single: int | None = None

    @classmethod
    def from_freqs(cls, freqs: list[int]) -> Code:
        used = [i for i, f in enumerate(freqs) if f]
        if len(used) <= 1:
            return cls([0] * len(freqs), single=used[0] if used else 0)
        lengths = code_lengths(freqs)
        return cls(lengths, canonical_codes(lengths))

    def put(self, bits: BitWriter, symbol: int) -> None:
        if self.single is None:
            bits.write(self.codes[symbol], self.lengths[symbol])
        else:
            assert symbol == self.single


# ── The LZH stream ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Params:
    window_bits: int
    offset_bits: int
    """Width of the offset table's count field."""


PARAMS = {
    "-lh4-": Params(12, 4),
    "-lh5-": Params(13, 4),
    "-lh6-": Params(15, 5),
    "-lh7-": Params(16, 5),
}
"""What LHA itself writes: lh4's 4 KiB window, lh5's 8 KiB, lh6's 32 KiB, lh7's 64 KiB."""

_MIN_MATCH = 3
_MAX_MATCH = 256
_NC = 510
_NT = 19


def commands(
    data: bytes, window_bits: int, *, matches: bool = True
) -> list[tuple[int, int]]:
    """Greedy LZ77: ``(byte, 0)`` literals and ``(length, distance)`` matches."""
    out: list[tuple[int, int]] = []
    window = 1 << window_bits
    heads: dict[bytes, list[int]] = {}
    i = 0
    n = len(data)
    while i < n:
        best_len = 0
        best_dist = 0
        if matches and i + _MIN_MATCH <= n:
            key = data[i : i + _MIN_MATCH]
            for j in reversed(heads.get(key, [])[-16:]):
                if i - j > window:
                    break
                length = _MIN_MATCH
                while (
                    length < _MAX_MATCH
                    and i + length < n
                    and data[j + length] == data[i + length]
                ):
                    length += 1
                if length > best_len:
                    best_len, best_dist = length, i - j
                    if length == _MAX_MATCH:
                        break
        step = best_len if best_len >= _MIN_MATCH else 1
        if best_len >= _MIN_MATCH:
            out.append((best_len, best_dist))
        else:
            out.append((data[i], 0))
        for k in range(i, min(i + step, n - _MIN_MATCH + 1)):
            heads.setdefault(data[k : k + _MIN_MATCH], []).append(k)
        i += step
    return out


def _offset_symbol(distance: int) -> tuple[int, int, int]:
    """The offset table's symbol for ``distance``, and the low bits after it."""
    d = distance - 1
    bits = d.bit_length()
    if bits <= 1:
        return bits, 0, 0
    return bits, d - (1 << (bits - 1)), bits - 1


def _write_lengths(bits: BitWriter, lengths: list[int], skip_after_third: bool) -> None:
    """Lengths as three bits, past 6 a 7 and a run of 1 bits ended by a 0."""
    i = 0
    n = len(lengths)
    while i < n:
        length = lengths[i]
        if length < 7:
            bits.write(length, 3)
        else:
            bits.write(7, 3)
            for _ in range(length - 7):
                bits.write(1, 1)
            bits.write(0, 1)
        if skip_after_third and i == 2:
            run = 0
            while run < 3 and i + 1 + run < n and lengths[i + 1 + run] == 0:
                run += 1
            bits.write(run, 2)
            i += run
        i += 1


def _trim(lengths: list[int]) -> list[int]:
    n = len(lengths)
    while n and lengths[n - 1] == 0:
        n -= 1
    return lengths[:n]


def _command_length_symbols(lengths: list[int]) -> list[tuple[int, int, int]]:
    """The command table's lengths as temp-table symbols: (symbol, extra, extra bits)."""
    out: list[tuple[int, int, int]] = []
    i = 0
    n = len(lengths)
    while i < n:
        if lengths[i]:
            out.append((lengths[i] + 2, 0, 0))
            i += 1
            continue
        run = 1
        while i + run < n and lengths[i + run] == 0:
            run += 1
        take = run
        while take:
            if take >= 20:
                step = min(take, 20 + 511)
                out.append((2, step - 20, 9))
            elif take >= 3:
                step = min(take, 18)
                out.append((1, step - 3, 4))
            else:
                step = 1
                out.append((0, 0, 0))
            take -= step
        i += run
    return out


def write_block(
    bits: BitWriter,
    block: list[tuple[int, int]],
    offset_bits: int,
    *,
    commands: bool = True,
) -> None:
    """One block: its command count, the three tables, then the commands. With
    ``commands`` false, the tables ``block`` needs and a count of 0, as a block with
    no commands."""
    c_freq = [0] * _NC
    p_freq = [0] * (1 << offset_bits)
    for value, distance in block:
        if distance == 0:
            c_freq[value] += 1
        else:
            c_freq[value - _MIN_MATCH + 256] += 1
            p_freq[_offset_symbol(distance)[0]] += 1
    c_code = Code.from_freqs(c_freq)
    bits.write(len(block) if commands else 0, 16)
    if c_code.single is not None:
        # The temp table and the command table are both one symbol.
        bits.write(0, 5)
        bits.write(0, 5)
        bits.write(0, 9)
        bits.write(c_code.single, 9)
    else:
        c_lengths = _trim(c_code.lengths)
        symbols = _command_length_symbols(c_lengths)
        t_freq = [0] * _NT
        for symbol, _, _ in symbols:
            t_freq[symbol] += 1
        t_code = Code.from_freqs(t_freq)
        if t_code.single is not None:
            bits.write(0, 5)
            bits.write(t_code.single, 5)
        else:
            t_lengths = _trim(t_code.lengths)
            bits.write(len(t_lengths), 5)
            _write_lengths(bits, t_lengths, skip_after_third=True)
        bits.write(len(c_lengths), 9)
        for symbol, extra, extra_bits in symbols:
            t_code.put(bits, symbol)
            bits.write(extra, extra_bits)
    p_code = Code.from_freqs(p_freq)
    if p_code.single is not None:
        bits.write(0, offset_bits)
        bits.write(p_code.single, offset_bits)
    else:
        p_lengths = _trim(p_code.lengths)
        bits.write(len(p_lengths), offset_bits)
        _write_lengths(bits, p_lengths, skip_after_third=False)
    if not commands:
        return
    for value, distance in block:
        if distance == 0:
            c_code.put(bits, value)
        else:
            c_code.put(bits, value - _MIN_MATCH + 256)
            symbol, low, low_bits = _offset_symbol(distance)
            p_code.put(bits, symbol)
            bits.write(low, low_bits)


def compress(
    data: bytes,
    method: str = "-lh5-",
    *,
    block_size: int = 0xFFFF,
    matches: bool = True,
) -> bytes:
    """``data`` as an LZH stream of ``method``."""
    params = PARAMS[method]
    cmds = commands(data, params.window_bits, matches=matches)
    bits = BitWriter()
    for start in range(0, len(cmds), block_size):
        write_block(bits, cmds[start : start + block_size], params.offset_bits)
    return bits.getvalue()


# ── Headers ─────────────────────────────────────────────────────────────────────────


@dataclass
class Member:
    """One member to write. ``stored`` overrides the stored bytes (``None``: write
    ``data`` with ``method``)."""

    name: bytes
    data: bytes = b""
    method: str = "-lh5-"
    level: int = 2
    os_id: bytes = b"U"
    mtime: int = 1_600_000_000
    dos_time: int = 0x5A2C6000  # 2025-01-12 12:00:00
    directory: bytes | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    user: bytes | None = None
    group: bytes | None = None
    comment: bytes | None = None
    windows_times: tuple[int, int, int] | None = None
    sizes64: bool = False
    extra_records: list[tuple[int, bytes]] = field(default_factory=list)
    stored: bytes | None = None
    crc: int | None = None
    size: int | None = None
    header_crc: bool = True
    unix_area: bool = False
    """Level 0: LHa for UNIX's extended area (mode, uid, gid, mtime)."""

    def payload(self) -> bytes:
        if self.stored is not None:
            return self.stored
        if self.method in ("-lh0-", "-lz4-", "-pm0-", "-lhd-"):
            return self.data
        return compress(self.data, self.method)


def _records(member: Member) -> list[tuple[int, bytes]]:
    records: list[tuple[int, bytes]] = []
    if member.level >= 1:
        records.append((0x01, member.name))
    if member.directory is not None:
        records.append((0x02, member.directory))
    if member.comment is not None:
        records.append((0x3F, member.comment))
    if member.windows_times is not None:
        records.append((0x41, struct.pack("<QQQ", *member.windows_times)))
    if member.mode is not None:
        records.append((0x50, struct.pack("<H", member.mode)))
    if member.uid is not None or member.gid is not None:
        records.append((0x51, struct.pack("<HH", member.gid or 0, member.uid or 0)))
    if member.group is not None:
        records.append((0x52, member.group))
    if member.user is not None:
        records.append((0x53, member.user))
    if member.level == 1:
        records.append((0x54, struct.pack("<I", member.mtime)))
    records += member.extra_records
    return records


def _chain(records: Iterable[tuple[int, bytes]], field_size: int) -> bytes:
    """Extended headers, each ended by the next one's size; the first's size is not
    included."""
    parts = [bytes([kind]) + body for kind, body in records]
    out = bytearray()
    for i, part in enumerate(parts):
        out += part
        following = len(parts[i + 1]) + field_size if i + 1 < len(parts) else 0
        out += following.to_bytes(field_size, "little")
    return bytes(out)


def _first_size(records: list[tuple[int, bytes]], field_size: int) -> int:
    return 1 + len(records[0][1]) + field_size if records else 0


def member_bytes(member: Member) -> bytes:
    """One member's header and stored bytes."""
    payload = member.payload()
    size = len(member.data) if member.size is None else member.size
    crc = crc16(member.data) if member.crc is None else member.crc
    method = member.method.encode("ascii")
    if member.level == 0:
        name = (
            member.name
            if member.directory is None
            else member.directory.replace(b"\xff", b"\\") + member.name
        )
        body = (
            method
            + struct.pack("<III", len(payload), size, member.dos_time)
            + bytes([0x20, 0])
            + bytes([len(name)])
            + name
            + struct.pack("<H", crc)
        )
        if member.unix_area:
            body += (
                member.os_id
                + b"\0"
                + struct.pack(
                    "<IHHH",
                    member.mtime,
                    member.mode or 0o100644,
                    member.uid or 0,
                    member.gid or 0,
                )
            )
        return bytes([len(body), sum(body) & 0xFF]) + body + payload
    records = _records(member)
    if member.level == 1:
        # The name lives in the base header; the rest follow it.
        records = [r for r in records if r[0] != 0x01]
        chain = _chain(records, 2)
        stored = len(payload) + len(chain)
        body = (
            method
            + struct.pack("<III", stored, size, member.dos_time)
            + bytes([0x20, 1])
            + bytes([len(member.name)])
            + member.name
            + struct.pack("<H", crc)
            + member.os_id
            + struct.pack("<H", _first_size(records, 2))
        )
        return bytes([len(body), sum(body) & 0xFF]) + body + chain + payload
    field_size = 2 if member.level == 2 else 4
    if member.header_crc:
        records = [(0x00, b"\0\0"), *records]
    if member.sizes64:
        records.append((0x42, struct.pack("<QQ", len(payload), size)))
    chain = _chain(records, field_size)
    stored32 = len(payload) & 0xFFFFFFFF
    size32 = size & 0xFFFFFFFF
    if member.level == 2:
        fixed = 26
        total = fixed + len(chain)
        head = struct.pack("<H", total)
    else:
        fixed = 32
        total = fixed + len(chain)
        head = struct.pack("<H", 4)
    header = bytearray(
        head
        + method
        + struct.pack("<III", stored32, size32, member.mtime)
        + bytes([0x20, member.level])
        + struct.pack("<H", crc)
        + member.os_id
    )
    if member.level == 3:
        header += struct.pack("<I", total)
    header += _first_size(records, field_size).to_bytes(field_size, "little")
    assert len(header) == fixed, len(header)
    header += chain
    if member.level == 2 and total % 256 == 0:
        # LHA pads a level-2 header whose low size byte would be 0 (an end marker).
        header += b"\0"
        struct.pack_into("<H", header, 0, total + 1)
    if member.header_crc:
        at = fixed + 1
        struct.pack_into("<H", header, at, crc16(bytes(header)))
    return bytes(header) + payload


def archive(members: Iterable[Member], *, end: bytes = b"\0") -> bytes:
    """An archive of ``members``, then ``end`` (the end byte, by default)."""
    return b"".join(member_bytes(m) for m in members) + end
