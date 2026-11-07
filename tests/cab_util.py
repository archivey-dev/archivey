"""Writes Microsoft cabinets for the tests: stored, MSZIP and LZX folders.

No tool on Linux writes LZX (``gcab`` writes MSZIP, ``lcab`` stores), so the LZX
encoder is here: greedy matching over a hash of three bytes, the repeated-offset
slots, verbatim, aligned and uncompressed blocks, and the E8 translation, with
length-limited Huffman codes. It aims for coverage, not ratio. ``cabextract`` reads
what it writes (``test_cab.py`` checks that whenever ``cabextract`` is installed), so
the decoder is not only checked against its own reading of the format.

Layout from the Microsoft Cabinet Format specification (MS-CAB) and libmspack.
"""

from __future__ import annotations

import heapq
import struct
import zlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

FRAME = 32768

# ── Huffman codes ────────────────────────────────────────────────────────────────


def code_lengths(freqs: Sequence[int], limit: int) -> list[int]:
    """Huffman code lengths for ``freqs``, none over ``limit`` bits, filling the code
    space: a lone used symbol gets a partner, as LZX trees must be complete."""
    used = [i for i, f in enumerate(freqs) if f]
    lengths = [0] * len(freqs)
    if not used:
        return lengths
    if len(used) == 1:
        other = 0 if used[0] else 1
        lengths[used[0]] = lengths[other] = 1
        return lengths
    scaled = list(freqs)
    while True:
        heap = [(scaled[i], i, (i,)) for i in used]
        heapq.heapify(heap)
        depth = dict.fromkeys(used, 0)
        tie = len(freqs)
        while len(heap) > 1:
            fa, _, a = heapq.heappop(heap)
            fb, _, b = heapq.heappop(heap)
            for s in a + b:
                depth[s] += 1
            heapq.heappush(heap, (fa + fb, tie, a + b))
            tie += 1
        if max(depth.values()) <= limit:
            for s, d in depth.items():
                lengths[s] = d
            return lengths
        scaled = [(f + 1) // 2 if f else 0 for f in scaled]
        scaled = [max(f, 1) if freqs[i] else 0 for i, f in enumerate(scaled)]


def canonical_codes(lengths: Sequence[int]) -> list[int]:
    """The canonical code of each symbol, MSB first, as LZX assigns them."""
    codes = [0] * len(lengths)
    code = 0
    for length in range(1, 17):
        for symbol, sym_len in enumerate(lengths):
            if sym_len == length:
                codes[symbol] = code
                code += 1
        code <<= 1
    return codes


# ── Bits ─────────────────────────────────────────────────────────────────────────


class BitWriter:
    """MSB-first bits, stored as 16-bit little-endian words."""

    def __init__(self) -> None:
        self.out = bytearray()
        self._acc = 0
        self._n = 0

    def bits(self, value: int, n: int) -> None:
        for shift in range(n - 1, -1, -1):
            self._acc = (self._acc << 1) | ((value >> shift) & 1)
            self._n += 1
            if self._n == 16:
                self.out += self._acc.to_bytes(2, "little")
                self._acc = self._n = 0

    def align(self, *, whole_word_if_aligned: bool = False) -> None:
        """Pad to a 16-bit word; with ``whole_word_if_aligned``, a whole word of
        padding when already aligned (an uncompressed block's header)."""
        if self._n:
            self.bits(0, 16 - self._n)
        elif whole_word_if_aligned:
            self.bits(0, 16)

    def raw(self, data: bytes) -> None:
        assert self._n == 0
        self.out += data

    def take(self) -> bytes:
        assert self._n == 0
        data = bytes(self.out)
        self.out.clear()
        return data


# ── LZX ──────────────────────────────────────────────────────────────────────────

_SLOTS = (30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290)
_EXTRA = [0 if s < 4 else min(s // 2 - 1, 17) for s in range(290)]
_BASE = [0]
for _s in range(289):
    _BASE.append(_BASE[-1] + (1 << _EXTRA[_s]))


def _slot_of(formatted: int) -> int:
    lo, hi = 0, len(_BASE) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _BASE[mid] <= formatted:
            lo = mid
        else:
            hi = mid - 1
    return lo


def e8_translate(data: bytes, file_size: int) -> bytes:
    """What an encoder does to x86 code before LZX: relative ``CALL`` targets made
    absolute, the inverse of the decoder's step, frame by frame."""
    out = bytearray(data)
    for start in range(0, len(out), FRAME):
        size = min(FRAME, len(out) - start)
        if size <= 10 or start // FRAME >= 32768:
            continue
        i = start
        end = start + size - 10
        while i < end:
            if out[i] != 0xE8:
                i += 1
                continue
            cur = i
            rel = int.from_bytes(out[i + 1 : i + 5], "little", signed=True)
            if -cur <= rel < file_size - cur:
                value = rel + cur
            elif file_size - cur <= rel < file_size:
                value = rel - file_size
            else:
                value = rel
            out[i + 1 : i + 5] = (value & 0xFFFFFFFF).to_bytes(4, "little")
            i += 5
    return bytes(out)


@dataclass
class _Token:
    literal: int = -1
    length: int = 0
    slot: int = 0
    footer: int = 0  # the formatted offset's extra bits, for slots 3 and up


@dataclass
class LzxEncoder:
    """Encodes a whole stream, returning one chunk of bytes per 32 KiB frame.

    ``blocks`` picks each block's type in turn ("verbatim", "aligned",
    "uncompressed"), cycling, one block per ``block_size`` bytes of output.
    """

    window_bits: int = 16
    blocks: Sequence[str] = ("verbatim",)
    block_size: int = FRAME
    e8_file_size: int = 0
    use_runs: bool = True
    _main_lengths: list[int] = field(default_factory=list)
    _length_lengths: list[int] = field(default_factory=list)

    def encode(self, data: bytes) -> list[bytes]:
        window = 1 << self.window_bits
        main_symbols = 256 + _SLOTS[self.window_bits - 15] * 8
        self._main_lengths = [0] * main_symbols
        self._length_lengths = [0] * 249
        source = e8_translate(data, self.e8_file_size) if self.e8_file_size else data
        writer = BitWriter()
        frames: list[bytes] = []
        if self.e8_file_size:
            writer.bits(1, 1)
            writer.bits(self.e8_file_size >> 16, 16)
            writer.bits(self.e8_file_size & 0xFFFF, 16)
        else:
            writer.bits(0, 1)
        r = [1, 1, 1]
        pos = 0
        index = 0
        state = _FrameState(writer, frames)
        while pos < len(source):
            kind = self.blocks[index % len(self.blocks)]
            index += 1
            end = min(pos + self.block_size, len(source))
            if kind == "uncompressed":
                self._uncompressed(source, pos, end, r, state)
            else:
                tokens = self._match(source, pos, end, r, window)
                self._compressed(kind, tokens, pos, state, main_symbols)
            pos = end
        state.finish(len(source))
        return frames

    def _match(
        self, data: bytes, start: int, end: int, r: list[int], window: int
    ) -> list[_Token]:
        tokens: list[_Token] = []
        heads: dict[bytes, int] = {}
        pos = start
        # Seed the hash with the window before this block.
        for i in range(max(0, start - window + 3), start):
            heads[data[i : i + 3]] = i
        while pos < end:
            frame_end = (pos // FRAME + 1) * FRAME
            limit = min(end, frame_end, pos + 257) - pos
            best_len, best_dist = 0, 0
            # Repeated offsets first.
            for dist in r:
                if dist <= pos and dist <= window - 3:
                    n = 0
                    while n < limit and data[pos + n] == data[pos - dist + n]:
                        n += 1
                    if n >= 2 and n > best_len:
                        best_len, best_dist = n, dist
            key = data[pos : pos + 3]
            cand = heads.get(key)
            if cand is not None and pos - cand <= window - 3 and limit >= 3:
                dist = pos - cand
                n = 0
                while n < limit and data[pos + n] == data[cand + n]:
                    n += 1
                if n >= 3 and n > best_len + 1:
                    best_len, best_dist = n, dist
            if best_len >= 2:
                tokens.append(self._match_token(best_len, best_dist, r))
                for i in range(pos, pos + best_len):
                    heads[data[i : i + 3]] = i
                pos += best_len
            else:
                tokens.append(_Token(literal=data[pos]))
                heads[key] = pos
                pos += 1
        return tokens

    @staticmethod
    def _match_token(length: int, dist: int, r: list[int]) -> _Token:
        if dist == r[0]:
            slot, footer = 0, 0
        elif dist == r[1]:
            slot, footer = 1, 0
            r[0], r[1] = r[1], r[0]
        elif dist == r[2]:
            slot, footer = 2, 0
            r[0], r[2] = r[2], r[0]
        else:
            formatted = dist + 2
            slot = _slot_of(formatted)
            footer = formatted - _BASE[slot]
            r[2], r[1], r[0] = r[1], r[0], dist
        return _Token(length=length, slot=slot, footer=footer)

    def _compressed(
        self,
        kind: str,
        tokens: list[_Token],
        start: int,
        state: _FrameState,
        main_symbols: int,
    ) -> None:
        aligned = kind == "aligned"
        main_freq = [0] * main_symbols
        length_freq = [0] * 249
        aligned_freq = [0] * 8
        for t in tokens:
            if t.literal >= 0:
                main_freq[t.literal] += 1
                continue
            header = min(t.length - 2, 7)
            main_freq[256 + t.slot * 8 + header] += 1
            if header == 7:
                length_freq[t.length - 9] += 1
            if aligned and _EXTRA[t.slot] >= 3:
                aligned_freq[t.footer & 7] += 1
        if self.e8_file_size:
            main_freq[0xE8] += 1  # the decoder starts the E8 step on this
        main_lengths = code_lengths(main_freq, 16)
        length_lengths = code_lengths(length_freq, 16)
        aligned_lengths = code_lengths(aligned_freq, 7) if aligned else []
        if aligned and not any(aligned_lengths):
            aligned_lengths = [3] * 8
        w = state.writer
        size = sum(1 if t.literal >= 0 else t.length for t in tokens)
        w.bits(2 if aligned else 1, 3)
        w.bits(size >> 8, 16)
        w.bits(size & 0xFF, 8)
        if aligned:
            for n in aligned_lengths:
                w.bits(n, 3)
        self._write_lengths(w, self._main_lengths, main_lengths, 0, 256)
        self._write_lengths(w, self._main_lengths, main_lengths, 256, main_symbols)
        self._write_lengths(w, self._length_lengths, length_lengths, 0, 249)
        main_codes = canonical_codes(main_lengths)
        length_codes = canonical_codes(length_lengths)
        aligned_codes = canonical_codes(aligned_lengths) if aligned else []
        out = start
        for t in tokens:
            if t.literal >= 0:
                w.bits(main_codes[t.literal], main_lengths[t.literal])
                out += 1
            else:
                header = min(t.length - 2, 7)
                symbol = 256 + t.slot * 8 + header
                w.bits(main_codes[symbol], main_lengths[symbol])
                if header == 7:
                    footer = t.length - 9
                    w.bits(length_codes[footer], length_lengths[footer])
                extra = _EXTRA[t.slot] if t.slot >= 3 else 0
                if aligned and extra >= 3:
                    w.bits(t.footer >> 3, extra - 3)
                    low = t.footer & 7
                    w.bits(aligned_codes[low], aligned_lengths[low])
                elif extra:
                    w.bits(t.footer, extra)
                out += t.length
            state.advance(out)

    def _write_lengths(
        self,
        w: BitWriter,
        previous: list[int],
        lengths: list[int],
        first: int,
        last: int,
    ) -> None:
        # Pretree symbols for the deltas, with runs of zeros and of equal values.
        ops: list[tuple[int, int, int]] = []  # (symbol, extra bits value, nbits)
        x = first
        while x < last:
            if self.use_runs and lengths[x] == 0:
                run = 0
                while x + run < last and lengths[x + run] == 0 and run < 51:
                    run += 1
                if run >= 20:
                    ops.append((18, run - 20, 5))
                    x += run
                    continue
                if run >= 4:
                    ops.append((17, run - 4, 4))
                    x += run
                    continue
            if self.use_runs:
                run = 0
                while x + run < last and lengths[x + run] == lengths[x] and run < 5:
                    run += 1
                if run >= 4:
                    code = (previous[x] - lengths[x]) % 17
                    ops.append((19, run - 4, 1))
                    ops.append((code, -1, 0))
                    x += run
                    continue
            ops.append(((previous[x] - lengths[x]) % 17, -1, 0))
            x += 1
        freq = [0] * 20
        for symbol, extra, _ in ops:
            freq[symbol] += 1
        pre = code_lengths(freq, 15)
        codes = canonical_codes(pre)
        for n in pre:
            w.bits(n, 4)
        for symbol, extra, nbits in ops:
            w.bits(codes[symbol], pre[symbol])
            if extra >= 0:
                w.bits(extra, nbits)
        previous[first:last] = lengths[first:last]

    def _uncompressed(
        self, data: bytes, start: int, end: int, r: list[int], state: _FrameState
    ) -> None:
        w = state.writer
        size = end - start
        w.bits(3, 3)
        w.bits(size >> 8, 16)
        w.bits(size & 0xFF, 8)
        w.align(whole_word_if_aligned=True)
        w.raw(b"".join(v.to_bytes(4, "little") for v in r))
        pos = start
        while pos < end:
            frame_end = (pos // FRAME + 1) * FRAME
            stop = min(end, frame_end)
            w.raw(data[pos:stop])
            pos = stop
            state.advance(pos, raw=True)
        if size & 1:
            w.raw(b"\0")
            state.pad_pending()


class _FrameState:
    """Cuts the bit stream into frames as output crosses each 32 KiB."""

    def __init__(self, writer: BitWriter, frames: list[bytes]) -> None:
        self.writer = writer
        self.frames = frames
        self._next = FRAME
        self._pad = False

    def advance(self, out: int, *, raw: bool = False) -> None:
        if out >= self._next:
            assert out == self._next, "a match crossed a frame"
            if not raw:
                self.writer.align()
            self.frames.append(self.writer.take())
            self._next += FRAME

    def pad_pending(self) -> None:
        # The pad byte after an odd uncompressed block belongs to the next frame's
        # input when the block ended a frame.
        pass

    def finish(self, total: int) -> None:
        if total % FRAME or total == 0:
            self.writer.align()
            self.frames.append(self.writer.take())
        elif self.writer.out:
            self.frames[-1] += self.writer.take()


# ── Cabinets ─────────────────────────────────────────────────────────────────────


def checksum(data: bytes, seed: int = 0) -> int:
    """The CFDATA checksum (libmspack's ``cabd_checksum``)."""
    value = seed
    whole = len(data) // 4 * 4
    for (word,) in struct.iter_unpack("<I", data[:whole]):
        value ^= word
    tail = data[whole:]
    ul = 0
    if len(tail) == 3:
        ul = tail[0] << 16 | tail[1] << 8 | tail[2]
    elif len(tail) == 2:
        ul = tail[0] << 8 | tail[1]
    elif len(tail) == 1:
        ul = tail[0]
    return value ^ ul


def block_checksum(payload: bytes, decoded_size: int) -> int:
    return checksum(struct.pack("<HH", len(payload), decoded_size), checksum(payload))


@dataclass
class CabFile:
    name: str
    data: bytes
    folder: int = 0
    date: int = 0x5A21  # 2025-01-01
    time: int = 0x6000  # 12:00:00
    attribs: int = 0x20
    raw_name: bytes | None = None


@dataclass
class CabFolder:
    method: str = "none"  # none, mszip, lzx, quantum
    window_bits: int = 16
    lzx: LzxEncoder | None = None
    checksums: bool = True


def _folder_blocks(folder: CabFolder, data: bytes) -> list[tuple[bytes, int]]:
    """(payload, decoded size) per CFDATA block."""
    if folder.method == "none":
        return [
            (data[i : i + FRAME], len(data[i : i + FRAME]))
            for i in range(0, len(data), FRAME)
        ] or [(b"", 0)]
    if folder.method == "mszip":
        blocks = []
        history = b""
        for i in range(0, len(data), FRAME):
            chunk = data[i : i + FRAME]
            comp = (
                zlib.compressobj(9, zlib.DEFLATED, -15, zdict=history)
                if history
                else zlib.compressobj(9, zlib.DEFLATED, -15)
            )
            payload = b"CK" + comp.compress(chunk) + comp.flush()
            blocks.append((payload, len(chunk)))
            history = (history + chunk)[-FRAME:]
        return blocks
    if folder.method == "lzx":
        encoder = folder.lzx or LzxEncoder(window_bits=folder.window_bits)
        frames = encoder.encode(data)
        sizes = [min(FRAME, len(data) - i) for i in range(0, len(data), FRAME)]
        return list(zip(frames, sizes, strict=True))
    if folder.method == "quantum":
        return [(b"\0" * 16, len(data))]
    raise ValueError(folder.method)


_METHODS = {"none": 0, "mszip": 1, "quantum": 2, "lzx": 3}


def write_cab(
    files: Iterable[CabFile],
    folders: Sequence[CabFolder] = (CabFolder(),),
    *,
    reserve: tuple[int, int, int] | None = None,
    flags: int = 0,
    set_names: bytes = b"",
    version: tuple[int, int] = (3, 1),
) -> bytes:
    """A cabinet holding ``files``, each in its folder, in the order given."""
    files = list(files)
    contents: list[bytearray] = [bytearray() for _ in folders]
    offsets = []
    for f in files:
        offsets.append(len(contents[f.folder]))
        contents[f.folder] += f.data
    if reserve is not None:
        flags |= 4
    header_resv, folder_resv, data_resv = reserve or (0, 0, 0)
    head_len = 36 + (4 + header_resv if reserve is not None else 0) + len(set_names)
    folder_len = len(folders) * (8 + folder_resv)
    entries = b""
    for f, off in zip(files, offsets, strict=True):
        raw = f.raw_name if f.raw_name is not None else f.name.encode()
        entries += (
            struct.pack(
                "<IIHHHH", len(f.data), off, f.folder, f.date, f.time, f.attribs
            )
            + raw
            + b"\0"
        )
    data_start = head_len + folder_len + len(entries)
    folder_records = b""
    data = b""
    for folder, content in zip(folders, contents, strict=True):
        blocks = _folder_blocks(folder, bytes(content))
        start = data_start + len(data)
        for payload, size in blocks:
            csum = block_checksum(payload, size) if folder.checksums else 0
            data += (
                struct.pack("<IHH", csum, len(payload), size)
                + b"\0" * data_resv
                + payload
            )
        method = _METHODS[folder.method]
        if folder.method in ("lzx", "quantum"):
            method |= folder.window_bits << 8
        folder_records += (
            struct.pack("<IHH", start, len(blocks), method) + b"\0" * folder_resv
        )
    total = data_start + len(data)
    head = struct.pack(
        "<4sIIIIIBBHHHHH",
        b"MSCF",
        0,
        total,
        0,
        head_len + folder_len,
        0,
        version[0],
        version[1],
        len(folders),
        len(files),
        flags,
        0x1234,
        0,
    )
    if reserve is not None:
        head += (
            struct.pack("<HBB", header_resv, folder_resv, data_resv)
            + b"\xaa" * header_resv
        )
    head += set_names
    return head + folder_records + entries + data
