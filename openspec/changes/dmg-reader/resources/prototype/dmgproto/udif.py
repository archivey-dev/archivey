"""UDIF (.dmg) prototype: koly trailer, blkx/mish run tables, a random-access virtual disk."""

from __future__ import annotations

import bisect
import bz2
import lzma
import plistlib
import struct
import zlib
from dataclasses import dataclass
from typing import BinaryIO

from . import adc, lzfse

KOLY = struct.Struct(">4sIIIQQQQQII16sII128sQQ120sII128sIQ12s")
assert KOLY.size == 512
MISH_HEADER = struct.Struct(">4sIQQQII24sII128sI")
assert MISH_HEADER.size == 204, MISH_HEADER.size
RUN = struct.Struct(">IIQQQQ")

ZERO, RAW, IGNORE = 0, 1, 2
ADC, ZLIB, BZIP2, LZFSE, LZMA = 0x80000004, 0x80000005, 0x80000006, 0x80000007, 0x80000008
COMMENT, END = 0x7FFFFFFE, 0xFFFFFFFF
RUN_NAMES = {ZERO: "zero", RAW: "raw", IGNORE: "ignore", ADC: "adc", ZLIB: "zlib",
             BZIP2: "bzip2", LZFSE: "lzfse", LZMA: "lzma", COMMENT: "comment", END: "end"}

MAX_PLIST = 64 << 20
MAX_RUN_SECTORS = 1 << 20  # hdiutil writes at most 2048 sectors (1 MiB) per run in practice
SECTOR = 512


class DmgError(Exception):
    pass


@dataclass(frozen=True)
class Run:
    kind: int
    sector: int  # absolute sector in the disk
    count: int
    offset: int  # absolute file offset
    length: int


@dataclass
class Koly:
    version: int
    flags: int
    data_fork_offset: int
    data_fork_length: int
    rsrc_fork_offset: int
    rsrc_fork_length: int
    segment_number: int
    segment_count: int
    data_checksum: tuple[int, int, bytes]
    xml_offset: int
    xml_length: int
    master_checksum: tuple[int, int, bytes]
    image_variant: int
    sector_count: int


def parse_koly(block: bytes) -> Koly:
    f = KOLY.unpack(block)
    if f[0] != b"koly" or f[1] != 4 or f[2] != 512:
        raise DmgError("no koly block")
    return Koly(f[1], f[3], f[5], f[6], f[7], f[8], f[9], f[10], (f[12], f[13], f[14]),
                f[15], f[16], (f[18], f[19], f[20]), f[21], f[22])


def crc32_checksum(ck: tuple[int, int, bytes]) -> int | None:
    kind, bits, data = ck
    if kind == 2 and bits == 32:  # UDIFChecksumTypeCRC32
        return struct.unpack(">I", data[:4])[0]
    return None


@dataclass
class Partition:
    name: str
    first_sector: int
    sector_count: int
    runs: list[Run]
    checksum: int | None


class UdifImage:
    def __init__(self, f: BinaryIO, size: int, *, cache_runs: int = 4) -> None:
        self.f = f
        self.size = size
        f.seek(size - 512)
        tail = f.read(512)
        base = 0
        try:
            self.koly = parse_koly(tail)
        except DmgError:
            f.seek(0)
            self.koly = parse_koly(f.read(512))  # old front-placed layout
        k = self.koly
        if k.segment_count > 1:
            raise DmgError(f"segmented image ({k.segment_count} segments) not supported")
        if k.xml_length == 0:
            raise DmgError("image without XML property list (resource-fork-only) not supported")
        if k.xml_length > MAX_PLIST or k.xml_offset + k.xml_length > size:
            raise DmgError("property list out of range")
        f.seek(k.xml_offset)
        self.plist = plistlib.loads(f.read(k.xml_length))  # expat; entity declarations refused
        blkx = self.plist.get("resource-fork", {}).get("blkx")
        if not isinstance(blkx, list):
            raise DmgError("no blkx table")
        self.partitions: list[Partition] = []
        runs: list[Run] = []
        for entry in blkx:
            data = entry["Data"]
            if len(data) < MISH_HEADER.size:
                raise DmgError("short mish block")
            h = MISH_HEADER.unpack_from(data)
            if h[0] != b"mish":
                raise DmgError("bad mish signature")
            first, count, data_off, n = h[2], h[3], h[4], h[11]
            if MISH_HEADER.size + n * RUN.size > len(data):
                raise DmgError("mish run table longer than its block")
            ck = crc32_checksum((h[8], h[9], h[10]))
            pruns = []
            for i in range(n):
                kind, _c, sec, cnt, off, ln = RUN.unpack_from(data, MISH_HEADER.size + i * RUN.size)
                if kind in (COMMENT, END):
                    continue
                if kind not in RUN_NAMES:
                    raise DmgError(f"unknown run type {kind:#x}")
                if cnt > MAX_RUN_SECTORS:
                    raise DmgError("run too large")
                r = Run(kind, first + sec, cnt, base + data_off + off, ln)
                if r.offset + r.length > size:
                    raise DmgError("run past end of file")
                pruns.append(r)
            self.partitions.append(Partition(entry.get("CFName") or entry.get("Name", ""), first, count, pruns, ck))
            runs.extend(pruns)
        runs.sort(key=lambda r: r.sector)
        prev_end = 0
        for r in runs:
            if r.sector < prev_end:
                raise DmgError("overlapping runs")
            prev_end = r.sector + r.count
        self.runs = runs
        self._starts = [r.sector for r in runs]
        self.sector_count = max(k.sector_count, prev_end)
        self.disk_size = self.sector_count * SECTOR
        self._cache: dict[int, bytes] = {}
        self._cache_order: list[int] = []
        self._cache_runs = cache_runs
        self.decoded_bytes = 0

    # --- decoding -------------------------------------------------------------------------
    def _decode(self, i: int) -> bytes:
        r = self.runs[i]
        want = r.count * SECTOR
        if r.kind in (ZERO, IGNORE):
            return bytes(want)
        self.f.seek(r.offset)
        src = self.f.read(r.length)
        if len(src) != r.length:
            raise DmgError("truncated run")
        if r.kind == RAW:
            out = src
        elif r.kind == ZLIB:
            d = zlib.decompressobj()
            out = d.decompress(src, want)
        elif r.kind == BZIP2:
            d = bz2.BZ2Decompressor()
            out = d.decompress(src, want)
        elif r.kind == LZMA:
            d = lzma.LZMADecompressor()
            out = d.decompress(src, want)
        elif r.kind == LZFSE:
            out = lzfse.decompress(src, want)
        elif r.kind == ADC:
            out = adc.decompress(src, want)
        else:
            raise DmgError(f"run type {r.kind:#x}")
        if len(out) != want:
            raise DmgError(f"run at sector {r.sector} decoded to {len(out)} bytes, expected {want}")
        self.decoded_bytes += want
        return out

    def run_bytes(self, i: int) -> bytes:
        b = self._cache.get(i)
        if b is None:
            b = self._decode(i)
            self._cache[i] = b
            self._cache_order.append(i)
            if len(self._cache_order) > self._cache_runs:
                del self._cache[self._cache_order.pop(0)]
        return b

    def read(self, offset: int, n: int) -> bytes:
        """Disk bytes; a hole between runs reads as zeros (hdiutil leaves none)."""
        end = min(offset + n, self.disk_size)
        out = bytearray()
        pos = offset
        while pos < end:
            sec = pos // SECTOR
            i = bisect.bisect_right(self._starts, sec) - 1
            if i < 0 or sec >= self.runs[i].sector + self.runs[i].count:
                nxt = self._starts[i + 1] * SECTOR if i + 1 < len(self.runs) else end
                take = min(end, nxt) - pos
                out += bytes(take)
                pos += take
                continue
            r = self.runs[i]
            data = self.run_bytes(i)
            rel = pos - r.sector * SECTOR
            take = min(end - pos, len(data) - rel)
            out += data[rel:rel + take]
            pos += take
        return bytes(out)

    def verify(self) -> dict[str, object]:
        """Check each partition's CRC32 over its decoded sectors, and the data-fork CRC32."""
        res: dict[str, object] = {}
        for p in self.partitions:
            if p.checksum is None:
                continue
            c = 0
            for r in p.runs:
                if r.kind == IGNORE:  # measured: the CRC skips "ignore" runs, includes zero-fill
                    continue
                c = zlib.crc32(self.run_bytes(self.runs.index(r)), c)
            res[p.name] = c == p.checksum
        dc = crc32_checksum(self.koly.data_checksum)
        if dc is not None:
            self.f.seek(self.koly.data_fork_offset)
            c = 0
            left = self.koly.data_fork_length
            while left:
                b = self.f.read(min(left, 1 << 20))
                if not b:
                    break
                c = zlib.crc32(b, c)
                left -= len(b)
            res["data fork"] = c == dc
        return res


class DiskView:
    """A partition of the virtual disk, read like a file-backed source."""

    def __init__(self, img: UdifImage, start: int, length: int) -> None:
        self.img, self.start, self.length = img, start, length

    def read_at(self, off: int, n: int) -> bytes:
        if off < 0 or off >= self.length:
            return b""
        n = min(n, self.length - off)
        return self.img.read(self.start + off, n)


class FileView:
    def __init__(self, f: BinaryIO, start: int, length: int) -> None:
        self.f, self.start, self.length = f, start, length

    def read_at(self, off: int, n: int) -> bytes:
        if off < 0 or off >= self.length:
            return b""
        self.f.seek(self.start + off)
        return self.f.read(min(n, self.length - off))
