"""LZO1X, and the ``.lzo`` file format ``lzop`` writes around it.

LZO1X has no stream framing of its own: a block is decoded whole, to a size the
container stores (a SquashFS block, an lzop block). ``python-lzo`` binds liblzo2 and is
used when it is installed. It is GPL and has no Linux wheels, so archivey does not
depend on it and carries the decoder in Python too (:func:`lzo1x_decompress_python`). It
follows ``lzo1x_decompress_safe`` in the Linux kernel (``lib/lzo/lzo1x_decompress_safe.c``),
without the LZO-RLE extension, which neither lzop nor SquashFS writes.

Every read is checked: a run of literals or a match that would pass the end of the
input, write past the limit or copy from before the start of the output raises
:class:`LzoError`, and so does input left after the end marker.

The lzop format (``lzop`` 1.04, ``header.c`` and ``lzop.c``): a 9-byte magic, a header
with the method, flags, mode, mtime and stored name, closed by a checksum, then blocks.
Each block is its decoded length (0 ends the file), its stored length, the optional
checksums the flags ask for, then the data: stored as is when the two lengths are equal,
else LZO1X. A further file may follow, starting with the magic again.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Callable
from typing import BinaryIO

from archivey.exceptions import CorruptionError, UnsupportedFeatureError
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.isolated import IN_PROCESS, Natives
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    Decoder,
    SeekPoint,
)
from archivey.types import OptionalLibrary


class LzoError(ValueError):
    """The data is not a valid LZO1X stream, or decodes to more than the limit."""


def _python_lzo(
    excluded: frozenset[OptionalLibrary], natives: Natives = IN_PROCESS
) -> Callable[[bytes, int], bytes] | None:
    """``python-lzo``'s decoder, in this process or a child as ``natives`` says, or
    ``None`` when it is absent or ``excluded``."""
    if OptionalLibrary.LZO in excluded or not natives.package_available(deps.lzo):
        return None
    errors = natives.lzo_errors()

    def decompress(data: bytes, limit: int) -> bytes:
        try:
            return natives.lzo_decompress(data, limit)
        except errors as exc:
            raise LzoError(str(exc)) from None

    return decompress


def lzo1x_decompressor(
    excluded: frozenset[OptionalLibrary] = frozenset(),
    natives: Natives = IN_PROCESS,
) -> Callable[[bytes, int], bytes]:
    """The LZO1X block decoder to use: ``python-lzo`` when present and allowed, else
    :func:`lzo1x_decompress_python`, which is Python and so runs in this process
    whatever ``natives`` says."""
    return _python_lzo(excluded, natives) or lzo1x_decompress_python


def lzo1x_decompress_python(data: bytes, limit: int) -> bytes:
    """Decode the LZO1X block ``data`` (no header) to at most ``limit`` bytes."""
    out = bytearray()
    end = len(data)
    ip = 0
    # ``state`` is the number of literals the last instruction copied (0 to 3), or 4
    # after a longer literal run; it decides what an instruction byte below 16 means.
    state = 0
    if end and data[0] > 17:
        t = data[0] - 17
        ip = 1
        if ip + t > end:
            raise LzoError("a literal run passes the end of the input")
        if t > limit:
            raise LzoError(f"the data decodes to more than {limit} bytes")
        out += data[ip : ip + t]
        ip += t
        state = 4 if t > 3 else t
    while True:
        if ip >= end:
            raise LzoError("the input ends inside an instruction")
        t = data[ip]
        ip += 1
        if t < 16:
            if state == 0:
                # A literal run of 4 or more bytes.
                if t == 0:
                    zeros = ip
                    while ip < end and data[ip] == 0:
                        ip += 1
                    if ip >= end:
                        raise LzoError("the input ends inside an instruction")
                    t = (ip - zeros) * 255 + 15 + data[ip]
                    ip += 1
                count = t + 3
                if ip + count > end:
                    raise LzoError("a literal run passes the end of the input")
                if len(out) + count > limit:
                    raise LzoError(f"the data decodes to more than {limit} bytes")
                out += data[ip : ip + count]
                ip += count
                state = 4
                continue
            if ip >= end:
                raise LzoError("the input ends inside an instruction")
            if state != 4:
                # A 2-byte match close behind, after a short literal run.
                distance = 1 + (t >> 2) + (data[ip] << 2)
                length = 2
            else:
                # A 3-byte match from 2 to 3 KiB back, after a long literal run.
                distance = 0x801 + (t >> 2) + (data[ip] << 2)
                length = 3
            ip += 1
            nxt = t & 3
        elif t >= 64:
            if ip >= end:
                raise LzoError("the input ends inside an instruction")
            distance = 1 + ((t >> 2) & 7) + (data[ip] << 3)
            ip += 1
            length = (t >> 5) + 1
            nxt = t & 3
        else:
            if t >= 32:
                length = t & 31
                base = 31
            else:
                length = t & 7
                base = 7
            if length == 0:
                zeros = ip
                while ip < end and data[ip] == 0:
                    ip += 1
                if ip >= end:
                    raise LzoError("the input ends inside an instruction")
                length = (ip - zeros) * 255 + base + data[ip]
                ip += 1
            length += 2
            if ip + 2 > end:
                raise LzoError("the input ends inside an instruction")
            field = data[ip] | data[ip + 1] << 8
            ip += 2
            nxt = field & 3
            if t >= 32:
                distance = 1 + (field >> 2)
            else:
                distance = ((t & 8) << 11) + (field >> 2)
                if distance == 0:
                    # The end marker: 17, 0, 0, which only a 3 in ``length`` spells.
                    if length != 3:
                        raise LzoError("a damaged end marker")
                    if ip != end:
                        raise LzoError(f"{end - ip} bytes follow the end marker")
                    return bytes(out)
                distance += 0x4000
        start = len(out) - distance
        if start < 0:
            raise LzoError("a match refers to bytes before the start of the output")
        if len(out) + length > limit:
            raise LzoError(f"the data decodes to more than {limit} bytes")
        if distance >= length:
            out += out[start : start + length]
        else:
            # The match overlaps what it writes: it repeats its last ``distance`` bytes.
            pattern = bytes(out[start:])
            whole, rest = divmod(length, distance)
            out += pattern * whole + pattern[:rest]
        if nxt:
            if ip + nxt > end:
                raise LzoError("a literal run passes the end of the input")
            if len(out) + nxt > limit:
                raise LzoError(f"the data decodes to more than {limit} bytes")
            out += data[ip : ip + nxt]
            ip += nxt
        state = nxt


# --- lzop ------------------------------------------------------------------------------

LZOP_MAGIC = b"\x89LZO\x00\r\n\x1a\n"

_F_ADLER32_D = 0x1
_F_ADLER32_C = 0x2
_F_H_EXTRA_FIELD = 0x40
_F_CRC32_D = 0x100
_F_CRC32_C = 0x200
_F_H_FILTER = 0x800
_F_H_CRC32 = 0x1000
# lzop's F_MASK, F_OS_MASK and F_CS_MASK: any other bit is one lzop refuses.
_F_KNOWN = 0x3FFF | 0xFF000000 | 0x00F00000
# M_LZO1X_1, M_LZO1X_1_15 and M_LZO1X_999 all write LZO1X.
_LZO1X_METHODS = frozenset({1, 2, 3})
# lzop's MAX_BLOCK_SIZE: it writes 256 KiB blocks (BLOCK_SIZE) and reads up to 64 MiB.
# A block is decoded whole, so a block's declared size is what it allocates: above
# 64 MiB lzop itself refuses the file, and archivey does too (CorruptionError). Below
# it, the codec checks the size against the caller's limits (``_block_check`` in
# ``lzo_codec``, which ``LzopCodec.decompressor`` passes to ``LzopDecompressor``).
LZOP_BLOCK_SIZE = 256 * 1024
_MAX_BLOCK = 64 * 1024 * 1024

_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")


class LzopHeader:
    """The fields of an lzop file header that archivey uses."""

    __slots__ = ("flags", "length", "method", "mode", "mtime", "name")

    def __init__(
        self,
        *,
        flags: int,
        method: int,
        mode: int,
        mtime: int,
        name: bytes,
        length: int,
    ) -> None:
        self.flags = flags
        self.method = method
        self.mode = mode
        self.mtime = mtime
        self.name = name
        # The header's length from the magic through its checksum and extra field.
        self.length = length


def parse_lzop_header(
    buf: bytes | bytearray, check_size: Callable[[int], None] | None = None
) -> LzopHeader | None:
    """The header at the start of ``buf``, or ``None`` when ``buf`` ends inside it.

    Raises :class:`CorruptionError` for a damaged header and
    :class:`UnsupportedFeatureError` for a method or filter archivey does not decode.
    ``check_size`` is given an extra field's declared length before the field is
    waited for, as a block's decoded size is, and raises to refuse it.
    """
    if len(buf) < len(LZOP_MAGIC):
        return None
    if buf[: len(LZOP_MAGIC)] != LZOP_MAGIC:
        raise CorruptionError("not an lzop file: bad magic")
    pos = len(LZOP_MAGIC)
    start = pos

    def take(n: int) -> bytes | None:
        nonlocal pos
        if pos + n > len(buf):
            return None
        piece = bytes(buf[pos : pos + n])
        pos += n
        return piece

    fixed = take(4)
    if fixed is None:
        return None
    version = _U16.unpack_from(fixed, 0)[0]
    if version < 0x0900:
        raise CorruptionError(
            f"lzop header version {version:#x} is not one lzop writes"
        )
    new = version >= 0x0940
    if new:
        needed_raw = take(2)
        if needed_raw is None:
            return None
        needed = _U16.unpack(needed_raw)[0]
        if needed > 0x1040:
            raise UnsupportedFeatureError(
                f"this lzop file needs lzop {needed:#x} or later to extract"
            )
    method_level = take(2 if new else 1)
    if method_level is None:
        return None
    method = method_level[0]
    flags_raw = take(4)
    if flags_raw is None:
        return None
    flags = _U32.unpack(flags_raw)[0]
    if flags & ~_F_KNOWN & 0xFFFFFFFF:
        raise CorruptionError(f"lzop header has unknown flags {flags:#x}")
    if flags & _F_H_FILTER:
        filt = take(4)
        if filt is None:
            return None
        if _U32.unpack(filt)[0] != 0:
            raise UnsupportedFeatureError(
                "lzop files written with a filter are not supported"
            )
    # The mode, the low 32 bits of the mtime, and from 0x0940 the high 32 bits.
    times = take(12 if new else 8)
    if times is None:
        return None
    mode = _U32.unpack_from(times, 0)[0]
    mtime = _U32.unpack_from(times, 4)[0]
    if new:
        mtime |= _U32.unpack_from(times, 8)[0] << 32
    name_len_raw = take(1)
    if name_len_raw is None:
        return None
    name = take(name_len_raw[0])
    if name is None:
        return None
    checksum_raw = take(4)
    if checksum_raw is None:
        return None
    covered = bytes(buf[start : pos - 4])
    expected = _U32.unpack(checksum_raw)[0]
    actual = zlib.crc32(covered) if flags & _F_H_CRC32 else zlib.adler32(covered)
    if actual != expected:
        raise CorruptionError("lzop header checksum mismatch")
    if method not in _LZO1X_METHODS:
        raise UnsupportedFeatureError(
            f"lzop method {method} is not supported (only the LZO1X methods 1 to 3)"
        )
    if flags & _F_H_EXTRA_FIELD:
        extra_len_raw = take(4)
        if extra_len_raw is None:
            return None
        extra_len = _U32.unpack(extra_len_raw)[0]
        if extra_len > _MAX_BLOCK:
            raise CorruptionError("lzop header extra field is too long")
        if check_size is not None:
            check_size(extra_len)
        extra = take(extra_len)
        if extra is None:
            return None
        extra_checksum_raw = take(4)
        if extra_checksum_raw is None:
            return None
        # As lzop's read_header: the checksum covers the length and the field.
        covered = extra_len_raw + extra
        expected = _U32.unpack(extra_checksum_raw)[0]
        actual = zlib.crc32(covered) if flags & _F_H_CRC32 else zlib.adler32(covered)
        if actual != expected:
            raise CorruptionError("lzop header extra field checksum mismatch")
    return LzopHeader(
        flags=flags, method=method, mode=mode, mtime=mtime, name=name, length=pos
    )


class LzopDecompressor:
    """One lzop file, with the ``bz2.BZ2Decompressor`` interface (``FramedDecoder``).

    Holds at most one block of input and its output, each at most 64 MiB, the most
    lzop reads. ``check_block`` is given each block's declared decoded size, and the
    header's extra field length, before anything is allocated for it, and raises to
    refuse it.
    """

    def __init__(
        self,
        decode_block: Callable[[bytes, int], bytes],
        check_block: Callable[[int], None] | None = None,
    ) -> None:
        self._decode_block = decode_block
        self._check_block = check_block
        self._in = bytearray()
        self._out = bytearray()
        self._header: LzopHeader | None = None
        self._ended = False
        self.unused_data = b""

    @property
    def eof(self) -> bool:
        return self._ended and not self._out

    @property
    def needs_input(self) -> bool:
        return not self._out and not self._ended

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._ended:
            if data:
                self.unused_data += data
        else:
            self._in += data
        self._fill()
        n = len(self._out) if max_length < 0 else min(max_length, len(self._out))
        out = bytes(self._out[:n])
        del self._out[:n]
        # With the output used up, decode the next block the input holds, so
        # ``needs_input`` is true only when no whole block is left unread.
        self._fill()
        return out

    def _fill(self) -> None:
        """Decode a block only when the output held is used up, so ``max_length``
        bounds what is held to about one block."""
        while not self._out and not self._ended and self._step():
            pass

    def _step(self) -> bool:
        """Parse the header or one block from the input held; False when more input
        is needed first."""
        buf = self._in
        if self._header is None:
            header = parse_lzop_header(buf, self._check_block)
            if header is None:
                return False
            self._header = header
            del buf[: header.length]
            return True
        flags = self._header.flags
        if len(buf) < 4:
            return False
        dst_len = _U32.unpack_from(buf, 0)[0]
        if dst_len == 0:
            self._ended = True
            self.unused_data = bytes(buf[4:])
            buf.clear()
            return False
        if dst_len > _MAX_BLOCK:
            raise CorruptionError(
                f"lzop block of {dst_len} bytes is over the 64 MiB lzop reads"
            )
        if self._check_block is not None:
            self._check_block(dst_len)
        if len(buf) < 8:
            return False
        src_len = _U32.unpack_from(buf, 4)[0]
        if src_len > dst_len or src_len == 0:
            raise CorruptionError(
                f"lzop block stores {src_len} bytes for {dst_len} decoded bytes"
            )
        pos = 8
        d_adler = d_crc = c_adler = c_crc = None
        if flags & _F_ADLER32_D:
            d_adler, pos = pos, pos + 4
        if flags & _F_CRC32_D:
            d_crc, pos = pos, pos + 4
        if src_len < dst_len:
            if flags & _F_ADLER32_C:
                c_adler, pos = pos, pos + 4
            if flags & _F_CRC32_C:
                c_crc, pos = pos, pos + 4
        if len(buf) < pos + src_len:
            return False
        raw = bytes(buf[pos : pos + src_len])

        def check(at: int | None, value: int, what: str) -> None:
            if at is not None and _U32.unpack_from(buf, at)[0] != value:
                raise CorruptionError(f"lzop block {what} checksum mismatch")

        check(c_adler, zlib.adler32(raw), "compressed data")
        check(c_crc, zlib.crc32(raw), "compressed data")
        if src_len == dst_len:
            block = raw
        else:
            try:
                block = self._decode_block(raw, dst_len)
            except LzoError as exc:
                raise CorruptionError(f"lzop block: {exc}") from None
            if len(block) != dst_len:
                raise CorruptionError(
                    f"lzop block decodes to {len(block)} bytes, not the {dst_len} stored"
                )
        check(d_adler, zlib.adler32(block), "data")
        check(d_crc, zlib.crc32(block), "data")
        del buf[: pos + src_len]
        self._out += block
        return True


class Lzo1xDecoder(BaseDecoder):
    """A whole raw LZO1X member (a SquashFS block), decoded once its input has ended.

    LZO1X has no framing a decoder could stream over, and its end marker (17, 0, 0)
    can also occur inside the data, so the input is held whole and decoded at the end
    of the source. ``size`` is the most the data may decode to: a SquashFS block's
    decoded length is the block size or less. It also bounds the input held, to the
    most LZO1X takes to store that many bytes.
    """

    def __init__(self, decode_block: Callable[[bytes, int], bytes], size: int) -> None:
        self._decode_block = decode_block
        self._size = size
        # The most input any decodable LZO1X stream takes for ``size`` bytes, so longer
        # input is refused as it arrives rather than held. Only a literal run's
        # instruction byte takes input that is not output; a run (4 bytes or more,
        # after the first) is always followed by a match of 3 bytes or more, which
        # takes no more input than it writes. So at most one byte in 7 is extra, plus
        # the first run's byte and the 3-byte end marker. liblzo2's
        # ``lzo1x_worst_compress`` (``size // 16``) bounds what its compressor writes,
        # not what its decoder accepts, and a valid stream can be longer.
        self._max_input = size + size // 7 + 64 + 3
        self._in = bytearray()
        self._done = False

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Decoder:
        del point, inner
        return Lzo1xDecoder(self._decode_block, self._size)

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        del max_length
        if self._done:
            self._past_end(chunk)
        else:
            if len(self._in) + len(chunk) > self._max_input:
                raise CorruptionError(
                    f"LZO block: over {self._max_input} bytes of input, more than "
                    f"LZO1X takes to store {self._size} bytes"
                )
            self._in += chunk
        return DecodeOut(b"")

    def flush(self) -> DecodeOut:
        if self._done:
            return DecodeOut(b"")
        self._done = True
        # Released before the decode, so the input is not held twice while it runs.
        data = bytes(self._in)
        self._in = bytearray()
        # The container stores the block's length, so input that ends inside an
        # instruction is a damaged block, not a cut-off one.
        try:
            out = self._decode_block(data, self._size)
        except LzoError as exc:
            raise CorruptionError(f"LZO block: {exc}") from None
        return DecodeOut(out)

    @property
    def finished(self) -> bool:
        return self._done
