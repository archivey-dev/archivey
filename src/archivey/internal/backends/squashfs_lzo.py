"""LZO1X decompression, for the blocks of an LZO-compressed SquashFS image.

``python-lzo`` binds liblzo2 and is used when it is installed, but it is GPL and has no
Linux wheels, so archivey also carries this decoder in Python. It follows
``lzo1x_decompress_safe`` in the Linux kernel (``lib/lzo/lzo1x_decompress_safe.c``),
without the LZO-RLE extension, which SquashFS does not write. A SquashFS block decodes to
at most its block size (1 MiB), so a decoder in Python is slow but bounded.

Every read is checked: a run of literals or a match that would pass the end of the
input, write past ``limit`` or copy from before the start of the output raises
:class:`LzoError`, and so does input left after the end marker.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable


class LzoError(ValueError):
    """The data is not a valid LZO1X stream, or decodes to more than the limit."""


def _python_lzo() -> Callable[[bytes, int], bytes] | None:
    try:
        # By name: python-lzo is optional and untyped, so the checkers see ``Any``.
        lzo = importlib.import_module("lzo")
    except ImportError:
        return None

    def decompress(data: bytes, limit: int) -> bytes:
        try:
            return lzo.decompress(data, False, limit)
        except lzo.error as exc:
            raise LzoError(str(exc)) from None

    return decompress


def decompress(data: bytes, limit: int) -> bytes:
    """Decode the LZO1X stream ``data`` (no header) to at most ``limit`` bytes."""
    native = _python_lzo()
    if native is not None:
        return native(data, limit)
    return decompress_python(data, limit)


def decompress_python(data: bytes, limit: int) -> bytes:
    """Decode ``data`` in Python; :func:`decompress` without ``python-lzo``."""
    out = bytearray()
    end = len(data)
    ip = 0

    def byte() -> int:
        nonlocal ip
        if ip >= end:
            raise LzoError("the input ends inside an instruction")
        value = data[ip]
        ip += 1
        return value

    def le16() -> int:
        nonlocal ip
        if ip + 2 > end:
            raise LzoError("the input ends inside an instruction")
        value = data[ip] | data[ip + 1] << 8
        ip += 2
        return value

    def run_length(t: int, base: int) -> int:
        """A length field of ``t`` zero bits: each zero byte adds 255, then a byte."""
        nonlocal ip
        if t:
            return t
        zeros = 0
        while ip < end and data[ip] == 0:
            zeros += 1
            ip += 1
        return zeros * 255 + base + byte()

    def literals(count: int) -> None:
        nonlocal ip
        if ip + count > end:
            raise LzoError("a literal run passes the end of the input")
        if len(out) + count > limit:
            raise LzoError(f"the data decodes to more than {limit} bytes")
        out.extend(data[ip : ip + count])
        ip += count

    def match(distance: int, length: int) -> None:
        start = len(out) - distance
        if start < 0:
            raise LzoError("a match refers to bytes before the start of the output")
        if len(out) + length > limit:
            raise LzoError(f"the data decodes to more than {limit} bytes")
        if distance >= length:
            out.extend(out[start : start + length])
            return
        # The match overlaps what it writes: it repeats its last ``distance`` bytes.
        pattern = bytes(out[start:])
        whole, rest = divmod(length, distance)
        out.extend(pattern * whole + pattern[:rest])

    # ``state`` is the number of literals the last instruction copied (0 to 3), or 4
    # after a longer literal run; it decides what a byte below 16 means.
    state = 0
    if end and data[0] > 17:
        ip = 1
        t = data[0] - 17
        literals(t)
        state = min(4, t)
    while True:
        t = byte()
        if t < 16:
            if state == 0:
                literals(run_length(t, 15) + 3)
                state = 4
                continue
            if state != 4:
                # A 2-byte match close behind, after a short literal run.
                distance = 1 + (t >> 2) + (byte() << 2)
                length, nxt = 2, t & 3
            else:
                # A 3-byte match from 2 to 3 KiB back, after a long literal run.
                distance = 1 + 0x0800 + (t >> 2) + (byte() << 2)
                length, nxt = 3, t & 3
        elif t >= 64:
            distance = 1 + ((t >> 2) & 7) + (byte() << 3)
            length, nxt = (t >> 5) + 1, t & 3
        elif t >= 32:
            length = run_length(t & 31, 31) + 2
            field = le16()
            distance, nxt = 1 + (field >> 2), field & 3
        else:
            length = run_length(t & 7, 7) + 2
            field = le16()
            distance = ((t & 8) << 11) + (field >> 2)
            if distance == 0:
                # The end marker: 17, 0, 0, which only a 3 in ``length`` spells.
                if length != 3:
                    raise LzoError("a damaged end marker")
                if ip != end:
                    raise LzoError(f"{end - ip} bytes follow the end marker")
                return bytes(out)
            distance += 0x4000
            nxt = field & 3
        match(distance, length)
        literals(nxt)
        state = nxt
