"""Apple Data Compression (ADC), as old UDIF disk images store a run (type
``0x80000004``), decoded in Python.

ADC is a byte-oriented LZ77 with a window of 64 KiB and no framing. Each command's first
byte says what it is:

- ``1LLLLLLL``: a literal run of ``L + 1`` bytes (1 to 128) that follow;
- ``01LLLLLL DDDDDDDD DDDDDDDD``: a match of ``L + 4`` bytes (4 to 67), ``D + 1`` bytes
  back (1 to 65 536);
- ``00LLLLDD DDDDDDDD``: a match of ``L + 3`` bytes (3 to 18), ``D + 1`` bytes back
  (1 to 1024).

The layout is the one 7-Zip's ``DmgHandler.cpp`` and dmg2img decode. Each run is a
stream of its own: a match may not reach back before the run's first byte. The input
must be used up exactly, and the output may not pass ``max_length``; the caller checks
that the run decoded to its declared size.
"""

from __future__ import annotations

from archivey.exceptions import CorruptionError, TruncatedError


def adc_decompress(data: bytes, max_length: int) -> bytes:
    """Decode one ADC run. Raises :class:`TruncatedError` when the input ends inside a
    command, and :class:`CorruptionError` for a match before the start or output past
    ``max_length``."""
    src = bytes(data)
    n = len(src)
    out = bytearray()
    i = 0
    while i < n:
        b = src[i]
        if b & 0x80:
            count = (b & 0x7F) + 1
            if i + 1 + count > n:
                raise TruncatedError("ADC data ends inside a literal run")
            if len(out) + count > max_length:
                raise CorruptionError(
                    f"ADC data decodes to more than {max_length} bytes"
                )
            out += src[i + 1 : i + 1 + count]
            i += 1 + count
            continue
        if b & 0x40:
            if i + 3 > n:
                raise TruncatedError("ADC data ends inside a match")
            length = (b & 0x3F) + 4
            dist = ((src[i + 1] << 8) | src[i + 2]) + 1
            i += 3
        else:
            if i + 2 > n:
                raise TruncatedError("ADC data ends inside a match")
            length = ((b >> 2) & 0xF) + 3
            dist = (((b & 3) << 8) | src[i + 1]) + 1
            i += 2
        size = len(out)
        if dist > size:
            raise CorruptionError("ADC match reaches before the start of the run")
        if size + length > max_length:
            raise CorruptionError(f"ADC data decodes to more than {max_length} bytes")
        start = size - dist
        if dist >= length:
            out += out[start : start + length]
        else:
            chunk = out[start:]
            reps, rest = divmod(length, dist)
            out += chunk * reps + chunk[:rest]
    return bytes(out)
