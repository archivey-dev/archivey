"""archivey's Python decoders in the API of ``archivey_codecs``.

Each module here is the Python twin of the package module of the same name, with the
classes, functions, arguments and attributes call sites use. The package's state
methods (``getstate``, ``from_state``, and ``copy`` where no call site needs it) are
left out. The twins raise archivey's errors, as the package's kernels do through
:mod:`archivey.internal.kernels.rust`.
"""

from __future__ import annotations

import operator
from typing import SupportsIndex

from archivey.internal.kernels.python._buffers import raw_bytes


def _crc16_table() -> list[int]:
    table: list[int] = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC16_TABLE = _crc16_table()


def crc16_arc(
    data: bytes | bytearray | memoryview, value: SupportsIndex | None = 0, /
) -> int:
    """CRC-16/ARC (polynomial 0x8005, reflected) of ``data``, going on from ``value``:
    the checksum LHA keeps for its data and headers."""
    # As the package: ``None`` is 0, and an int is compared however large.
    value = 0 if value is None else operator.index(value)
    if not 0 <= value <= 0xFFFF:
        # As the package: a CRC-16 has 16 bits, so a value outside them is a mistake.
        raise ValueError("CRC-16 value is outside 0 to 0xFFFF")
    table = _CRC16_TABLE
    crc = value
    for byte in raw_bytes(data):
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc
