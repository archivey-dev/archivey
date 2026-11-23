"""LZO1X blocks in Python, as ``archivey_codecs.lzo1x``: the decoder is
:func:`archivey.internal.streams.codecs.lzo_decoder.lzo1x_decompress_python`."""

from __future__ import annotations

from archivey.exceptions import CorruptionError


def decompress(
    block: bytes | bytearray | memoryview,
    /,
    *,
    out_size: int | None = None,
    max_size: int | None = None,
) -> bytes:
    """One LZO1X block: exactly ``out_size`` bytes (lzop records each block's size), or
    at most ``max_size`` (SquashFS records only the most a block may decode to). Exactly
    one of the two is given. Damage raises ``CorruptionError``."""
    from archivey.internal.streams.codecs.lzo_decoder import (
        LzoError,
        lzo1x_decompress_python,
    )

    if (out_size is None) == (max_size is None):
        raise TypeError(
            "lzo1x.decompress() takes exactly one of out_size= and max_size="
        )
    limit = out_size if out_size is not None else max_size
    assert limit is not None
    try:
        out = lzo1x_decompress_python(bytes(block), limit)
    except LzoError as exc:
        raise CorruptionError(str(exc)) from None
    if out_size is not None and len(out) != out_size:
        raise CorruptionError(f"the block decodes to {len(out)} bytes, not {out_size}")
    return out
