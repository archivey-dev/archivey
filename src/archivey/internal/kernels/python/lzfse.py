"""LZFSE in Python, as ``archivey_codecs.lzfse``: the decoder is
:func:`archivey.internal.streams.codecs.lzfse_decoder.lzfse_decompress`."""

from __future__ import annotations

from archivey.exceptions import CorruptionError
from archivey.internal.kernels.python._buffers import raw_bytes


def decompress(
    data: bytes | bytearray | memoryview,
    /,
    *,
    out_size: int | None = None,
    max_size: int | None = None,
) -> bytes:
    """Decode a whole LZFSE stream (blocks up to ``bvx$``, nothing after it): exactly
    ``out_size`` bytes, or at most ``max_size``. Exactly one of the two is given. Damage
    raises ``CorruptionError`` or ``TruncatedError``."""
    from archivey.internal.streams.codecs.lzfse_decoder import lzfse_decompress

    if (out_size is None) == (max_size is None):
        raise TypeError(
            "lzfse.decompress() takes exactly one of out_size= and max_size="
        )
    limit = out_size if out_size is not None else max_size
    assert limit is not None
    out = lzfse_decompress(raw_bytes(data), limit)
    if out_size is not None and len(out) != out_size:
        raise CorruptionError(f"the data decodes to {len(out)} bytes, not {out_size}")
    return out
