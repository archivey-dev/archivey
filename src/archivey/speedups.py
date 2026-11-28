"""The interfaces of the speedups a format or codec plugin can ask archivey for.

**Experimental**, as :mod:`archivey.formats` is: any release may change it.

archivey-speedups, archivey's optional Rust package, has fast versions of some decoders.
A plugin asks for one by name with :meth:`archivey.formats.ReaderContext.speedup` or
:meth:`archivey.formats.CodecCall.speedup`. The call returns the speedup when it can
run: the package is installed, recent enough, and allowed by the caller's library
policy, and, for a decoder under ``ProcessIsolation.NATIVE_DECODERS``, a decoder child
can run it. ``"crc16_arc"`` is a checksum, and checksums run in this process under every
isolation setting. Otherwise it returns ``None``, and the plugin uses a Python decoder
of its own with the same interface::

    make = context.speedup("lzw") or my_lzw.Decompressor

``speedup()`` checks what can run: under ``NATIVE_DECODERS`` a decoder child starts
when a decoder is made or a block decoded, and that call raises
``ResourceUnavailableError`` if none can start then.

A speedup gives the same bytes and raises the same errors as a correct Python decoder
of the same interface: the choice changes speed only. A speedup's own fault (a Rust
panic) raises ``CorruptionError``. archivey gives back the decoder child of every
object it handed out when the reader closes (for ``ReaderContext.speedup``) or when
the member stream closes (for ``CodecCall.speedup``), so a plugin does not close
them.
"""

from __future__ import annotations

from typing import Literal, Protocol, overload

__all__ = [
    "BlockDecompress",
    "Crc16",
    "LzwDecompressor",
    "LzwFactory",
    "LzxDecompressor",
    "LzxFactory",
    "SpeedupName",
]

SpeedupName = Literal["crc16_arc", "lzfse", "lzo1x", "lzvn", "lzw", "lzx"]
"""The speedups a plugin can ask for, and what each one returns:

- ``"crc16_arc"``: :class:`Crc16`, CRC-16/ARC (LHA).
- ``"lzfse"``, ``"lzvn"``: :class:`BlockDecompress`, Apple's LZFSE and raw LZVN (DMG).
- ``"lzo1x"``: :class:`BlockDecompress`, one LZO1X block (lzop, SquashFS).
- ``"lzw"``: :class:`LzwFactory`, Unix ``compress`` (``.Z``).
- ``"lzx"``: :class:`LzxFactory`, Microsoft LZX (CAB).
"""


class Crc16(Protocol):
    """``crc16_arc(data, value=0)``: the CRC-16/ARC of ``data``, going on from
    ``value``."""

    def __call__(
        self, data: bytes | bytearray | memoryview, value: int = 0, /
    ) -> int: ...


class BlockDecompress(Protocol):
    """Decode one whole block. Pass exactly one of ``out_size=``, the block's exact
    decoded size, and ``max_size=``, the most it may decode to."""

    @overload
    def __call__(
        self, block: bytes | bytearray | memoryview, /, *, out_size: int
    ) -> bytes: ...

    @overload
    def __call__(
        self, block: bytes | bytearray | memoryview, /, *, max_size: int
    ) -> bytes: ...

    def __call__(
        self,
        block: bytes | bytearray | memoryview,
        /,
        *,
        out_size: int | None = None,
        max_size: int | None = None,
    ) -> bytes: ...


class LzwDecompressor(Protocol):
    """One Unix ``compress`` stream, with the interface of ``lzma.LZMADecompressor``
    plus ``flush()``, which marks the end of the input and returns the rest of the
    output. ``max_length`` bounds what each call returns, ``flush()`` included. A bad
    code after some output returns the bytes decoded before it, and the error raises
    from the next call.

    A decompressor made with a stream's :attr:`header_params` and
    :attr:`nine_bit_widens` decodes from any of the :attr:`clear_offsets` a decode of
    that stream reported.
    """

    def decompress(
        self, data: bytes | bytearray | memoryview, max_length: int = -1
    ) -> bytes: ...

    def flush(self, max_length: int = -1) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    @property
    def unused_data(self) -> bytes: ...

    @property
    def truncation(self) -> str | None:
        """After ``flush()``, what showed that the stream was cut short, else
        ``None``."""
        ...

    @property
    def header_params(self) -> tuple[int, bool] | None:
        """The header's maximum code width and block mode, once read (or as
        given)."""
        ...

    @property
    def nine_bit_widens(self) -> bool | None:
        """The layout a full 9-bit table takes, once the decode has found it (or as
        given)."""
        ...

    @property
    def clear_offsets(self) -> list[tuple[int, int]]:
        """The CLEAR codes the last call passed, as (input offset, output offset)
        pairs counted as :attr:`total_in` and :attr:`total_out` count."""
        ...

    @property
    def total_in(self) -> int: ...

    @property
    def total_out(self) -> int: ...


class LzwFactory(Protocol):
    """``Decompressor(*, max_width=None, block_mode=None, nine_bit_widens=None)``.
    ``max_width`` and ``block_mode`` (both or neither) describe a stream without its
    3-byte header; with neither, the decompressor reads the header.
    ``nine_bit_widens`` fixes the layout a full 9-bit table takes (``None``: probe
    the stream)."""

    def __call__(
        self,
        *,
        max_width: int | None = None,
        block_mode: bool | None = None,
        nine_bit_widens: bool | None = None,
    ) -> LzwDecompressor: ...


class LzxDecompressor(Protocol):
    """One LZX stream (a CAB folder), with the interface of ``lzma.LZMADecompressor``
    plus ``flush()`` and ``set_output_size()``. The stream ends at its output size, so
    it has no ``unused_data``."""

    def set_output_size(self, output_size: int, /) -> None: ...

    def decompress(
        self, data: bytes | bytearray | memoryview, max_length: int = -1
    ) -> bytes: ...

    def flush(self, max_length: int = -1) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    @property
    def output_size(self) -> int | None: ...

    @property
    def total_out(self) -> int: ...


class LzxFactory(Protocol):
    """``Decompressor(window_bits, *, output_size=None)``."""

    def __call__(
        self, window_bits: int, *, output_size: int | None = None
    ) -> LzxDecompressor: ...
