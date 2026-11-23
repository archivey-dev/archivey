from typing import Protocol, Self

from _typeshed import ReadableBuffer as Buffer

class _Readable(Protocol):
    def read(self, n: int, /) -> Buffer: ...

class Decompressor:
    def __init__(
        self,
        main: _Readable,
        call: _Readable,
        jump: _Readable,
        rc: _Readable,
        *,
        out_size: int,
    ) -> None: ...
    def read(self, max_length: int = -1) -> bytes:
        """Up to ``max_length`` bytes (all when negative). The bytes before an error
        come first, and the error raises from the next call. ``read(0)`` decodes
        nothing and reads no input: it raises an error the decoder holds."""
    def getstate(self) -> bytes: ...
    @classmethod
    def from_state(
        cls,
        state: Buffer,
        main: _Readable,
        call: _Readable,
        jump: _Readable,
        rc: _Readable,
    ) -> Self: ...
    @property
    def eof(self) -> bool: ...
    @property
    def out_size(self) -> int: ...
    @property
    def decoded(self) -> int:
        """Output bytes decoded so far, returned or not: ahead of ``total_out``."""
    @property
    def total_in(self) -> tuple[int, int, int, int]: ...
    @property
    def total_out(self) -> int: ...
