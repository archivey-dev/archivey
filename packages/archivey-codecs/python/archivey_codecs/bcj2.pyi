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
    def read(self, max_length: int = -1) -> bytes: ...
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
    def total_in(self) -> tuple[int, int, int, int]: ...
    @property
    def total_out(self) -> int: ...
