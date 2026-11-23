from typing import overload

from _typeshed import ReadableBuffer as Buffer

@overload
def decompress(block: Buffer, /, *, out_size: int) -> bytes: ...
@overload
def decompress(block: Buffer, /, *, max_size: int) -> bytes: ...
