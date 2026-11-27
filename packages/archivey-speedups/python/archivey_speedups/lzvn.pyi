from typing import overload

from _typeshed import ReadableBuffer as Buffer

@overload
def decompress(data: Buffer, /, *, out_size: int) -> bytes: ...
@overload
def decompress(data: Buffer, /, *, max_size: int) -> bytes: ...
