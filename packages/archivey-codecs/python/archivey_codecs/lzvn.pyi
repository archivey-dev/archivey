from typing import SupportsIndex, overload

from _typeshed import ReadableBuffer as Buffer

@overload
def decompress(data: Buffer, /, *, out_size: SupportsIndex) -> bytes: ...
@overload
def decompress(data: Buffer, /, *, max_size: SupportsIndex) -> bytes: ...
