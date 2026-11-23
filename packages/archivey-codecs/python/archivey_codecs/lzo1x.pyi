from typing import SupportsIndex, overload

from _typeshed import ReadableBuffer as Buffer

@overload
def decompress(block: Buffer, /, *, out_size: SupportsIndex) -> bytes: ...
@overload
def decompress(block: Buffer, /, *, max_size: SupportsIndex) -> bytes: ...
