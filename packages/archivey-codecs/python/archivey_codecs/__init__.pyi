from collections.abc import Mapping
from typing import Final

from _typeshed import ReadableBuffer as Buffer

from archivey_codecs import (
    bcj2 as bcj2,
    filters as filters,
    lzfse as lzfse,
    lzo1x as lzo1x,
    lzvn as lzvn,
    lzw as lzw,
    lzx as lzx,
    zipcrypto as zipcrypto,
)

KERNELS: Final[Mapping[str, int]]

class CodecError(ValueError): ...
class CorruptDataError(CodecError): ...
class TruncatedDataError(CodecError): ...
class UnsupportedDataError(CodecError): ...

def crc16_arc(data: Buffer, value: int = 0, /) -> int: ...
