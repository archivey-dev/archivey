"""TAR blocks built field by field, for tests that need a header ``tarfile`` will not
write: a bad checksum, a base-256 number, a PAX record of any length."""

from __future__ import annotations

from collections.abc import Callable

from archivey.internal.backends.tar_parser import BLOCKSIZE


def octal(value: int, width: int) -> bytes:
    return f"{value:0{width - 1}o}".encode() + b"\x00"


def block(
    name: bytes = b"f",
    *,
    size: int = 0,
    typeflag: bytes = b"0",
    magic: bytes = b"ustar\x0000",
    linkname: bytes = b"",
    prefix: bytes = b"",
    patch: Callable[[bytearray], None] | None = None,
    checksum: bool = True,
) -> bytes:
    """One header block, built field by field."""
    h = bytearray(BLOCKSIZE)
    h[0 : len(name)] = name
    h[100:108] = octal(0o644, 8)
    h[108:116] = octal(1000, 8)
    h[116:124] = octal(1000, 8)
    h[124:136] = octal(size, 12)
    h[136:148] = octal(1_700_000_000, 12)
    h[156:157] = typeflag
    h[157 : 157 + len(linkname)] = linkname
    h[257 : 257 + len(magic)] = magic
    h[345 : 345 + len(prefix)] = prefix
    if patch is not None:
        patch(h)
        assert len(h) == BLOCKSIZE, "a patch must keep the block's length"
    if checksum:
        h[148:156] = b" " * 8
        h[148:156] = f"{sum(h):06o}".encode() + b"\x00 "
    return bytes(h)


def field(start: int, end: int, value: bytes) -> Callable[[bytearray], None]:
    """A ``block`` patch writing ``value``, NUL-padded, over bytes ``start:end``."""
    assert len(value) <= end - start, (start, end, value)

    def patch(h: bytearray) -> None:
        h[start:end] = value.ljust(end - start, b"\x00")

    return patch


def data(payload: bytes) -> bytes:
    return payload + b"\x00" * (-len(payload) % BLOCKSIZE)


def pax_record(key: bytes, value: bytes) -> bytes:
    """One PAX record, its length prefix computed."""
    payload = b" " + key + b"=" + value + b"\n"
    length = len(payload) + 1
    while length != len(str(length)) + len(payload):
        length = len(str(length)) + len(payload)
    return str(length).encode() + payload


def pax(
    records: dict[str, str] | list[tuple[str, str]], *, typeflag: bytes = b"x"
) -> bytes:
    """A PAX header block and its records."""
    items = records.items() if isinstance(records, dict) else records
    body = b"".join(pax_record(key.encode(), value.encode()) for key, value in items)
    return pax_body(body, typeflag=typeflag)


def pax_body(body: bytes, *, typeflag: bytes = b"x") -> bytes:
    """A PAX header block whose data is ``body``, written as given."""
    return block(b"PaxHeader", size=len(body), typeflag=typeflag) + data(body)


END = b"\x00" * (2 * BLOCKSIZE)
