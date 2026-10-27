"""Unit tests for the native TAR header parser and walker (``tar_parser.py``).

The archives here are written by stdlib ``tarfile`` (the fixture writer for TAR) or
built block by block where only a crafted archive has the shape. The differential
tests against ``tarfile`` and GNU tar listings are in
``test_tar_parser_differential.py``.
"""

from __future__ import annotations

import io
import tarfile
from collections.abc import Callable

import pytest

from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.tar_parser import (
    BLOCKSIZE,
    HeaderBlock,
    HeaderFormat,
    NameSource,
    RejectedBlock,
    SparseFormat,
    SparseMap,
    TarEnd,
    TarEndKind,
    TarEntry,
    TarWalker,
    ZeroBlock,
    _checksum_matches,
    parse_header_block,
    parse_number,
    parse_pax_records,
    read_sparse_map_1_0,
    shown_value,
    sparse_map_0_0,
    sparse_map_0_1,
    validate_sparse_map,
)
from tests.tar_build import (
    END as _END,
    block as _block,
    data as _data,
    field as _field,
    octal as _octal,
    pax as _pax,
    pax_record as _rec,
)


def _walk(
    data: bytes, *, seekable: bool = True, budget=None
) -> tuple[list[TarEntry], TarEnd]:
    walker = TarWalker(io.BytesIO(data), seekable=seekable)
    entries = []
    while isinstance(entry := walker.next_entry(budget), TarEntry):
        entries.append(entry)
    assert walker.end is not None
    return entries, walker.end


def _tarfile_bytes(build: Callable[[tarfile.TarFile], None], **kwargs) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", **kwargs) as t:
        build(t)
    return buf.getvalue()


def _add(t: tarfile.TarFile, name: str, data: bytes = b"", **attrs) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    for key, value in attrs.items():
        setattr(info, key, value)
    t.addfile(info, io.BytesIO(data) if data else None)


# ---------------------------------------------------------------------- numbers


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        (b"0000644\x00", 0o644),
        (b"   644 \x00", 0o644),
        (b"00000000017\x00", 15),
        (b"\x00" * 8, 0),
        (b" " * 8, 0),
        (b"", 0),
        # GNU base-256: 0x80 positive, 0xFF negative, two's complement.
        (b"\x80" + (2**40).to_bytes(11, "big"), 2**40),
        (b"\xff" * 12, -1),
        (b"\xff" + b"\xff" * 10 + b"\xfe", -2),
        # As GNU tar 1.35 reads octal (``from_header``): the digits end at the first
        # NUL or blank, and the bytes after it are not read.
        (b"644\x00XYZ\x00", 0o644),
        (b"12 34\x00\x00\x00", 0o12),
        (b"12\t34\x00\x00\x00", 0o12),
        (b"\t12\x00\x00\x00\x00\x00", 0o12),
        (b"\x00\x00junk\x00\x00", 0),
        (b" \x00junk\x00\x00", 0),
        (b"12345670", 0o12345670),
        # One leading NUL is skipped: an old writer put it there when the previous
        # field overflowed.
        (b"\x0014000000000", 0o14000000000),
        (b"\x000000012", 0o12),
    ],
)
def test_parse_number(field: bytes, expected: int) -> None:
    assert parse_number(field) == expected


@pytest.mark.parametrize(
    "field",
    [
        b"12a\x00",
        b"0x12\x00",
        b"1_0\x00",
        b"+12\x00",
        b"9\x00",
        b"12X\x00\x00\x00",
        b"0000089\x00",
        # The leading NUL is skipped, never taken as the end of an empty number.
        b"\x00junk\x00\x00\x00",
        b"\xa012\x00\x00\x00\x00\x00",
    ],
)
def test_parse_number_refuses_what_is_not_octal(field: bytes) -> None:
    with pytest.raises(ValueError):
        parse_number(field)


@pytest.mark.parametrize(
    ("start", "end", "field", "value"),
    [
        (100, 108, "mode", 0o644),
        (108, 116, "uid", 0o1750),
        (124, 136, "size", 0),
        (136, 148, "mtime", 0o1234567),
    ],
)
def test_header_number_with_bytes_after_its_terminator_is_read(
    start: int, end: int, field: str, value: int
) -> None:
    """GNU tar and tarfile read a numeric field up to its NUL; the bytes after it are
    not part of the number, and a header holding them is no damage."""
    digits = f"{value:o}".encode()
    patch = _field(start, end, digits + b"\x00XYZ")
    parsed = parse_header_block(_block(patch=patch), 0)
    assert isinstance(parsed, HeaderBlock)
    assert getattr(parsed, field) == value


def test_checksum_field_with_bytes_after_its_terminator_is_read() -> None:
    """GNU tar reads the checksum field with the same rule as every other field."""

    def checksum(h: bytearray) -> None:
        h[148:156] = b" " * 8
        h[148:156] = f"{sum(h):06o}".encode() + b"\x00X"

    parsed = parse_header_block(_block(patch=checksum, checksum=False), 0)
    assert isinstance(parsed, HeaderBlock)


def test_v7_header_has_no_owner_names_or_device_numbers() -> None:
    """A v7 header ends at byte 257. GNU tar reads no uname, gname or device number
    from it, so bytes there are neither listed nor damage."""
    patch = _field(
        265,
        345,
        b"someuser\x00" + b"x" * 23 + b"grp\x00" + b"z" * 28 + b"junkjunkjunkjunk",
    )
    for typeflag in (b"0", b"3"):
        parsed = parse_header_block(
            _block(magic=b"", typeflag=typeflag, patch=patch), 0
        )
        assert isinstance(parsed, HeaderBlock)
        assert parsed.format is HeaderFormat.V7
        assert (parsed.uname, parsed.gname) == (b"", b"")
        assert (parsed.devmajor, parsed.devminor) == (None, None)


@pytest.mark.parametrize("typeflag", [b"0", b"5", b"6"])
def test_device_numbers_are_read_only_for_devices(typeflag: bytes) -> None:
    """GNU tar parses devmajor and devminor for a character or block device only; in
    any other ustar header the two fields are not read."""
    patch = _field(329, 345, b"junkjunkjunkjunk")
    parsed = parse_header_block(_block(typeflag=typeflag, patch=patch), 0)
    assert isinstance(parsed, HeaderBlock)
    assert (parsed.devmajor, parsed.devminor) == (None, None)


@pytest.mark.parametrize("typeflag", [b"3", b"4"])
def test_device_numbers_of_a_device(typeflag: bytes) -> None:
    good = _field(329, 345, _octal(5, 8) + _octal(7, 8))
    parsed = parse_header_block(_block(typeflag=typeflag, patch=good), 0)
    assert isinstance(parsed, HeaderBlock)
    assert (parsed.devmajor, parsed.devminor) == (5, 7)
    # A device number that is not a number does not reject the header: GNU tar
    # reports it and lists the device. The header names the fault and keeps neither.
    for bad, field in (
        (_octal(5, 8) + b"junkjunk", "devminor"),
        (b"junkjunk" + _octal(7, 8), "devmajor"),
    ):
        parsed = parse_header_block(
            _block(typeflag=typeflag, patch=_field(329, 345, bad)), 0
        )
        assert isinstance(parsed, HeaderBlock)
        assert (parsed.devmajor, parsed.devminor) == (None, None)
        assert parsed.device_number_fault is not None
        assert field in parsed.device_number_fault


# ------------------------------------------------------------------ header blocks


def test_zero_block() -> None:
    assert parse_header_block(bytes(BLOCKSIZE), 1024) == ZeroBlock(1024)


@pytest.mark.parametrize(
    ("block", "reason"),
    [
        (_block(checksum=False), "bad header checksum"),
        (
            _block(
                patch=lambda h: h.__setitem__(slice(148, 156), b"0001234\x00"),
                checksum=False,
            ),
            "bad header checksum",
        ),
        (
            _block(
                patch=lambda h: h.__setitem__(slice(124, 136), b"12z4\x00" + bytes(7))
            ),
            "the size field is not a number",
        ),
        (
            _block(patch=lambda h: h.__setitem__(slice(124, 136), b"\xff" * 12)),
            "negative size -1",
        ),
        (b"\xff" * BLOCKSIZE, "bad header checksum"),
    ],
)
def test_rejected_blocks(block: bytes, reason: str) -> None:
    parsed = parse_header_block(block, 0)
    assert parsed == RejectedBlock(0, reason)


def test_signed_checksum_is_accepted() -> None:
    """Old Sun tar summed the block as signed bytes; GNU tar accepts either sum."""
    name = b"\xe9t\xe9"  # bytes >= 0x80 make the two sums differ

    def signed(h: bytearray) -> None:
        h[0:3] = name
        h[148:156] = b" " * 8
        total = sum(b - 256 if b >= 0x80 else b for b in h)
        h[148:156] = f"{total:06o}".encode() + b"\x00 "

    parsed = parse_header_block(_block(patch=signed, checksum=False), 0)
    assert isinstance(parsed, HeaderBlock)
    assert parsed.name == name


@pytest.mark.parametrize("fill", [0x00, 0x01, 0x7F, 0x80, 0xFF])
def test_checksum_sum_is_exact_for_any_byte_values(fill: int) -> None:
    """The block sum behind the checksum check is exact even when every byte is at
    its largest, where a half block sums closest to the Adler-32 modulus it is
    computed with. Summing whole 512-byte blocks (``_SUM_PIECE = 512``) fails the
    0xFF case: 128 776 is past the modulus."""
    block = bytearray([fill]) * BLOCKSIZE
    block[148:156] = b" " * 8
    unsigned = sum(block)
    assert _checksum_matches(bytes(block), unsigned)
    assert not _checksum_matches(bytes(block), unsigned + 1)
    assert not _checksum_matches(bytes(block), unsigned - 1)


def test_header_layouts() -> None:
    ustar = parse_header_block(_block(b"name", prefix=b"some/dir"), 0)
    assert isinstance(ustar, HeaderBlock)
    assert (ustar.format, ustar.name) == (HeaderFormat.USTAR, b"some/dir/name")
    # Old GNU has no prefix: its bytes 345.. hold atime, ctime and sparse slots.
    gnu = parse_header_block(
        _block(b"name", magic=b"ustar  \x00", prefix=b"00000000001"), 0
    )
    assert isinstance(gnu, HeaderBlock)
    assert (gnu.format, gnu.name) == (HeaderFormat.GNU, b"name")
    v7 = parse_header_block(_block(b"name", magic=b"", prefix=b"junk"), 0)
    assert isinstance(v7, HeaderBlock)
    assert (v7.format, v7.name) == (HeaderFormat.V7, b"name")


# ---------------------------------------------------------------------- PAX records


def test_pax_records_with_padding() -> None:
    data = _rec(b"path", b"abc") + _rec(b"a", b"\xff\xfe") + b"\x00" * 20
    records = parse_pax_records(data, binary_default=False)
    assert [(k, v.value, v.binary) for k, v in records.values.items()] == [
        (b"path", b"abc", False),
        (b"a", b"\xff\xfe", False),
    ]


def test_pax_repeated_key_keeps_its_last_value() -> None:
    data = _rec(b"a", b"1") + _rec(b"a", b"2") + _rec(b"b", b"3")
    records = parse_pax_records(data, binary_default=False).values
    assert {k: v.value for k, v in records.items()} == {b"a": b"2", b"b": b"3"}


def test_pax_hdrcharset_binary_marks_the_block() -> None:
    data = _rec(b"hdrcharset", b"BINARY") + _rec(b"path", b"abc")
    records = parse_pax_records(data, binary_default=False).values
    assert all(v.binary for v in records.values())
    records = parse_pax_records(b"12 path=abc\n", binary_default=True).values
    assert records[b"path"].binary


@pytest.mark.parametrize(
    "data",
    [
        b"13 path=abc\n",  # length one past the record
        b"11 path=abc\n",  # length one short
        b"4 x=\n",  # shorter than any record
        b"x path=abc\n",
        b"12 pathabc\nX",  # no "="
        b"6 =ab\n",  # no key
        b"99 path=abc\n",  # runs past the data
    ],
)
def test_pax_records_refuse_bad_framing(data: bytes) -> None:
    with pytest.raises(CorruptionError):
        parse_pax_records(data, binary_default=False)


# ---------------------------------------------------------------------- sparse maps


def _never(nbytes: int, what: str) -> None:
    raise AssertionError("charged")


def _budget(limit: int) -> Callable[[int, str], None]:
    left = [limit]

    def charge(nbytes: int, what: str) -> None:
        if nbytes > left[0]:
            raise ResourceLimitError(f"{what} {nbytes} > {left[0]}")
        left[0] -= nbytes

    return charge


def test_sparse_0_1() -> None:
    sparse = sparse_map_0_1(b"0,5,100,3", "f", _budget(48))
    assert (list(sparse.offsets), list(sparse.lengths)) == ([0, 100], [5, 3])
    with pytest.raises(ResourceLimitError):
        sparse_map_0_1(b"0,5,100,3", "f", _budget(47))
    with pytest.raises(CorruptionError):
        sparse_map_0_1(b"0,5,100", "f", _budget(100))
    with pytest.raises(CorruptionError):
        sparse_map_0_1(b"0,5,-1,3", "f", _budget(100))


_PAST_ANY_FILE = str(2**63).encode()


def test_sparse_numbers_past_any_file_are_damage() -> None:
    largest = str(2**63 - 1).encode()
    assert list(sparse_map_0_1(b"0," + largest, "f", _budget(10**6)).lengths) == [
        2**63 - 1
    ]
    for value in (_PAST_ANY_FILE, b"9" * 20):
        with pytest.raises(CorruptionError, match=r"has \d+, past any file"):
            sparse_map_0_1(b"0," + value, "f", _budget(10**6))
        records = parse_pax_records(
            _rec(b"GNU.sparse.offset", value) + _rec(b"GNU.sparse.numbytes", b"0"),
            binary_default=False,
        )
        with pytest.raises(CorruptionError, match=r"has \d+, past any file"):
            sparse_map_0_0(
                records.sparse_offsets, records.sparse_numbytes, "f", _budget(10**6)
            )
        map_text = _data(b"1\n0\n" + value + b"\n")
        with pytest.raises(CorruptionError, match=r"has \d+, past any file"):
            read_sparse_map_1_0(_reader(map_text), BLOCKSIZE, "f", _budget(10**6))


def test_sparse_0_1_is_charged_before_it_is_parsed() -> None:
    """A map of 100 000 entries is refused from its comma count alone."""
    value = b",".join([b"1"] * 200_000)
    with pytest.raises(ResourceLimitError):
        sparse_map_0_1(value, "f", _budget(1024))


def test_sparse_0_0() -> None:
    records = parse_pax_records(
        _rec(b"GNU.sparse.offset", b"0")
        + _rec(b"GNU.sparse.numbytes", b"5")
        + _rec(b"GNU.sparse.offset", b"100")
        + _rec(b"GNU.sparse.numbytes", b"3"),
        binary_default=False,
    )
    offsets, lengths = records.sparse_offsets, records.sparse_numbytes
    sparse = sparse_map_0_0(offsets, lengths, "f", _budget(48))
    assert (list(sparse.offsets), list(sparse.lengths)) == ([0, 100], [5, 3])
    with pytest.raises(CorruptionError):
        sparse_map_0_0(offsets, lengths[:1], "f", _budget(48))


def test_sparse_0_0_holds_one_number_per_record() -> None:
    records = parse_pax_records(
        _rec(b"GNU.sparse.offset", b"1,2") + _rec(b"GNU.sparse.numbytes", b"3"),
        binary_default=False,
    )
    with pytest.raises(CorruptionError):
        sparse_map_0_0(
            records.sparse_offsets, records.sparse_numbytes, "f", _budget(10**6)
        )


def test_sparse_map_refuses_an_entry_too_large_to_store() -> None:
    with pytest.raises(CorruptionError):
        SparseMap.from_pairs([0, 2**63])


def _reader(data: bytes) -> Callable[[int], bytes]:
    return io.BytesIO(data).read


def test_sparse_1_0() -> None:
    map_text = _data(b"2\n0\n5\n100\n3\n")
    sparse, used = read_sparse_map_1_0(
        _reader(map_text + b"abcdexyz"), len(map_text) + 8, "f", _budget(48)
    )
    assert (list(sparse.offsets), list(sparse.lengths), used) == (
        [0, 100],
        [5, 3],
        BLOCKSIZE,
    )


def test_sparse_1_0_map_over_several_blocks() -> None:
    entries = 200
    text = (
        f"{entries}\n" + "".join(f"{i * 1000}\n7\n" for i in range(entries))
    ).encode()
    map_text = _data(text)
    assert len(map_text) > BLOCKSIZE
    sparse, used = read_sparse_map_1_0(
        _reader(map_text), len(map_text), "f", _budget(10**6)
    )
    assert len(sparse) == entries and used == len(map_text)


@pytest.mark.parametrize(
    ("data", "stored", "error"),
    [
        (_data(b"1\n" + b"9" * 21 + b"\n5\n"), BLOCKSIZE, CorruptionError),  # 21 digits
        (_data(b"1" * 600), 2 * BLOCKSIZE, CorruptionError),  # a number with no end
        (_data(b"2\n0\n5\n"), BLOCKSIZE, CorruptionError),  # map runs past the data
        (b"2\n0\n5\n", BLOCKSIZE, TruncatedError),  # archive ends inside the map
        (_data(b"1\nx\n5\n"), BLOCKSIZE, CorruptionError),
    ],
)
def test_sparse_1_0_refusals(data: bytes, stored: int, error: type[Exception]) -> None:
    with pytest.raises(error):
        read_sparse_map_1_0(_reader(data), stored, "f", _budget(10**6))


def test_sparse_1_0_is_charged_from_its_count() -> None:
    with pytest.raises(ResourceLimitError):
        read_sparse_map_1_0(_reader(_data(b"1000000\n")), BLOCKSIZE, "f", _budget(1024))


def _map(*pairs: int) -> SparseMap:
    return SparseMap.from_pairs(list(pairs))


@pytest.mark.parametrize(
    ("sparse", "size", "stored", "error"),
    [
        (_map(0, 5, 100, 3, 200, 0), 200, 8, None),
        (_map(), 0, 0, None),
        (
            _map(0, 5, 0, 0, 100, 3),
            200,
            8,
            None,
        ),  # an empty entry is never out of order
        (_map(0, -5), 200, 0, CorruptionError),
        (_map(190, 20), 200, 20, CorruptionError),  # past the logical size
        (_map(0, 5), 200, 6, CorruptionError),  # a stored byte nothing names
        (_map(0, 5), 200, 4, CorruptionError),  # claims more than is stored
        (_map(100, 3, 0, 5), 200, 8, UnsupportedFeatureError),  # out of order
        (_map(0, 5, 3, 5), 200, 10, UnsupportedFeatureError),  # overlapping
        (_map(100, 3, 0, 5), 200, 9, CorruptionError),  # damage outranks order
        (_map(0, 1), 2**63, 1, CorruptionError),
    ],
)
def test_validate_sparse_map(
    sparse: SparseMap, size: int, stored: int, error: type[Exception] | None
) -> None:
    result = validate_sparse_map(sparse, size, stored, "f")
    if error is None:
        assert result is None
    else:
        assert type(result) is error


# --------------------------------------------------------------------------- walker


def test_walk_plain_members_and_their_data() -> None:
    data = _tarfile_bytes(
        lambda t: (_add(t, "a", b"hello"), _add(t, "b", b"x" * 600)),
        format=tarfile.USTAR_FORMAT,
    )
    entries, end = _walk(data)
    assert [(e.name, e.size, e.stored_size) for e in entries] == [
        (b"a", 5, 5),
        (b"b", 600, 600),
    ]
    assert entries[0].data_offset == BLOCKSIZE
    assert data[entries[1].data_offset : entries[1].data_offset + 600] == b"x" * 600
    assert end.kind is TarEndKind.ZERO_BLOCK


@pytest.mark.parametrize("seekable", [True, False])
def test_walk_ends(seekable: bool) -> None:
    one = _block(b"a", size=3) + _data(b"abc")
    assert _walk(one + _END, seekable=seekable)[1] == TarEnd(
        TarEndKind.ZERO_BLOCK, 1024
    )
    assert _walk(one, seekable=seekable)[1] == TarEnd(TarEndKind.ABSENT, 1024)
    assert _walk(one + b"\x00" * 100, seekable=seekable)[1] == TarEnd(
        TarEndKind.SHORT, 1024, observed_bytes=100
    )
    end = _walk(one + b"\xff" * BLOCKSIZE, seekable=seekable)[1]
    assert (end.kind, end.offset) == (TarEndKind.REJECTED, 1024)


@pytest.mark.parametrize("seekable", [True, False])
def test_walk_truncated_inside_member_data(seekable: bool) -> None:
    data = _block(b"a", size=2000) + b"x" * 1500
    walker = TarWalker(io.BytesIO(data), seekable=seekable)
    assert isinstance(walker.next_entry(), TarEntry)
    with pytest.raises(TruncatedError):
        walker.next_entry()


def _long_name(name: bytes) -> bytes:
    return _block(b"././@LongLink", size=len(name) + 1, typeflag=b"L") + _data(
        name + b"\x00"
    )


_DANGLING = {
    "x": _pax({"path": "b"}),
    "L": _long_name(b"b"),
    "g": _pax({"comment": "c"}, typeflag=b"g"),
}


@pytest.mark.parametrize("seekable", [True, False])
@pytest.mark.parametrize("typeflag", list(_DANGLING))
def test_extended_header_before_the_end_marker_ends_the_walk(
    seekable: bool, typeflag: str
) -> None:
    """GNU tar 1.35 lists these archives cleanly. A chain with no member names the
    header it left unused, so the reader can report it; a global header starts no
    chain."""
    one = _block(b"a", size=3) + _data(b"abc")
    extended = _DANGLING[typeflag]
    entries, end = _walk(one + extended + _END, seekable=seekable)
    assert [e.name for e in entries] == [b"a"]
    assert (end.kind, end.offset) == (TarEndKind.ZERO_BLOCK, 1024 + len(extended))
    if typeflag == "g":
        assert end.reason == ""
    else:
        assert "extended header at offset 1024" in end.reason


@pytest.mark.parametrize("seekable", [True, False])
@pytest.mark.parametrize("typeflag", ["x", "L"])
def test_extended_header_followed_by_a_block_that_is_no_header_is_rejected(
    seekable: bool, typeflag: str
) -> None:
    one = _block(b"a", size=3) + _data(b"abc")
    extended = _DANGLING[typeflag]
    entries, end = _walk(one + extended + b"\xff" * BLOCKSIZE, seekable=seekable)
    assert [e.name for e in entries] == [b"a"]
    assert (end.kind, end.offset) == (TarEndKind.REJECTED, 1024 + len(extended))
    assert "extended header at offset 1024" in end.reason


@pytest.mark.parametrize("seekable", [True, False])
def test_extended_header_at_the_end_of_the_stream_is_truncation(
    seekable: bool,
) -> None:
    with pytest.raises(TruncatedError):
        _walk(_block(b"a") + _pax({"path": "b"}), seekable=seekable)


@pytest.mark.parametrize("typeflag", [b"x", b"g"])
def test_pax_records_that_do_not_parse_reject_the_header(typeflag: bytes) -> None:
    one = _block(b"a")
    bad = _block(b"PaxHeader", size=10, typeflag=typeflag) + _data(b"99 path=x\n")
    entries, end = _walk(one + bad + _block(b"b") + _END)
    assert [e.name for e in entries] == [b"a"]
    assert (end.kind, end.offset) == (TarEndKind.REJECTED, BLOCKSIZE)


def test_walk_truncated_inside_an_extended_header() -> None:
    data = _block(b"PaxHeader", size=1000, typeflag=b"x") + b"20 path=x\n"
    with pytest.raises(TruncatedError):
        _walk(data)


def test_walk_refuses_an_offset_past_any_file() -> None:
    def huge(h: bytearray) -> None:
        h[124:136] = b"\x80" + (2**63 - 600).to_bytes(11, "big")

    data = _block(b"a", patch=huge) + _END
    walker = TarWalker(io.BytesIO(data), seekable=True)
    assert isinstance(walker.next_entry(), TarEntry)
    with pytest.raises(CorruptionError):
        walker.next_entry()


def test_pax_overrides_and_gnu_long_names() -> None:
    long = "d/" + "n" * 150
    data = _tarfile_bytes(lambda t: _add(t, long, b"x"), format=tarfile.GNU_FORMAT)
    (entry,), _ = _walk(data)
    assert (entry.name, entry.name_source) == (long.encode(), NameSource.GNU_LONG)
    data = _tarfile_bytes(
        lambda t: _add(t, long, b"x", uid=5, uname="me", pax_headers={"uid": "7"}),
        format=tarfile.PAX_FORMAT,
    )
    (entry,), _ = _walk(data)
    assert (entry.name, entry.name_source, entry.uid, entry.uname) == (
        long.encode(),
        NameSource.PAX,
        7,
        b"me",
    )


@pytest.mark.parametrize("pax_first", [True, False])
def test_pax_path_wins_over_a_gnu_long_name_in_either_order(pax_first: bool) -> None:
    """GNU tar applies the PAX records last, whichever header came first."""
    long_name = _block(b"././@LongLink", size=6, typeflag=b"L") + _data(b"gnu-n\x00")
    pax = _pax({"path": "pax-n"})
    chain = pax + long_name if pax_first else long_name + pax
    (entry,), _ = _walk(chain + _block(b"short") + _END)
    assert entry.name == b"pax-n"


def test_empty_pax_value_cancels_a_global() -> None:
    data = (
        _pax({"uname": "global"}, typeflag=b"g")
        + _block(b"a")
        + _pax({"uname": ""})
        + _block(b"b")
        + _END
    )
    a, b = _walk(data)[0]
    assert a.uname_pax is not None and a.uname_pax.value == b"global"
    assert b.uname_pax is None


def test_global_records_are_shared_until_a_global_header_changes_them() -> None:
    data = (
        _pax({"comment": "one"}, typeflag=b"g")
        + _block(b"a")
        + _block(b"b")
        + _pax({"comment": "x"})
        + _block(b"c")
        + _pax({"comment": "two"}, typeflag=b"g")
        + _block(b"d")
        + _END
    )
    a, b, c, d = _walk(data)[0]
    assert a.pax is b.pax
    assert c.pax[b"comment"].value == b"x" and c.has_own_pax
    assert d.pax[b"comment"].value == b"two"
    assert a.pax[b"comment"].value == b"one"  # the old snapshot is unchanged


def test_global_empty_value_deletes_the_key() -> None:
    data = (
        _pax({"comment": "one"}, typeflag=b"g")
        + _pax({"comment": ""}, typeflag=b"g")
        + _block(b"a")
        + _END
    )
    (entry,), _ = _walk(data)
    assert b"comment" not in entry.pax


def test_global_hdrcharset_binary_applies_to_later_members() -> None:
    data = (
        _pax({"hdrcharset": "BINARY"}, typeflag=b"g")
        + _pax({"path": "p"})
        + _block(b"a")
        + _END
    )
    (entry,), _ = _walk(data)
    assert (entry.name, entry.name_binary) == (b"p", True)


def test_a_link_name_is_kept_only_on_a_link() -> None:
    long_link = _block(b"././@LongLink", size=4, typeflag=b"K") + _data(b"tgt\x00")
    data = (
        long_link
        + _block(b"file", linkname=b"stale")
        + long_link
        + _block(b"sym", typeflag=b"2")
        + _END
    )
    file, sym = _walk(data)[0]
    assert file.linkname is None
    assert (sym.linkname, sym.linkname_source) == (b"tgt", NameSource.GNU_LONG)


def test_old_style_directory_data_is_skipped() -> None:
    """An AREGTYPE (NUL) entry named "d/" is a directory; GNU tar skips its declared
    data, so a header inside that data is not listed."""
    smuggled = _block(b"smuggled", size=0)
    data = (
        _block(b"d/", size=BLOCKSIZE, typeflag=b"\x00")
        + smuggled
        + _block(b"after")
        + _END
    )
    entries, end = _walk(data)
    assert [(e.name, e.old_style_directory) for e in entries] == [
        (b"d/", True),
        (b"after", False),
    ]
    assert end.kind is TarEndKind.ZERO_BLOCK


def test_old_style_directory_uses_the_final_name() -> None:
    long_name = _block(b"././@LongLink", size=9, typeflag=b"L") + _data(b"longdir/\x00")
    data = (
        long_name
        + _block(b"x", size=BLOCKSIZE, typeflag=b"\x00")
        + _block(b"smuggled")
        + _block(b"after")
        + _END
    )
    entries, _ = _walk(data)
    assert [e.name for e in entries] == [b"longdir/", b"after"]


@pytest.mark.parametrize("typeflag", [b"1", b"2", b"3", b"4", b"5", b"6"])
def test_types_without_a_data_area(typeflag: bytes) -> None:
    """A link, device, FIFO or directory announces no data with its size field:
    ``tarfile`` and GNU tar read the next block as a header."""
    data = _block(b"n", size=5, typeflag=typeflag) + _block(b"next") + _END
    entries, _ = _walk(data)
    assert [e.name for e in entries] == [b"n", b"next"]
    assert entries[0].stored_size == 0


def test_unknown_types_have_their_data_skipped() -> None:
    data = (
        _block(b"vol", size=5, typeflag=b"V") + _data(b"xxxxx") + _block(b"next") + _END
    )
    assert [e.name for e in _walk(data)[0]] == [b"vol", b"next"]


def test_extended_header_chain_shares_one_budget() -> None:
    """Four 300 KB PAX headers ahead of one member exceed a 1 MiB cap together."""
    chunk = "a" * 300_000
    data = b"".join(_pax({f"k{i}": chunk}) for i in range(4)) + _block(b"m") + _END
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=1048576"):
        _walk(data, budget=(1 << 20, 1 << 20))
    entries, _ = _walk(data, budget=(1 << 22, 1 << 22))
    assert len(entries) == 1


def test_extended_header_is_charged_before_it_is_read() -> None:
    """A header declaring 8 GiB over a few bytes of archive is refused, not read."""
    data = _block(b"PaxHeader", size=8 << 30, typeflag=b"x") + b"20 path=x\n"
    with pytest.raises(ResourceLimitError):
        _walk(data, budget=(1 << 20, 1 << 20))


def test_old_gnu_sparse_with_extension_blocks() -> None:
    chunks = [(i * 1024, 512) for i in range(30)]
    realsize = 30 * 1024

    def header(h: bytearray) -> None:
        for i, (offset, length) in enumerate(chunks[:4]):
            h[386 + 24 * i : 398 + 24 * i] = _octal(offset, 12)
            h[398 + 24 * i : 410 + 24 * i] = _octal(length, 12)
        h[482] = 1
        h[483:495] = _octal(realsize, 12)

    extension = bytearray(BLOCKSIZE)
    for i, (offset, length) in enumerate(chunks[4:25]):
        extension[24 * i : 24 * i + 12] = _octal(offset, 12)
        extension[24 * i + 12 : 24 * i + 24] = _octal(length, 12)
    extension[504] = 1
    last = bytearray(BLOCKSIZE)
    for i, (offset, length) in enumerate(chunks[25:]):
        last[24 * i : 24 * i + 12] = _octal(offset, 12)
        last[24 * i + 12 : 24 * i + 24] = _octal(length, 12)
    stored = 30 * 512
    data = (
        _block(b"sp", size=stored, typeflag=b"S", magic=b"ustar  \x00", patch=header)
        + bytes(extension)
        + bytes(last)
        + b"d" * stored
        + _block(b"after")
        + _END
    )
    (entry, after), _ = _walk(data)
    assert entry.sparse_format is SparseFormat.OLD_GNU
    assert entry.sparse is not None
    assert list(zip(entry.sparse.offsets, entry.sparse.lengths, strict=True)) == chunks
    assert (entry.size, entry.stored_size, entry.data_offset) == (
        realsize,
        stored,
        3 * BLOCKSIZE,
    )
    assert (
        validate_sparse_map(entry.sparse, entry.size, entry.stored_size, "sp") is None
    )
    assert after.name == b"after"
    with pytest.raises(ResourceLimitError):
        _walk(data, budget=(10 * 24, 10 * 24))


def test_old_gnu_extension_block_with_a_bad_number_rejects_the_header() -> None:
    """tarfile rejects the whole header on a bad extension-block number; so does the
    walk, so the reader classifies it like any rejected block."""

    def header(h: bytearray) -> None:
        h[386:398] = _octal(0, 12)
        h[398:410] = _octal(5, 12)
        h[482] = 1
        h[483:495] = _octal(10, 12)

    extension = bytearray(BLOCKSIZE)
    extension[0:12] = b"zz" + bytes(10)  # an offset that is not a number
    extension[12:24] = _octal(5, 12)
    data = (
        _block(b"a")
        + _block(b"sp", size=5, typeflag=b"S", magic=b"ustar  \x00", patch=header)
        + bytes(extension)
        + _data(b"ddddd")
        + _END
    )
    entries, end = _walk(data)
    assert [e.name for e in entries] == [b"a"]
    assert (end.kind, end.offset) == (TarEndKind.REJECTED, BLOCKSIZE)
    assert "extension block" in end.reason


def _base_256(value: int) -> bytes:
    return b"\x80" + value.to_bytes(11, "big")


def test_old_gnu_header_slot_past_any_file_rejects_the_block() -> None:
    def header(h: bytearray) -> None:
        h[386:398] = _base_256(2**70)
        h[398:410] = _octal(5, 12)
        h[483:495] = _octal(10, 12)

    block = _block(b"sp", size=5, typeflag=b"S", magic=b"ustar  \x00", patch=header)
    parsed = parse_header_block(block, 0)
    assert isinstance(parsed, RejectedBlock)


def test_old_gnu_header_slot_below_any_offset_rejects_the_block() -> None:
    def header(h: bytearray) -> None:
        h[386:398] = b"\xff" + (-(2**70) % 2**88).to_bytes(11, "big")
        h[398:410] = _octal(5, 12)
        h[483:495] = _octal(10, 12)

    block = _block(b"sp", size=5, typeflag=b"S", magic=b"ustar  \x00", patch=header)
    parsed = parse_header_block(block, 0)
    assert isinstance(parsed, RejectedBlock)


@pytest.mark.parametrize(
    "realsize",
    [b"\xff" * 12, _base_256(2**63), _base_256(2**80)],
    ids=["-1", "2**63", "2**80"],
)
def test_old_gnu_realsize_out_of_range_rejects_the_block(realsize: bytes) -> None:
    """The realsize is the member's listed size. GNU tar 1.35 refuses one outside
    off_t ("Archive value -1 is out of off_t range"); a negative one with an empty
    map would otherwise read as an empty file with no error."""

    def header(h: bytearray) -> None:
        h[483:495] = realsize

    block = _block(b"sp", typeflag=b"S", magic=b"ustar  \x00", patch=header)
    parsed = parse_header_block(block, 0)
    assert isinstance(parsed, RejectedBlock)
    assert "real size" in parsed.reason


def test_negative_sparse_size_is_damage() -> None:
    error = validate_sparse_map(SparseMap.from_pairs([]), -1, 0, "'sp'")
    assert isinstance(error, CorruptionError)


def test_old_gnu_negative_slot_that_fits_reaches_validation() -> None:
    def header(h: bytearray) -> None:
        h[386:398] = b"\xff" * 12  # -1 in base-256
        h[398:410] = _octal(5, 12)
        h[483:495] = _octal(10, 12)

    data = _block(b"sp", size=5, typeflag=b"S", magic=b"ustar  \x00", patch=header)
    (entry,), _ = _walk(data + _data(b"abcde") + _END)
    assert entry.sparse is not None
    error = validate_sparse_map(entry.sparse, entry.size, entry.stored_size, "'sp'")
    assert isinstance(error, CorruptionError)
    assert "negative entry" in str(error)


def test_old_gnu_extension_slot_past_any_file_rejects_the_header() -> None:
    def header(h: bytearray) -> None:
        h[386:398] = _octal(0, 12)
        h[398:410] = _octal(5, 12)
        h[482] = 1
        h[483:495] = _octal(10, 12)

    extension = bytearray(BLOCKSIZE)
    extension[0:12] = _base_256(2**70)
    extension[12:24] = _octal(5, 12)
    data = (
        _block(b"sp", size=5, typeflag=b"S", magic=b"ustar  \x00", patch=header)
        + bytes(extension)
        + _data(b"ddddd")
        + _END
    )
    entries, end = _walk(data)
    assert entries == []
    assert end.kind is TarEndKind.REJECTED


def test_pax_sparse_1_0_member() -> None:
    map_text = _data(b"1\n10\n3\n")
    records = {
        "GNU.sparse.major": "1",
        "GNU.sparse.minor": "0",
        "GNU.sparse.name": "real",
        "GNU.sparse.realsize": "20",
    }
    data = (
        _pax(records)
        + _block(b"GNUSparseFile.1/real", size=len(map_text) + 3)
        + map_text
        + _data(b"abc")
        + _END
    )
    (entry,), _ = _walk(data)
    assert (entry.name, entry.sparse_format, entry.size) == (
        b"real",
        SparseFormat.PAX_1_0,
        20,
    )
    # The map is read during the walk; the stored bytes are the chunks after it.
    assert entry.sparse is not None
    assert list(zip(entry.sparse.offsets, entry.sparse.lengths, strict=True)) == [
        (10, 3)
    ]
    assert (entry.data_offset, entry.stored_size) == (4 * BLOCKSIZE, 3)
    assert entry.data_end == 5 * BLOCKSIZE


def test_pax_sparse_1_0_bad_map_fails_the_walk() -> None:
    """A 1.0 map that does not parse fails the listing, as tarfile's does."""
    records = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"}
    bad = _data(b"x\n")
    data = _pax(records) + _block(b"s", size=len(bad)) + bad + _END
    for seekable in (True, False):
        with pytest.raises(CorruptionError):
            _walk(data, seekable=seekable)


def test_pax_sparse_1_0_map_is_charged_during_the_walk() -> None:
    records = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"}
    big = _data(b"1000000\n")
    data = _pax(records) + _block(b"s", size=len(big)) + big + _END
    with pytest.raises(ResourceLimitError):
        _walk(data, budget=(4096, 4096))


def _pax_1_0_member(
    major: str, minor: str, extra: dict[str, str] | None = None
) -> bytes:
    map_text = _data(b"1\n10\n3\n")
    records = {
        "GNU.sparse.major": major,
        "GNU.sparse.minor": minor,
        "GNU.sparse.name": "real",
        "GNU.sparse.realsize": "20",
        **(extra or {}),
    }
    return (
        _pax(records)
        + _block(b"GNUSparseFile.1/real", size=len(map_text) + 3)
        + map_text
        + _data(b"abc")
        + _END
    )


@pytest.mark.parametrize(("major", "minor"), [("1", "1"), ("2", "0"), ("9", "9")])
def test_pax_sparse_later_versions_read_as_1_0(major: str, minor: str) -> None:
    """GNU tar 1.35 reads any major version of 1 or more with its 1.0 reader."""
    (entry,), _ = _walk(_pax_1_0_member(major, minor))
    assert (entry.sparse_format, entry.size, entry.stored_size) == (
        SparseFormat.PAX_1_0,
        20,
        3,
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"GNU.sparse.size": "20"},
        {"GNU.sparse.map": "10,3"},
        {"GNU.sparse.offset": "10", "GNU.sparse.numbytes": "3"},
    ],
    ids=["0.0-size", "0.1-map", "0.0-map"],
)
def test_pax_sparse_major_chooses_1_0_over_0_x_records(extra: dict[str, str]) -> None:
    """The major version chooses the encoding, not which records are present: GNU
    tar 1.35 reads a member with major 1 as 1.0 whatever 0.x records it carries."""
    (entry,), _ = _walk(_pax_1_0_member("1", "0", extra))
    assert (entry.sparse_format, entry.size, entry.stored_size) == (
        SparseFormat.PAX_1_0,
        20,
        3,
    )
    assert entry.sparse is not None
    assert list(zip(entry.sparse.offsets, entry.sparse.lengths, strict=True)) == [
        (10, 3)
    ]


def test_pax_sparse_major_of_many_digits_reads_as_1_0() -> None:
    """A major past Python's int() digit limit is still a version of 1 or more."""
    (entry,), _ = _walk(_pax_1_0_member("0" * 5000 + "1", "0"))
    assert entry.sparse_format is SparseFormat.PAX_1_0


@pytest.mark.parametrize("major", ["0", "x", ""])
def test_pax_sparse_version_with_no_map_is_damage(major: str) -> None:
    """GNU tar refuses these, the empty value included. Serving the member as a
    plain file would hand the map blocks out as its content."""
    with pytest.raises(CorruptionError):
        _walk(_pax_1_0_member(major, "0"))


def _pax_1_0_member_without_major(records: dict[str, str]) -> bytes:
    map_text = _data(b"1\n10\n3\n")
    return (
        _pax({"GNU.sparse.name": "real", **records})
        + _block(b"GNUSparseFile.1/real", size=len(map_text) + 3)
        + map_text
        + _data(b"abc")
        + _END
    )


def test_pax_sparse_realsize_without_a_major_is_damage() -> None:
    """A realsize declares a 1.0 member's logical size; with no major the map
    cannot be read, and GNU tar fails on the member."""
    with pytest.raises(CorruptionError):
        _walk(_pax_1_0_member_without_major({"GNU.sparse.realsize": "20"}))


_LONG_NUMBER = "1" * 5000  # past CPython's 4300-digit int() limit


@pytest.mark.parametrize("key", ["size", "GNU.sparse.size", "GNU.sparse.major"])
def test_pax_number_past_any_file_is_damage(key: str) -> None:
    """A PAX number of thousands of digits is CorruptionError, not the builtin
    ValueError that ``int()`` raises past ``sys.int_max_str_digits``. GNU tar
    reports it out of range."""
    records = {key: _LONG_NUMBER}
    if key == "GNU.sparse.size":
        records["GNU.sparse.map"] = "0,0"
    data = _pax(records) + _block(b"a") + _END
    with pytest.raises(CorruptionError):
        _walk(data)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"\xff\xfe12abcd", r"'\xff\xfe12abcd'"),
        (b"junk\x00\x00", r"'junk\x00\x00'"),
        (b"\x81junkju\x00", r"'\x81junkju\x00'"),
        (b"1" * 41, "'" + "1" * 40 + "...'"),
        (b"\xff" * 41, "'" + r"\xff" * 40 + "...'"),
        ("abc", "'abc'"),
        ("9" * 41, "'" + "9" * 40 + "...'"),
    ],
)
def test_shown_value_escapes_each_byte_once(value: bytes | str, expected: str) -> None:
    """One escape per byte, whatever the byte is, and the cut marked inside the
    quotes: a reader can tell the archive's bytes from the escape and a cut value
    from a whole one."""
    assert shown_value(value) == expected


def test_long_sparse_major_is_cut_in_the_message() -> None:
    data = _pax({"GNU.sparse.major": "0" * 5000}) + _block(b"a") + _END
    with pytest.raises(CorruptionError, match=r"major version '0{40}\.\.\.' and no"):
        _walk(data)


def test_pax_size_past_max_offset_is_damage() -> None:
    """A 20-digit PAX size is a number ``_pax_decimal`` reads; past 2**63 - 1 it is
    no file's size, and the message quotes the value with the cut inside the
    quotes."""
    with pytest.raises(CorruptionError, match=f"PAX size '{2**63}' .* past any file"):
        _walk(_pax({"size": str(2**63)}) + _block(b"a") + _END)
    with pytest.raises(CorruptionError, match=r"'1{40}\.\.\.'"):
        _walk(_pax({"size": _LONG_NUMBER}) + _block(b"a") + _END)


@pytest.mark.parametrize("key", ["uid", "gid"])
@pytest.mark.parametrize(
    "value", [_LONG_NUMBER, "9" * 21, "9" * 20, str(2**32)], ids=lambda v: v[:12]
)
def test_pax_id_out_of_range_keeps_the_header_value(key: str, value: str) -> None:
    """Past 2**32 - 1, uid_t's range, GNU tar 1.35 reports the id ("out of range
    0..4294967295") and keeps the header's, as for an id that is not a number."""
    (entry,), _ = _walk(_pax({key: value}) + _block(b"a") + _END)
    assert (entry.uid, entry.gid) == (1000, 1000)


@pytest.mark.parametrize("key", ["uid", "gid"])
def test_largest_pax_id_is_read(key: str) -> None:
    (entry,), _ = _walk(_pax({key: str(2**32 - 1)}) + _block(b"a") + _END)
    assert getattr(entry, key) == 2**32 - 1


def test_pax_numbers_may_have_leading_zeros() -> None:
    """GNU tar reads PAX numbers with strtoumax: leading zeros do not count."""
    zeros = "0" * 30
    data = (
        _pax({"size": zeros + "3", "uid": zeros + "7"}) + _block(b"a") + _data(b"abc")
    )
    (entry,), _ = _walk(data + _END)
    assert (entry.stored_size, entry.uid) == (3, 7)


def test_pax_sparse_minor_alone_reads_as_a_plain_member() -> None:
    """GNU tar lists a member with only a minor record as a plain file, exit 0."""
    (entry,), _ = _walk(_pax_1_0_member_without_major({"GNU.sparse.minor": "0"}))
    assert (entry.sparse_format, entry.sparse) == (None, None)


@pytest.mark.parametrize(
    "records",
    [
        {"GNU.sparse.realsize": "20"},
        {"GNU.sparse.size": "20"},
        {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"},
        {"GNU.sparse.map": "0,3"},
    ],
)
def test_global_sparse_records_make_no_member_sparse(records: dict[str, str]) -> None:
    """A map describes one member's data area, so a global sparse record leaves the
    plain members after it plain, and the walk goes on. GNU tar 1.35 lists both."""
    data = (
        _pax(records, typeflag=b"g")
        + _block(b"a", size=3)
        + _data(b"abc")
        + _block(b"b", size=3)
        + _data(b"xyz")
        + _END
    )
    entries, _ = _walk(data)
    assert [(e.name, e.sparse_format, e.stored_size) for e in entries] == [
        (b"a", None, 3),
        (b"b", None, 3),
    ]


def _pax_0_x_member(records: dict[str, str]) -> bytes:
    """A PAX 0.0 or 0.1 member whose 20-byte file holds ``abc`` at offset 10."""
    return (
        _pax({"GNU.sparse.name": "real", **records})
        + _block(b"GNUSparseFile.1/real", size=3)
        + _data(b"abc")
        + _END
    )


_PAX_0_0 = {
    "GNU.sparse.size": "20",
    "GNU.sparse.numblocks": "1",
    "GNU.sparse.offset": "10",
    "GNU.sparse.numbytes": "3",
}
_PAX_0_1 = {
    "GNU.sparse.size": "20",
    "GNU.sparse.numblocks": "1",
    "GNU.sparse.map": "10,3",
}


@pytest.mark.parametrize(
    ("records", "sparse_format"),
    [(_PAX_0_0, SparseFormat.PAX_0_0), (_PAX_0_1, SparseFormat.PAX_0_1)],
    ids=["0.0", "0.1"],
)
def test_pax_sparse_0_x_is_detected(
    records: dict[str, str], sparse_format: SparseFormat
) -> None:
    (entry,), _ = _walk(_pax_0_x_member(records))
    assert (entry.name, entry.sparse_format, entry.size, entry.stored_size) == (
        b"real",
        sparse_format,
        20,
        3,
    )
    assert entry.sparse is not None
    assert (list(entry.sparse.offsets), list(entry.sparse.lengths)) == ([10], [3])


def test_pax_sparse_0_1_empty_map_is_damage() -> None:
    """An empty map record is damage, as GNU tar reports it; read as a plain file,
    the member would serve its compacted data as the content."""
    with pytest.raises(CorruptionError):
        _walk(_pax_0_x_member({**_PAX_0_1, "GNU.sparse.map": ""}))


@pytest.mark.parametrize(
    "records",
    [
        {**_PAX_0_0, "GNU.sparse.size": ""},
        {k: v for k, v in _PAX_0_0.items() if k != "GNU.sparse.size"},
    ],
    ids=["size-empty", "size-absent"],
)
def test_pax_sparse_0_0_without_a_size_is_refused(records: dict[str, str]) -> None:
    """The offset records make the member sparse, so it is never read as a plain
    file; the map then ends past the logical size of 0, which is damage."""
    (entry,), _ = _walk(_pax_0_x_member(records))
    assert (entry.sparse_format, entry.size) == (SparseFormat.PAX_0_0, 0)
    assert entry.sparse is not None
    error = validate_sparse_map(entry.sparse, entry.size, entry.stored_size, "'real'")
    assert isinstance(error, CorruptionError)


def test_sparse_records_on_a_type_without_data_make_no_sparse_member() -> None:
    records = {
        "GNU.sparse.major": "1",
        "GNU.sparse.minor": "0",
        "GNU.sparse.name": "real",
        "GNU.sparse.realsize": "20",
    }
    (entry,), _ = _walk(_pax(records) + _block(b"d", typeflag=b"5") + _END)
    assert (entry.name, entry.sparse_format, entry.sparse) == (b"real", None, None)


@pytest.mark.parametrize("seekable", [True, False])
def test_the_walk_stays_failed_after_an_error(seekable: bool) -> None:
    records = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"}
    bad = _data(b"x\n")
    data = _block(b"a") + _pax(records) + _block(b"s", size=len(bad)) + bad + _END
    walker = TarWalker(io.BytesIO(data), seekable=seekable)
    assert isinstance(walker.next_entry(), TarEntry)
    for _ in range(2):
        with pytest.raises(CorruptionError):
            walker.next_entry()


def test_bad_pax_size_is_damage() -> None:
    with pytest.raises(CorruptionError):
        _walk(_pax({"size": "12x"}) + _block(b"a") + _END)


def test_forward_only_data_stream() -> None:
    data = _tarfile_bytes(lambda t: (_add(t, "a", b"hello"), _add(t, "b", b"world")))
    walker = TarWalker(io.BytesIO(data), seekable=False)
    a = walker.next_entry()
    assert isinstance(a, TarEntry)
    stream = walker.open_data(a.span())
    assert stream.read(2) == b"he"
    b = walker.next_entry()  # reads through the rest of "a"
    assert isinstance(b, TarEntry)
    with pytest.raises(ValueError):
        stream.read()
    assert walker.open_data(b.span()).read() == b"world"


def test_numeric_field_split_matches_the_field_table() -> None:
    # parse_header_block cuts the numeric fields with one struct unpack; it must cut
    # the same bytes as the _FIELDS table the error message reads.
    from archivey.internal.backends import tar_parser

    block = bytes(i % 251 for i in range(BLOCKSIZE))
    assert tar_parser._split_numbers(block) == tuple(
        block[start:end] for _, start, end in tar_parser._FIELDS
    )


@pytest.mark.parametrize(
    ("field", "start", "end"),
    [
        ("mode", 100, 108),
        ("uid", 108, 116),
        ("gid", 116, 124),
        ("size", 124, 136),
        ("mtime", 136, 148),
    ],
)
def test_each_bad_numeric_field_is_named(field: str, start: int, end: int) -> None:
    def spoil(h: bytearray) -> None:
        h[start:end] = b"9" + bytes(end - start - 1)  # 9 is not an octal digit

    parsed = parse_header_block(_block(patch=spoil), 0)
    assert isinstance(parsed, RejectedBlock)
    assert parsed.reason == f"the {field} field is not a number"


def test_number_cache_is_bounded_and_agrees_with_the_parse() -> None:
    from archivey.internal.backends import tar_parser

    cache = tar_parser._cached_number
    cache.cache_clear()
    maxsize = cache.cache_info().maxsize
    assert maxsize is not None
    for i in range(maxsize * 2):
        mtime = 1_600_000_000 + i
        block = _block(
            patch=lambda h, t=mtime: h.__setitem__(slice(136, 148), _octal(t, 12))
        )
        parsed = parse_header_block(block, 0)
        assert isinstance(parsed, HeaderBlock)
        assert parsed.mtime == mtime
    assert cache.cache_info().currsize <= maxsize
