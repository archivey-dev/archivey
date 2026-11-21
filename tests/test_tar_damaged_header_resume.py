"""A TAR member header that fails its checksum no longer ends the listing
(``openspec/changes/archive/2026-11-21-salvage-step-2-tar``).

The walk reads the damaged header from its other fields and follows its size, as the
RAR walk follows a damaged header (``tests/test_rar_damaged_header_resume.py``). It
goes on when the block there is a header that passes its checksum and has the
``ustar`` magic, or the end-of-archive marker with only zeros after it. The damaged
member is listed, each read of it reports ``MEMBER_HEADER_DAMAGED``, and the pass
still ends in ``CorruptionError``.
"""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, DiagnosticPolicy, open_archive
from archivey.diagnostics import DiagnosticCode, MemberHeaderDamageContext
from archivey.exceptions import CorruptionError, DiagnosticRaisedError, TruncatedError
from archivey.internal.backends import tar_parser
from archivey.internal.backends.rar_forward import KEEP_BYTES
from archivey.internal.backends.tar_parser import BLOCKSIZE

_SIZES = (100, 2000, 3000, 50, 0)


class _Pipe(io.RawIOBase):
    """A non-seekable source over ``data``, read in small pieces."""

    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._data.read(min(len(buffer), 4093))
        memoryview(buffer).cast("B")[: len(data)] = data
        return len(data)


def _source(data: bytes, access: str) -> object:
    if access == "pipe":
        return io.BufferedReader(_Pipe(data))
    return io.BytesIO(data)


def _content(index: int, size: int) -> bytes:
    return bytes([65 + index % 26]) * size


def _build(
    sizes: tuple[int, ...] = _SIZES,
    *,
    fmt: int = tarfile.GNU_FORMAT,
    long_names: bool = False,
) -> tuple[bytes, list[int]]:
    """A TAR of one file per size, and the offset of each member's first header."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tar:
        for index, size in enumerate(sizes):
            name = f"dir/file{index}.txt"
            if long_names:
                name = f"dir/{'n' * 120}{index}.txt"
            info = tarfile.TarInfo(name)
            info.size = size
            info.mtime = 1_700_000_000
            tar.addfile(info, io.BytesIO(_content(index, size)))
    data = buf.getvalue()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        offsets = [m.offset for m in tar.getmembers()]
    return data, offsets


def _flip(data: bytes, *offsets: int) -> bytes:
    out = bytearray(data)
    for offset in offsets:
        out[offset] ^= 0x41
    return bytes(out)


def _member_header(data: bytes, chain_start: int) -> int:
    """The offset of the member header that ends the chain starting at
    ``chain_start`` (past any extended headers)."""
    offset = chain_start
    while data[offset + 156 : offset + 157] in (b"x", b"g", b"L", b"K"):
        size = int(data[offset + 124 : offset + 136].strip(b"\0 ") or b"0", 8)
        offset += BLOCKSIZE + -(-size // BLOCKSIZE) * BLOCKSIZE
    return offset


def _read_pass(
    source: object, *, streaming: bool = False, config: ArchiveyConfig | None = None
) -> tuple[list[tuple[str, object, list[str]]], BaseException | None]:
    """Each member's name, its bytes (or the read's error type) and its stream's
    diagnostic codes, then the error that ended the pass."""
    seen: list[tuple[str, object, list[str]]] = []
    error: BaseException | None = None
    with open_archive(source, streaming=streaming, config=config) as reader:  # type: ignore[arg-type]
        try:
            for member, stream in reader.stream_members():
                if stream is None:
                    seen.append((member.name, None, []))
                    continue
                try:
                    content: object = stream.read()
                except DiagnosticRaisedError as exc:
                    content = type(exc)
                codes = [d.code.value for d in stream.diagnostics.retained]
                seen.append((member.name, content, codes))
        except CorruptionError as exc:
            error = exc
    return seen, error


def _names(
    data: bytes, access: str = "random"
) -> tuple[list[str], BaseException | None]:
    seen, error = _read_pass(_source(data, access), streaming=access != "random")
    return [name for name, _, _ in seen], error


_ALL = [f"dir/file{i}.txt" for i in range(len(_SIZES))]

# ---------------------------------------------------------------------------
# The damaged member is listed, flagged, and the walk goes on
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", [tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT])
@pytest.mark.parametrize("where", ["name_byte", "uname_byte", "checksum_field"])
@pytest.mark.parametrize("access", ["random", "streaming", "pipe"])
def test_a_damaged_member_header_is_followed_and_listed_flagged(
    where: str, access: str, fmt: int
) -> None:
    """Every member is listed, the damaged one under the name its bytes hold; only its
    read reports ``MEMBER_HEADER_DAMAGED``, and the pass ends in ``CorruptionError``
    that names the header and says the walk went on."""
    data, offsets = _build(fmt=fmt)
    header = offsets[2]
    byte = {"name_byte": 5, "uname_byte": 266, "checksum_field": 150}[where]
    damaged = _flip(data, header + byte)
    seen, error = _read_pass(_source(damaged, access), streaming=access != "random")

    assert len(seen) == len(_SIZES)
    for index, (name, content, codes) in enumerate(seen):
        assert content == _content(index, _SIZES[index])
        if index == 2:
            assert codes == ["member_header_damaged"]
            if where == "name_byte":
                assert name == "dir/f(le2.txt"
            else:
                assert name == _ALL[2]
        else:
            assert name == _ALL[index]
            assert codes == []
    assert isinstance(error, CorruptionError)
    assert not isinstance(error, TruncatedError)
    assert f"offset {header} failed its checksum" in str(error)
    assert "which the header there confirmed" in str(error)


def test_the_listing_reports_nothing_and_the_read_reports_the_damage() -> None:
    data, offsets = _build()
    damaged = _flip(data, offsets[2] + 5)
    with open_archive(io.BytesIO(damaged)) as reader:
        report = reader.members_report()
        assert len(report.members) == len(_SIZES)
        assert isinstance(report.error, CorruptionError)
        assert all(not m.diagnostics for m in report.members)
        with reader.open(report.members[2]) as stream:
            assert stream.read() == _content(2, _SIZES[2])
        found = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_HEADER_DAMAGED
        ]
    assert len(found) == 1
    context = found[0].context
    assert isinstance(context, MemberHeaderDamageContext)
    assert context.member_name == "dir/f(le2.txt"
    assert context.header_offset == offsets[2]
    assert context.volume_index is None
    assert context.format == "TAR"


@pytest.mark.parametrize("access", ["random", "streaming"])
def test_strict_refuses_the_damaged_member_only(access: str) -> None:
    data, offsets = _build()
    damaged = _flip(data, offsets[2] + 5)
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    seen, error = _read_pass(
        io.BytesIO(damaged), streaming=access == "streaming", config=strict
    )
    assert [content for _, content, _ in seen] == [
        _content(0, 100),
        _content(1, 2000),
        DiagnosticRaisedError,
        _content(3, 50),
        b"",
    ]
    assert isinstance(error, CorruptionError)


def test_extract_all_writes_every_member_then_raises(tmp_path: Path) -> None:
    data, offsets = _build()
    damaged = _flip(data, offsets[2] + 5)
    with (
        open_archive(io.BytesIO(damaged)) as reader,
        pytest.raises(CorruptionError, match="failed its checksum"),
    ):
        reader.extract_all(tmp_path)
    written = sorted(p.name for p in (tmp_path / "dir").iterdir())
    assert written == ["f(le2.txt", "file0.txt", "file1.txt", "file3.txt", "file4.txt"]


def test_a_damaged_last_member_is_confirmed_by_the_trailer() -> None:
    """The size of the last member points at the end-of-archive marker, and only
    zeros follow it to the end: that is where the archive's own trailer starts."""
    data, offsets = _build()
    damaged = _flip(data, offsets[-1] + 5)
    for access in ("random", "streaming", "pipe"):
        names, error = _names(damaged, access)
        assert names == [*_ALL[:4], "dir/f(le4.txt"], access
        assert isinstance(error, CorruptionError)


def test_a_trailer_with_data_after_it_does_not_confirm() -> None:
    """A zero block is common inside member data, so the marker confirms only when
    nothing but zeros follows it: with bytes after the trailer, the walk stops."""
    data, offsets = _build()
    damaged = _flip(data, offsets[-1] + 5) + b"x" * BLOCKSIZE
    names, error = _names(damaged)
    assert names == _ALL[:4]
    assert isinstance(error, CorruptionError)
    assert "does not parse (bad header checksum)" in str(error)


# ---------------------------------------------------------------------------
# What stops the walk as before
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("access", ["random", "streaming", "pipe"])
def test_a_damaged_size_field_stops_the_walk_as_before(access: str) -> None:
    data, offsets = _build()
    damaged = _flip(data, offsets[2] + 130)
    names, error = _names(damaged, access)
    assert names == _ALL[:2]
    assert isinstance(error, CorruptionError)
    assert f"offset {offsets[2]} does not parse (bad header checksum)" in str(error)


def test_a_damaged_magic_is_not_followed() -> None:
    """A header without the ``ustar`` magic is not followed: member data where a
    header was expected also fails its checksum, and its empty fields parse."""
    data, offsets = _build()
    damaged = _flip(data, offsets[2] + 257)
    names, error = _names(damaged)
    assert names == _ALL[:2]
    assert isinstance(error, CorruptionError)


def test_a_v7_archive_is_not_followed() -> None:
    """A v7 header has no magic, so nothing confirms a jump in a v7 archive."""
    data, offsets = _build(fmt=tarfile.USTAR_FORMAT)
    v7 = bytearray(data)
    for offset in offsets:
        v7[offset + 257 : offset + 265] = bytes(8)
        block = bytes(v7[offset : offset + BLOCKSIZE])
        v7[offset : offset + BLOCKSIZE] = tar_parser.with_fixed_checksum(block)
    damaged = _flip(bytes(v7), offsets[2] + 5)
    names, _ = _names(damaged)
    assert names == _ALL[:2]


def test_two_damaged_headers_in_a_row_are_both_followed() -> None:
    data, offsets = _build()
    damaged = _flip(data, offsets[2] + 6, offsets[3] + 5)
    seen, error = _read_pass(io.BytesIO(damaged))
    assert [codes for _, _, codes in seen] == [
        [],
        [],
        ["member_header_damaged"],
        ["member_header_damaged"],
        [],
    ]
    assert isinstance(error, CorruptionError)
    assert "; also the member header at offset" in str(error)


def test_two_damaged_headers_apart_are_both_followed() -> None:
    data, offsets = _build()
    damaged = _flip(data, offsets[1] + 6, offsets[3] + 5)
    names, error = _names(damaged)
    assert len(names) == len(_SIZES)
    assert isinstance(error, CorruptionError)


def test_eight_damaged_headers_in_a_row_are_followed_nine_are_not() -> None:
    sizes = (10,) * 11
    data, offsets = _build(sizes)
    eight = _flip(data, *(offsets[i] + 5 for i in range(1, 9)))
    names, _ = _names(eight)
    assert len(names) == 11
    nine = _flip(data, *(offsets[i] + 5 for i in range(1, 10)))
    names, error = _names(nine)
    assert names == ["dir/file0.txt"]
    assert f"offset {offsets[1]} does not parse" in str(error)


# ---------------------------------------------------------------------------
# Extended headers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT])
@pytest.mark.parametrize("access", ["random", "pipe"])
def test_a_damaged_extended_header_is_followed(fmt: int, access: str) -> None:
    """A damaged ``L`` or ``x`` header is followed by its size to the member header,
    which confirms it; the member keeps its long name (the records are not under the
    checksum) and is flagged."""
    data, offsets = _build(fmt=fmt, long_names=True)
    damaged = _flip(data, offsets[2] + 266)
    seen, error = _read_pass(_source(damaged, access), streaming=access != "random")
    assert [name for name, _, _ in seen] == [
        f"dir/{'n' * 120}{i}.txt" for i in range(len(_SIZES))
    ]
    assert seen[2][2] == ["member_header_damaged"]
    assert isinstance(error, CorruptionError)


@pytest.mark.parametrize("fmt", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT])
def test_a_damaged_member_header_after_an_extended_header(fmt: int) -> None:
    data, offsets = _build(fmt=fmt, long_names=True)
    header = _member_header(data, offsets[2])
    damaged = _flip(data, header + 266)
    seen, error = _read_pass(io.BytesIO(damaged))
    assert len(seen) == len(_SIZES)
    assert seen[2][2] == ["member_header_damaged"]
    assert isinstance(error, CorruptionError)


def test_a_damaged_extended_header_size_stops_where_it_stopped() -> None:
    data, offsets = _build(fmt=tarfile.PAX_FORMAT, long_names=True)
    damaged = _flip(data, offsets[2] + 130)
    names, error = _names(damaged)
    assert len(names) == 2
    assert isinstance(error, CorruptionError)
    assert f"offset {offsets[2]} does not parse (bad header checksum)" in str(error)


# ---------------------------------------------------------------------------
# Pipes and compressed TARs
# ---------------------------------------------------------------------------


def test_the_pipe_hold_is_the_rar_one() -> None:
    assert tar_parser._FORWARD_HOLD == KEEP_BYTES


def test_a_pipe_stops_at_a_damaged_header_past_its_held_bytes() -> None:
    """A pipe holds the span a RAR pipe holds: a damaged member larger than that
    cannot be confirmed there, and the error says to save the archive to a file."""
    sizes = (10, KEEP_BYTES + BLOCKSIZE, 10)
    data, offsets = _build(sizes)
    damaged = _flip(data, offsets[1] + 5)
    names, error = _names(damaged, "pipe")
    assert names == ["dir/file0.txt"]
    assert isinstance(error, CorruptionError)
    assert "save the archive to a file" in str(error)
    names, error = _names(damaged, "random")
    assert len(names) == 3


@pytest.mark.parametrize("access", ["random", "streaming", "pipe"])
def test_a_compressed_tar_follows_the_same_way(access: str) -> None:
    data, offsets = _build()
    damaged = gzip.compress(_flip(data, offsets[2] + 5), mtime=0)
    seen, error = _read_pass(_source(damaged, access), streaming=access != "random")
    assert [content for _, content, _ in seen] == [
        _content(i, size) for i, size in enumerate(_SIZES)
    ]
    assert seen[2][2] == ["member_header_damaged"]
    assert isinstance(error, CorruptionError)


def test_archivey_test_reads_every_member_then_fails(tmp_path: Path) -> None:
    from archivey.cli.exit_codes import EXIT_OK
    from archivey.cli.main import main

    data, offsets = _build()
    path = tmp_path / "damaged.tar"
    path.write_bytes(_flip(data, offsets[2] + 5))
    out, err = io.StringIO(), io.StringIO()
    assert main(["test", str(path)], out=out, err=err) != EXIT_OK
    text = out.getvalue() + err.getvalue()
    assert "listed from a header that failed its checksum" in text
    assert "failed its checksum (bad header checksum)" in text


@pytest.mark.parametrize("access", ["pipe", "streaming"])
def test_many_damaged_headers_apart_on_a_forward_walk(access: str) -> None:
    """A forward-only walk replays the bytes each look ahead read. Followed damaged
    headers apart from each other (no run cap applies) must not stack those replays:
    the walk stays flat and ends in the archive's damage error."""
    count = 2500
    data, offsets = _build((10,) * count)
    damaged = _flip(data, *(offset + 5 for offset in offsets[1::2]))
    source = _source(damaged, "pipe" if access == "pipe" else "random")
    seen, error = _read_pass(source, streaming=True)
    assert len(seen) == count
    assert isinstance(error, CorruptionError)
    assert [content for _, content, _ in seen[:2]] == [_content(0, 10), _content(1, 10)]


@pytest.mark.parametrize("access", ["random", "pipe"])
def test_a_damaged_header_after_a_links_zero_span_is_not_followed(access: str) -> None:
    """A hard link whose declared blocks are all zeros, then a header that fails its
    checksum: as for any block there that is no header, the zeros are the trailer and
    the listing ends at the link, as GNU tar and ``tarfile`` read it. Following the
    damaged size would choose between that reading and a member on unchecked bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tar:
        first = tarfile.TarInfo("a.txt")
        first.size = 3
        tar.addfile(first, io.BytesIO(b"abc"))
        link = tarfile.TarInfo("link")
        link.type = tarfile.LNKTYPE
        link.linkname = "a.txt"
        link.size = 2 * BLOCKSIZE
        tar.addfile(link, io.BytesIO(bytes(2 * BLOCKSIZE)))
        last = tarfile.TarInfo("b.txt")
        last.size = 3
        tar.addfile(last, io.BytesIO(b"def"))
    data = buf.getvalue()
    last_header = 5 * BLOCKSIZE
    assert data[last_header : last_header + 5] == b"b.txt"
    seen, error = _read_pass(
        _source(_flip(data, last_header + 1), access), streaming=True
    )
    assert [(name, content) for name, content, _ in seen] == [
        ("a.txt", b"abc"),
        ("link", None),
    ]
    assert error is None
