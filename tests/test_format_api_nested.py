"""The plugin API's nested archives: ``ForwardStream.take`` and
``ReaderContext.open_nested``.

The test format, BOXES, holds archives one after another: an 8-digit length and a
one-letter kind (``T`` a tar, ``X`` a tar.xz, ``Z`` a ZIP, ``7`` a 7z), then that many bytes of the
inner archive. A length of 0 ends it. The walk lists inner archive ``n``'s members under
``n/``. Each test registers it on a registry restored afterwards (``boxes`` fixture).
"""

from __future__ import annotations

import inspect
import io
import lzma
import tarfile
import zipfile
from collections.abc import Iterator

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveMember,
    ArchiveyUsageError,
    ContainerFormat,
    CorruptionError,
    MemberType,
    PluginContainer,
    StreamFormat,
    TruncatedError,
    UnsupportedFeatureError,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
from archivey.formats import (
    ForwardStream,
    Magic,
    MemberSpan,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
    register_format,
)
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.format_adapter import (
    MAX_NESTED_DEPTH,
    _NestedData,
    _outer_copy,
    registration_scope,
)
from tests.streams_util import NonSeekableBytesIO

_KINDS = {
    b"T": ArchiveFormat.TAR,
    b"X": ArchiveFormat(ContainerFormat.TAR, StreamFormat.XZ),
    b"Z": ArchiveFormat.ZIP,
    b"7": ArchiveFormat.SEVEN_Z,
}


class BoxesContainer(PluginContainer):
    BOXES = "boxes"


class BoxesReader(SequentialReader):
    def __init__(self, context: ReaderContext) -> None:
        self._context = context

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        if stream.read_exact(5) != b"BOXES":
            raise CorruptionError("not BOXES")
        box = 0
        while True:
            size = int(stream.read_exact(8))
            if not size:
                return
            kind = _KINDS[stream.read_exact(1)]
            for span in self._context.open_nested(stream.take(size), kind):
                member = span.member
                member.name = f"{box}/{member.name}"
                if member.type is MemberType.HARDLINK and member.link_target:
                    target = self._context.normalize_name(
                        member.link_target, MemberType.FILE
                    )
                    member.link_target = f"{box}/{target}"
                yield span
            box += 1


class BoxesHandler(SequentialFormatHandler):
    format = ArchiveFormat(BoxesContainer.BOXES, StreamFormat.UNCOMPRESSED)
    magic = (Magic(0, b"BOXES"),)

    def open_sequential(self, context: ReaderContext) -> BoxesReader:
        return BoxesReader(context)


@pytest.fixture
def boxes() -> Iterator[None]:
    with registration_scope():
        register_format(BoxesHandler)
        yield


def _tar(
    members: list[tuple[str, bytes]], *, xz: bool = False, raw: bool = False
) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if name.endswith("@link"):
                info.name = name.removesuffix("@link")
                info.type = tarfile.LNKTYPE
                info.linkname = data.decode()
                tar.addfile(info)
                continue
            info.size = len(data)
            info.mtime = 1_700_000_000
            tar.addfile(info, io.BytesIO(data))
    data = out.getvalue()
    return lzma.compress(data) if xz else data


def _zip() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("z.txt", b"zip")
    return out.getvalue()


def _boxes(*inner: tuple[bytes, bytes], tail: bytes = b"00000000") -> bytes:
    return (
        b"BOXES"
        + b"".join(b"%08d" % len(data) + kind + data for kind, data in inner)
        + tail
    )


_TWO = _boxes(
    (b"T", _tar([("./etc/conf", b"conf"), ("./etc/hard@link", b"./etc/conf")])),
    (b"X", _tar([("./usr/bin/x", b"x" * 5000), ("./usr/share/y", b"y")], xz=True)),
)
_LISTED = {
    "0/etc/conf": (MemberType.FILE, b"conf"),
    "0/etc/hard": (MemberType.HARDLINK, None),
    "1/usr/bin/x": (MemberType.FILE, b"x" * 5000),
    "1/usr/share/y": (MemberType.FILE, b"y"),
}


@pytest.mark.usefixtures("boxes")
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_inner_members_are_listed_and_read_in_one_pass(pipe: bool) -> None:
    source = NonSeekableBytesIO(_TWO) if pipe else io.BytesIO(_TWO)
    with open_archive(source, format=BoxesHandler.format, streaming=True) as reader:
        listed = {
            member.name: (member.type, stream.read() if stream else None)
            for member, stream in reader.stream_members()
        }
        assert not reader.diagnostics.retained
    assert listed == _LISTED


@pytest.mark.usefixtures("boxes")
def test_inner_members_open_in_any_order() -> None:
    """Random access: an inner member's data is reached again by walking the outer
    archive, and the inner one, from the start."""
    with open_archive(io.BytesIO(_TWO), format=BoxesHandler.format) as reader:
        members = reader.members()
        assert [m.name for m in members] == list(_LISTED)
        assert [m._member_id for m in members] == [0, 1, 2, 3]
        assert reader.read("1/usr/share/y") == b"y"
        assert reader.read("0/etc/conf") == b"conf"
        assert reader.read("1/usr/bin/x") == b"x" * 5000
        hard = members[1]
        assert hard.link_target == "0/etc/conf"


@pytest.mark.usefixtures("boxes")
def test_an_inner_report_names_the_member_as_the_outer_listing_numbers_it() -> None:
    """A TAR header with an unknown type flag, the third member listed: the inner
    reader counts it as its first, and the report says 2."""
    inner = bytearray(_tar([("odd", b"data")]))
    inner[156:157] = b"Q"
    checksum = sum(inner[:148]) + 8 * 32 + sum(inner[156:512])
    inner[148:156] = b"%06o\0 " % checksum
    data = _boxes((b"T", _tar([("a", b"a"), ("b", b"b")])), (b"T", bytes(inner)))
    with open_archive(io.BytesIO(data), format=BoxesHandler.format) as reader:
        members = reader.members()
        retained = reader.diagnostics.retained
    assert [m.name for m in members] == ["0/a", "0/b", "1/odd"]
    unknown = [d for d in retained if d.code is DiagnosticCode.MEMBER_TYPE_UNKNOWN]
    assert len(unknown) == 1
    assert unknown[0].context.member_id == 2  # type: ignore[attr-defined]
    assert unknown[0] in members[2].diagnostics


@pytest.mark.usefixtures("boxes")
def test_names_are_checked_once_by_the_outer_listing() -> None:
    """A duplicate inside one inner archive, and one across two: each reported once."""
    data = _boxes(
        (b"T", _tar([("a", b"1"), ("a", b"2")])),
        (b"T", _tar([("a", b"3")])),
    )
    with open_archive(io.BytesIO(data), format=BoxesHandler.format) as reader:
        reader.members()
        codes = [d.code for d in reader.diagnostics.retained]
    assert codes.count(DiagnosticCode.MEMBER_NAME_DUPLICATE) == 1


@pytest.mark.usefixtures("boxes")
def test_the_walk_resumes_after_the_taken_bytes() -> None:
    """The inner tar ends before its box does: the rest of the box is skipped, and
    the walk reads the next box where it starts."""
    padded = _tar([("a", b"1")]) + b"\0" * 4096
    data = _boxes((b"T", padded), (b"T", _tar([("b", b"2")])))
    with open_archive(io.BytesIO(data), format=BoxesHandler.format) as reader:
        assert [m.name for m in reader.members()] == ["0/a", "1/b"]


@pytest.mark.usefixtures("boxes")
def test_a_cut_inner_archive_raises() -> None:
    data = _TWO[: len(_TWO) - 200]
    with (
        pytest.raises((TruncatedError, CorruptionError)),
        open_archive(io.BytesIO(data), format=BoxesHandler.format) as reader,
    ):
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()


@pytest.mark.usefixtures("boxes")
def test_a_zip_inside_is_read_forward() -> None:
    data = _boxes((b"Z", _zip()))
    with open_archive(
        NonSeekableBytesIO(data), format=BoxesHandler.format, streaming=True
    ) as reader:
        listed = {m.name: s.read() for m, s in reader.stream_members() if s}
    assert listed == {"0/z.txt": b"zip"}


@pytest.mark.usefixtures("boxes")
def test_a_format_that_needs_seeking_is_refused() -> None:
    data = _boxes((b"7", b"7z\xbc\xaf\x27\x1c" + b"\0" * 32))
    with (
        pytest.raises(UnsupportedFeatureError, match="seekable"),
        open_archive(io.BytesIO(data), format=BoxesHandler.format) as reader,
    ):
        reader.members()


def test_open_nested_outside_a_walk_is_refused() -> None:
    caught: list[BaseException] = []

    class Early(BoxesReader):
        def __init__(self, context: ReaderContext) -> None:
            super().__init__(context)
            try:
                context.open_nested(io.BytesIO(b""), ArchiveFormat.TAR)
            except ArchiveyUsageError as exc:
                caught.append(exc)

    class EarlyHandler(BoxesHandler):
        def open_sequential(self, context: ReaderContext) -> BoxesReader:
            return Early(context)

    with registration_scope():
        register_format(EarlyHandler)
        with open_archive(io.BytesIO(_TWO), format=BoxesHandler.format) as reader:
            reader.members()
    assert caught


def test_take_stream_ends_and_hands_back() -> None:
    data = io.BytesIO(b"0123456789")

    def skip(offset: int, n: int) -> None:
        data.read(n)

    forward = ForwardStream(data.read, skip)
    taken = forward.take(4)
    assert taken.read(2) == b"01"
    # The walk moves on: the rest of the taken bytes are skipped.
    assert forward.read(2) == b"45"
    assert forward.offset == 6
    with pytest.raises(ArchiveyUsageError, match="after the walk moved past"):
        taken.read()
    # A sized read after the walk moved on raises too, whatever an earlier read took.
    sized = forward.take(3)
    assert sized.read(1) == b"6"
    forward.read(1)
    with pytest.raises(ArchiveyUsageError, match="after the walk moved past"):
        sized.read(1)
    short = forward.take(10)
    with pytest.raises(TruncatedError):
        short.read()


def _nest(depth: int) -> bytes:
    """A tar inside ``depth`` BOXES layers, each naming BOXES as its inner kind."""
    data = _boxes((b"T", _tar([("a", b"a")])))
    for _ in range(depth - 1):
        data = _boxes((b"B", data))
    return data


@pytest.mark.usefixtures("boxes")
def test_nesting_is_bounded() -> None:
    """A walk that names its own format inside itself is refused past 8 levels of
    nesting, with an archivey error and not Python's recursion limit."""
    _KINDS[b"B"] = BoxesHandler.format
    try:
        # The tar is MAX_NESTED_DEPTH archives deep: read.
        with open_archive(io.BytesIO(_nest(MAX_NESTED_DEPTH))) as reader:
            names = [m.name for m in reader.members()]
        assert names == ["0/" * (MAX_NESTED_DEPTH - 1) + "0/a"]
        for depth in (MAX_NESTED_DEPTH + 1, 400):
            with (
                pytest.raises(UnsupportedFeatureError, match="nested more than 8"),
                open_archive(io.BytesIO(_nest(depth))) as reader,
            ):
                reader.members()
    finally:
        del _KINDS[b"B"]


def test_an_iterator_the_walk_keeps_is_closed_with_the_archive() -> None:
    kept: list[Iterator[MemberSpan]] = []

    class Keeper(BoxesReader):
        def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
            stream.read_exact(5 + 8 + 1)
            spans = self._context.open_nested(
                stream.take(len(_TAR_A)), ArchiveFormat.TAR
            )
            kept.append(spans)
            yield next(spans)

    class KeeperHandler(BoxesHandler):
        def open_sequential(self, context: ReaderContext) -> BoxesReader:
            return Keeper(context)

    with registration_scope():
        register_format(KeeperHandler)
        data = _boxes((b"T", _TAR_A))
        with open_archive(io.BytesIO(data), format=BoxesHandler.format) as reader:
            assert [m.name for m in reader.members()] == ["a"]
            assert inspect.getgeneratorstate(kept[0]) != inspect.GEN_CLOSED
    assert inspect.getgeneratorstate(kept[0]) == inspect.GEN_CLOSED


_TAR_A = _tar([("a", b"a"), ("b", b"b")])


def test_reports_made_while_data_is_read_reach_the_listed_member() -> None:
    """What the inner reader attaches to its member during a read is attached to the
    member the walk yielded, after the reports already there."""
    inner = ArchiveMember(name="x", type=MemberType.FILE, size=1)
    outer = _outer_copy(inner)
    earlier, later = object(), object()
    object.__setattr__(outer, "_diagnostics", (earlier,))

    class Reporting(io.BytesIO):
        def read(self, n: int | None = -1) -> bytes:
            if not inner._diagnostics:
                object.__setattr__(inner, "_diagnostics", (later,))
            return super().read(n)

    collector = DiagnosticCollector()
    data = _NestedData(Reporting(b"x"), collector, 0, inner, outer)  # type: ignore[arg-type]
    assert data.read() == b"x"
    data.close()
    assert outer._diagnostics == (earlier, later)
