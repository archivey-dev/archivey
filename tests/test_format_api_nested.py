"""The plugin API's nested archives: ``ForwardStream.take`` and
``ReaderContext.open_nested``.

The test format, BOXES, holds archives one after another: an 8-digit length and a
one-letter kind (``T`` a tar, ``X`` a tar.xz, ``Z`` a ZIP, ``7`` a 7z), then that many bytes of the
inner archive. A length of 0 ends it. The walk lists inner archive ``n``'s members under
``n/``. Each test registers it on a registry restored afterwards (``boxes`` fixture).
"""

from __future__ import annotations

import gzip
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
    ArchiveyConfig,
    ArchiveyUsageError,
    Budget,
    CompressionAlgorithm,
    ContainerFormat,
    CorruptionError,
    DecoderLimits,
    FormatPolicy,
    ListingLimits,
    MemberType,
    PluginContainer,
    PluginStream,
    ResourceLimitError,
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
from archivey.internal import format_adapter
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.format_adapter import (
    MAX_NESTED_DEPTH,
    _NestedData,
    _outer_copy,
    _Primed,
    registration_scope,
)
from archivey.internal.listing_limits import ListingLimitTracker
from tests.streams_util import (
    NonSeekableBytesIO,
    hold_views,
    lzma_alone_with_filter,
)

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
                    # As the inner archive stores it: archivey normalizes it.
                    member.link_target = f"{box}/{member.link_target}"
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


def test_a_zero_byte_read_or_skip_leaves_an_open_take_alone() -> None:
    data = io.BytesIO(b"0123456789")

    def skip(offset: int, n: int) -> None:
        data.read(n)

    forward = ForwardStream(data.read, skip)
    taken = forward.take(4)
    assert forward.read(0) == b""
    assert forward.read_exact(0) == b""
    forward.skip(0)
    assert forward.offset == 0
    assert taken.read() == b"0123"
    assert forward.read(1) == b"4"


class LinksInDataBoxesReader(BoxesReader):
    """BOXES, but a symlink's target is its data, as CPIO stores it."""

    link_target_in_data = True


class LinksInDataBoxesContainer(PluginContainer):
    LINKS_IN_DATA_BOXES = "links-in-data-boxes"


class LinksInDataBoxesHandler(BoxesHandler):
    format = ArchiveFormat(
        LinksInDataBoxesContainer.LINKS_IN_DATA_BOXES, StreamFormat.UNCOMPRESSED
    )
    magic = ()

    def open_sequential(self, context: ReaderContext) -> BoxesReader:
        return LinksInDataBoxesReader(context)


def _tar_with_empty_symlink() -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.GNU_FORMAT) as tar:
        link = tarfile.TarInfo("sym")
        link.type = tarfile.SYMTYPE
        tar.addfile(link)
        after = tarfile.TarInfo("after.txt")
        after.size = 5
        tar.addfile(after, io.BytesIO(b"after"))
    return out.getvalue()


def test_an_inner_symlink_with_no_target_does_not_end_the_inner_walk() -> None:
    """An outer format whose links keep their target in the data, and an inner TAR
    symlink with an empty target: the span has no data to read the target from, and
    the walk goes on to the inner archive's next member."""
    data = _boxes((b"T", _tar_with_empty_symlink()), (b"T", _tar([("b", b"b")])))
    with registration_scope():
        register_format(LinksInDataBoxesHandler)
        with open_archive(
            io.BytesIO(data), format=LinksInDataBoxesHandler.format
        ) as reader:
            listed = {
                member.name: (member.type, member.link_target, s.read() if s else None)
                for member, s in reader.stream_members()
            }
            retained = reader.diagnostics.retained
    assert listed == {
        "0/sym": (MemberType.SYMLINK, None, None),
        "0/after.txt": (MemberType.FILE, None, b"after"),
        "1/b": (MemberType.FILE, None, b"b"),
    }
    empty = [d for d in retained if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE]
    assert len(empty) == 1


class NestedCodec(PluginStream):
    NESTED = "nested-codec"


@pytest.mark.usefixtures("boxes")
@pytest.mark.parametrize(
    ("inner", "what"),
    [
        (BoxesHandler.format, "plugin format"),
        # Refused before the reader lookup, so the codec need not be registered.
        (ArchiveFormat(ContainerFormat.TAR, NestedCodec.NESTED), "plugin codec"),
    ],
    ids=["container", "codec"],
)
def test_a_plugin_format_inside_is_refused_under_plugins_false(
    monkeypatch: pytest.MonkeyPatch, inner: ArchiveFormat, what: str
) -> None:
    """plugins=False holds for nested archives. No built-in reader calls open_nested
    yet, so the outer BOXES stands in for one: the open's own check passes it, and the
    plugin format or codec inside it is refused."""
    refusal = FormatPolicy._refusal

    def outer_allowed(self: FormatPolicy, fmt: ArchiveFormat) -> str | None:
        return None if fmt == BoxesHandler.format else refusal(self, fmt)

    monkeypatch.setattr(FormatPolicy, "_refusal", outer_allowed)
    monkeypatch.setitem(_KINDS, b"B", inner)
    data = _boxes((b"B", _boxes((b"T", _tar([("a", b"a")])))))
    if inner == BoxesHandler.format:
        with open_archive(io.BytesIO(data), format=BoxesHandler.format) as reader:
            assert [m.name for m in reader.members()] == ["0/0/a"]
    config = ArchiveyConfig(formats=FormatPolicy(plugins=False))
    with (
        pytest.raises(UnsupportedFeatureError, match=f"turns off every {what}"),
        open_archive(io.BytesIO(data), format=BoxesHandler.format, config=config) as r,
    ):
        r.members()


# One nest of archives has one budget for each limit (maintainer ruling, 2026-11-08:
# "charge across the nesting"). Each test below builds a nest of 3 levels in which
# every level alone fits the limit, and all 3 together do not.


class HoldingBoxesContainer(PluginContainer):
    HOLDING_BOXES = "holding-boxes"


class HoldingBoxesReader(BoxesReader):
    """BOXES, but the walk keeps a 400-byte name, charged with ``hold()``, until it
    ends, as a reader keeps a manifest it never yields."""

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        kept = ArchiveMember(name="m" * 400, type=MemberType.FILE)
        self._context.hold(kept, reason="manifests")
        yield from super().walk(stream)


class HoldingBoxesHandler(BoxesHandler):
    format = ArchiveFormat(
        HoldingBoxesContainer.HOLDING_BOXES, StreamFormat.UNCOMPRESSED
    )
    magic = ()

    def open_sequential(self, context: ReaderContext) -> BoxesReader:
        return HoldingBoxesReader(context)


@pytest.mark.parametrize(("limit", "refused"), [(1000, True), (1500, False)])
def test_what_inner_levels_keep_counts_against_one_metadata_budget(
    monkeypatch: pytest.MonkeyPatch, limit: int, refused: bool
) -> None:
    """3 levels keep 400 bytes each: 1200 in all, over a 1000-byte limit each level
    alone fits."""
    monkeypatch.setitem(_KINDS, b"H", HoldingBoxesHandler.format)
    data = _boxes((b"H", _boxes((b"H", _boxes((b"T", _tar([("a", b"a")])))))))
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=limit))
    with registration_scope():
        register_format(HoldingBoxesHandler)
        if refused:
            with pytest.raises(
                ResourceLimitError, match="max_metadata_bytes=1000.*inner archive"
            ):
                _names(data, HoldingBoxesHandler.format, config)
            return
        with open_archive(
            io.BytesIO(data), format=HoldingBoxesHandler.format, config=config
        ) as reader:
            assert [m.name for m in reader.members()] == ["0/0/0/a"]
            # The inner levels' charges came off when they closed.
            tracker = reader._listing_tracker  # type: ignore[attr-defined]
            assert tracker._nested_bytes == 0


def test_a_member_the_nest_refuses_to_hold_is_not_drawn_from_the_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 3rd level's held member crosses the nest's 1000 bytes: the shared budget
    keeps the 2 members the outer levels drew, not 3."""
    monkeypatch.setitem(_KINDS, b"H", HoldingBoxesHandler.format)
    data = _boxes((b"H", _boxes((b"H", _boxes((b"T", _tar([("a", b"a")])))))))
    budget = Budget(max_members=100)
    config = ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=1000), budget=budget
    )
    with registration_scope():
        register_format(HoldingBoxesHandler)
        with pytest.raises(
            ResourceLimitError, match="max_metadata_bytes=1000.*inner archive"
        ):
            _names(data, HoldingBoxesHandler.format, config)
    assert budget.members == 2


def test_a_hold_the_budget_refuses_takes_its_nest_charge_back() -> None:
    """The nest's charge goes first; when the shared budget then refuses the member,
    the outermost tracker keeps nothing of it."""
    budget = Budget(max_members=1)
    limits = ListingLimits(max_metadata_bytes=10_000)
    outer = ListingLimitTracker(limits, budget=budget)
    inner = ListingLimitTracker(limits, budget=budget, outer=outer)
    inner.hold_member(ArchiveMember(name="a", type=MemberType.FILE), "held")
    charged = outer._nested_bytes
    assert charged > 0
    with pytest.raises(ResourceLimitError, match="max_members"):
        inner.hold_member(ArchiveMember(name="b", type=MemberType.FILE), "held")
    assert budget.members == 1
    assert outer._nested_bytes == inner._charged_outward == charged
    inner.leave_nest()
    assert outer._nested_bytes == 0


class ChargingBoxesContainer(PluginContainer):
    CHARGING_BOXES = "charging-boxes"


class ChargingBoxesReader(BoxesReader):
    """BOXES, but the walk keeps a 400-byte name table, charged with
    ``charge_metadata()``, until it ends."""

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        self._context.charge_metadata(400, what="a name table")
        yield from super().walk(stream)


class ChargingBoxesHandler(BoxesHandler):
    format = ArchiveFormat(
        ChargingBoxesContainer.CHARGING_BOXES, StreamFormat.UNCOMPRESSED
    )
    magic = ()

    def open_sequential(self, context: ReaderContext) -> BoxesReader:
        return ChargingBoxesReader(context)


@pytest.mark.parametrize(("limit", "refused"), [(1000, True), (1500, False)])
def test_walk_charges_of_inner_levels_count_against_one_metadata_budget(
    monkeypatch: pytest.MonkeyPatch, limit: int, refused: bool
) -> None:
    """3 levels each charge a 400-byte table with ``charge_metadata``: 1200 in all,
    over a 1000-byte limit each level alone fits."""
    monkeypatch.setitem(_KINDS, b"C", ChargingBoxesHandler.format)
    data = _boxes((b"C", _boxes((b"C", _boxes((b"T", _tar([("a", b"a")])))))))
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=limit))
    with registration_scope():
        register_format(ChargingBoxesHandler)
        if refused:
            with pytest.raises(
                ResourceLimitError,
                match="max_metadata_bytes=1000.*inner archive for a name table",
            ):
                _names(data, ChargingBoxesHandler.format, config)
            return
        with open_archive(
            io.BytesIO(data), format=ChargingBoxesHandler.format, config=config
        ) as reader:
            assert [m.name for m in reader.members()] == ["0/0/0/a"]
            # The inner levels' walk charges came off when their walks ended.
            tracker = reader._listing_tracker  # type: ignore[attr-defined]
            assert tracker._nested_bytes == 0


def _names(data: bytes, fmt: ArchiveFormat, config: ArchiveyConfig) -> list[str]:
    with open_archive(io.BytesIO(data), format=fmt, config=config) as reader:
        return [m.name for m in reader.members()]


class LzmaBoxesContainer(PluginContainer):
    LZMA_BOXES = "lzma-boxes"


# lc=3, lp=0, pb=2: the LZMA properties byte xz and 7-Zip write by default.
_LZMA_LCLPPB = (2 * 5 + 0) * 9 + 3


def _lzma_box(kind: bytes, inner: bytes, dict_size: int) -> bytes:
    """One LZMA_BOXES box: ``inner`` as raw LZMA1 with a ``dict_size`` dictionary."""
    packed = lzma.compress(
        inner,
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size}],
    )
    properties = bytes([_LZMA_LCLPPB]) + dict_size.to_bytes(4, "little")
    return b"%08d%08d" % (len(packed), len(inner)) + kind + properties + packed


class LzmaBoxesReader(BoxesReader):
    """BOXES, but each box is raw LZMA1 that the walk decodes with
    ``ReaderContext.decompress``, which checks the dictionary the box declares."""

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        if stream.read_exact(5) != b"BOXES":
            raise CorruptionError("not BOXES")
        box = 0
        while True:
            packed = int(stream.read_exact(8))
            if not packed:
                return
            size = int(stream.read_exact(8))
            kind = _KINDS[stream.read_exact(1)]
            properties = stream.read_exact(5)
            decoded = self._context.decompress(
                stream.take(packed),
                CompressionAlgorithm.LZMA,
                size=size,
                properties=properties,
            )
            for span in self._context.open_nested(decoded, kind):
                span.member.name = f"{box}/{span.member.name}"
                yield span
            box += 1


class LzmaBoxesHandler(BoxesHandler):
    format = ArchiveFormat(LzmaBoxesContainer.LZMA_BOXES, StreamFormat.UNCOMPRESSED)
    magic = ()

    def open_sequential(self, context: ReaderContext) -> BoxesReader:
        return LzmaBoxesReader(context)


@pytest.mark.parametrize(
    ("limit", "refused"), [(5 * 2**20 // 2, True), (7 * 2**20 // 2, False)]
)
def test_decoders_of_every_level_count_against_one_decoder_memory_budget(
    monkeypatch: pytest.MonkeyPatch, limit: int, refused: bool
) -> None:
    """Each level declares a 1 MiB dictionary, and its decoder runs while the levels
    inside it decode: 3 MiB in all, over a 2.5 MiB limit each level alone fits."""
    monkeypatch.setitem(_KINDS, b"L", LzmaBoxesHandler.format)
    mib = 2**20
    level3 = b"BOXES" + _lzma_box(b"T", _tar([("a", b"a")]), mib) + b"00000000"
    level2 = b"BOXES" + _lzma_box(b"L", level3, mib) + b"00000000"
    data = b"BOXES" + _lzma_box(b"L", level2, mib) + b"00000000"
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=limit))
    with registration_scope():
        register_format(LzmaBoxesHandler)
        if refused:
            with pytest.raises(ResourceLimitError, match="max_decoder_memory="):
                _names(data, LzmaBoxesHandler.format, config)
        else:
            assert _names(data, LzmaBoxesHandler.format, config) == ["0/0/0/a"]


@pytest.mark.usefixtures("boxes")
@pytest.mark.parametrize(
    ("limit", "refused"), [(5 * 2**20 // 2, True), (7 * 2**20 // 2, False)]
)
def test_xz_levels_count_against_one_decoder_memory_budget(
    monkeypatch: pytest.MonkeyPatch, limit: int, refused: bool
) -> None:
    """The same with xz, whose dictionary liblzma reads and checks itself: a BOXES.xz
    holds a BOXES.xz, which holds a tar.xz, each with a 1 MiB dictionary."""
    monkeypatch.setitem(
        _KINDS, b"W", ArchiveFormat(BoxesContainer.BOXES, StreamFormat.XZ)
    )
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": 2**20}]

    def xz(data: bytes) -> bytes:
        # The check is named: PyPy's lzma passes the default -1 on to liblzma with a
        # filter chain, which refuses it ("Internal error").
        return lzma.compress(data, check=lzma.CHECK_CRC64, filters=filters)

    level4 = xz(_tar([("a", b"a")]))
    level3 = xz(_boxes((b"X", level4)))
    data = _boxes((b"W", xz(_boxes((b"W", level3)))))
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=limit))
    if refused:
        with pytest.raises(ResourceLimitError, match="max_decoder_memory="):
            _names(data, BoxesHandler.format, config)
    else:
        assert _names(data, BoxesHandler.format, config) == ["0/0/0/a"]


class CodecBoxesContainer(PluginContainer):
    CODEC_BOXES = "codec-boxes"


_CODECS = {b"x": StreamFormat.XZ, b"a": StreamFormat.LZMA_ALONE}


class CodecBoxesReader(BoxesReader):
    """BOXES, but each box is compressed on its own (``x`` xz, ``a`` LZMA Alone) and
    decoded with ``ReaderContext.decompress``, whose decoder reads the dictionary
    from the data only when the inner archive is first read."""

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        if stream.read_exact(5) != b"BOXES":
            raise CorruptionError("not BOXES")
        box = 0
        while True:
            packed = int(stream.read_exact(8))
            if not packed:
                return
            kind = _KINDS[stream.read_exact(1)]
            codec = _CODECS[stream.read_exact(1)]
            decoded = self._context.decompress(stream.take(packed), codec)
            for span in self._context.open_nested(decoded, kind):
                span.member.name = f"{box}/{span.member.name}"
                yield span
            box += 1


class CodecBoxesHandler(BoxesHandler):
    format = ArchiveFormat(CodecBoxesContainer.CODEC_BOXES, StreamFormat.UNCOMPRESSED)
    magic = ()

    def open_sequential(self, context: ReaderContext) -> BoxesReader:
        return CodecBoxesReader(context)


@pytest.mark.parametrize("codec", [b"x", b"a"], ids=["xz", "alone"])
@pytest.mark.parametrize(
    ("limit", "refused"), [(5 * 2**20 // 2, True), (7 * 2**20 // 2, False)]
)
def test_member_decoders_liblzma_checks_count_against_one_budget(
    monkeypatch: pytest.MonkeyPatch, codec: bytes, limit: int, refused: bool
) -> None:
    """Each level decodes one member with a 1 MiB xz or LZMA Alone dictionary through
    ``ReaderContext.decompress`` and reads an archive from it. The decoder declares
    its dictionary only once it reads its data, after ``open_nested`` is called."""
    monkeypatch.setitem(_KINDS, b"C", CodecBoxesHandler.format)

    def pack(inner: bytes) -> bytes:
        if codec == b"x":
            # The check is named: PyPy's lzma passes the default -1 on to liblzma with a
            # filter chain, which refuses it ("Internal error").
            filters = [{"id": lzma.FILTER_LZMA2, "dict_size": 2**20}]
            return lzma.compress(inner, check=lzma.CHECK_CRC64, filters=filters)
        lzma1 = {"id": lzma.FILTER_LZMA1, "dict_size": 2**20}
        return lzma_alone_with_filter(inner, lzma1)

    def box(kind: bytes, inner: bytes) -> bytes:
        packed = pack(inner)
        return b"BOXES%08d" % len(packed) + kind + codec + packed + b"00000000"

    data = box(b"C", box(b"C", box(b"T", _tar([("a", b"a")]))))
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=limit))
    with registration_scope():
        register_format(CodecBoxesHandler)
        if refused:
            with pytest.raises(ResourceLimitError, match="max_decoder_memory="):
                _names(data, CodecBoxesHandler.format, config)
        else:
            assert _names(data, CodecBoxesHandler.format, config) == ["0/0/0/a"]


def test_a_primed_stream_gives_its_head_then_the_rest() -> None:
    primed = _Primed(b"ab", io.BytesIO(b"cdef"))
    assert primed.read(1) == b"a"
    assert primed.read(3) == b"b"
    assert primed.read() == b"cdef"
    assert primed.read() == b""


def test_a_primed_stream_releases_its_views_of_the_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``RawIOBase.read`` resizes the buffer after ``readinto`` returns. PyPy frees a
    dropped view only at a collection, so a view still alive makes the resize raise
    ``BufferError``. ``hold_views`` keeps every view alive, the cast one included,
    which shows that on CPython too."""
    held = hold_views(monkeypatch, format_adapter)
    primed = _Primed(b"ab", io.BytesIO(b"cdef"))
    for want in (b"ab", b"cdef", b""):
        buffer = bytearray(8)
        n = primed.readinto(buffer)
        del buffer[n:]  # BufferError while a view of it is alive
        assert buffer == want
    assert len(held) == 6  # the view and its cast, for each of the three calls


class PaddedBoxesContainer(PluginContainer):
    PADDED_BOXES = "padded-boxes"


class PaddedBoxesReader(BoxesReader):
    """BOXES whose kind ``P`` box is padding the walk skips."""

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        if stream.read_exact(5) != b"BOXES":
            raise CorruptionError("not BOXES")
        box = 0
        while True:
            size = int(stream.read_exact(8))
            if not size:
                return
            letter = stream.read_exact(1)
            if letter == b"P":
                stream.skip(size)
                continue
            for span in self._context.open_nested(stream.take(size), _KINDS[letter]):
                span.member.name = f"{box}/{span.member.name}"
                yield span
            box += 1


class PaddedBoxesHandler(BoxesHandler):
    format = ArchiveFormat(PaddedBoxesContainer.PADDED_BOXES, StreamFormat.UNCOMPRESSED)
    magic = ()

    def open_sequential(self, context: ReaderContext) -> BoxesReader:
        return PaddedBoxesReader(context)


@pytest.mark.parametrize(("max_ratio", "refused"), [(2000.0, True), (None, False)])
def test_every_level_is_held_to_the_ratio_of_the_outermost_archive(
    monkeypatch: pytest.MonkeyPatch, max_ratio: float | None, refused: bool
) -> None:
    """An xz level holds a gzip level, which holds 8 MiB of padding its walk skips.
    Each level decodes less than 2000 times its own input, and the gzip level more
    than 2000 times the bytes the caller handed over."""
    monkeypatch.setitem(
        _KINDS,
        b"G",
        ArchiveFormat(PaddedBoxesContainer.PADDED_BOXES, StreamFormat.GZIP),
    )
    padding = 8 * 2**20
    level3 = gzip.compress(
        b"BOXES"
        + b"%08dP" % padding
        + bytes(padding)
        + b"%08dT" % len(_TAR_A)
        + _TAR_A
        + b"00000000",
        mtime=0,
    )
    level2 = lzma.compress(_boxes((b"G", level3)))
    data = _boxes((b"X", level2))
    assert padding < 2000 * len(level3)
    assert len(level3) < 2000 * len(level2)
    assert padding > 2000 * len(data)
    monkeypatch.setitem(
        _KINDS, b"X", ArchiveFormat(PaddedBoxesContainer.PADDED_BOXES, StreamFormat.XZ)
    )
    config = ArchiveyConfig(
        decoder_limits=DecoderLimits(
            max_ratio=max_ratio,
            ratio_activation_threshold=2**20,
            live_ratio_activation_threshold=2**20,
        )
    )
    with registration_scope():
        register_format(PaddedBoxesHandler)
        if refused:
            with pytest.raises(ResourceLimitError, match="max_ratio"):
                _names(data, PaddedBoxesHandler.format, config)
        else:
            names = _names(data, PaddedBoxesHandler.format, config)
            assert names == ["0/0/0/a", "0/0/0/b"]
