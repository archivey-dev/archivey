"""Limits per nest: ``open_archive(parent=)`` and the totals a nest shares.

A nest is an archive's reader and every reader opened inside it. Its readers draw
decoded bytes (``DecoderLimits.max_nest_decoded_bytes``) and members
(``ListingLimits.max_members``) from one account, and the nest is held to
``max_ratio`` times its outermost archive's size, counting each reader's bytes once per
pass.
"""

from __future__ import annotations

import gzip
import io
import random
import tarfile
import threading
import zipfile
from typing import Any

import pytest

import archivey
from archivey import (
    ArchiveyConfig,
    ArchiveyUsageError,
    DecoderLimits,
    ListingLimits,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from archivey.internal.nesting import MAX_NESTED_DEPTH, NestAccount, NestDraws
from tests.conftest import requires_binary

_MEMBER = 100_000


def _zip(count: int = 5, *, size: int = _MEMBER) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(count):
            zf.writestr(f"m{i}.bin", bytes([i]) * size)
    return buf.getvalue()


def _tar(count: int = 3, *, size: int = _MEMBER) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i in range(count):
            info = tarfile.TarInfo(f"t{i}.bin")
            info.size = size
            tf.addfile(info, io.BytesIO(b"t" * size))
    return buf.getvalue()


def _stored_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


# A nest counts decoded bytes only under a cap: tests that read the count set one no
# read reaches.
_UNREACHED = 1 << 60


class _Nest:
    """One nest for a test, with a decoded-byte and a member cap.

    Its outermost reader is a tiny archive, closed at once; every reader the test
    opens joins it with ``parent=``, so the test's readers count on one account. The
    ratio is off: these tests count bytes, and the tiny outermost archive would make
    any read a bomb by the nest ratio.
    """

    def __init__(
        self,
        *,
        max_decoded_bytes: int | None = _UNREACHED,
        max_members: int | None = None,
    ) -> None:
        self.config = ArchiveyConfig(
            decoder_limits=DecoderLimits(
                max_nest_decoded_bytes=max_decoded_bytes, max_ratio=None
            ),
            listing_limits=ListingLimits(max_members=max_members),
        )
        with archivey.open_archive(
            io.BytesIO(_stored_zip({})), config=self.config
        ) as root:
            self.root = root

    def open(self, source: Any, **kwargs: Any) -> archivey.ArchiveReader:
        return archivey.open_archive(source, parent=self.root, **kwargs)

    @property
    def draws(self) -> NestDraws:
        return self.root._nest  # type: ignore[attr-defined]

    @property
    def account(self) -> NestAccount:
        return self.draws.account

    @property
    def decoded_bytes(self) -> int:
        return self.account.decoded_bytes

    @property
    def members(self) -> int:
        return self.account.members


def _open(data: bytes, nest: _Nest, **kwargs: Any) -> archivey.ArchiveReader:
    return nest.open(io.BytesIO(data), **kwargs)


def test_a_bad_nest_cap_is_refused_at_construction() -> None:
    with pytest.raises(ArchiveyUsageError, match="max_nest_decoded_bytes"):
        DecoderLimits(max_nest_decoded_bytes=-1)


@pytest.mark.parametrize("parent", [10, "reader", ArchiveyConfig()])
def test_open_archive_refuses_a_parent_that_is_not_a_reader(parent: object) -> None:
    with pytest.raises(ArchiveyUsageError, match="parent="):
        archivey.open_archive(io.BytesIO(_zip()), parent=parent)  # type: ignore[arg-type]


def test_a_config_has_no_budget() -> None:
    assert not hasattr(ArchiveyConfig(), "budget")
    assert not hasattr(archivey, "Budget")


def test_one_config_reused_across_nests_never_runs_out() -> None:
    """Each ``open_archive`` without ``parent=`` starts a nest, counting from zero, so
    one config with a nest cap serves every request."""
    data = _zip(count=1)
    config = ArchiveyConfig(
        decoder_limits=DecoderLimits(max_nest_decoded_bytes=_MEMBER)
    )
    for _ in range(5):
        with archivey.open_archive(io.BytesIO(data), config=config) as r:
            r.read(r.members()[0])
            assert r._nest.account.decoded_bytes == _MEMBER  # type: ignore[attr-defined]


def test_reads_of_two_readers_draw_from_one_pool() -> None:
    data = _zip()
    budget = _Nest(max_decoded_bytes=3 * _MEMBER + _MEMBER // 2)
    with _open(data, budget) as first:
        assert len(first.read("m0.bin")) == _MEMBER
        assert len(first.read("m1.bin")) == _MEMBER
    with _open(data, budget) as second:
        assert len(second.read("m2.bin")) == _MEMBER
        with pytest.raises(ResourceLimitError, match="max_nest_decoded_bytes=350000"):
            second.read("m3.bin")
    # The crossing read decoded one byte past what was left, not the whole member.
    assert budget.decoded_bytes == 3 * _MEMBER + _MEMBER // 2 + 1


def test_a_spent_budget_decodes_nothing_more() -> None:
    data = _zip()
    budget = _Nest(max_decoded_bytes=10)
    with _open(data, budget) as reader:
        with pytest.raises(ResourceLimitError):
            reader.read("m0.bin")
        spent = budget.decoded_bytes
        with pytest.raises(ResourceLimitError), reader.open("m1.bin") as stream:
            stream.read(1)
    assert budget.decoded_bytes == spent


def test_a_member_under_the_budget_reads_whole() -> None:
    budget = _Nest(max_decoded_bytes=_MEMBER)
    with _open(_zip(1), budget) as reader:
        assert reader.read("m0.bin") == b"\0" * _MEMBER
    assert budget.decoded_bytes == _MEMBER


def test_tar_member_reads_draw_too() -> None:
    budget = _Nest(max_decoded_bytes=2 * _MEMBER)
    with _open(_tar(), budget, streaming=True) as reader:
        read = []
        with pytest.raises(ResourceLimitError, match="Nest limit reached"):
            for member, stream in reader.stream_members():
                assert stream is not None
                read.append((member.name, len(stream.read())))
    assert read == [("t0.bin", _MEMBER), ("t1.bin", _MEMBER)]


def test_a_forward_seek_draws_the_bytes_it_skips() -> None:
    budget = _Nest(max_decoded_bytes=_MEMBER // 2)
    with (
        _open(_zip(1), budget, seekable_members=True) as reader,
        reader.open("m0.bin") as stream,
    ):
        stream.seek(1000)
        assert stream.read(1) == b"\0"
        assert budget.decoded_bytes == 1001
        stream.seek(_MEMBER - 1)
        with pytest.raises(ResourceLimitError, match="Nest limit reached"):
            stream.read(1)
    assert budget.decoded_bytes <= _MEMBER // 2 + 1


def test_members_draw_once_per_reader() -> None:
    data = _zip(5)
    budget = _Nest(max_members=12)
    with _open(data, budget) as reader:
        assert len(reader.members()) == 5
        assert len(list(reader)) == 5
        assert len(reader.members()) == 5
    assert budget.members == 5
    with _open(data, budget) as reader:
        reader.members()
    assert budget.members == 10
    with (
        pytest.raises(ResourceLimitError, match="max_members=12"),
        _open(data, budget) as reader,
    ):
        reader.members()
    # The refused member is not counted.
    assert budget.members == 12


def test_extraction_stops_at_a_spent_budget(tmp_path) -> None:
    budget = _Nest(max_decoded_bytes=2 * _MEMBER + 10)
    with (
        _open(_zip(5), budget) as reader,
        pytest.raises(ResourceLimitError, match="Nest limit reached"),
    ):
        reader.extract_all(tmp_path)
    written = sorted(p.name for p in tmp_path.iterdir() if p.stat().st_size == _MEMBER)
    assert written == ["m0.bin", "m1.bin"]
    # The extraction stopped: no member after the crossing one was opened.
    assert budget.decoded_bytes == 2 * _MEMBER + 11


def test_a_nested_reader_given_the_budget_draws_from_it() -> None:
    inner = _zip(2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("inner.zip", inner)
    budget = _Nest(max_decoded_bytes=len(inner) + _MEMBER + _MEMBER // 2)
    with _open(buf.getvalue(), budget) as outer:
        nested_bytes = outer.read("inner.zip")
        assert budget.decoded_bytes == len(inner)
        with _open(nested_bytes, budget) as nested:
            assert len(nested.read("m0.bin")) == _MEMBER
            with pytest.raises(ResourceLimitError, match="Nest limit reached"):
                nested.read("m1.bin")


def test_threads_share_one_count() -> None:
    data = _zip(4, size=50_000)
    budget = _Nest()
    errors: list[BaseException] = []

    def work() -> None:
        try:
            with _open(data, budget) as reader:
                for member in reader.members():
                    reader.read(member)
        except BaseException as e:  # noqa: BLE001 - reported below
            errors.append(e)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert budget.decoded_bytes == 8 * 4 * 50_000
    assert budget.members == 8 * 4


def _no_translation(exc: Exception) -> None:
    return None


def test_two_holds_on_a_lazy_codec_handle_both_draw() -> None:
    # A codec handle not yet opened can get a ratio hold and the budget's hold; the
    # second wraps outside the first. Fails if ``_hold_inner`` keeps only the last.
    from archivey.internal.streams.archive_stream import ArchiveStreamImpl
    from archivey.internal.streams.counting import BudgetDrawStream

    first, second = _Nest(), _Nest()
    stream = ArchiveStreamImpl(
        lambda: io.BytesIO(b"abc"), translate=_no_translation, lazy=True
    )
    assert stream._inner is None
    stream._hold_inner(lambda inner: BudgetDrawStream(inner, first.draws))
    stream._hold_inner(lambda inner: BudgetDrawStream(inner, second.draws))
    assert stream.read() == b"abc"
    assert (first.decoded_bytes, second.decoded_bytes) == (3, 3)


def test_a_collapsed_lazy_handle_keeps_its_hold() -> None:
    # A lazy handle collapsed into another before it opened still serves through
    # its hold. Fails if ``_collapse_nested`` drops ``_inner_wrap``.
    from archivey.internal.streams.archive_stream import ArchiveStreamImpl
    from archivey.internal.streams.counting import BudgetDrawStream

    budget = _Nest()
    nested = ArchiveStreamImpl(
        lambda: io.BytesIO(b"abc"), translate=_no_translation, lazy=True
    )
    nested._hold_inner(lambda inner: BudgetDrawStream(inner, budget.draws))
    outer = ArchiveStreamImpl(lambda: nested, translate=_no_translation)
    assert outer.read() == b"abc"
    assert nested.closed
    assert budget.decoded_bytes == 3


def test_a_seek_to_the_end_is_held_to_the_budget() -> None:
    budget = _Nest(max_decoded_bytes=1000)
    with (
        _open(_zip(1, size=5 * _MEMBER), budget, seekable_members=True) as reader,
        reader.open("m0.bin") as stream,
        pytest.raises(ResourceLimitError, match="Nest limit reached"),
    ):
        stream.seek(0, io.SEEK_END)
    # The deflate stream cannot size its end, so the seek decodes toward it in drawn
    # steps and stops one byte past the budget.
    assert budget.decoded_bytes <= 1001


def test_a_refused_seek_to_a_known_target_draws_nothing() -> None:
    from archivey.internal.streams.counting import BudgetDrawStream

    budget = _Nest(max_decoded_bytes=1000)
    stream = BudgetDrawStream(io.BytesIO(b"x" * 5000), budget.draws)
    with pytest.raises(ResourceLimitError, match="a seek would decode 4000 more"):
        stream.seek(4000)
    # Refused before the inner stream moved: nothing decoded, nothing drawn, and the
    # room stays for another reader.
    assert budget.decoded_bytes == 0
    with _open(_zip(1, size=1000), budget) as other:
        assert len(other.read("m0.bin")) == 1000
    assert budget.decoded_bytes == 1000


def test_a_seek_to_an_unsized_end_reads_there_and_draws() -> None:
    from archivey.internal.streams.counting import BudgetDrawStream

    budget = _Nest(max_decoded_bytes=1000)
    stream = BudgetDrawStream(io.BytesIO(b"x" * 5000), budget.draws)
    assert stream.try_get_size() is None
    with pytest.raises(ResourceLimitError, match="Nest limit reached"):
        stream.seek(0, io.SEEK_END)
    assert budget.decoded_bytes == 1001
    roomy = _Nest(max_decoded_bytes=10_000)
    stream = BudgetDrawStream(io.BytesIO(b"x" * 5000), roomy.draws)
    assert stream.seek(-10, io.SEEK_END) == 4990
    assert stream.read() == b"x" * 10
    # The ten bytes after the seek back are read again, so they count again.
    assert roomy.decoded_bytes == 5010


# Bytes decoded for members nobody reads: every format draws them where they are
# decoded, so skipping a member does not decode it for free, and a member that is read
# is drawn once, not again by its own stream.


class _Unseekable(io.RawIOBase):
    """A write-only sink zipfile cannot seek back in: it writes data descriptors."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:  # type: ignore[override]
        self.data += b
        return len(b)


def _zip_bit3(count: int = 4) -> bytes:
    sink = _Unseekable()
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(count):
            with zf.open(f"m{i}.bin", "w") as out:
                out.write(bytes([i]) * _MEMBER)
    return bytes(sink.data)


def _tar_gz(count: int = 3) -> bytes:
    return gzip.compress(_tar(count), mtime=0)


def _read_last(reader: archivey.ArchiveReader, last: str) -> bytes:
    """Iterate ``reader``'s members, reading only ``last``."""
    out = b""
    for member, stream in reader.stream_members():
        if member.name == last:
            assert stream is not None
            out = stream.read()
    return out


@pytest.mark.parametrize("streaming", [True, False], ids=["streaming", "random"])
def test_a_tar_gz_draws_the_members_it_decodes_past(streaming: bool) -> None:
    budget = _Nest()
    with _open(_tar_gz(), budget, streaming=streaming) as reader:
        assert _read_last(reader, "t2.bin") == b"t" * _MEMBER
    assert budget.decoded_bytes >= 3 * _MEMBER


def test_a_tar_gz_skip_stops_at_the_budget() -> None:
    budget = _Nest(max_decoded_bytes=_MEMBER + _MEMBER // 2)
    with (
        _open(_tar_gz(), budget, streaming=True) as reader,
        pytest.raises(ResourceLimitError, match="Nest limit reached"),
    ):
        _read_last(reader, "t2.bin")


def test_a_tar_gz_member_read_is_drawn_once() -> None:
    data = _tar(3)
    budget = _Nest()
    with _open(gzip.compress(data, mtime=0), budget, streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert len(stream.read()) == _MEMBER
    # The headers and the members, decoded once: never more than the whole tar.
    assert 3 * _MEMBER <= budget.decoded_bytes <= len(data)


def _sparse_tar(size: int) -> bytes:
    """A PAX 0.1 sparse member of ``size`` logical bytes: a hole, then 5 stored."""

    def record(key: str, value: str) -> bytes:
        body = f" {key}={value}\n".encode()
        length = len(body) + 1
        while len(str(length)) + len(body) != length:
            length += 1
        return str(length).encode() + body

    def block(data: bytes) -> bytes:
        return data + bytes(-len(data) % tarfile.BLOCKSIZE)

    payload = (
        record("GNU.sparse.size", str(size))
        + record("GNU.sparse.numblocks", "1")
        + record("GNU.sparse.map", f"{size - 5},5")
    )
    xhdr = tarfile.TarInfo("./PaxHeaders/holes.bin")
    xhdr.type = tarfile.XHDTYPE
    xhdr.size = len(payload)
    member = tarfile.TarInfo("holes.bin")
    member.size = 5
    return b"".join(
        [
            xhdr.tobuf(format=tarfile.USTAR_FORMAT),
            block(payload),
            member.tobuf(format=tarfile.USTAR_FORMAT),
            block(b"hello"),
            bytes(2 * tarfile.BLOCKSIZE),
        ]
    )


@pytest.mark.parametrize("compress", [False, True], ids=["tar", "tar.gz"])
def test_sparse_holes_draw_in_a_compressed_tar_too(compress: bool) -> None:
    """A compressed tar's members draw nothing themselves; the holes, which no
    decoder makes, still draw, and stop at the budget."""
    data = _sparse_tar(4 * _MEMBER)
    if compress:
        data = gzip.compress(data, mtime=0)
    budget = _Nest()
    with _open(data, budget) as reader:
        assert reader.read("holes.bin").endswith(b"hello")
    assert budget.decoded_bytes >= 4 * _MEMBER
    budget = _Nest(max_decoded_bytes=_MEMBER)
    with (
        _open(data, budget) as reader,
        pytest.raises(ResourceLimitError, match="Nest limit reached"),
    ):
        reader.read("holes.bin")
    assert budget.decoded_bytes <= _MEMBER + 1 + len(data) + 2048


def test_a_streaming_zip_draws_the_members_it_drains() -> None:
    """A bit-3 member nobody reads is decoded as far as the pass needs (the start a
    link target could be), and the scan finds the rest: that decode is drawn."""
    data = _zip_bit3()
    budget = _Nest()
    with _open_pipe(data, budget) as reader:
        assert _read_last(reader, "m3.bin") == b"\3" * _MEMBER
    drained = budget.decoded_bytes - _MEMBER
    assert drained > 0
    budget = _Nest(max_decoded_bytes=_MEMBER + drained - 1)
    with (
        _open_pipe(data, budget) as reader,
        pytest.raises(ResourceLimitError, match="Nest limit reached"),
    ):
        _read_last(reader, "m3.bin")


def test_a_streaming_zip_member_read_is_drawn_once() -> None:
    budget = _Nest()
    with _open_pipe(_zip_bit3(), budget) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert len(stream.read()) == _MEMBER
    assert budget.decoded_bytes == 4 * _MEMBER


def _open_pipe(data: bytes, budget: _Nest) -> archivey.ArchiveReader:
    from tests.streams_util import NonSeekableBytesIO

    return budget.open(NonSeekableBytesIO(data), streaming=True)


def test_a_cab_folder_draws_the_members_it_decodes_past() -> None:
    from tests.cab_util import CabFile, CabFolder, write_cab

    files = [CabFile(f"c{i}.bin", bytes([i]) * _MEMBER) for i in range(3)]
    data = write_cab(files, [CabFolder("mszip")])
    budget = _Nest()
    with _open(data, budget) as reader:
        assert reader.read("c2.bin") == b"\2" * _MEMBER
    assert budget.decoded_bytes == 3 * _MEMBER
    budget = _Nest(max_decoded_bytes=_MEMBER)
    with (
        _open(data, budget) as reader,
        pytest.raises(ResourceLimitError, match="Nest limit reached"),
    ):
        reader.read("c2.bin")
    # The skip stops within a block (32 KiB) of the budget.
    assert budget.decoded_bytes <= _MEMBER + 32768


def test_a_plugin_layer_draws_the_members_it_decodes_past() -> None:
    """An RPM's payload is a ``decompress()`` layer of the format adapter."""
    from tests.test_rpm import _F, _build, _Package

    blobs = [bytes([i]) * _MEMBER for i in range(3)]
    files = [_F(f"/opt/f{i}".encode(), data=b) for i, b in enumerate(blobs)]
    data = _build(_Package(files))
    budget = _Nest()
    with _open(data, budget, streaming=True) as reader:
        assert _read_last(reader, "opt/f2") == blobs[2]
    assert budget.decoded_bytes >= 3 * _MEMBER
    # Read whole, each member is drawn once: by the layer, not again by itself.
    budget = _Nest()
    with _open(data, budget, streaming=True) as reader:
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()
    assert 3 * _MEMBER <= budget.decoded_bytes < 4 * _MEMBER


def test_an_outer_compressed_cpio_draws_the_members_it_decodes_past() -> None:
    from tests.test_cpio import _newc

    raw = _newc(
        *((f"f{i}".encode(), 0o100644, i + 1, 1, b"c" * _MEMBER) for i in range(3))
    )
    data = gzip.compress(raw, mtime=0)
    budget = _Nest()
    with _open(data, budget, streaming=True) as reader:
        assert _read_last(reader, "f2") == b"c" * _MEMBER
    assert budget.decoded_bytes >= 3 * _MEMBER
    budget = _Nest()
    with _open(data, budget, streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            stream.read()
    assert 3 * _MEMBER <= budget.decoded_bytes <= len(raw)


@pytest.mark.parametrize("pipe", [False, True], ids=["seekable", "pipe"])
def test_a_tar_gz_on_a_pipe_stops_one_byte_past_the_budget(pipe: bool) -> None:
    """A buffer over a codec on a source that cannot seek fills by ``read_ahead``,
    in 1 MiB steps for member data: capped like a read, it stops one byte past."""
    from tests.streams_util import NonSeekableBytesIO

    member = random.Random(3).randbytes(3_000_000)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("big.bin")
        info.size = len(member)
        tf.addfile(info, io.BytesIO(member))
    data = gzip.compress(buf.getvalue(), mtime=0)
    budget = _Nest(max_decoded_bytes=20_000)
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with (
        budget.open(source, streaming=True) as reader,
        pytest.raises(ResourceLimitError, match="Nest limit reached"),
    ):
        for _member, stream in reader.stream_members():
            assert stream is not None
            stream.read()
    assert budget.decoded_bytes == 20_001


def test_members_held_before_they_are_listed_draw_as_they_are_held() -> None:
    """A newc archive holds each hard-link placeholder until the trailer: the nest
    refuses the one past its cap when it is held, not after all are. The child's own
    config lifts its per-reader cap, which cannot loosen the nest's."""
    from tests.test_cpio import _newc

    raw = _newc(*((f"f{i}".encode(), 0o100644, i + 1, 2, b"") for i in range(40)))
    budget = _Nest(max_members=5)
    own = ArchiveyConfig(
        listing_limits=ListingLimits(max_members=None),
        decoder_limits=DecoderLimits(max_ratio=None),
    )
    with (
        pytest.raises(ResourceLimitError, match="would list 6 members"),
        _open(raw, budget, config=own) as reader,
    ):
        reader.members()
    assert budget.members == 5
    # Held, then listed: each member is drawn once.
    budget = _Nest()
    with _open(raw, budget) as reader:
        assert len(reader.members()) == 40
    assert budget.members == 40


@requires_binary("unrar")
def test_a_solid_rar_open_draws_the_prefix_unrar_decodes_first() -> None:
    """``unrar`` decodes a solid member's earlier members and emits only the member:
    the prefix is drawn before the process starts, and refused there when it does
    not fit."""
    from pathlib import Path

    path = Path(__file__).parent / "fixtures" / "rar" / "basic_solid__.rar"
    budget = _Nest()
    with budget.open(path) as reader:
        assert reader.read("subdir/file2.txt") == b"Hello, universe!"
    # file1.txt (13 bytes) comes first in the solid stream.
    assert budget.decoded_bytes == 13 + 16
    budget = _Nest(max_decoded_bytes=20)
    with (
        budget.open(path) as reader,
        pytest.raises(ResourceLimitError, match="solid prefix"),
    ):
        reader.read("implicit_subdir/file3.txt")
    assert budget.decoded_bytes == 0


def test_an_encoded_7z_header_is_drawn_before_it_decodes() -> None:
    """A 7z header stored compressed is decoded whole into memory at open: drawn
    then, or refused, drawing nothing, when it does not fit."""
    from pathlib import Path

    path = Path(__file__).parent / "fixtures" / "sevenzip" / "solid_three_members.7z"
    budget = _Nest()
    with budget.open(path):
        header = budget.decoded_bytes
    assert header > 0
    budget = _Nest(max_decoded_bytes=header - 1)
    with (
        pytest.raises(ResourceLimitError, match="encoded 7z header"),
        budget.open(path),
    ):
        pass
    assert budget.decoded_bytes == 0


def test_a_reader_opened_without_parent_starts_its_own_nest() -> None:
    """Readers opened without ``parent=``, even while a nest's reader is open, draw
    nothing from it."""
    data = _zip(count=1)
    budget = _Nest()
    with _open(data, budget) as first:
        with archivey.open_archive(io.BytesIO(data)) as other:
            other.read(other.members()[0])
            assert other._nest.account is not budget.account  # type: ignore[attr-defined]
        assert budget.decoded_bytes == 0
        first.read(first.members()[0])
    assert budget.decoded_bytes == _MEMBER


# --- Joining a nest (archive-reading, "A reader opened inside another joins its nest")


def _payload(size: int, zeros_per_byte: int, seed: int = 1) -> bytes:
    """``size`` bytes of one random byte then ``zeros_per_byte`` zeros, repeated: the
    run length sets how far gzip compresses it."""
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        out += rng.randbytes(1) + b"\0" * zeros_per_byte
    return bytes(out[:size])


def _tar_of(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_a_child_with_no_config_uses_its_parents() -> None:
    outer = _stored_zip({"a": b"a"})
    inner = _stored_zip({f"m{i}": b"x" for i in range(3)})
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=2))
    # ZIP applies ``max_members`` at parse: the open raises.
    with (
        archivey.open_archive(io.BytesIO(outer), config=config) as parent,
        pytest.raises(ResourceLimitError, match="max_members=2"),
    ):
        archivey.open_archive(io.BytesIO(inner), parent=parent).close()


def test_a_closed_parent_still_takes_children() -> None:
    """Extract, leave the ``with``, then open what was extracted: the nest holds."""
    outer = _stored_zip({f"o{i}": b"x" for i in range(3)})
    inner = _stored_zip({f"i{i}": b"x" for i in range(3)})
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=5))
    with archivey.open_archive(io.BytesIO(outer), config=config) as parent:
        parent.members()
    with archivey.open_archive(io.BytesIO(inner), parent=parent) as child:
        assert child._nest_parent is parent  # type: ignore[attr-defined]
        with pytest.raises(ResourceLimitError, match="max_members=5"):
            child.members()
    # Without ``parent=``, a separate nest lists all three.
    with archivey.open_archive(io.BytesIO(inner), config=config) as alone:
        assert len(alone.members()) == 3


def test_a_child_listed_twice_counts_its_members_once() -> None:
    data = _stored_zip({f"m{i}": b"x" for i in range(3)})
    nest = _Nest()
    with _open(data, nest) as child:
        child.members()
        list(child)
        child.members()
    assert nest.members == 3


def test_nine_archives_chain_and_the_tenth_is_refused() -> None:
    data = _stored_zip({"a": b"a"})
    readers = [archivey.open_archive(io.BytesIO(data))]
    try:
        for _ in range(MAX_NESTED_DEPTH):
            readers.append(archivey.open_archive(io.BytesIO(data), parent=readers[-1]))
        assert len(readers) == MAX_NESTED_DEPTH + 1
        with pytest.raises(UnsupportedFeatureError, match="nested more than"):
            archivey.open_archive(io.BytesIO(data), parent=readers[-1])
    finally:
        for reader in readers:
            reader.close()


def test_a_parent_child_runs_its_own_name_checks() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for content in (b"1", b"2"):
            info = tarfile.TarInfo("same")
            info.size = 1
            tf.addfile(info, io.BytesIO(content))
    data = buf.getvalue()
    with (
        archivey.open_archive(io.BytesIO(_stored_zip({"a": b"a"}))) as parent,
        archivey.open_archive(io.BytesIO(data), parent=parent) as child,
    ):
        child.members()
        codes = set(child.diagnostics.counts)
    assert "member_name_duplicate" in codes


def test_a_child_config_tightens_the_nest_total_but_cannot_loosen_it() -> None:
    outer = _stored_zip({f"o{i}": b"x" for i in range(5)})
    eight = _stored_zip({f"i{i}": b"x" for i in range(8)})
    with archivey.open_archive(io.BytesIO(outer)) as parent:
        parent.members()
        tight = ArchiveyConfig(
            listing_limits=ListingLimits(max_members=10, max_metadata_bytes=None)
        )
        # 5 drawn by the parent; the child's own 10 holds its draws on the nest,
        # though its own listing of 8 would fit.
        with (
            archivey.open_archive(io.BytesIO(eight), parent=parent, config=tight) as c,
            pytest.raises(ResourceLimitError, match="would list 11 members"),
        ):
            c.members()
    small = ArchiveyConfig(listing_limits=ListingLimits(max_members=5))
    three = _stored_zip({f"i{i}": b"x" for i in range(3)})
    with archivey.open_archive(
        io.BytesIO(_stored_zip({f"o{i}": b"x" for i in range(3)})), config=small
    ) as parent:
        parent.members()
        loose = ArchiveyConfig(listing_limits=ListingLimits.UNLIMITED)
        with (
            archivey.open_archive(io.BytesIO(three), parent=parent, config=loose) as c,
            pytest.raises(ResourceLimitError, match="max_members=5"),
        ):
            c.members()


def test_a_reader_a_password_provider_opens_does_not_join_the_nest(
    tmp_path,
) -> None:
    """The first reader built in the open takes the link; one a callback opens later
    in it (here, to answer a header-encrypted 7z's password) stays outside."""
    pytest.importorskip("py7zr")
    pytest.importorskip("cryptography")
    from tests.test_sevenzip_reader import _write_py7zr_archive

    archive = tmp_path / "enc.7z"
    _write_py7zr_archive(
        archive, {"a.txt": b"a"}, password="secret", header_encryption=True
    )
    other_data = _stored_zip({f"x{i}": b"x" for i in range(4)})
    seen: list[object] = []

    def provider(request: object) -> str:
        with archivey.open_archive(io.BytesIO(other_data)) as other:
            other.members()
            seen.append(other._nest_parent)  # type: ignore[attr-defined]
        return "secret"

    nest = _Nest()
    with nest.open(archive, password=provider) as child:
        assert child._nest_parent is nest.root  # type: ignore[attr-defined]
        assert child.read("a.txt") == b"a"
    assert seen == [None]
    assert nest.members == 1


def test_extraction_limits_stay_per_call(tmp_path) -> None:
    data = _stored_zip({"a": b"x" * 1000, "b": b"y" * 1000})
    limits = archivey.ExtractionLimits(max_extracted_bytes=1500)
    with archivey.open_archive(io.BytesIO(data)) as parent:
        with pytest.raises(ResourceLimitError):
            parent.extract_all(tmp_path / "p", limits=limits)
        with (
            archivey.open_archive(io.BytesIO(data), parent=parent) as child,
            pytest.raises(ResourceLimitError),
        ):
            child.extract_all(tmp_path / "c", limits=limits)
        ok = archivey.ExtractionLimits(max_extracted_bytes=2000)
        with archivey.open_archive(io.BytesIO(data), parent=parent) as child:
            child.extract_all(tmp_path / "c2", limits=ok)


# --- The nest ratio (archive-reading, "Limits apply per nest", Ratio) ---------------

_RATIO = ArchiveyConfig(
    decoder_limits=DecoderLimits(max_ratio=100, ratio_activation_threshold=64 * 1024)
)


def test_a_small_bomb_in_a_large_outer_is_refused_linked_or_not(tmp_path) -> None:
    """Linking never loosens the child's own rule: it is judged against its own
    size, not the larger outer archive's."""
    bomb = gzip.compress(_tar_of({"z": b"\0" * (4 << 20)}), mtime=0)
    outer = _stored_zip(
        {"bomb.tar.gz": bomb, "pad": random.Random(2).randbytes(1 << 20)}
    )
    with archivey.open_archive(io.BytesIO(outer), config=_RATIO) as parent:
        copy = tmp_path / "bomb.tar.gz"
        copy.write_bytes(parent.read("bomb.tar.gz"))
        for kwargs in ({"parent": parent}, {"config": _RATIO}):
            with (
                archivey.open_archive(copy, **kwargs) as child,  # type: ignore[arg-type]
                pytest.raises(ResourceLimitError, match="ratio"),
            ):
                child.read("z")


def _compounding_outer() -> tuple[bytes, bytes]:
    """A ``.tar.gz`` of forty copies of one ``.tar.gz``: each level within 100:1 on
    its own, the nest's sum about 400 times the outer archive's size."""
    inner_raw = _tar_of({"p.bin": _payload(400_000, 60)})
    inner = gzip.compress(inner_raw, mtime=0)
    files = {f"i{k}.tar.gz": inner for k in range(40)}
    files["pad.bin"] = random.Random(1).randbytes(20_000)
    outer = gzip.compress(_tar_of(files), mtime=0)
    assert len(inner_raw) / len(inner) < 100
    return outer, inner


def test_nesting_cannot_compound_the_ratio() -> None:
    outer, _inner = _compounding_outer()
    with archivey.open_archive(io.BytesIO(outer), config=_RATIO) as parent:
        names = [m.name for m in parent.members() if m.name.endswith(".tar.gz")]
        with pytest.raises(ResourceLimitError, match="Nest decompression ratio"):
            for name in names:
                with archivey.open_archive(
                    io.BytesIO(parent.read(name)), parent=parent
                ) as child:
                    child.read("p.bin")


def test_unlinked_the_same_levels_each_pass() -> None:
    outer, _inner = _compounding_outer()
    with archivey.open_archive(io.BytesIO(outer), config=_RATIO) as parent:
        for member in parent.members():
            if member.name.endswith(".tar.gz"):
                data = parent.read(member)
                with archivey.open_archive(io.BytesIO(data), config=_RATIO) as child:
                    child.read("p.bin")


def test_an_outermost_directory_leaves_the_nest_ratio_off(tmp_path) -> None:
    outer, _inner = _compounding_outer()
    with archivey.open_archive(io.BytesIO(outer), config=_RATIO) as source:
        source.extract_all(tmp_path / "d")
    with archivey.open_archive(tmp_path / "d", config=_RATIO) as parent:
        for member in parent.members():
            if member.name.endswith(".tar.gz"):
                with archivey.open_archive(
                    io.BytesIO(parent.read(member)), parent=parent
                ) as child:
                    child.read("p.bin")


def _honest_tar_gz() -> tuple[bytes, bytes]:
    """A ``.tar.gz`` of about 500:1, past the default activation floor."""
    raw = _tar_of({f"f{i}": _payload(3 << 20, 4000, seed=i) for i in range(3)})
    data = gzip.compress(raw, mtime=0)
    assert 400 < len(raw) / len(data) < 800, len(raw) / len(data)
    return raw, data


def test_a_nest_of_one_is_held_only_to_its_own_rules(tmp_path) -> None:
    """Listed, read in full, then extracted twice: the nest ratio counts one pass."""
    _raw, data = _honest_tar_gz()
    with archivey.open_archive(io.BytesIO(data)) as reader:
        for member in reader.members():
            reader.read(member)
        reader.extract_all(tmp_path / "a")
        reader.extract_all(tmp_path / "b")


def test_rereads_add_nothing_to_the_nest_ratio() -> None:
    _raw, data = _honest_tar_gz()
    with archivey.open_archive(io.BytesIO(data)) as parent:
        mark = None
        for _ in range(50):
            parent.read("f0")
        mark = parent._nest._mark  # type: ignore[attr-defined]
        parent.read("f0")
        assert parent._nest._mark == mark  # type: ignore[attr-defined]


def test_a_deb_inner_tar_adds_nothing_to_the_nest_ratio() -> None:
    from tests.test_deb import _deb

    payload = _payload(8 << 20, 9000)
    deb = _deb(data=[("./", None), ("./big", payload)], data_kind="gz")
    # Over a quarter of the ratio: four overlapping counts of it would cross it.
    assert 250 < len(payload) / len(deb) < 800, len(payload) / len(deb)
    with archivey.open_archive(io.BytesIO(deb), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()


def test_a_childs_decoder_memory_is_its_own(tmp_path) -> None:
    """A ``parent=`` child is not charged the parent's declared working set."""
    import lzma

    raw = _tar_of({"a": b"a" * 1000})
    xz = lzma.compress(
        raw,
        format=lzma.FORMAT_XZ,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 40 << 20}],
    )
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=64 << 20))
    with archivey.open_archive(io.BytesIO(xz), config=config) as parent:
        parent.members()
        with archivey.open_archive(io.BytesIO(xz), parent=parent) as child:
            assert child.read("a") == b"a" * 1000


def test_nest_draws_unit_rules() -> None:
    """A lone reader's growth is never judged; a second reader's is, against the
    outermost size; growth past a reader's own mark is all that counts."""
    config = ArchiveyConfig(
        decoder_limits=DecoderLimits(max_ratio=10, ratio_activation_threshold=0)
    )
    account = NestAccount(lambda: 100)
    first = NestDraws(account, root=config, own=config, judges_ratio=True)
    second = NestDraws(account, root=config, own=config, judges_ratio=True)
    inner = NestDraws(account, root=config, own=config, judges_ratio=False)
    first.report_pass(900)
    first.report_pass(500)  # below its mark: nothing
    inner.report_pass(10_000)  # an open_nested reader adds nothing
    assert account.ratio_sum == 900
    second.report_pass(100)
    assert account.ratio_sum == 1000
    with pytest.raises(ResourceLimitError, match="Nest decompression ratio 10"):
        second.report_pass(101)


def test_a_nest_with_no_byte_cap_puts_no_counting_layer_on_reads() -> None:
    """With no ``max_nest_decoded_bytes`` anywhere, reads pay for no counting."""
    nest = _Nest(max_decoded_bytes=None)
    with nest.open(io.BytesIO(_zip(1, size=1000))) as reader:
        assert len(reader.read("m0.bin")) == 1000
    assert nest.decoded_bytes == 0
