"""``ArchiveyConfig.budget``: one pool of decoded bytes and members for many readers."""

from __future__ import annotations

import copy
import dataclasses
import gzip
import io
import pickle
import random
import tarfile
import threading
import zipfile

import pytest

import archivey
from archivey import ArchiveyConfig, ArchiveyUsageError, Budget, ResourceLimitError

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


def _open(data: bytes, budget: Budget, **kwargs: object) -> archivey.ArchiveReader:
    return archivey.open_archive(
        io.BytesIO(data), config=ArchiveyConfig(budget=budget), **kwargs
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_decoded_bytes": -1},
        {"max_members": True},
        {"max_members": "10"},
        {"max_decoded_bytes": 1.5},
    ],
)
def test_bad_limits_are_refused_at_construction(kwargs: dict[str, object]) -> None:
    with pytest.raises(ArchiveyUsageError, match="Budget"):
        Budget(**kwargs)  # type: ignore[arg-type]


def test_config_refuses_a_budget_of_another_type() -> None:
    with pytest.raises(ArchiveyUsageError, match="budget="):
        ArchiveyConfig(budget=10)  # type: ignore[arg-type]


def test_reads_of_two_readers_draw_from_one_pool() -> None:
    data = _zip()
    budget = Budget(max_decoded_bytes=3 * _MEMBER + _MEMBER // 2)
    with _open(data, budget) as first:
        assert len(first.read("m0.bin")) == _MEMBER
        assert len(first.read("m1.bin")) == _MEMBER
    with _open(data, budget) as second:
        assert len(second.read("m2.bin")) == _MEMBER
        with pytest.raises(ResourceLimitError, match="max_decoded_bytes=350000"):
            second.read("m3.bin")
    # The crossing read decoded one byte past what was left, not the whole member.
    assert budget.decoded_bytes == 3 * _MEMBER + _MEMBER // 2 + 1


def test_a_spent_budget_decodes_nothing_more() -> None:
    data = _zip()
    budget = Budget(max_decoded_bytes=10)
    with _open(data, budget) as reader:
        with pytest.raises(ResourceLimitError):
            reader.read("m0.bin")
        spent = budget.decoded_bytes
        with pytest.raises(ResourceLimitError), reader.open("m1.bin") as stream:
            stream.read(1)
    assert budget.decoded_bytes == spent


def test_a_member_under_the_budget_reads_whole() -> None:
    budget = Budget(max_decoded_bytes=_MEMBER)
    with _open(_zip(1), budget) as reader:
        assert reader.read("m0.bin") == b"\0" * _MEMBER
    assert budget.decoded_bytes == _MEMBER


def test_tar_member_reads_draw_too() -> None:
    budget = Budget(max_decoded_bytes=2 * _MEMBER)
    with _open(_tar(), budget, streaming=True) as reader:
        read = []
        with pytest.raises(ResourceLimitError, match="Budget exhausted"):
            for member, stream in reader.stream_members():
                assert stream is not None
                read.append((member.name, len(stream.read())))
    assert read == [("t0.bin", _MEMBER), ("t1.bin", _MEMBER)]


def test_a_forward_seek_draws_the_bytes_it_skips() -> None:
    budget = Budget(max_decoded_bytes=_MEMBER // 2)
    with (
        _open(_zip(1), budget, seekable_members=True) as reader,
        reader.open("m0.bin") as stream,
    ):
        stream.seek(1000)
        assert stream.read(1) == b"\0"
        assert budget.decoded_bytes == 1001
        stream.seek(_MEMBER - 1)
        with pytest.raises(ResourceLimitError, match="Budget exhausted"):
            stream.read(1)
    assert budget.decoded_bytes <= _MEMBER // 2 + 1


def test_members_draw_once_per_reader() -> None:
    data = _zip(5)
    budget = Budget(max_members=12)
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
    budget = Budget(max_decoded_bytes=2 * _MEMBER + 10)
    with (
        _open(_zip(5), budget) as reader,
        pytest.raises(ResourceLimitError, match="Budget exhausted"),
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
    budget = Budget(max_decoded_bytes=len(inner) + _MEMBER + _MEMBER // 2)
    with _open(buf.getvalue(), budget) as outer:
        nested_bytes = outer.read("inner.zip")
        assert budget.decoded_bytes == len(inner)
        with _open(nested_bytes, budget) as nested:
            assert len(nested.read("m0.bin")) == _MEMBER
            with pytest.raises(ResourceLimitError, match="Budget exhausted"):
                nested.read("m1.bin")


def test_threads_share_one_count() -> None:
    data = _zip(4, size=50_000)
    budget = Budget(max_decoded_bytes=None)
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


def test_copies_share_the_budget_and_pickle_is_refused() -> None:
    budget = Budget(max_members=3)
    config = ArchiveyConfig(budget=budget)
    assert copy.copy(budget) is budget
    assert copy.deepcopy(budget) is budget
    assert copy.deepcopy(config).budget is budget
    assert dataclasses.replace(config, read_link_targets=False).budget is budget
    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(budget)


def test_repr_shows_limits_and_counts() -> None:
    budget = Budget(max_decoded_bytes=5, max_members=None)
    assert repr(budget) == (
        "Budget(max_decoded_bytes=5, max_members=None; decoded_bytes=0, members=0)"
    )


def _no_translation(exc: Exception) -> None:
    return None


def test_two_holds_on_a_lazy_codec_handle_both_draw() -> None:
    # A codec handle not yet opened can get a ratio hold and the budget's hold; the
    # second wraps outside the first. Fails if ``_hold_inner`` keeps only the last.
    from archivey.internal.streams.archive_stream import ArchiveStreamImpl
    from archivey.internal.streams.counting import BudgetDrawStream

    first, second = Budget(), Budget()
    stream = ArchiveStreamImpl(
        lambda: io.BytesIO(b"abc"), translate=_no_translation, lazy=True
    )
    assert stream._inner is None
    stream._hold_inner(lambda inner: BudgetDrawStream(inner, first))
    stream._hold_inner(lambda inner: BudgetDrawStream(inner, second))
    assert stream.read() == b"abc"
    assert (first.decoded_bytes, second.decoded_bytes) == (3, 3)


def test_a_collapsed_lazy_handle_keeps_its_hold() -> None:
    # A lazy handle collapsed into another before it opened still serves through
    # its hold. Fails if ``_collapse_nested`` drops ``_inner_wrap``.
    from archivey.internal.streams.archive_stream import ArchiveStreamImpl
    from archivey.internal.streams.counting import BudgetDrawStream

    budget = Budget()
    nested = ArchiveStreamImpl(
        lambda: io.BytesIO(b"abc"), translate=_no_translation, lazy=True
    )
    nested._hold_inner(lambda inner: BudgetDrawStream(inner, budget))
    outer = ArchiveStreamImpl(lambda: nested, translate=_no_translation)
    assert outer.read() == b"abc"
    assert nested.closed
    assert budget.decoded_bytes == 3


def test_a_seek_to_the_end_is_held_to_the_budget() -> None:
    budget = Budget(max_decoded_bytes=1000)
    with (
        _open(_zip(1, size=5 * _MEMBER), budget, seekable_members=True) as reader,
        reader.open("m0.bin") as stream,
        pytest.raises(ResourceLimitError, match="Budget exhausted"),
    ):
        stream.seek(0, io.SEEK_END)
    # The deflate stream cannot size its end, so the seek decodes toward it in drawn
    # steps and stops one byte past the budget.
    assert budget.decoded_bytes <= 1001


def test_a_refused_seek_to_a_known_target_draws_nothing() -> None:
    from archivey.internal.streams.counting import BudgetDrawStream

    budget = Budget(max_decoded_bytes=1000)
    stream = BudgetDrawStream(io.BytesIO(b"x" * 5000), budget)
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

    budget = Budget(max_decoded_bytes=1000)
    stream = BudgetDrawStream(io.BytesIO(b"x" * 5000), budget)
    assert stream.try_get_size() is None
    with pytest.raises(ResourceLimitError, match="Budget exhausted"):
        stream.seek(0, io.SEEK_END)
    assert budget.decoded_bytes == 1001
    roomy = Budget(max_decoded_bytes=10_000)
    stream = BudgetDrawStream(io.BytesIO(b"x" * 5000), roomy)
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
    budget = Budget()
    with _open(_tar_gz(), budget, streaming=streaming) as reader:
        assert _read_last(reader, "t2.bin") == b"t" * _MEMBER
    assert budget.decoded_bytes >= 3 * _MEMBER


def test_a_tar_gz_skip_stops_at_the_budget() -> None:
    budget = Budget(max_decoded_bytes=_MEMBER + _MEMBER // 2)
    with (
        _open(_tar_gz(), budget, streaming=True) as reader,
        pytest.raises(ResourceLimitError, match="Budget exhausted"),
    ):
        _read_last(reader, "t2.bin")


def test_a_tar_gz_member_read_is_drawn_once() -> None:
    data = _tar(3)
    budget = Budget()
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
    budget = Budget()
    with _open(data, budget) as reader:
        assert reader.read("holes.bin").endswith(b"hello")
    assert budget.decoded_bytes >= 4 * _MEMBER
    budget = Budget(max_decoded_bytes=_MEMBER)
    with (
        _open(data, budget) as reader,
        pytest.raises(ResourceLimitError, match="Budget exhausted"),
    ):
        reader.read("holes.bin")
    assert budget.decoded_bytes <= _MEMBER + 1 + len(data) + 2048


def test_a_streaming_zip_draws_the_members_it_drains() -> None:
    """A bit-3 member nobody reads is decoded as far as the pass needs (the start a
    link target could be), and the scan finds the rest: that decode is drawn."""
    data = _zip_bit3()
    budget = Budget()
    with _open_pipe(data, budget) as reader:
        assert _read_last(reader, "m3.bin") == b"\3" * _MEMBER
    drained = budget.decoded_bytes - _MEMBER
    assert drained > 0
    budget = Budget(max_decoded_bytes=_MEMBER + drained - 1)
    with (
        _open_pipe(data, budget) as reader,
        pytest.raises(ResourceLimitError, match="Budget exhausted"),
    ):
        _read_last(reader, "m3.bin")


def test_a_streaming_zip_member_read_is_drawn_once() -> None:
    budget = Budget()
    with _open_pipe(_zip_bit3(), budget) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert len(stream.read()) == _MEMBER
    assert budget.decoded_bytes == 4 * _MEMBER


def _open_pipe(data: bytes, budget: Budget) -> archivey.ArchiveReader:
    from tests.streams_util import NonSeekableBytesIO

    return archivey.open_archive(
        NonSeekableBytesIO(data), config=ArchiveyConfig(budget=budget), streaming=True
    )


def test_a_cab_folder_draws_the_members_it_decodes_past() -> None:
    from tests.cab_util import CabFile, CabFolder, write_cab

    files = [CabFile(f"c{i}.bin", bytes([i]) * _MEMBER) for i in range(3)]
    data = write_cab(files, [CabFolder("mszip")])
    budget = Budget()
    with _open(data, budget) as reader:
        assert reader.read("c2.bin") == b"\2" * _MEMBER
    assert budget.decoded_bytes == 3 * _MEMBER
    budget = Budget(max_decoded_bytes=_MEMBER)
    with (
        _open(data, budget) as reader,
        pytest.raises(ResourceLimitError, match="Budget exhausted"),
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
    budget = Budget()
    with _open(data, budget, streaming=True) as reader:
        assert _read_last(reader, "opt/f2") == blobs[2]
    assert budget.decoded_bytes >= 3 * _MEMBER
    # Read whole, each member is drawn once: by the layer, not again by itself.
    budget = Budget()
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
    budget = Budget()
    with _open(data, budget, streaming=True) as reader:
        assert _read_last(reader, "f2") == b"c" * _MEMBER
    assert budget.decoded_bytes >= 3 * _MEMBER
    budget = Budget()
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
    budget = Budget(max_decoded_bytes=20_000)
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with (
        archivey.open_archive(
            source, config=ArchiveyConfig(budget=budget), streaming=True
        ) as reader,
        pytest.raises(ResourceLimitError, match="Budget exhausted"),
    ):
        for _member, stream in reader.stream_members():
            assert stream is not None
            stream.read()
    assert budget.decoded_bytes == 20_001
