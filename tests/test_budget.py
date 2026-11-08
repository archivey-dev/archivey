"""``ArchiveyConfig.budget``: one pool of decoded bytes and members for many readers."""

from __future__ import annotations

import copy
import dataclasses
import io
import pickle
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
