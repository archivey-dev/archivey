"""The once-per-reader INFO record for an ``open()`` that decodes a solid block again.

On a 7z folder or a solid RAR each ``open()`` decodes the member's block from its
start, so an open whose member sits past bytes an earlier open decoded decodes them
again. The first such open logs one INFO record on ``archivey.backends``. A compressed
TAR keeps one decoder position across opens, so it never logs (its backward seeks are
``STREAM_REWIND_REDECOMPRESSES``), and neither does a ``DIRECT`` reader.
"""

from __future__ import annotations

import io
import logging
import tarfile
import threading
import zipfile
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, RarDecompressor, open_archive
from archivey.cli.logging_config import cli_logging, cli_opens_members
from archivey.cost import AccessCost
from tests.conftest import binary_refusal

_LOGGER = "archivey.backends"
_NAMES = ("a.txt", "b.txt", "c.txt")
_FIXTURES = Path(__file__).parent / "fixtures"
_SOLID_7Z = _FIXTURES / "sevenzip" / "solid_three_members.7z"
_NONSOLID_7Z = _FIXTURES / "sevenzip" / "links_mid_folder_nonsolid.7z"
_RAR_SOLID = _FIXTURES / "rar" / "basic_solid__.rar"
_RAR_GROUPS = _FIXTURES / "rar" / "solid_groups__.rar"
_UNRAR_REFUSAL = binary_refusal("unrar")
_UNAR_REFUSAL = binary_refusal("unar")


def _records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r for r in caplog.records if r.name == _LOGGER and "is solid" in r.getMessage()
    ]


def _data(name: str) -> bytes:
    return name.encode() * 10


def _tar_gz(tmp_path: Path) -> Path:
    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name in _NAMES:
            info = tarfile.TarInfo(name)
            info.size = len(_data(name))
            tar.addfile(info, io.BytesIO(_data(name)))
    return path


def _zip(tmp_path: Path) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name in _NAMES:
            z.writestr(name, _data(name))
    return path


def test_an_open_that_decodes_a_7z_folder_again_logs_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_SOLID_7Z) as reader:
        assert reader.cost.access_cost is AccessCost.SOLID
        assert reader.read("a.txt") == _data("a.txt")
        assert _records(caplog) == []
        assert reader.read("b.txt") == _data("b.txt")
        (record,) = _records(caplog)
        assert record.levelno == logging.INFO
        message = record.getMessage()
        assert "solid_three_members.7z" in message
        assert "'b.txt' decoded again 50 bytes" in message
        assert "stream_members()" in message
        reader.read("c.txt")
        with reader.open("b.txt") as stream:
            stream.read()
        assert len(_records(caplog)) == 1


def test_reading_the_first_member_again_does_not_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_SOLID_7Z) as reader:
        # a starts the folder: reading it again decodes only itself, which a
        # non-solid archive would pay too.
        reader.read("a.txt")
        reader.read("a.txt")
        assert _records(caplog) == []
        reader.read("b.txt")
        assert len(_records(caplog)) == 1


@pytest.mark.parametrize(
    ("first", "second", "again"),
    [
        # b decoded a as its prefix; opening a decodes a again.
        ("b.txt", "a.txt", 50),
        # c decoded a and b; b decodes a and itself again.
        ("c.txt", "b.txt", 100),
        # A member's own bytes do not count when it is read again; its prefix does.
        ("b.txt", "b.txt", 50),
    ],
)
def test_an_earlier_member_counts_the_bytes_decoded_again(
    caplog: pytest.LogCaptureFixture, first: str, second: str, again: int
) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_SOLID_7Z) as reader:
        reader.read(first)
        assert _records(caplog) == []
        reader.read(second)
        (record,) = _records(caplog)
        assert f"{second!r} decoded again {again} bytes" in record.getMessage()


def test_a_non_solid_7z_keeps_no_runs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_NONSOLID_7Z) as reader:
        assert reader.cost.access_cost is AccessCost.DIRECT
        for member in reader.members():
            if member.is_file:
                reader.read(member.name)
        assert reader._solid_decoded == {}
    assert _records(caplog) == []


def test_a_tar_gz_read_in_archive_order_does_not_log(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_tar_gz(tmp_path)) as reader:
        assert reader.cost.access_cost is AccessCost.SOLID
        for member in reader.members():
            assert reader.read(member.name) == _data(member.name)
    assert _records(caplog) == []


def test_each_reader_logs_its_own_record(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    path = _SOLID_7Z
    for _ in range(2):
        with open_archive(path) as reader:
            reader.read("a.txt")
            reader.read("b.txt")
    assert len(_records(caplog)) == 2


def test_stream_members_does_not_count(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_SOLID_7Z) as reader:
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()
        reader.read("b.txt")
    assert _records(caplog) == []


def test_a_direct_archive_never_logs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_zip(tmp_path)) as reader:
        assert reader.cost.access_cost is AccessCost.DIRECT
        for name in ("c.txt", "a.txt", "b.txt", "a.txt"):
            reader.read(name)
    assert _records(caplog) == []


def test_a_failed_open_does_not_count(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_SOLID_7Z) as reader:
        reader.read("a.txt")
        with pytest.raises(KeyError):
            reader.open("missing.txt")
        assert _records(caplog) == []
        reader.read("b.txt")
        assert len(_records(caplog)) == 1


def test_concurrent_opens_log_one_record(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_SOLID_7Z, concurrent_operations=True) as reader:
        reader.read("a.txt")
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def read(name: str) -> None:
            try:
                barrier.wait()
                reader.read(name)
            except BaseException as exc:  # noqa: BLE001 - re-raised in the main thread
                errors.append(exc)

        threads = [threading.Thread(target=read, args=(n,)) for n in ("b.txt", "c.txt")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
    assert len(_records(caplog)) == 1


@pytest.mark.skipif(_UNRAR_REFUSAL is not None, reason=f"needs unrar: {_UNRAR_REFUSAL}")
def test_a_solid_rar_logs_on_the_second_member(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    with open_archive(_RAR_SOLID) as reader:
        assert reader.cost.access_cost is AccessCost.SOLID
        reader.read("file1.txt")
        assert _records(caplog) == []
        reader.read("subdir/file2.txt")
        assert len(_records(caplog)) == 1


@pytest.mark.skipif(_UNAR_REFUSAL is not None, reason=f"needs unar: {_UNAR_REFUSAL}")
def test_unar_counts_each_solid_stream_on_its_own(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Two solid streams: a, b and then c, d. unar decodes only the member's stream.
    caplog.set_level(logging.INFO, logger=_LOGGER)
    config = ArchiveyConfig(rar_decompressor=RarDecompressor.UNAR)
    with open_archive(_RAR_GROUPS, config=config) as reader:
        reader.read("b.txt")
        reader.read("c.txt")
        assert _records(caplog) == []
        reader.read("d.txt")
        (record,) = _records(caplog)
        assert "'d.txt' decoded again 840 bytes" in record.getMessage()


def test_the_cli_drops_the_advice_for_its_own_opens() -> None:
    path = _SOLID_7Z
    err = io.StringIO()
    with cli_logging(verbose=True, err=err):
        with open_archive(path) as reader, cli_opens_members():
            reader.read("a.txt")
            reader.read("b.txt")
        assert "is solid" not in err.getvalue()
        with open_archive(path) as reader:
            reader.read("a.txt")
            reader.read("b.txt")
    assert "INFO: Archive" in err.getvalue()
    assert "is solid" in err.getvalue()
