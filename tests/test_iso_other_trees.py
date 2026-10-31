"""An ISO image whose Joliet or UDF tree holds a file the listed tree does not.

Linux and xorriso read Rock Ridge; Windows and 7-Zip read Joliet, and UDF first where
the image has it. A file put in one tree only is seen by some readers and hidden from
the others, so ``MEMBER_READERS_DISAGREE`` reports a file that only an unlisted tree
holds, matched by the data each file points at.
"""

from __future__ import annotations

import io
import logging

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticPolicy,
    ReaderDisagreementContext,
)
from archivey.exceptions import DiagnosticRaisedError
from tests.conftest import requires

pytestmark = requires("pycdlib")


def _image(
    files: dict[str, tuple[bytes, set[str]]],
    *,
    rock_ridge: bool = True,
    udf: bool = False,
) -> bytes:
    """An image holding each file in the trees named ("iso", "joliet", "udf").

    Rock Ridge names ride the ISO 9660 records, so "iso" puts a file in both.
    """
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(
        interchange_level=3,
        rock_ridge="1.09" if rock_ridge else None,
        joliet=3,
        udf="2.60" if udf else None,
    )
    for name, (data, trees) in files.items():
        iso_path = f"/{name.upper()}.;1"
        kwargs: dict[str, str] = {"joliet_path": f"/{name}"}
        if rock_ridge:
            kwargs["rr_name"] = name
        if udf:
            kwargs["udf_path"] = f"/{name}"
        iso.add_fp(io.BytesIO(data), len(data), iso_path, **kwargs)
        if "iso" not in trees:
            iso.rm_hard_link(iso_path=iso_path)
        if "joliet" not in trees:
            iso.rm_hard_link(joliet_path=f"/{name}")
        if udf and "udf" not in trees:
            iso.rm_hard_link(udf_path=f"/{name}")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _reported(image: bytes) -> tuple[list[str], list[tuple[str, str]]]:
    with open_archive(io.BytesIO(image)) as reader:
        names = sorted(m.name for m in reader.members())
        found = [
            (d.context.member_name, d.context.shape)
            for d in reader.diagnostics.retained
            if isinstance(d.context, ReaderDisagreementContext)
        ]
    return names, sorted(found)


ALL = {"iso", "joliet", "udf"}


def test_a_file_only_in_joliet_is_reported() -> None:
    image = _image({"both": (b"both", ALL), "hidden": (b"hidden", {"joliet"})})
    assert _reported(image) == (["both"], [("hidden", "file_only_in_joliet")])


def test_a_file_only_in_udf_is_reported() -> None:
    image = _image({"both": (b"both", ALL), "hidden": (b"hidden", {"udf"})}, udf=True)
    assert _reported(image) == (["both"], [("hidden", "file_only_in_udf")])


def test_a_file_the_listed_tree_alone_holds_is_not_reported() -> None:
    """The listed tree's members are all visible; only an unseen file is hidden."""
    image = _image({"both": (b"both", ALL), "rr": (b"rock ridge", {"iso"})})
    assert _reported(image) == (["both", "rr"], [])


def test_files_in_every_tree_report_nothing() -> None:
    image = _image(
        {"a": (b"one", ALL), "b": (b"two", ALL), "empty": (b"", ALL)}, udf=True
    )
    assert _reported(image) == (["a", "b", "empty"], [])


def test_empty_files_are_not_compared() -> None:
    """Empty files share one extent, so a hidden one cannot be told apart."""
    image = _image({"both": (b"both", ALL), "empty": (b"", {"joliet"})})
    assert _reported(image) == (["both"], [])


def test_joliet_listed_compares_udf_only() -> None:
    """Without Rock Ridge, Joliet is the listed tree."""
    image = _image(
        {"both": (b"both", ALL), "hidden": (b"hidden", {"udf"})},
        rock_ridge=False,
        udf=True,
    )
    assert _reported(image) == (["both"], [("hidden", "file_only_in_udf")])


def test_the_reports_stop_at_sixteen_per_tree() -> None:
    files = {"both": (b"both", ALL)} | {
        f"h{i:02}": (f"hidden {i}".encode(), {"joliet"}) for i in range(20)
    }
    _, found = _reported(_image(files))
    assert len(found) == 16


def test_advisory_info_and_pedantic_refuses(caplog: pytest.LogCaptureFixture) -> None:
    image = _image({"both": (b"both", ALL), "hidden": (b"hidden", {"joliet"})})
    caplog.set_level(logging.DEBUG, logger="archivey")
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with open_archive(io.BytesIO(image), config=strict) as reader:
        reader.members()
    levels = {
        record.levelno
        for record in caplog.records
        if getattr(record, "diagnostic_code", None)
        is DiagnosticCode.MEMBER_READERS_DISAGREE
    }
    assert levels == {logging.INFO}
    pedantic = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.PEDANTIC)
    with (
        open_archive(io.BytesIO(image), config=pedantic) as reader,
        pytest.raises(DiagnosticRaisedError),
    ):
        reader.members()
