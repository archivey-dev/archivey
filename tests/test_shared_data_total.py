"""Members that hand out the same data bytes are held to one total across members.

A XAR heap entry can be named by many ``<file>`` records (``xar --coalesce-heap``
writes that for identical files), and an ISO extent by many directory records (how ISO
stores hard links). A hard link or symlink in a TAR or RPM is its own member whose
read hands out its target's data. Each such member costs the archive a small record
and its read is no bigger than its target's, so the per-member ratio never refuses
one. The archive-wide ratio counts each member the caller reads (``ReadRatioTally`` on
``open()`` and ``stream_members()``, ``BombTracker`` on extraction), a link as its own
member, so the members together stop at ``max_ratio`` times the archive's size. ZIP
and CAB refuse overlapping members as damage instead (``test_zip_*`` and
``test_cab.py``). Extraction writes a link as a link, so only the sharing formats are
extracted here.
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import zlib
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveReader,
    ArchiveyConfig,
    DecoderLimits,
    open_archive,
)
from archivey.internal.bomb_tracker import AlwaysStopResourceLimitError
from tests.conftest import requires
from tests.test_rpm import _F, _build, _Package
from tests.xar_util import pack_xar

_KIB = 1024
# Random, so the shared bytes do not compress and each member's ratio stays near 1.
_DATA = os.urandom(64 * _KIB)
_SHARERS = 40
# The total, 40 times the shared bytes, is far over 4 times the archive's size; one
# member, about its size, is not. A floor of 0 judges from the first byte.
_TIGHT = ArchiveyConfig(
    decoder_limits=DecoderLimits(max_ratio=4.0, ratio_activation_threshold=0)
)


def _xar_sharing_one_heap_entry(count: int, *, encoding: str) -> bytes:
    """A XAR whose ``count`` files all name heap offset 0."""
    if encoding == "gzip":
        stored, style = zlib.compress(_DATA), "application/x-gzip"
    else:
        stored, style = _DATA, "application/octet-stream"
    digest = hashlib.sha1(_DATA).hexdigest()
    files = "".join(
        f'<file id="{i + 1}"><name>f{i}</name><type>file</type><data>'
        f"<length>{len(stored)}</length><offset>0</offset><size>{len(_DATA)}</size>"
        f'<encoding style="{style}"/>'
        f'<extracted-checksum style="sha1">{digest}</extracted-checksum>'
        "</data></file>"
        for i in range(count)
    )
    toc = f'<?xml version="1.0" encoding="UTF-8"?>\n<xar><toc>{files}</toc></xar>'
    return pack_xar(toc.encode(), stored, algorithm=0)


def _iso_sharing_one_extent(count: int) -> bytes:
    """An ISO whose ``count`` records all name one file's extent."""
    import pycdlib  # optional; the tests that call this require it

    iso = pycdlib.PyCdlib()
    iso.new()
    iso.add_fp(io.BytesIO(_DATA), len(_DATA), "/F0.;1")
    for index in range(1, count):
        iso.add_hard_link(iso_old_path="/F0.;1", iso_new_path=f"/F{index}.;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _rpm_hard_link_set(count: int) -> bytes:
    """An RPM whose ``count`` files form one hard-link set over one payload copy."""
    files = [_F(b"/opt/s", mode=0o040755)] + [
        _F(f"/opt/s/h{i}".encode(), data=_DATA, inode=7) for i in range(count)
    ]
    return _build(_Package(files))


def _tar_links(count: int, link_type: bytes) -> bytes:
    """A ``.tar.gz`` of one file and ``count - 1`` links of ``link_type`` to it."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo("f0")
        info.size = len(_DATA)
        tar.addfile(info, io.BytesIO(_DATA))
        for index in range(1, count):
            link = tarfile.TarInfo(f"f{index}")
            link.type = link_type
            link.linkname = "f0"
            tar.addfile(link)
    return out.getvalue()


_BUILDERS = {
    "xar-stored": lambda count: _xar_sharing_one_heap_entry(count, encoding="none"),
    "xar-gzip": lambda count: _xar_sharing_one_heap_entry(count, encoding="gzip"),
    "iso": _iso_sharing_one_extent,
    "rpm": _rpm_hard_link_set,
    "tar-hardlinks": lambda count: _tar_links(count, tarfile.LNKTYPE),
    "tar-symlinks": lambda count: _tar_links(count, tarfile.SYMTYPE),
}
_FORMATS = {
    "xar-stored": ArchiveFormat.XAR,
    "xar-gzip": ArchiveFormat.XAR,
    "iso": ArchiveFormat.ISO,
    "rpm": ArchiveFormat.RPM,
    "tar-hardlinks": ArchiveFormat.TAR_GZ,
    "tar-symlinks": ArchiveFormat.TAR_GZ,
}
_CASES = [
    pytest.param("xar-stored"),
    pytest.param("xar-gzip"),
    pytest.param("iso", marks=requires("pycdlib")),
    pytest.param("rpm"),
    pytest.param("tar-hardlinks"),
    pytest.param("tar-symlinks"),
]
# A pass hands out no stream for a link, so only the formats whose sharers are files.
_PASS_CASES = _CASES[:3]


def _open(case: str, raw: bytes, config: ArchiveyConfig | None = None) -> ArchiveReader:
    return open_archive(io.BytesIO(raw), format=_FORMATS[case], config=config)


def _drain_all(reader: ArchiveReader) -> int:
    """Read every member that hands out data, links included, as a scanner hashing
    each member would."""
    total = 0
    for member in reader.members():
        if member.is_file or member.is_link:
            total += len(reader.read(member))
    return total


@pytest.mark.parametrize("case", _CASES)
def test_reads_of_members_sharing_data_stop_at_the_archive_ratio(case: str) -> None:
    raw = _BUILDERS[case](_SHARERS)
    with (
        _open(case, raw, _TIGHT) as reader,
        pytest.raises(AlwaysStopResourceLimitError, match="Archive-wide"),
    ):
        _drain_all(reader)


@pytest.mark.parametrize("case", _PASS_CASES)
def test_a_pass_over_members_sharing_data_stops_at_the_archive_ratio(
    case: str,
) -> None:
    raw = _BUILDERS[case](_SHARERS)
    with (
        _open(case, raw, _TIGHT) as reader,
        pytest.raises(AlwaysStopResourceLimitError, match="Archive-wide"),
    ):
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()


@pytest.mark.parametrize("case", ["xar-stored", "xar-gzip", "iso"])
def test_extracting_members_sharing_data_stops_at_the_archive_ratio(
    case: str, tmp_path: Path
) -> None:
    if case == "iso":
        pytest.importorskip("pycdlib")
    raw = _BUILDERS[case](_SHARERS)
    with (
        _open(case, raw, _TIGHT) as reader,
        pytest.raises(AlwaysStopResourceLimitError, match="Archive-wide"),
    ):
        reader.extract_all(tmp_path)


@pytest.mark.parametrize("case", _CASES)
def test_a_few_members_sharing_data_read_under_the_default_limits(case: str) -> None:
    """Sharing is how these formats store identical files and hard links, not damage:
    a handful of sharers reads in full."""
    raw = _BUILDERS[case](3)
    with _open(case, raw) as reader:
        assert _drain_all(reader) == 3 * len(_DATA)
