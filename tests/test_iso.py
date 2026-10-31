"""ISO 9660 backend tests — Stage 4 (namespace auto-select + fidelity, cost, write/
password rejection, non-seekable rejection, corrupt handling) and the registry
degradation slice (ISO without pycdlib). Skipped when pycdlib is absent."""

from __future__ import annotations

import builtins
import contextlib
import io
import os
import struct
import subprocess
from collections.abc import Callable, Generator
from pathlib import Path
from typing import IO, Any

import pytest

from archivey import (
    ArchiveFormat,
    CompressionAlgorithm,
    CompressionMethod,
    DiagnosticCode,
    MemberType,
    detect_format,
    format_availability,
    open_archive,
)
from archivey.config import ArchiveyConfig, ListingLimits
from archivey.cost import AccessCost, ListingCost, StreamCapability
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    StreamNotSeekableError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.iso_reader import IsoHandler, _strip_version
from archivey.internal.format_adapter import IndexedReaderAdapter
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.streamtools import (
    DEFAULT_UNKNOWN_LENGTH_READ_STEP,
    SharedView,
)
from archivey.types import FormatSupport
from tests.conftest import requires, requires_binary
from tests.corruption_util import raises_corruption_not_truncation
from tests.streams_util import (
    FactSizedReadRecorder,
    NonSeekableBytesIO,
    ReadSizeRecorder,
    assert_seek_underflow_matches_bytesio,
)

pytestmark = requires("pycdlib")


def _build_iso(*, rock_ridge: bool, joliet: bool) -> bytes:
    """Build a small ISO with a file, a nested file, a directory, and (RR) a symlink."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    kwargs = {}
    if rock_ridge:
        kwargs["rock_ridge"] = "1.09"
    if joliet:
        kwargs["joliet"] = 3
    iso.new(interchange_level=3, **kwargs)
    iso.add_fp(
        io.BytesIO(b"hello world"),
        11,
        "/FILE.TXT;1",
        rr_name="file.txt" if rock_ridge else None,
        joliet_path="/file.txt" if joliet else None,
    )
    iso.add_fp(
        io.BytesIO(b""),
        0,
        "/EMPTY.TXT;1",
        rr_name="empty.txt" if rock_ridge else None,
        joliet_path="/empty.txt" if joliet else None,
    )
    iso.add_directory(
        "/DIR",
        rr_name="subdir" if rock_ridge else None,
        joliet_path="/subdir" if joliet else None,
    )
    iso.add_fp(
        io.BytesIO(b"nested!"),
        7,
        "/DIR/N.TXT;1",
        rr_name="n.txt" if rock_ridge else None,
        joliet_path="/subdir/n.txt" if joliet else None,
    )
    if rock_ridge:
        iso.add_symlink("/SYM.TXT;1", "sym", "file.txt")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


@pytest.fixture
def rock_ridge_iso(tmp_path: Path) -> Path:
    path = tmp_path / "rr.iso"
    path.write_bytes(_build_iso(rock_ridge=True, joliet=True))
    return path


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_iso_detected_by_extended_window() -> None:
    info = detect_format(io.BytesIO(_build_iso(rock_ridge=True, joliet=False)))
    assert info.format == ArchiveFormat.ISO
    assert info.detected_by == "magic"  # CD001 at offset 32 769


# ---------------------------------------------------------------------------
# Cost / format properties
# ---------------------------------------------------------------------------


def test_iso_cost(rock_ridge_iso: Path) -> None:
    with open_archive(rock_ridge_iso) as ar:
        assert ar.format == ArchiveFormat.ISO
        assert ar.cost.listing_cost == ListingCost.INDEXED
        assert ar.cost.access_cost == AccessCost.DIRECT
        assert ar.cost.stream_capability == StreamCapability.SEEKABLE
        assert ar.info.is_solid is False


# ---------------------------------------------------------------------------
# Namespace auto-select + metadata fidelity
# ---------------------------------------------------------------------------


def test_rock_ridge_namespace_and_fidelity(rock_ridge_iso: Path) -> None:
    with open_archive(rock_ridge_iso) as ar:
        assert ar.info.extra["iso.namespace"] == "rock_ridge"
        by_name = {m.name: m for m in ar.members()}
        f = by_name["file.txt"]  # original case + length preserved
        assert f.mode is not None and f.uid is not None and f.gid is not None
        assert f.modified is not None and f.modified.tzinfo is not None
        # pycdlib's TF record carries no creation time, only the attribute-change
        # time (st_ctime): that is ``ctime`` and ``created`` stays None.
        assert f.created is None
        assert f.ctime.tzinfo is not None
        sym = by_name["sym"]
        assert sym.type == MemberType.SYMLINK
        assert sym.link_target == "file.txt"
        assert by_name["subdir/"].type == MemberType.DIRECTORY


def test_rock_ridge_tf_with_both_times_fills_created_and_ctime(tmp_path: Path) -> None:
    # Rock Ridge stores a creation time and an attribute-change time side by side, so
    # a member can carry both. pycdlib writes TF flags 0x0e (modify, access,
    # attributes); rewriting them to 0x0b (creation, modify, attributes) keeps the
    # record length and turns the first stamp into a creation time, moved to 2020.
    image = _build_iso(rock_ridge=True, joliet=True)
    written = b"TF\x1a\x01\x0e\x7e"
    assert written in image
    path = tmp_path / "rr-created.iso"
    path.write_bytes(image.replace(written, b"TF\x1a\x01\x0b\x78"))
    with open_archive(path) as ar:
        f = ar.get("file.txt")
    assert f.created is not None and f.ctime is not None
    assert f.created.year == 2020
    assert f.ctime.year != 2020


def test_joliet_namespace_and_fidelity(tmp_path: Path) -> None:
    path = tmp_path / "joliet.iso"
    path.write_bytes(_build_iso(rock_ridge=False, joliet=True))
    with open_archive(path) as ar:
        assert ar.info.extra["iso.namespace"] == "joliet"
        f = ar.get("file.txt")  # Joliet preserves case
        # Joliet carries no POSIX metadata.
        assert f.mode is None and f.uid is None and f.gid is None
        assert f.ctime is None


def test_plain_iso_namespace_and_fidelity(tmp_path: Path) -> None:
    path = tmp_path / "plain.iso"
    path.write_bytes(_build_iso(rock_ridge=False, joliet=False))
    with open_archive(path) as ar:
        assert ar.info.extra["iso.namespace"] == "iso9660"
        names = {m.name for m in ar.members()}
        # Plain ISO 9660: upper-case 8.3 names, ;version suffix stripped.
        assert "FILE.TXT" in names
        assert "DIR/" in names
        assert ar.get("FILE.TXT").mode is None  # no POSIX metadata


_PVD_VOLUME_ID = slice(16 * 2048 + 40, 16 * 2048 + 72)


@requires_binary("xorriso")
def test_volume_id_written_as_utf8_is_the_comment(tmp_path: Path) -> None:
    """xorriso 1.5.6 stores ``-V`` as UTF-8 in the primary descriptor (its Joliet copy
    turns each non-ASCII byte into ``_``), so the comment reads it as a name is read."""
    (tmp_path / "a.txt").write_bytes(b"hi")
    path = tmp_path / "v.iso"
    subprocess.run(
        ["xorriso", "-as", "mkisofs", "-quiet", "-R", "-J", "-V", "Café vol"]
        + ["-o", str(path), str(tmp_path / "a.txt")],
        check=True,
        capture_output=True,
    )
    assert path.read_bytes()[_PVD_VOLUME_ID].startswith("Café vol".encode())
    with open_archive(path) as ar:
        assert ar.info.comment == "Café vol"


@pytest.mark.parametrize(
    ("encoding", "expected"),
    [(None, "caf\udce9 vol"), ("cp1252", "café vol"), ("utf-8", "caf\udce9 vol")],
)
def test_volume_id_decodes_as_a_byte_name(
    tmp_path: Path, encoding: str | None, expected: str
) -> None:
    # Not UTF-8: encoding= decodes it, as for a Rock Ridge or ISO 9660 name, and a byte
    # nothing decodes survives as a lone surrogate rather than U+FFFD.
    image = bytearray(_build_iso(rock_ridge=True, joliet=True))
    image[_PVD_VOLUME_ID] = b"caf\xe9 vol".ljust(32, b" ")
    path = tmp_path / "v.iso"
    path.write_bytes(image)
    with open_archive(path, encoding=encoding) as ar:
        assert ar.info.comment == expected


def test_volume_id_keeps_its_own_trailing_character(tmp_path: Path) -> None:
    # Only the standard's space padding is removed: a label ending in a no-break space
    # keeps it, though Python counts it as whitespace.
    image = bytearray(_build_iso(rock_ridge=True, joliet=True))
    image[_PVD_VOLUME_ID] = "Café\xa0".encode().ljust(32, b" ")
    path = tmp_path / "v.iso"
    path.write_bytes(image)
    with open_archive(path) as ar:
        assert ar.info.comment == "Café\xa0"


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def test_read_members(rock_ridge_iso: Path) -> None:
    with open_archive(rock_ridge_iso) as ar:
        assert ar.read("file.txt") == b"hello world"
        assert ar.read("subdir/n.txt") == b"nested!"
        assert ar.read("file.txt") == b"hello world"  # re-read / random access


def test_read_symlink_follows_to_target(rock_ridge_iso: Path) -> None:
    with open_archive(rock_ridge_iso) as ar:
        assert ar.read("sym") == b"hello world"


def test_read_from_seekable_stream() -> None:
    data = _build_iso(rock_ridge=True, joliet=False)
    with open_archive(io.BytesIO(data)) as ar:
        assert ar.read("file.txt") == b"hello world"


def test_read_empty_member(rock_ridge_iso: Path) -> None:
    with open_archive(rock_ridge_iso) as ar:
        assert ar.read("empty.txt") == b""


def test_seek_within_opened_member(rock_ridge_iso: Path) -> None:
    # The opened member stream (a view of the file's extent) is seekable once
    # SEEKABLE is declared.
    with (
        open_archive(rock_ridge_iso, seekable_members=True) as ar,
        ar.open("file.txt") as f,
    ):
        assert f.read(5) == b"hello"
        f.seek(0)
        assert f.read() == b"hello world"


def test_streaming_over_seekable_iso(rock_ridge_iso: Path) -> None:
    # ISO is random-access, but a streaming=True (forward-only) pass over a seekable source
    # still works and yields the members with their data.
    with open_archive(rock_ridge_iso, streaming=True) as ar:
        collected = {
            m.name: (s.read() if s is not None else None)
            for m, s in ar.stream_members()
        }
        assert collected["file.txt"] == b"hello world"
        assert collected["empty.txt"] == b""


def test_file_member_storage_attributes(rock_ridge_iso: Path) -> None:
    # ISO members are stored uncompressed and unencrypted, with no per-member checksum.
    with open_archive(rock_ridge_iso) as ar:
        m = ar.get("file.txt")
        assert m.type == MemberType.FILE
        assert m.size == len(b"hello world")
        assert m.compressed_size == m.size
        assert m.compression == (CompressionMethod(algo=CompressionAlgorithm.STORED),)
        assert m.is_encrypted is False
        assert not m.hashes


# ---------------------------------------------------------------------------
# Rejections: password, write, non-seekable
# ---------------------------------------------------------------------------


def test_password_is_accepted_and_recorded(rock_ridge_iso: Path) -> None:
    from archivey.diagnostics import DiagnosticCode

    with open_archive(rock_ridge_iso, password=b"secret") as reader:
        assert reader.diagnostics.counts[DiagnosticCode.PASSWORD_ARGUMENT_UNUSED] == 1


def test_non_seekable_iso_rejected() -> None:
    data = _build_iso(rock_ridge=True, joliet=False)
    with pytest.raises(StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(data), format=ArchiveFormat.ISO)


# ---------------------------------------------------------------------------
# Corrupt input
# ---------------------------------------------------------------------------

# Fixed tree (same member order as corpus ``basic``); layout varies by namespace flags.
_PYCDLIB_CYCLE_ENTRIES: tuple[tuple[str, bytes, bool], ...] = (
    ("file1.txt", b"Hello, world!", False),
    ("subdir/", b"", True),
    ("empty_file.txt", b"", False),
    ("empty_subdir/", b"", True),
    ("subdir/file2.txt", b"Hello, universe!", False),
    ("implicit_subdir/file3.txt", b"Hello there!", False),
)
# ``(rock_ridge, joliet) -> (image_len, bitflip_offset, byte_before_flip)``
_PYCDLIB_CYCLE_CASES: tuple[tuple[bool, bool, int, int, int], ...] = (
    # Plain ISO 9660 PVD walk: ``/SUBDIR`` extent 26, +66 closes a back-edge to root 23.
    (False, False, 61440, 53314, 0x01),
    # Rock Ridge PVD walk: RR padding shifts the cycle byte to +32 on the same extent.
    (True, False, 63488, 53280, 0x01),
    # Joliet SVD walk on the RR+Joliet image (found by the mutation harness).
    (True, True, 81920, 71746, 0x01),
)


def _build_pycdlib_cycle_fixture(*, rock_ridge: bool, joliet: bool) -> bytes:
    """ISO built from ``_PYCDLIB_CYCLE_ENTRIES`` with the requested namespaces."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    kwargs: dict[str, object] = {"interchange_level": 3}
    if rock_ridge:
        kwargs["rock_ridge"] = "1.09"
    if joliet:
        kwargs["joliet"] = 3
    iso.new(**kwargs)
    made_dirs: set[str] = set()

    def _ensure_dirs(rel: str) -> None:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            joined = "/".join(parts[:i])
            if joined and joined not in made_dirs:
                made_dirs.add(joined)
                iso_path = "/" + "/".join(p.upper()[:8] for p in joined.split("/"))
                iso.add_directory(
                    iso_path,
                    rr_name=parts[i - 1] if rock_ridge else None,
                    joliet_path="/" + joined if joliet else None,
                )

    counter = 0
    for name, contents, is_dir in _PYCDLIB_CYCLE_ENTRIES:
        rel = name.rstrip("/")
        _ensure_dirs(name)
        if is_dir:
            if rel not in made_dirs:
                made_dirs.add(rel)
                iso_path = "/" + "/".join(p.upper()[:8] for p in rel.split("/"))
                iso.add_directory(
                    iso_path,
                    rr_name=rel.split("/")[-1] if rock_ridge else None,
                    joliet_path="/" + rel if joliet else None,
                )
        else:
            counter += 1
            iso_dir = "/".join(p.upper()[:8] for p in rel.split("/")[:-1])
            iso_path = ("/" + iso_dir + "/" if iso_dir else "/") + f"F{counter}.TXT;1"
            iso.add_fp(
                io.BytesIO(contents),
                len(contents),
                iso_path,
                rr_name=rel.split("/")[-1] if rock_ridge else None,
                joliet_path="/" + rel if joliet else None,
            )
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _pycdlib_directory_cycle_image(
    *,
    rock_ridge: bool,
    joliet: bool,
    expected_len: int,
    bitflip_offset: int,
    byte_before_flip: int,
) -> bytes:
    """Flip one bit in ``/subdir``'s directory extent so pycdlib's open walk cycles."""
    data = bytearray(_build_pycdlib_cycle_fixture(rock_ridge=rock_ridge, joliet=joliet))
    assert len(data) == expected_len, (
        "fixture layout drifted — revisit cycle case table"
    )
    assert data[bitflip_offset] == byte_before_flip
    data[bitflip_offset] ^= 0x01
    return bytes(data)


def test_an_image_cut_inside_its_first_descriptor_is_truncated() -> None:
    # CD001 is present (so detection still picks ISO) but the volume descriptor is cut
    # off: the file ends before the image does.
    from archivey.exceptions import TruncatedError

    truncated = _build_iso(rock_ridge=True, joliet=False)[:32780]
    with pytest.raises(TruncatedError, match="ends before"):
        open_archive(io.BytesIO(truncated), format=ArchiveFormat.ISO)


def test_a_parser_error_is_named_without_its_repr() -> None:
    """A parser failure inside pycdlib (here ``struct.error`` from a path table moved
    to block 0) is shown as ``TypeName: text``, not as the repr of a Python error, and
    the message does not claim the image is damaged: the same arm catches errors from
    this backend's own code. The original stays the cause."""
    image = bytearray(_build_iso(rock_ridge=True, joliet=False))
    # Byte 140 of the primary descriptor is the low byte of the type L path table's
    # location.
    image[16 * 2048 + 140] = 0
    with (
        raises_corruption_not_truncation() as excinfo,
        open_archive(io.BytesIO(bytes(image)), format=ArchiveFormat.ISO),
    ):
        pass
    assert isinstance(excinfo.value.__cause__, struct.error)
    message = str(excinfo.value)
    cause = excinfo.value.__cause__
    assert message.startswith(
        "Error reading ISO image: a structure in the image could not be parsed "
        f"(struct.error: {cause})"
    )
    assert "damaged" not in message
    assert "error(" not in message


def test_an_error_from_this_backends_own_code_is_not_called_damage() -> None:
    exc = AttributeError("'NoneType' object has no attribute 'ce_entries'")
    translated = IsoHandler().translate_exception(exc)
    assert isinstance(translated, CorruptionError)
    assert str(translated) == (
        "Error reading ISO image: a structure in the image could not be parsed "
        "(AttributeError: 'NoneType' object has no attribute 'ce_entries')"
    )


def test_a_cut_image_keeps_pycdlib_text_without_its_repr() -> None:
    from archivey.exceptions import TruncatedError

    truncated = _build_iso(rock_ridge=True, joliet=False)[:32780]
    with pytest.raises(TruncatedError) as excinfo:
        open_archive(io.BytesIO(truncated), format=ArchiveFormat.ISO)
    message = str(excinfo.value)
    cause = excinfo.value.__cause__
    assert cause is not None
    assert str(cause)
    assert f"({cause})" in message
    assert f"{type(cause).__name__}(" not in message


# What pycdlib raises for a directory tree that loops back on itself.
_ISO_LOOP = r"ISO Directory Records form a loop"
_UDF_LOOP = r"UDF File Entries form a loop"


@pytest.mark.timeout(5)
@pytest.mark.parametrize(
    (
        "rock_ridge",
        "joliet",
        "expected_len",
        "bitflip_offset",
        "byte_before_flip",
    ),
    [
        pytest.param(*case, id=case_id)
        for case, case_id in zip(
            _PYCDLIB_CYCLE_CASES,
            ("plain", "rock-ridge", "joliet"),
            strict=True,
        )
    ],
)
def test_pycdlib_directory_cycle_does_not_hang(
    rock_ridge: bool,
    joliet: bool,
    expected_len: int,
    bitflip_offset: int,
    byte_before_flip: int,
) -> None:
    """Regression: corrupt ``/subdir`` must not hang pycdlib during ``open_fp``.

    ``pycdlib._walk_directories`` (used for the PVD / Rock Ridge tree *and* each
    supplementary namespace such as Joliet) enqueued child directory extents with no visit
    tracking before 1.22. One flipped bit in a directory record can add a child that points back at an
    ancestor extent; such a pycdlib then looped forever. ``open_fp`` walks every present namespace,
    so a Joliet-only cycle still bites RR+Joliet images even when archivey reads Rock Ridge.
    pycdlib before 1.22 hung here until pytest-timeout killed the test. From 1.22 it
    detects the loop and raises "ISO Directory Records form a loop", so the image is
    refused at open.
    """
    image = _pycdlib_directory_cycle_image(
        rock_ridge=rock_ridge,
        joliet=joliet,
        expected_len=expected_len,
        bitflip_offset=bitflip_offset,
        byte_before_flip=byte_before_flip,
    )
    with pytest.raises(CorruptionError, match=_ISO_LOOP):
        open_archive(io.BytesIO(image), format=ArchiveFormat.ISO)


def _udf_file_identifiers(data: bytes | bytearray) -> list[int]:
    """Offsets of every UDF File Identifier Descriptor (ECMA-167 4/14.4, tag 257)."""
    from pycdlib import udf

    return [
        offset
        for offset in range(0, len(data) - 40, 4)  # descriptors are 4-byte aligned
        if data[offset : offset + 2] == b"\x01\x01"
        and data[offset + 5] == 0
        and udf._compute_csum(bytes(data[offset : offset + 16])) == data[offset + 4]
    ]


def _udf_directory_cycle_image() -> bytes:
    """An ISO 9660 + UDF image whose UDF directory ``/D`` points back at the root.

    No tool writes a cyclic UDF tree, so the image is crafted (DR-24): pycdlib writes
    ``/D/F.TXT`` in both trees, then the root's File Identifier for ``D`` gets the
    root's own ICB block, and its tag CRC and checksum are recomputed so it still
    parses. The ISO 9660 tree is untouched.
    """
    import pycdlib
    from pycdlib import udf

    iso = pycdlib.PyCdlib()
    iso.new(udf="2.60")
    iso.add_directory("/D", udf_path="/D")
    iso.add_fp(io.BytesIO(b"x"), 1, "/D/F.TXT;1", udf_path="/D/F.TXT")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    data = bytearray(out.getvalue())

    def icb_block(offset: int) -> int:
        return int(struct.unpack_from("<I", data, offset + 24)[0])

    def identifier(offset: int) -> bytes:
        length = data[offset + 19]
        start = offset + 38 + struct.unpack_from("<H", data, offset + 36)[0]
        return bytes(data[start : start + length])

    fids = _udf_file_identifiers(data)
    # The root's parent entry (characteristics bit 3) names the root's own ICB.
    root_block = next(icb_block(off) for off in fids if data[off + 18] & 0x08)
    (target,) = [off for off in fids if identifier(off) == b"\x08D"]
    struct.pack_into("<I", data, target + 24, root_block)
    crc_length = struct.unpack_from("<H", data, target + 10)[0]
    body = bytes(data[target + 16 : target + 16 + crc_length])
    struct.pack_into("<H", data, target + 8, udf.crc_ccitt(body))
    data[target + 4] = udf._compute_csum(bytes(data[target : target + 16]))
    return bytes(data)


@pytest.mark.timeout(10)
def test_pycdlib_udf_directory_cycle_does_not_hang() -> None:
    """A UDF directory naming an ancestor must not hang pycdlib's walk in ``open_fp``.

    ``PyCdlib._walk_udf_directories`` enqueues each directory's File Entry with no
    visit tracking before 1.22, so this image made it parse the root's entries again and
    again, with memory growing about 65 MB a second, under default limits. From 1.22 it
    detects the loop and raises "UDF File Entries form a loop", so the image is refused
    at open, although its ISO 9660 tree is intact.
    """
    image = _udf_directory_cycle_image()
    with pytest.raises(CorruptionError, match=_UDF_LOOP):
        open_archive(io.BytesIO(image), format=ArchiveFormat.ISO)


def _udf_image_with_links(count: int) -> bytes:
    """An image whose ISO 9660 tree holds one file and whose UDF tree holds ``count``.

    A UDF hard link adds a name to the UDF tree only, so the UDF tree can outgrow the
    ISO 9660 one and a limit can be set between the two.
    """
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(udf="2.60")
    iso.add_fp(io.BytesIO(b"x"), 1, "/F.TXT;1", udf_path="/F0.TXT")
    for index in range(1, count):
        iso.add_hard_link(udf_old_path="/F0.TXT", udf_new_path=f"/F{index}.TXT")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def test_listing_limits_count_udf_entries_as_pycdlib_parses_them() -> None:
    """``max_members`` counts the UDF tree pycdlib parses at open, per tree.

    The ISO 9660 tree holds one file and the UDF tree twenty names. pycdlib parses 21
    File Identifiers in the UDF root, the parent entry and the twenty names, and only
    the twenty count: the parent entry is not a member. So a cap of exactly 20 opens,
    which is what pins that exclusion.
    """
    image = _udf_image_with_links(20)
    fits = ArchiveyConfig(listing_limits=ListingLimits(max_members=20))
    with open_archive(io.BytesIO(image), config=fits) as reader:
        assert [m.name for m in reader.members()] == ["F.TXT"]

    # A cap of five fits the one-member tree archivey lists, but pycdlib still parses
    # every UDF entry inside ``open_fp``, so the UDF tree is held to the same cap.
    below = ArchiveyConfig(listing_limits=ListingLimits(max_members=5))
    with pytest.raises(ResourceLimitError, match="max_members=5.*UDF"):
        open_archive(io.BytesIO(image), config=below)


def test_listing_limits_count_udf_bytes_as_pycdlib_parses_them() -> None:
    """``max_metadata_bytes`` weighs the UDF File Identifiers and File Entries too.

    Each UDF name costs a File Identifier and a File Entry of at least 176 bytes, so
    twenty names hold more than 4000 bytes while the ISO 9660 tree, with one file,
    holds well under 2000.
    """
    image = _udf_image_with_links(20)
    tight = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=2000))
    with pytest.raises(
        ResourceLimitError, match="max_metadata_bytes=2000.*UDF directory tree"
    ):
        open_archive(io.BytesIO(image), config=tight)
    with open_archive(io.BytesIO(_udf_image_with_links(1)), config=tight) as reader:
        assert [m.name for m in reader.members()] == ["F.TXT"]


def _image_with_trees(count: int, *, joliet: bool = True, udf: bool = True) -> bytes:
    """An image holding ``count`` files in its PVD tree and in each tree it asks for."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(
        interchange_level=3, joliet=3 if joliet else None, udf="2.60" if udf else None
    )
    for index in range(count):
        iso.add_fp(
            io.BytesIO(b"x"),
            1,
            f"/F{index}.TXT;1",
            joliet_path=f"/f{index}.txt" if joliet else None,
            udf_path=f"/f{index}.txt" if udf else None,
        )
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def test_max_metadata_bytes_is_one_budget_for_the_whole_image() -> None:
    """``max_metadata_bytes`` bounds the bytes of every tree pycdlib parses, together.

    pycdlib keeps every tree it parses, so a budget per tree let one image hold the
    budget once for each of its PVD, Joliet and UDF trees. With ten files, this image
    weighs about 540 bytes in its PVD tree, 580 in its Joliet tree and 2,540 in its
    UDF tree: each tree is under 3,000 bytes, and the three together are about 3,670.
    ``max_members`` stays per tree
    (``test_listing_limits_count_udf_entries_as_pycdlib_parses_them``).

    The first leg does not depend on UDF sizes: the same ten files weigh 542 bytes in a
    PVD-only image and 1,124 with a Joliet tree (542 + 582), so a cap of 800 opens the
    first and refuses the second, whose trees are each under it.
    """
    iso_trees_only = ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=800)
    )
    with open_archive(
        io.BytesIO(_image_with_trees(10, joliet=False, udf=False)),
        config=iso_trees_only,
    ) as reader:
        assert len(reader.members()) == 10
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=800"):
        open_archive(
            io.BytesIO(_image_with_trees(10, udf=False)), config=iso_trees_only
        )

    image = _image_with_trees(10)
    under_total = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=3000))
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=3000"):
        open_archive(io.BytesIO(image), config=under_total)

    fits = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=4000))
    with open_archive(io.BytesIO(image), config=fits) as reader:
        assert len(reader.members()) == 10


@pytest.mark.parametrize(
    ("tag", "fixed"),
    [pytest.param(261, 176, id="file-entry"), pytest.param(266, 216, id="extended")],
)
def test_a_udf_file_entry_is_weighed_by_the_lengths_it_declares(
    tag: int, fixed: int
) -> None:
    """The weight of a File Entry is its fixed part plus ``L_EA`` plus ``L_AD``.

    ECMA-167 puts the two lengths in the last 8 bytes of the fixed part: 176 bytes for
    a File Entry (4/14.9) and 216 for an Extended File Entry (4/14.17). pycdlib writes
    only File Entries, so the Extended one is a synthetic header here; it fails if
    tag 266 is read at the File Entry's offsets. The weight is capped by the bytes read.
    """
    from archivey.internal.backends.iso_reader import _udf_file_entry_size

    header = bytearray(fixed)
    struct.pack_into("<H", header, 0, tag)
    struct.pack_into("<LL", header, fixed - 8, 10, 48)
    assert _udf_file_entry_size(bytes(header) + bytes(1000)) == fixed + 58
    assert _udf_file_entry_size(bytes(header) + bytes(20)) == fixed + 20


def test_filesystem_oserror_propagates_unwrapped(tmp_path: Path) -> None:
    # A genuine OSError (missing file) is unrelated to ISO decoding and must propagate
    # unchanged, not be reclassified as CorruptionError (error-handling spec).
    missing = tmp_path / "does-not-exist.iso"
    with pytest.raises(FileNotFoundError):
        open_archive(missing, format=ArchiveFormat.ISO)


# ---------------------------------------------------------------------------
# Availability (FULL when pycdlib is present)
# ---------------------------------------------------------------------------


def test_iso_full_support_with_pycdlib() -> None:
    assert format_availability(ArchiveFormat.ISO).support == FormatSupport.FULL


def test_open_from_mid_positioned_stream(rock_ridge_iso: Path) -> None:
    # pycdlib addresses the image with absolute offsets; open_archive normalizes a
    # mid-positioned stream to a zero-origin view, so an embedded image still opens.
    junk = b"J" * 51
    stream = io.BytesIO(junk + rock_ridge_iso.read_bytes())
    stream.seek(len(junk))
    with open_archive(stream, format=ArchiveFormat.ISO) as ar:
        assert any(m.is_file for m in ar.members())


# ---------------------------------------------------------------------------
# Header-sized allocations
# ---------------------------------------------------------------------------


def _iso_with_oversized_root_directory(declared: int) -> bytes:
    """An ISO whose root directory record claims ``declared`` bytes of directory data.

    pycdlib clamps a *file*'s ``data_length`` to the image length before reading it
    but not a *directory*'s, and the root record sits at a fixed offset inside the
    primary volume descriptor, so only those eight bytes change. The both-endian
    field must be rewritten in both orders or pycdlib rejects it before reading.
    """
    blob = bytearray(_build_iso(rock_ridge=False, joliet=False))
    offset = 32768 + 156 + 10  # PVD + root directory record + data_length
    blob[offset : offset + 8] = struct.pack("<I", declared) + struct.pack(
        ">I", declared
    )
    return bytes(blob)


@pytest.mark.parametrize("length", ["fact", "hint", "unknown"])
def test_directory_data_length_does_not_drive_the_allocation(length: str) -> None:
    """A directory record's 32-bit length must not size a read of the image.

    It is read at ``open_fp`` time, before a member is listed, so a small image buys
    an allocation of up to 4 GiB — and the ``MemoryError`` it produced is not an
    ``ArchiveyError`` at all. Asking for the bytes is the observable: whether the
    allocation then succeeds depends on the machine.

    The three parameters are the three things the source can know about the image's
    length, and they take different branches of the bound. ``fact`` is a ``BytesIO``,
    whose length the boundary reads from its buffer, so the read is clamped to what is
    left; it fails against handing pycdlib an unbounded source, which passes
    4 294 967 040 straight through. ``hint`` advertises the fsspec ``size`` attribute,
    a caller's unverified claim, which must not clamp (an understating hint would
    truncate a legitimate read), so the read is stepped. ``unknown`` has neither, which
    is what an ordinary caller-supplied seekable file-like looks like; it is stepped
    too, and fails against bounding only when the length is known.
    """
    declared = 0xFFFFFF00
    data = _iso_with_oversized_root_directory(declared)
    source: FactSizedReadRecorder | ReadSizeRecorder = (
        FactSizedReadRecorder(data)
        if length == "fact"
        else ReadSizeRecorder(data, advertise_size=length == "hint")
    )

    with raises_corruption_not_truncation():
        open_archive(source, format=ArchiveFormat.ISO)

    assert source.requested, "the source was never read"
    # As in the TAR equivalent: a raw source sits under a ``BufferedReader`` whose
    # refill size is a runtime constant (``io.DEFAULT_BUFFER_SIZE``: 8 KiB through
    # 3.13, 128 KiB from 3.14), larger than this image on a recent Python. The bound is
    # one refill or, whichever is larger, the image when its length is a fact and the
    # step when it is not; what is pinned is that no read scales with ``declared``.
    reach = len(data) if length == "fact" else DEFAULT_UNKNOWN_LENGTH_READ_STEP
    bound = max(reach, io.DEFAULT_BUFFER_SIZE)
    assert max(source.requested) <= bound, (
        f"asked the source for {max(source.requested)} bytes "
        f"from a {len(data)}-byte image"
    )


def test_a_path_source_is_read_through_the_archive_source(
    rock_ridge_iso: Path,
) -> None:
    """Bounding a path source is only possible while pycdlib reads archivey's object.

    A path handed to ``PyCdlib.open`` would open its own file and leave nothing of
    archivey's underneath it, so there would be nowhere to put the bound. This pins
    the object rather than the allocation: the allocation itself is what the bound
    prevents, and provoking it to prove that costs gigabytes.
    ``test_directory_data_length_does_not_drive_the_allocation`` covers the bound on a
    source that can record what was asked of it.
    """
    with open_archive(rock_ridge_iso) as reader:
        assert isinstance(reader, IndexedReaderAdapter)
        assert isinstance(reader._source, ArchiveSource)
        assert reader._source.path == rock_ridge_iso
        # pycdlib reads a view of the shared source, which reads the archive source.
        assert isinstance(reader._reader._iso._cdfp, SharedView)
        assert reader._shared._handle is reader._source
        assert [m.name for m in reader.members()]


def test_a_path_source_refuses_the_same_image(tmp_path: Path) -> None:
    """The refusal reaches the path branch, not only the stream one."""
    path = tmp_path / "bomb.iso"
    path.write_bytes(_iso_with_oversized_root_directory(0xFFFFFF00))

    with raises_corruption_not_truncation():
        open_archive(path)


@contextlib.contextmanager
def _recording_opens(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[list[IO[bytes]], None, None]:
    """Collect every file object opened for ``path`` while the block runs.

    A handle leak is asserted on the objects themselves rather than on
    ``/proc/self/fd``, which does not exist on the Windows and macOS legs. Anything
    still open is closed on the way out, so a failing assertion does not leak from the
    test either.
    """
    real_open = builtins.open
    opened: list[IO[bytes]] = []

    def recording_open(file, *args, **kwargs):  # type: ignore[no-untyped-def]
        fp = real_open(file, *args, **kwargs)
        if isinstance(file, (str, os.PathLike)) and Path(file) == path:
            opened.append(fp)
        return fp

    monkeypatch.setattr(builtins, "open", recording_open)
    try:
        yield opened
    finally:
        # No ``monkeypatch.undo()``: the fixture unwinds it, and undoing here would
        # also drop patches a caller set before entering this block.
        for fp in opened:
            fp.close()


def test_a_refused_path_source_does_not_hold_its_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path open that fails must close the handle it opened, not wait for the GC.

    The ``ArchiveSource`` opens the path lazily, on pycdlib's first read, so it has
    something to bound (see ``test_a_path_source_is_read_through_the_archive_source``).
    A refusal after that open leaves the source reachable from the constructor's frame,
    and the exception's traceback keeps that frame alive for as long as the caller holds
    the exception — which an inventory or fuzz loop that catches and continues does for
    the whole batch, one descriptor per refused image. ``pytest.raises`` holds it here
    the same way.

    Fails against removing ``open_archive``'s close of the source when a backend
    constructor raises: every fp recorded below is then still open at the assertion.
    """
    path = tmp_path / "bomb.iso"
    path.write_bytes(_iso_with_oversized_root_directory(0xFFFFFF00))

    with _recording_opens(path, monkeypatch) as opened:
        with raises_corruption_not_truncation() as excinfo:
            open_archive(path, format=ArchiveFormat.ISO)
        # The traceback is what pinned the handle; assert it is still here, so this
        # test cannot pass by the exception having been collected instead.
        assert excinfo.value.__traceback__ is not None
        assert opened, "the source did not open the path"
        assert [fp for fp in opened if not fp.closed] == []


def test_a_failure_after_open_fp_is_translated_and_releases(
    rock_ridge_iso: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The release guard covers the whole constructor, not just ``open_fp``.

    The namespace auto-select runs two more pycdlib calls on the image after
    ``open_fp`` returns. They sat outside the ``try`` at first, which left two claims
    untrue of that window: a raise there leaked ``_owned_fp``, and it escaped as a bare
    ``PyCdlibException`` rather than as ``CorruptionError``. Neither is reachable
    through a crafted image — ``has_rock_ridge`` raises only on an uninitialized object
    — so the failure is injected rather than provoked. An unreachable window is still
    the shape the comment, the threat model and the PR body all describe, and the next
    call added to that block need not be as safe.

    Fails against a guard that ends at ``open_fp``: the raise arrives as
    ``PyCdlibInvalidISO`` and the recorded handle is still open.
    """
    from pycdlib.pycdlibexception import PyCdlibInvalidISO

    def boom(self) -> bool:  # type: ignore[no-untyped-def]
        raise PyCdlibInvalidISO("injected")

    monkeypatch.setattr("pycdlib.PyCdlib.has_rock_ridge", boom)

    with _recording_opens(rock_ridge_iso, monkeypatch) as opened:
        with raises_corruption_not_truncation() as excinfo:
            open_archive(rock_ridge_iso, format=ArchiveFormat.ISO)
        assert excinfo.value.__traceback__ is not None
        assert opened, "the reader did not open the path itself"
        assert [fp for fp in opened if not fp.closed] == []


def test_a_failing_iso_close_still_releases_the_handle(
    rock_ridge_iso: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closing is two steps, and the second must not depend on the first succeeding.

    ``_release_archive_handles`` closes the ``PyCdlib`` and then the handle this reader
    opened. Without the ``finally`` a raise out of the first skips the second, which
    leaks a descriptor on the ordinary close and, on the ``__init__`` path, replaces
    the error the image produced with the close error *and* leaves the fp open — the
    outcome the guard was added to prevent.

    Injected, like ``test_a_failure_after_open_fp_is_translated_and_releases``:
    ``PyCdlib.close()`` raises only on an object it never opened, which the
    ``_iso_opened`` flag already excludes. The same reasoning applies — a helper that
    promises one release path must not give up half of it on its own first failure.

    Fails against the sequential form: the close error still propagates, but the
    recorded handle is left open.
    """

    def boom(self) -> None:  # type: ignore[no-untyped-def]
        raise RuntimeError("injected close failure")

    monkeypatch.setattr("pycdlib.PyCdlib.close", boom)

    with _recording_opens(rock_ridge_iso, monkeypatch) as opened:
        reader = open_archive(rock_ridge_iso, format=ArchiveFormat.ISO)
        with pytest.raises(RuntimeError, match="injected close failure"):
            reader.close()
        assert opened, "the reader did not open the path itself"
        assert [fp for fp in opened if not fp.closed] == []


def test_listing_limits_count_records_as_pycdlib_parses_them(
    rock_ridge_iso: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``max_members`` is checked inside ``open_fp``, per tree, as the listing counts.

    The image lists five members (two files, a directory, a nested file, a symlink)
    and its Joliet tree holds four of them again. A budget of five opens it unchanged;
    four is refused as ``ResourceLimitError`` from inside pycdlib's walk, not
    re-wrapped as ``CorruptionError`` by the pycdlib error boundary, and the handle the
    reader opened is released like on any other failed open.
    """
    with open_archive(rock_ridge_iso) as reader:
        expected = [m.name for m in reader.members()]
    assert len(expected) == 5
    exact = ArchiveyConfig(listing_limits=ListingLimits(max_members=5))
    with open_archive(rock_ridge_iso, config=exact) as reader:
        assert [m.name for m in reader.members()] == expected

    below = ArchiveyConfig(listing_limits=ListingLimits(max_members=4))
    with _recording_opens(rock_ridge_iso, monkeypatch) as opened:
        with pytest.raises(ResourceLimitError, match="max_members=4") as excinfo:
            open_archive(rock_ridge_iso, config=below)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__traceback__ is not None
        assert opened, "the source did not open the path"
        assert [fp for fp in opened if not fp.closed] == []


def test_listing_limits_count_directory_record_bytes_at_open(
    rock_ridge_iso: Path,
) -> None:
    """``max_metadata_bytes`` weighs the directory records pycdlib parses at open."""
    tight = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=200))
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=200"):
        open_archive(rock_ridge_iso, config=tight)


def test_the_pycdlib_hooks_are_inert_outside_archivey_opens() -> None:
    """Every hook archivey installs in pycdlib leaves a direct pycdlib open alone.

    The hooks on ``DirectoryRecord.parse``, ``RockRidge.parse``,
    ``PyCdlib._parse_path_table``, ``PathTableRecord.parse``,
    ``pycdlib.udf.parse_file_ident`` and ``pycdlib.udf.parse_file_entry`` act only
    while ``IsoReader`` has set its two ``ContextVar``s around its own ``open_fp``;
    outside, both are unset, and a Rock Ridge and Joliet image (path tables included)
    and a UDF image open and read through pycdlib as they would without archivey.
    """
    import pycdlib

    from archivey.internal.backends import iso_reader

    assert iso_reader._PARSE_BUDGET.get() is None
    assert not iso_reader._inside_our_open()
    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(_build_iso(rock_ridge=True, joliet=True)))
    try:
        assert iso.get_record(rr_path="/subdir/n.txt").get_data_length() == 7
    finally:
        iso.close()
    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(_udf_image_with_links(3)))
    try:
        # pycdlib yields ``None`` for the root's parent entry.
        children = iso.list_children(udf_path="/")
        names = [entry.file_identifier() for entry in children if entry is not None]
        assert sorted(names) == [
            b"F0.TXT",
            b"F1.TXT",
            b"F2.TXT",
        ]
    finally:
        iso.close()


def test_a_clean_image_is_unaffected(rock_ridge_iso: Path) -> None:
    """The bound may not shorten a read a well-formed image legitimately makes."""
    with open_archive(rock_ridge_iso) as reader:
        names = [m.name for m in reader.members()]
    assert "file.txt" in names


# --- listing follows records, not names ----------------------------------------------


def _build_rr_iso(populate: Callable[[Any], None]) -> bytes:
    """A Rock Ridge image whose contents ``populate(iso)`` adds."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    populate(iso)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _two_rr_files(iso: Any) -> None:
    iso.add_fp(io.BytesIO(b"AAAA"), 4, "/AAA.;1", rr_name="aaa")
    iso.add_fp(io.BytesIO(b"BBBB"), 4, "/BBB.;1", rr_name="bbb")


def test_a_rock_ridge_name_holding_a_slash_costs_no_sibling() -> None:
    """A name pycdlib's own path lookup cannot find again used to abort the listing."""
    data = _build_rr_iso(_two_rr_files)
    nm = b"NM\x08\x01\x00aaa"
    assert data.count(nm) == 1
    data = data.replace(nm, b"NM\x08\x01\x00a/a")
    with open_archive(io.BytesIO(data)) as ar:
        names = {m.name for m in ar.members()}
        assert {"a/a", "bbb"} <= names
        assert ar.read("bbb") == b"BBBB"
        assert ar.read("a/a") == b"AAAA"


def test_duplicate_rock_ridge_names_all_list() -> None:
    def populate(iso: Any) -> None:
        iso.add_directory("/AAA", rr_name="dup")
        iso.add_directory("/BBB", rr_name="dup")
        iso.add_fp(io.BytesIO(b"x"), 1, "/AAA/F.;1", rr_name="f")

    with open_archive(io.BytesIO(_build_rr_iso(populate))) as ar:
        members = ar.members()
        assert [m.name for m in members].count("dup/") == 2
        assert ar.read("dup/f") == b"x"


def _empty_and_regular_rr_files(iso: Any) -> None:
    iso.add_fp(io.BytesIO(b""), 0, "/AAA.;1", rr_name="aaa")
    iso.add_fp(io.BytesIO(b"BBBB"), 4, "/BBB.;1", rr_name="bbb")


# PX mode is a both-endian 32-bit field: 0o100444 (regular, r--r--r--).
_PX_REGULAR = struct.pack("<I", 0o100444) + struct.pack(">I", 0o100444)
_PX_CHAR_DEVICE = struct.pack("<I", 0o020666) + struct.pack(">I", 0o020666)


def test_a_rock_ridge_device_node_without_data_is_other(tmp_path: Path) -> None:
    """A PX mode naming a device over an empty extent is OTHER (what genisoimage and
    xorriso write for a FIFO): nothing to read, and extraction skips it."""
    data = _build_rr_iso(_empty_and_regular_rr_files)
    assert data.count(_PX_REGULAR) == 2
    data = data.replace(_PX_REGULAR, _PX_CHAR_DEVICE, 1)
    with open_archive(io.BytesIO(data)) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert by_name["aaa"].type is MemberType.OTHER
        assert by_name["aaa"].size is None
        assert by_name["aaa"].mode == 0o666
        assert by_name["aaa"].extra["special_file_type"] == "char_device"
        assert by_name["bbb"].type is MemberType.FILE
        assert "special_file_type" not in by_name["bbb"].extra
        codes = [d.code for d in ar.diagnostics.retained]
        assert DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA not in codes
        ar.extract_all(tmp_path / "out")
    assert not (tmp_path / "out" / "aaa").exists()
    assert (tmp_path / "out" / "bbb").read_bytes() == b"BBBB"


_PX_DIRECTORY = struct.pack("<I", 0o040755) + struct.pack(">I", 0o040755)


def test_a_directory_mode_on_an_empty_file_record_is_other_without_a_kind() -> None:
    """A PX mode of ``S_IFDIR`` on a file record (not a directory record) over an
    empty extent is OTHER, but it names no device, FIFO or socket, so there is no
    ``extra["special_file_type"]``: the key records a special file, not "OTHER"."""
    data = _build_rr_iso(_empty_and_regular_rr_files)
    assert data.count(_PX_REGULAR) == 2
    data = data.replace(_PX_REGULAR, _PX_DIRECTORY, 1)
    with open_archive(io.BytesIO(data)) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert by_name["aaa"].type is MemberType.OTHER
        assert "special_file_type" not in by_name["aaa"].extra
        assert by_name["bbb"].type is MemberType.FILE
        codes = [d.code for d in ar.diagnostics.retained]
        assert DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA not in codes


def test_a_rock_ridge_device_node_with_data_is_a_file(tmp_path: Path) -> None:
    """A device mode over a non-empty extent is a FILE whose bytes are the content:
    the extent is the structure, the PX mode an attribute (DR-25). The stored type
    stays in ``extra`` and an advisory diagnostic reports the mismatch."""
    data = _build_rr_iso(_two_rr_files)
    assert data.count(_PX_REGULAR) == 2
    data = data.replace(_PX_REGULAR, _PX_CHAR_DEVICE, 1)
    with open_archive(io.BytesIO(data)) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert by_name["aaa"].type is MemberType.FILE
        assert by_name["aaa"].size == 4
        assert by_name["aaa"].mode == 0o666
        assert by_name["aaa"].extra["special_file_type"] == "char_device"
        assert ar.read("aaa") == b"AAAA"
        diags = [
            d
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
        ]
        assert len(diags) == 1
        assert diags[0].context is not None
        context = diags[0].context.to_dict()
        assert context["kind"] == "special_file_data"
        assert context["member_name"] == "aaa"
        assert context["special_file_type"] == "char_device"
        assert context["size"] == 4
        ar.extract_all(tmp_path / "out")
    assert (tmp_path / "out" / "aaa").read_bytes() == b"AAAA"
    assert (tmp_path / "out" / "bbb").read_bytes() == b"BBBB"


def test_plain_iso_versions_keep_the_newest_current(tmp_path: Path) -> None:
    """The newest ``;N`` takes the bare name (the empty-extension dot goes too); an
    older version keeps its stored identifier and ``is_current=False``, as a RAR
    history row does.
    Every version records its number in ``iso.version``."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    iso.add_fp(io.BytesIO(b"OLD VERSION"), 11, "/FOO.;1")
    iso.add_fp(io.BytesIO(b"NEW VERSION"), 11, "/FOO.;2")
    iso.add_fp(io.BytesIO(b"text"), 4, "/BAR.TXT;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()

    with open_archive(io.BytesIO(out.getvalue())) as ar:
        rows = [(m.name, m.extra["iso.version"], m.is_current) for m in ar.members()]
        assert sorted(rows) == [
            ("BAR.TXT", 1, True),
            ("FOO", 2, True),
            ("FOO.;1", 1, False),
        ]
        assert ar.read("FOO") == b"NEW VERSION"
        assert ar.read("FOO.;1") == b"OLD VERSION"
        ar.extract_all(tmp_path / "out")
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["BAR.TXT", "FOO"]
    assert (tmp_path / "out" / "FOO").read_bytes() == b"NEW VERSION"


def test_a_directory_identifier_keeps_its_version_like_suffix() -> None:
    """ECMA-119 gives a version only to a file identifier. A directory's ``;1`` is
    part of its name, so the directory lists under the path its children use."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    iso.add_directory("/DIAB")
    iso.add_fp(io.BytesIO(b"x"), 1, "/DIAB/X.TXT;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    # The directory record and both path tables spell the identifier.
    data = out.getvalue().replace(b"DIAB", b"DI;1")

    with open_archive(io.BytesIO(data)) as ar:
        rows = [(m.name, dict(m.extra)) for m in ar.members()]
        assert rows == [("DI;1/", {}), ("DI;1/X.TXT", {"iso.version": 1})]
        assert ar.read("DI;1/X.TXT") == b"x"


def test_rock_ridge_relocation_directory_is_not_listed() -> None:
    """Deep trees are parked under ``rr_moved`` and relinked; only the logical tree lists."""

    def populate(iso: Any) -> None:
        path = ""
        for depth in range(12):
            path += f"/D{depth}"
            iso.add_directory(path, rr_name=f"dir{depth}")
        iso.add_fp(io.BytesIO(b"deep"), 4, path + "/F.;1", rr_name="f.txt")

    data = _build_rr_iso(populate)
    assert b"RR_MOVED" in data
    with open_archive(io.BytesIO(data)) as ar:
        names = [m.name for m in ar.members()]
        assert not any(n.lower().startswith("rr_moved") for n in names)
        deep = "/".join(f"dir{d}" for d in range(12)) + "/f.txt"
        assert deep in names
        assert len(names) == 13
        assert ar.read(deep) == b"deep"


def test_a_rock_ridge_record_without_entries_lists_under_its_iso_name() -> None:
    """An RR image whose one record has no System Use entries keeps that member,
    names it from the ISO 9660 identifier, and says what was lost."""
    from archivey import DiagnosticCode

    data = bytearray(_build_rr_iso(_two_rr_files))
    at = data.index(b"AAA.;1")
    start = at - 33  # the identifier sits at offset 33 of its directory record
    length, ident_len = data[start], data[start + 32]
    su = start + 33 + ident_len + (1 if ident_len % 2 == 0 else 0)
    data[su : start + length] = bytes(start + length - su)

    with open_archive(io.BytesIO(bytes(data))) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert set(by_name) == {"AAA", "bbb"}
        assert ar.read("AAA") == b"AAAA"
        assert [d.code for d in by_name["AAA"].diagnostics] == [
            DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        ]
        assert by_name["bbb"].diagnostics == ()


def test_the_record_walk_descends_each_directory_extent_once() -> None:
    """A child record pointing back at an ancestor extent is listed but not entered.

    pycdlib's parse-time guard keeps such a cycle out of a parsed tree, so the cycle
    is spliced into the parsed records here to reach the walk's own guard.
    """
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    iso.add_directory("/A")
    iso.add_directory("/A/B")
    iso.add_fp(io.BytesIO(b"x"), 1, "/A/B/F.;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()

    with open_archive(io.BytesIO(out.getvalue())) as ar:
        reader: Any = ar
        a = reader._reader._iso.get_record(iso_path="/A")
        b = reader._reader._iso.get_record(iso_path="/A/B")
        b.children.append(a)  # B now lists its own parent A as a child
        names = [m.name for m in ar.members()]
    assert sorted(names) == ["A/", "A/B/", "A/B/A/", "A/B/F"]


def test_listing_reads_nothing_from_the_image() -> None:
    """On an image with no repeated identifier and no file ending at the end of the
    image, materialization only touches catalog records pycdlib parsed at open: the
    audit the handle-lock requirement relies on. Either of those makes listing re-read
    one directory extent, under the handle guard (``IsoReader._raw_directory``)."""

    class Counting(io.BytesIO):
        calls = 0

        def read(self, size: int | None = -1, /) -> bytes:
            Counting.calls += 1
            return super().read(size)

        def seek(self, offset: int, whence: int = 0, /) -> int:
            Counting.calls += 1
            return super().seek(offset, whence)

    with open_archive(Counting(_build_rr_iso(_two_rr_files))) as ar:
        before = Counting.calls
        assert len(ar.members()) == 2
        assert Counting.calls == before


def test_rock_ridge_long_form_tf_time_is_read() -> None:
    """A TF record with LONG_FORM set carries 17-byte dates (``VolumeDescriptorDate``:
    four-digit year, ``dayofmonth``, hundredths). They used to come back as ``None``
    because only the 7-byte field names were read."""
    from datetime import datetime, timedelta, timezone

    from pycdlib.dates import DirectoryRecordDate, VolumeDescriptorDate

    from archivey.internal.backends.iso_reader import _dr_date_to_datetime

    long_form = VolumeDescriptorDate()
    # 2024-03-05 06:07:08.09, gmtoffset +8 (15-minute units: UTC+2).
    long_form.parse(b"2024030506070809" + struct.pack("=b", 8))
    assert _dr_date_to_datetime(long_form) == datetime(
        2024, 3, 5, 6, 7, 8, 90_000, tzinfo=timezone(timedelta(hours=2))
    )

    unspecified = VolumeDescriptorDate()
    unspecified.parse(b"0" * 16 + b"\x00")
    assert _dr_date_to_datetime(unspecified) is None

    short_form = DirectoryRecordDate()
    short_form.parse(struct.pack("=BBBBBBb", 124, 3, 5, 6, 7, 8, 8))
    assert _dr_date_to_datetime(short_form) == datetime(
        2024, 3, 5, 6, 7, 8, tzinfo=timezone(timedelta(hours=2))
    )


def test_rock_ridge_tf_modification_time_wins_over_record_date() -> None:
    """Through the reader: a TF modification time that differs from the directory
    record's date is the one ``modified`` reports. The record date used to win,
    because it is always present."""
    from datetime import UTC, datetime

    import pycdlib
    from pycdlib.dates import DirectoryRecordDate

    iso = pycdlib.PyCdlib()
    iso.new(rock_ridge="1.09")
    iso.add_fp(io.BytesIO(b"hi"), 2, "/A.TXT;1", rr_name="a.txt")
    tf_date = DirectoryRecordDate()
    tf_date.parse(struct.pack("=BBBBBBb", 101, 1, 2, 3, 4, 5, 0))
    record = iso.get_record(rr_path="/a.txt")
    record.rock_ridge.dr_entries.tf_record.modification_time = tf_date
    image = io.BytesIO()
    iso.write_fp(image)
    iso.close()

    with open_archive(io.BytesIO(image.getvalue())) as archive:
        (member,) = [m for m in archive.members() if m.name == "a.txt"]
    assert member.modified == datetime(2001, 1, 2, 3, 4, 5, tzinfo=UTC)


# --- data the directory record's own inode does not cover -----------------------------


def test_the_el_torito_boot_catalog_reads_and_extracts(tmp_path: Path) -> None:
    """pycdlib keeps the boot catalog in memory and gives its record no inode, so
    opening it used to raise ``CorruptionError`` and stop ``extract_all`` on every
    bootable image. Its bytes are read from its extent, as a mounted image shows."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    iso.add_fp(io.BytesIO(b"\0" * 2048), 2048, "/BOOT.IMG;1")
    iso.add_eltorito("/BOOT.IMG;1", "/BOOT.CAT;1")
    iso.add_fp(io.BytesIO(b"hi"), 2, "/A.TXT;1")
    image = io.BytesIO()
    iso.write_fp(image)
    iso.close()

    with open_archive(io.BytesIO(image.getvalue())) as ar:
        catalog = ar.read("BOOT.CAT")
        ar.extract_all(tmp_path)
    # The El Torito validation entry: header id 1, key bytes 0x55 0xAA at 30-31.
    assert len(catalog) == 2048
    assert catalog[0] == 1 and catalog[30:32] == b"\x55\xaa"
    assert (tmp_path / "BOOT.CAT").read_bytes() == catalog
    assert (tmp_path / "A.TXT").read_bytes() == b"hi"


def _split_into_extents(
    image: bytes, identifier: bytes, *, flags: tuple[bool, ...] = (True,), gap: int = 0
) -> bytes:
    """Rewrite a root file's directory record as several, the way a 4 GiB file is stored.

    The file becomes ``len(flags) + 1`` records with one name. Each record but the
    last covers one block, and the last covers the rest. Record ``i`` carries the
    multi-extent flag when ``flags[i]`` is true. With every flag set, the records are
    one file, as a writer stores it. A record without the flag ends its file, so the
    next record with the same identifier is an unrelated file. The second record
    starts ``gap`` blocks after the first ends, and the last is ``gap`` blocks
    shorter, so the records still end where the file did. All the records fit in the root
    directory's sector, whose padding absorbs the new ones.
    """
    buf = bytearray(image)
    root = struct.unpack_from("<I", buf, 16 * 2048 + 156 + 2)[0] * 2048
    offset = root
    while (
        buf[offset]
        and bytes(buf[offset + 33 : offset + 33 + buf[offset + 32]]) != identifier
    ):
        offset += buf[offset]
    length = buf[offset]
    assert length, "record not found"
    record = bytes(buf[offset : offset + length])
    extent = struct.unpack_from("<I", record, 2)[0]
    size = struct.unpack_from("<I", record, 10)[0]

    def both_endian(target: bytearray, at: int, value: int) -> None:
        struct.pack_into("<I", target, at, value)
        struct.pack_into(">I", target, at + 4, value)

    records = []
    for index, flag in enumerate(flags):
        chunk = bytearray(record)
        both_endian(chunk, 2, extent + index + (gap if index else 0))
        both_endian(chunk, 10, 2048)
        if flag:
            chunk[25] |= 0x80
        records.append(bytes(chunk))
    last = bytearray(record)
    both_endian(last, 2, extent + len(flags) + gap)
    both_endian(last, 10, size - 2048 * (len(flags) + gap))
    records.append(bytes(last))
    sector_end = root + 2048
    rest = bytes(buf[offset + length : sector_end])
    assert rest.endswith(b"\0" * length * len(flags)), "no room for the new records"
    buf[offset:sector_end] = (b"".join(records) + rest)[: sector_end - offset]
    return bytes(buf)


def _image_with_two_block_file() -> bytes:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    iso.add_fp(io.BytesIO(b"a" * 2048 + b"b" * 1000), 3048, "/BIG.BIN;1")
    iso.add_fp(io.BytesIO(b"hi"), 2, "/Z.TXT;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def test_a_multi_extent_file_lists_and_reads_every_extent() -> None:
    """A file of 4 GiB or more is several records with one name. Only the first
    reached the reader, so the member listed and read one extent's worth and dropped
    the rest without an error (measured: a 4 400 MiB xorriso file read as 4 GiB)."""
    image = _split_into_extents(_image_with_two_block_file(), b"BIG.BIN;1")
    with open_archive(io.BytesIO(image)) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert set(by_name) == {"BIG.BIN", "Z.TXT"}
        assert by_name["BIG.BIN"].size == 3048
        assert ar.read("BIG.BIN") == b"a" * 2048 + b"b" * 1000
        assert ar.read("Z.TXT") == b"hi"


def test_a_multi_extent_file_with_a_gap_reads_each_extent_where_it_is() -> None:
    """Extents need not be back to back: each is read where its record puts it, and
    the block between them is skipped. Read as one run from the first extent, the
    skipped ``b`` block came back as file data."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    content = b"a" * 2048 + b"b" * 2048 + b"c" * 1000
    iso.add_fp(io.BytesIO(content), len(content), "/BIG.BIN;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    image = _split_into_extents(out.getvalue(), b"BIG.BIN;1", gap=1)
    with open_archive(io.BytesIO(image), seekable_members=True) as ar:
        assert ar.get("BIG.BIN").size == 3048
        assert ar.read("BIG.BIN") == b"a" * 2048 + b"c" * 1000
        with ar.open("BIG.BIN") as stream:
            stream.seek(2040)
            assert stream.read(16) == b"a" * 8 + b"c" * 8
            stream.seek(0)
            assert stream.read(4) == b"aaaa"


def test_a_repeated_identifier_without_the_flag_lists_each_file(tmp_path: Path) -> None:
    """pycdlib links any record whose identifier repeats the previous one, sets the
    multi-extent flag on the first in memory, and its walk skips the second record.
    Only the flag as written in the image makes the two records one file. Without
    it they are two files with one name, and both list, as ZIP and TAR list two
    members with one name and as 7-Zip lists this image. The later one is current,
    and it is reported with ``MEMBER_NAME_DUPLICATE``.
    """
    image = _split_into_extents(
        _image_with_two_block_file(), b"BIG.BIN;1", flags=(False,)
    )
    with open_archive(io.BytesIO(image)) as ar:
        rows = [(m.name, m.size, m.is_current) for m in ar.members()]
        assert rows == [
            ("BIG.BIN", 2048, False),
            ("BIG.BIN", 1000, True),
            ("Z.TXT", 2, True),
        ]
        first, second, _ = ar.members()
        assert ar.read(first) == b"a" * 2048
        assert ar.read(second) == b"b" * 1000
        assert ar.read("BIG.BIN") == b"b" * 1000
        # The second record is reported: a reader that keeps the first lists another
        # file under that name.
        assert dict(ar.diagnostics.counts) == {DiagnosticCode.MEMBER_NAME_DUPLICATE: 1}
        ar.extract_all(tmp_path)
    assert (tmp_path / "BIG.BIN").read_bytes() == b"b" * 1000


def test_a_multi_extent_file_and_an_unrelated_file_with_its_name_both_list() -> None:
    """The flag ends a file at the first record without it, so a real multi-extent
    file followed by an unrelated record with the same identifier lists as two
    members: the flagged records joined, and the unrelated record on its own."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    content = b"a" * 2048 + b"b" * 2048 + b"c" * 1000
    iso.add_fp(io.BytesIO(content), len(content), "/BIG.BIN;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()

    for flags, expected in (
        ((True, False), [b"a" * 2048 + b"b" * 2048, b"c" * 1000]),
        ((False, True), [b"a" * 2048, b"b" * 2048 + b"c" * 1000]),
    ):
        image = _split_into_extents(out.getvalue(), b"BIG.BIN;1", flags=flags)
        with open_archive(io.BytesIO(image)) as ar:
            members = ar.members()
            assert [m.name for m in members] == ["BIG.BIN", "BIG.BIN"]
            assert [m.size for m in members] == [len(data) for data in expected]
            assert [ar.read(m) for m in members] == expected


def test_records_sharing_an_extent_keep_their_own_multi_extent_flags() -> None:
    """The flag is matched to a record by its position among the records with its
    identifier, not by its extent. Here the first two records share an extent and
    only the first is flagged: the second ends the file, and the third, at its own
    extent, is a second member. Matched by extent, the second record read as flagged
    and the third was swallowed into the first member."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    content = b"a" * 2048 + b"b" * 2048 + b"c" * 1000
    iso.add_fp(io.BytesIO(content), len(content), "/BIG.BIN;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    image = bytearray(
        _split_into_extents(out.getvalue(), b"BIG.BIN;1", flags=(True, False))
    )
    first = image.index(b"BIG.BIN;1") - 33
    second = first + image[first]
    assert image[second + 33 : second + 42] == b"BIG.BIN;1"
    image[second + 2 : second + 10] = image[first + 2 : first + 10]

    with open_archive(io.BytesIO(bytes(image))) as ar:
        first_member, second_member = ar.members()
        assert [first_member.size, second_member.size] == [4096, 1000]
        assert ar.read(second_member) == b"c" * 1000
        # The first member's two extents are the same block, so they overlap.
        with pytest.raises(CorruptionError, match="overlap"):
            ar.read(first_member)


def test_a_repeated_superseded_version_stays_not_current(tmp_path: Path) -> None:
    """Two records ``FOO.;1`` beside ``FOO.;2``: both older records list under their
    stored identifier and stay not current, though they share a name. The shared
    last-entry-wins pass keeps a backend's own "not current", so extraction writes
    only the newest version."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    iso.add_fp(io.BytesIO(b"a" * 2048 + b"b" * 1000), 3048, "/FOO.;1")
    iso.add_fp(io.BytesIO(b"NEW"), 3, "/FOO.;2")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    image = _split_into_extents(out.getvalue(), b"FOO.;1", flags=(False,))

    with open_archive(io.BytesIO(image)) as ar:
        rows = [(m.name, m.size, m.is_current) for m in ar.members()]
        assert rows == [
            ("FOO.;1", 2048, False),
            ("FOO.;1", 1000, False),
            ("FOO", 3, True),
        ]
        ar.extract_all(tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ["FOO"]
    assert (tmp_path / "FOO").read_bytes() == b"NEW"


@pytest.mark.parametrize(
    ("flags", "associated", "expected"),
    [
        # ECMA-119 §9.3 order: the associated file (a resource fork) first, then
        # the data file it belongs to, here stored in two extents.
        ((False, True), 0, [b"a" * 2048, b"b" * 2048 + b"c" * 1000]),
        # The associated file stored after a two-extent data file.
        ((True, False), 2, [b"a" * 2048 + b"b" * 2048, b"c" * 1000]),
    ],
    ids=["associated-first", "associated-last"],
)
def test_an_associated_file_and_a_file_with_its_identifier_both_list(
    flags: tuple[bool, ...], associated: int, expected: list[bytes]
) -> None:
    """pycdlib does not link an associated-file record (flag bit 2) to the records
    that share its identifier, and puts it before them whatever the order on disc,
    so its walk listed one record and hid the rest. The entries are worked out from
    the records as written: both files list in on-disc order, each with its own
    data, and the later one is current."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new()
    content = b"a" * 2048 + b"b" * 2048 + b"c" * 1000
    iso.add_fp(io.BytesIO(content), len(content), "/BIG.BIN;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    image = bytearray(_split_into_extents(out.getvalue(), b"BIG.BIN;1", flags=flags))
    at = image.index(b"BIG.BIN;1") - 33
    for _ in range(associated):
        at += image[at]
    image[at + 25] |= 0x04

    with open_archive(io.BytesIO(bytes(image))) as ar:
        members = ar.members()
        assert [m.name for m in members] == ["BIG.BIN", "BIG.BIN"]
        assert [m.size for m in members] == [len(data) for data in expected]
        assert [ar.read(m) for m in members] == expected
        assert [m.is_current for m in members] == [False, True]


def test_a_directory_and_a_file_with_one_identifier_both_list() -> None:
    """pycdlib links a file record to the record just before it when the two share an
    identifier, even when that record is a directory. A directory is never part of
    a file, so both list, as 7-Zip lists them. The reverse order, and two directories
    with one identifier, are refused by pycdlib at open."""
    import pycdlib

    from archivey.exceptions import CorruptionError

    def build(first: str) -> bytes:
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=4)
        directory, file = ("/DUP", "/DUQ") if first == "dir" else ("/DUQ", "/DUP")
        iso.add_directory(directory)
        iso.add_fp(io.BytesIO(b"x"), 1, file)
        iso.add_fp(io.BytesIO(b"inner"), 5, directory + "/IN")
        out = io.BytesIO()
        iso.write_fp(out)
        iso.close()
        # The directory record and both path tables spell the identifier.
        return out.getvalue().replace(b"DUQ", b"DUP")

    with open_archive(io.BytesIO(build("dir"))) as ar:
        rows = [(m.name, m.type, m.is_current) for m in ar.members()]
        assert rows == [
            ("DUP/", MemberType.DIRECTORY, True),
            ("DUP", MemberType.FILE, True),
            ("DUP/IN", MemberType.FILE, True),
        ]
        assert ar.read("DUP") == b"x"
        assert ar.read("DUP/IN") == b"inner"
    with pytest.raises(CorruptionError, match="duplicate name"):
        open_archive(io.BytesIO(build("file"))).close()


def test_a_boot_catalog_declared_past_the_image_end_reads_short() -> None:
    """pycdlib clamps a record running past the image only when it gives it an
    inode, and the boot catalog gets none; the inode built for it stops at the end
    of the image, and the read fails there."""
    import pycdlib

    from archivey.exceptions import TruncatedError

    iso = pycdlib.PyCdlib()
    iso.new()
    iso.add_fp(io.BytesIO(b"\0" * 2048), 2048, "/BOOT.IMG;1")
    iso.add_eltorito("/BOOT.IMG;1", "/BOOT.CAT;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    data = bytearray(out.getvalue())
    record = data.index(b"BOOT.CAT;1") - 33
    struct.pack_into("<I", data, record + 10, 0x40000000)
    struct.pack_into(">I", data, record + 14, 0x40000000)

    with open_archive(io.BytesIO(bytes(data))) as ar:
        assert ar.get("BOOT.CAT").size == 0x40000000
        with pytest.raises(TruncatedError, match="of 1073741824 expected bytes"):
            ar.read("BOOT.CAT")


def _truncated_image(*, joliet: bool, cut: str) -> bytes:
    """Three files and an empty one, cut in the middle of B.BIN (``"mid_b"``: B.BIN
    keeps 3 000 of its 5 000 bytes) or exactly where C.BIN starts (``"at_c"``: B.BIN
    survives whole). A.TXT always survives whole, and C.BIN has nothing left. At the
    sector-aligned cut, the empty file's extent is moved to the cut, where an empty
    file must still list as empty."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(joliet=3 if joliet else None)
    files = (("A.TXT", b"a", 100), ("B.BIN", b"b", 5000), ("C.BIN", b"c", 3000))
    for name, fill, size in (*files, ("E.TXT", b"", 0)):
        iso.add_fp(
            io.BytesIO(fill * size),
            size,
            f"/{name};1",
            joliet_path=f"/{name.lower()}" if joliet else None,
        )
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    data = bytearray(out.getvalue())
    if cut == "mid_b":
        return bytes(data[: data.index(b"b" * 5000) + 3000])
    end = data.index(b"c" * 3000)
    for ident in (b"E.TXT;1", "e.txt".encode("utf-16-be")):
        at = data.find(ident)
        while at != -1:
            record = at - 33
            struct.pack_into("<I", data, record + 2, end // 2048)
            struct.pack_into(">I", data, record + 6, end // 2048)
            at = data.find(ident, at + 1)
    return bytes(data[:end])


@pytest.mark.parametrize("cut", ["mid_b", "at_c"])
@pytest.mark.parametrize("joliet", [False, True], ids=["iso9660", "joliet"])
def test_a_truncated_image_lists_declared_sizes_and_reads_to_the_cut(
    joliet: bool, cut: str
) -> None:
    """pycdlib clamps a file running past the end of the image to end there and
    overwrites its declared length: zero for a file starting at the cut, negative
    for one starting past it. The listing reported those clamped sizes, and reading
    returned short with no error. The declared lengths are still in the directory
    records on disc."""
    from archivey.exceptions import TruncatedError

    image = _truncated_image(joliet=joliet, cut=cut)
    with open_archive(io.BytesIO(image)) as ar:
        by_name = {m.name.upper(): m for m in ar.members()}
        sizes = {name: m.size for name, m in by_name.items()}
        assert sizes == {"A.TXT": 100, "B.BIN": 5000, "C.BIN": 3000, "E.TXT": 0}
        assert ar.read(by_name["A.TXT"]) == b"a" * 100
        assert ar.read(by_name["E.TXT"]) == b""
        cut_files = [("C.BIN", 0)]
        if cut == "mid_b":
            cut_files.insert(0, ("B.BIN", 3000))
        else:
            assert ar.read(by_name["B.BIN"]) == b"b" * 5000
        for name, available in cut_files:
            with ar.open(by_name[name]) as stream:
                assert len(stream.read(available)) == available
                with pytest.raises(TruncatedError, match="expected bytes"):
                    stream.read()


def _three_file_image(*, udf: bool) -> bytes:
    """Rock Ridge and Joliet, or UDF: a directory holding three 5 000-byte files."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    if udf:
        iso.new(interchange_level=3, udf="2.60")
        iso.add_directory("/D", udf_path="/d")
    else:
        iso.new(interchange_level=3, joliet=3, rock_ridge="1.09")
        iso.add_directory("/D", rr_name="d", joliet_path="/d")
    for index in range(3):
        names = (
            {"udf_path": f"/d/f{index}"}
            if udf
            else {"rr_name": f"f{index}", "joliet_path": f"/d/f{index}"}
        )
        data = bytes([ord("A") + index]) * 5000
        iso.add_fp(io.BytesIO(data), len(data), f"/D/F{index}.;1", **names)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _iso_cut_points(*, udf: bool) -> dict[str, int]:
    """Offsets inside each structure of ``_three_file_image``, read from the image.

    Every structure lies inside the volume space the primary descriptor declares,
    so an image cut at any of these offsets is shorter than it says it is.
    """
    import pycdlib

    image = _three_file_image(udf=udf)
    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(image))
    block = iso.logical_block_size
    pvd = iso.pvd
    root = pvd.root_directory_record().extent_location() * block
    assert image[16 * block + 1 : 16 * block + 6] == b"CD001"
    points = {
        "primary-descriptor": 16 * block + 100,
        "path-table-le": pvd.path_table_location_le * block + 4,
        "path-table-be": pvd.path_table_location_be * block + 4,
        # The ``.`` record's own 34 bytes, then its System Use area.
        "root-directory-record": root + 10,
        "root-system-use": root + 40,
        "root-directory-padding": root + block // 2,
    }
    if udf:
        assert image[18 * block + 1 : 18 * block + 6] == b"BEA01"
        points["udf-volume-recognition"] = 18 * block + 100
        # pycdlib reads the anchor in the volume's last block once the ISO 9660
        # trees are parsed.
        points["udf-last-anchor"] = (pvd.space_size - 1) * block + 10
        points["udf-file-data"] = image.index(b"A" * 5000) + 100
    else:
        assert iso.joliet_vd is not None
        assert image[17 * block] == 2  # the Joliet supplementary descriptor
        assert image[18 * block] == 255  # the set terminator
        points["joliet-descriptor"] = 17 * block + 100
        points["at-descriptor-terminator"] = 18 * block
        points["joliet-path-table"] = iso.joliet_vd.path_table_location_le * block + 4
        points["joliet-root-directory"] = (
            iso.joliet_vd.root_directory_record().extent_location() * block + 40
        )
        directory = iso.get_record(rr_path="/d").extent_location() * block
        points["subdirectory"] = directory + 40
    iso.close()
    return points


_SHARED_CUTS = (
    "primary-descriptor",
    "path-table-le",
    "path-table-be",
    "root-directory-record",
    "root-system-use",
    "root-directory-padding",
)
_RICH_CUTS = (
    "joliet-descriptor",
    "at-descriptor-terminator",
    "joliet-path-table",
    "joliet-root-directory",
    "subdirectory",
)
_UDF_CUTS = ("udf-volume-recognition", "udf-last-anchor", "udf-file-data")


@pytest.mark.parametrize(
    ("udf", "point"),
    [(False, name) for name in _SHARED_CUTS + _RICH_CUTS]
    + [(True, name) for name in _SHARED_CUTS + _UDF_CUTS],
)
def test_an_image_cut_inside_its_metadata_is_truncated(udf: bool, point: str) -> None:
    """An image that ends before a structure its own descriptors point to raises
    ``TruncatedError`` at open, as TAR, RAR and 7z do for a cut header. It raised a
    plain ``CorruptionError`` because pycdlib reports a short read as an invalid
    image. A UDF image is refused at open even when the cut is in file data: pycdlib
    reads the anchor in the volume's last block."""
    from archivey.exceptions import TruncatedError

    image = _three_file_image(udf=udf)
    cut = _iso_cut_points(udf=udf)[point]
    with pytest.raises(TruncatedError, match="ends before"):
        open_archive(io.BytesIO(image[:cut]), format=ArchiveFormat.ISO)


def test_every_cut_of_an_image_is_truncated_or_opens() -> None:
    """A cut in each block of both images, up to the end of the last file's data:
    the image opens, and a file the cut reaches raises ``TruncatedError`` on read, or
    the open raises it. No cut is a plain ``CorruptionError``. (A UDF image cut inside
    its last block, after every file, opens and reads whole: pycdlib parses the
    anchor there from the bytes that are left.)"""
    from archivey.exceptions import TruncatedError

    for udf in (False, True):
        image = _three_file_image(udf=udf)
        data_end = image.index(b"C" * 5000) + 5000
        for cut in range(16 * 2048 + 700, data_end, 2048):
            try:
                with open_archive(io.BytesIO(image[:cut])) as ar:
                    for member in ar.members():
                        if member.is_file:
                            ar.read(member)
            except TruncatedError:
                continue
            raise AssertionError(f"udf={udf}: the image cut at {cut} read whole")


def _set_extent(image: bytearray, at: int, value: int) -> None:
    """Write a both-endian 32-bit field: little-endian at ``at``, big at ``at + 4``."""
    struct.pack_into("<I", image, at, value)
    struct.pack_into(">I", image, at + 4, value)


_ROOT_EXTENT = 16 * 2048 + 156 + 2  # in the primary descriptor's root record
_VOLUME_SPACE_SIZE = 16 * 2048 + 80


def test_a_cut_image_whose_root_points_past_its_volume_space_is_corruption() -> None:
    """The image is cut, and pycdlib's failing read ran into the end of the file, but
    that read started past the volume space the image declares: the root record is a
    wrong pointer, not a structure the cut removed. The cut keeps the path tables, so
    the failure is pycdlib's directory read, not the path-table bound."""
    image = bytearray(_three_file_image(udf=False))
    (space_size,) = struct.unpack_from("<I", image, _VOLUME_SPACE_SIZE)
    _set_extent(image, _ROOT_EXTENT, space_size + 1)
    cut = 70_000
    assert cut < len(image)
    with raises_corruption_not_truncation(match="Invalid directory record"):
        open_archive(io.BytesIO(bytes(image[:cut])), format=ArchiveFormat.ISO)


def test_a_full_length_image_declaring_a_larger_volume_space_is_truncated() -> None:
    """The volume space size is the one field that decides the label, so damage that
    raises it reads as a cut: the file holds less than the image declares, and
    pycdlib's read of the UDF anchor in the declared last block finds nothing."""
    from archivey.exceptions import TruncatedError

    image = bytearray(_three_file_image(udf=True))
    (space_size,) = struct.unpack_from("<I", image, _VOLUME_SPACE_SIZE)
    _set_extent(image, _VOLUME_SPACE_SIZE, space_size + 10)
    with pytest.raises(TruncatedError, match="ends before its own structures"):
        open_archive(io.BytesIO(bytes(image)), format=ArchiveFormat.ISO)


def _damage_primary_descriptor(image: bytearray, block: int) -> None:
    image[16 * block + 6] = 2  # descriptor version, 1 in ECMA-119


def _damage_directory_padding(image: bytearray, block: int) -> None:
    (root,) = struct.unpack_from("<I", image, 16 * block + 156 + 2)
    image[root * block + block - 1] = 0xFF  # past the last record: must be zero


def _damage_path_table_size(image: bytearray, block: int) -> None:
    # Larger than the whole volume space: a wrong size, not a cut image.
    struct.pack_into("<I", image, 16 * block + 132, len(image) * 4)
    struct.pack_into(">I", image, 16 * block + 136, len(image) * 4)


def _damage_root_extent(image: bytearray, block: int) -> None:
    # The root directory placed far past the volume space's end.
    struct.pack_into("<I", image, 16 * block + 156 + 2, 0x00FFFFFF)
    struct.pack_into(">I", image, 16 * block + 156 + 6, 0x00FFFFFF)


@pytest.mark.parametrize(
    "damage",
    [
        _damage_primary_descriptor,
        _damage_directory_padding,
        _damage_path_table_size,
        _damage_root_extent,
    ],
    ids=["primary-descriptor", "directory-padding", "path-table-size", "root-extent"],
)
def test_a_damaged_image_of_full_length_is_corruption_not_truncation(
    damage: Callable[[bytearray, int], None],
) -> None:
    """The counterpart of the cut tests: the image holds every byte its volume space
    declares, so a structure that does not parse, or that points past the end, is
    damage. A pointer past the end of a full image is a wrong pointer, not a cut."""
    image = bytearray(_three_file_image(udf=False))
    damage(image, 2048)
    with raises_corruption_not_truncation():
        open_archive(io.BytesIO(bytes(image)), format=ArchiveFormat.ISO)


def test_the_raw_directory_walk_crosses_sector_padding() -> None:
    """A zero length byte pads to the end of the sector, and records continue in
    the next one: a flag or a length there is still found."""
    from archivey.internal.backends.iso_reader import _parse_raw_directory

    def record(extent: int, length: int, ident: bytes, flags: int = 0) -> bytes:
        body = bytearray(33 + len(ident) + (1 - len(ident) % 2))
        body[0] = len(body)
        struct.pack_into("<I", body, 2, extent)
        struct.pack_into("<I", body, 10, length)
        body[25] = flags
        body[32] = len(ident)
        body[33 : 33 + len(ident)] = ident
        return bytes(body)

    first = record(100, 2048, b"BIG;1", flags=0x80) + record(101, 10, b"BIG;1")
    second = record(200, 2048, b"HUGE;1", flags=0x80) + record(201, 9000, b"HUGE;1")
    data = first.ljust(2048, b"\0") + second.ljust(2048, b"\0")

    raw = _parse_raw_directory(data, 2048, image_length=201 * 2048 + 5000)
    flags = {ident: [r.multi_extent for r in rs] for ident, rs in raw.repeated.items()}
    assert flags == {b"BIG;1": [True, False], b"HUGE;1": [True, False]}
    assert raw.lengths_to_end == {(201, b"HUGE;1"): 9000}


def test_format_version_is_not_pycdlibs_guess(rock_ridge_iso: Path) -> None:
    """ISO 9660 stores no interchange level; pycdlib's inferred one read 3 on nearly
    every image, a level-1 genisoimage default included."""
    with open_archive(rock_ridge_iso) as ar:
        assert ar.info.format_version is None


# --- System Use entries pycdlib refuses: zisofs, unknown entries, a malformed tail ----


def _zisofs(
    data: bytes,
    *,
    log2_block_size: int = 15,
    mangle: Callable[[bytes], bytes] = lambda chunk: chunk,
) -> bytes:
    """``data`` as ``mkzftree`` stores it: a header, block pointers, zlib blocks.

    A block of zeros is stored as two equal pointers, as ``mkzftree`` writes it.
    ``mangle`` rewrites each stored zlib block, and the pointers follow it.
    """
    import zlib

    block_size = 1 << log2_block_size
    blocks = [data[i : i + block_size] for i in range(0, len(data), block_size)]
    header = (
        b"\x37\xe4\x53\x96\xc9\xdb\xd6\x07"
        + struct.pack("<I", len(data))
        + bytes([4, log2_block_size, 0, 0])
    )
    offset = len(header) + 4 * (len(blocks) + 1)
    pointers = [offset]
    packed = b""
    for block in blocks:
        chunk = b"" if block == bytes(len(block)) else mangle(zlib.compress(block))
        packed += chunk
        pointers.append(pointers[-1] + len(chunk))
    return header + b"".join(struct.pack("<I", p) for p in pointers) + packed


def _zf_entry(
    size: int,
    *,
    tag: bytes = b"ZF",
    version: int = 1,
    algorithm: bytes = b"pz",
    header_size: int = 16,
    log2_block_size: int = 15,
) -> bytes:
    return (
        tag
        + b"\x10"
        + bytes([version])
        + algorithm
        + bytes([header_size // 4, log2_block_size])
        + struct.pack("<I", size)
        + struct.pack(">I", size)
    )


def _replace_tf(data: bytes, name: bytes, entries: bytes) -> bytes:
    """Replace the 26-byte ``TF`` entry after Rock Ridge name ``name`` by ``entries``."""
    at = data.index(b"NM" + bytes([5 + len(name)]) + b"\x01\x00" + name)
    tf = data.index(b"TF\x1a\x01", at)
    assert len(entries) == 26
    return data[:tf] + entries + data[tf + 26 :]


# A SUSP entry of a type nobody defines, which SUSP has a reader skip.
_UNKNOWN_ENTRY = b"XX\x0a\x01" + b"\x00" * 6


def _zisofs_image(
    plain: bytes,
    *,
    short: bool = False,
    mangle: Callable[[bytes], bytes] = lambda chunk: chunk,
    **zf: Any,
) -> bytes:
    """``plain`` stored as zisofs, with a ``ZF`` entry built from ``zf``; ``short``
    cuts the entry to 12 bytes, which cannot hold the fields. ``mangle`` as for
    ``_zisofs``."""
    stored = _zisofs(plain, mangle=mangle)

    def populate(iso: Any) -> None:
        iso.add_fp(io.BytesIO(stored), len(stored), "/ZZZ.;1", rr_name="zzz")
        iso.add_fp(io.BytesIO(b"BBBB"), 4, "/BBB.;1", rr_name="bbb")

    data = _build_rr_iso(populate)
    entry = _zf_entry(len(plain), **zf)
    if short:
        entry = entry[:2] + b"\x0c" + entry[3:12] + b"XX\x04\x01"
    return _replace_tf(data, b"zzz", entry + _UNKNOWN_ENTRY)


# Four 32 KiB blocks: text, text then zeros, all zeros (block 2, which ``_zisofs``
# stores as no data), zeros then ``tail``.
_ZISOFS_PLAIN = (b"zisofs block data " * 3000) + bytes(70_000) + b"tail"


def test_a_zisofs_member_lists_its_decoded_size_and_reads_decoded(
    tmp_path: Path,
) -> None:
    """pycdlib refuses a ``ZF`` entry, which cost the whole image. The member lists
    with the size the entry declares and reads the bytes ``mkzftree`` compressed,
    including a block of zeros stored as no data; its neighbour is untouched."""
    stored = _zisofs(_ZISOFS_PLAIN)
    count = -(-len(_ZISOFS_PLAIN) // (1 << 15)) + 1
    pointers = struct.unpack(f"<{count}I", stored[16 : 16 + 4 * count])
    assert pointers[2] == pointers[3] < pointers[4]  # block 2 is stored as no data
    data = _zisofs_image(_ZISOFS_PLAIN)
    with open_archive(io.BytesIO(data)) as ar:
        by_name = {m.name: m for m in ar.members()}
        zzz = by_name["zzz"]
        assert zzz.size == len(_ZISOFS_PLAIN)
        assert zzz.compressed_size == len(_zisofs(_ZISOFS_PLAIN))
        assert zzz.compression == (
            CompressionMethod(algo=CompressionAlgorithm.DEFLATE),
        )
        assert zzz.diagnostics == ()
        assert ar.read("zzz") == _ZISOFS_PLAIN
        assert ar.read("bbb") == b"BBBB"
        ar.extract_all(tmp_path / "out")
    assert (tmp_path / "out" / "zzz").read_bytes() == _ZISOFS_PLAIN


def test_a_zisofs_member_seeks_across_blocks() -> None:
    data = _zisofs_image(_ZISOFS_PLAIN)
    with (
        open_archive(io.BytesIO(data), seekable_members=True) as ar,
        ar.open("zzz") as stream,
    ):
        for offset in (70_000, 5, 54_000, len(_ZISOFS_PLAIN) - 3):
            stream.seek(offset)
            assert stream.read(10) == _ZISOFS_PLAIN[offset : offset + 10]


def test_a_zisofs_member_seeks_relative_and_clamps_underflow_to_zero() -> None:
    """``SEEK_CUR`` and ``SEEK_END`` land where they say, and a relative seek to
    before the start clamps to 0 as every member stream does; it is the caller's
    seek, not damage in the image."""
    data = _zisofs_image(_ZISOFS_PLAIN)
    with (
        open_archive(io.BytesIO(data), seekable_members=True) as ar,
        ar.open("zzz") as stream,
    ):
        assert stream.seek(-4, io.SEEK_END) == len(_ZISOFS_PLAIN) - 4
        assert stream.read() == b"tail"
        stream.seek(70_000)
        assert stream.seek(-60_000, io.SEEK_CUR) == 10_000
        assert stream.read(10) == _ZISOFS_PLAIN[10_000:10_010]
        assert stream.seek(-(10**7), io.SEEK_CUR) == 0
        assert stream.read(10) == _ZISOFS_PLAIN[:10]
        assert stream.seek(-(10**7), io.SEEK_END) == 0
        assert stream.read(10) == _ZISOFS_PLAIN[:10]
        stream.seek(0)
        assert_seek_underflow_matches_bytesio(stream)


def test_the_zisofs_stream_refuses_a_negative_absolute_seek_and_a_bad_whence() -> None:
    """The member contract above goes through ``ArchiveStream.seek``, which refuses
    both before the zisofs stream sees them. The stream refuses them itself too, with
    the caller's ``ValueError`` and without moving."""
    from archivey.internal.backends.iso_reader import _ZisofsEntry, _ZisofsStream

    entry = _ZisofsEntry(b"ZF", 1, b"pz", 16, 15, len(_ZISOFS_PLAIN))
    stored = _zisofs(_ZISOFS_PLAIN)
    stream = _ZisofsStream(io.BytesIO(stored), entry, len(stored))
    stream.seek(10)
    for offset, whence in ((-1, io.SEEK_SET), (0, 7)):
        with pytest.raises(ValueError) as excinfo:
            stream.seek(offset, whence)
        assert type(excinfo.value) is ValueError
        assert stream.tell() == 10


@pytest.mark.parametrize(
    "zf",
    [
        {"version": 2},
        {"algorithm": b"xz"},
        {"header_size": 20},
        {"log2_block_size": 20},
        {"tag": b"Z2", "version": 2},
        {"short": True},
    ],
    ids=["zisofs2", "algorithm", "header-size", "block-size", "z2-tag", "short"],
)
def test_a_zisofs_member_this_reader_cannot_decode_is_refused_alone(
    zf: dict[str, Any],
) -> None:
    data = _zisofs_image(_ZISOFS_PLAIN, **zf)
    with open_archive(io.BytesIO(data)) as ar:
        assert ar.get("zzz").compression == (
            CompressionMethod(algo=CompressionAlgorithm.UNKNOWN),
        )
        assert ar.read("bbb") == b"BBBB"
        with pytest.raises(UnsupportedFeatureError, match="zisofs"):
            ar.read("zzz")


def test_a_damaged_zisofs_block_is_corruption() -> None:
    data = bytearray(_zisofs_image(_ZISOFS_PLAIN))
    stored = _zisofs(_ZISOFS_PLAIN)
    at = data.index(stored)
    first_block = at + struct.unpack_from("<I", stored, 16)[0]  # pointer 0
    data[first_block : first_block + 8] = b"\xff" * 8
    with (
        open_archive(io.BytesIO(bytes(data))) as ar,
        raises_corruption_not_truncation(),
    ):
        ar.read("zzz")


@pytest.mark.parametrize(
    ("mangle", "match"),
    [
        (lambda chunk: chunk[:-4], "does not end"),
        (lambda chunk: chunk + b"junk" * 10, "does not end"),
        (lambda chunk: chunk + bytes(40_000), "spans"),
    ],
    ids=["checksum-cut", "trailing-bytes", "span-past-bound"],
)
def test_a_zisofs_block_that_does_not_end_at_its_pointer_is_corruption(
    mangle: Callable[[bytes], bytes], match: str
) -> None:
    """A block is accepted only when its zlib stream, checksum included, ends exactly
    where the next pointer says. A span longer than any deflated block of the block
    size is refused before it is read, so a pointer cannot size an allocation."""
    data = _zisofs_image(_ZISOFS_PLAIN, mangle=mangle)
    with open_archive(io.BytesIO(data)) as ar:
        assert ar.read("bbb") == b"BBBB"
        with raises_corruption_not_truncation(match=match):
            ar.read("zzz")


@pytest.mark.parametrize(
    ("cut", "match"),
    [(10, "header"), (20, "pointer"), (100, "block 0")],
    ids=["header", "pointer-table", "block-data"],
)
def test_a_zisofs_member_cut_by_the_image_end_is_truncated(
    cut: int, match: str
) -> None:
    """The declared-length check is off for zisofs members; the decoder raises
    ``TruncatedError`` where the stored data runs out instead. The member before it
    still reads."""
    from archivey.exceptions import TruncatedError

    data = _zisofs_image(_ZISOFS_PLAIN)
    at = data.index(_zisofs(_ZISOFS_PLAIN))
    assert data.index(b"BBBB") < at
    with open_archive(io.BytesIO(data[: at + cut])) as ar:
        assert ar.get("zzz").size == len(_ZISOFS_PLAIN)
        assert ar.read("bbb") == b"BBBB"
        with pytest.raises(TruncatedError, match=match):
            ar.read("zzz")


def test_a_zisofs_block_that_inflates_past_the_block_size_is_corruption() -> None:
    """The decoded length is capped one byte past the block, so an over-long block
    raises rather than being cut to fit."""
    import zlib

    good = _zisofs(bytes(range(256)) * 128)  # one full 32 KiB block
    header, pointers = good[:16], good[16:24]
    packed = zlib.compress(bytes(range(256)) * 128 + b"!")
    stored = header + struct.pack("<II", 24, 24 + len(packed)) + packed

    def populate(iso: Any) -> None:
        iso.add_fp(io.BytesIO(stored), len(stored), "/ZZZ.;1", rr_name="zzz")

    data = _replace_tf(
        _build_rr_iso(populate), b"zzz", _zf_entry(32 * 1024) + _UNKNOWN_ENTRY
    )
    assert pointers == struct.pack("<II", 24, len(good))
    with (
        open_archive(io.BytesIO(data)) as ar,
        raises_corruption_not_truncation(match="block 0"),
    ):
        ar.read("zzz")


def test_pycdlib_used_directly_is_not_filtered() -> None:
    """The filter runs only inside archivey's own ``open_fp``."""
    import pycdlib
    from pycdlib.pycdlibexception import PyCdlibInvalidISO

    iso = pycdlib.PyCdlib()
    with pytest.raises(PyCdlibInvalidISO, match="Unknown SUSP record"):
        iso.open_fp(io.BytesIO(_zisofs_image(_ZISOFS_PLAIN)))


def _cut_after(data: bytes, name: bytes) -> bytes:
    """Give the ``TF`` entry after Rock Ridge name ``name`` a version of 99."""
    at = data.index(b"NM" + bytes([5 + len(name)]) + b"\x01\x00" + name)
    tf = data.index(b"TF\x1a\x01", at)
    return data[: tf + 3] + b"\x63" + data[tf + 4 :]


def test_a_malformed_rock_ridge_entry_costs_its_own_member_only() -> None:
    """genisoimage wraps an ``SL`` length past 255 for a long symlink target, and pycdlib
    then refused the whole image. The area is read up to the malformed entry; the member
    keeps what came before it and says the rest was dropped."""
    from archivey import DiagnosticCode

    data = _cut_after(_build_rr_iso(_two_rr_files), b"aaa")
    with open_archive(io.BytesIO(data)) as ar:
        by_name = {m.name: m for m in ar.members()}
        aaa = by_name["aaa"]
        assert aaa.mode == 0o444  # from PX, which came before the cut
        assert ar.read("aaa") == b"AAAA"
        [diagnostic] = aaa.diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        assert diagnostic.context.list_truncated
        assert diagnostic.context.record == ""
        assert "version 99" in diagnostic.context.reason
        assert by_name["bbb"].diagnostics == ()


def test_a_report_made_while_listing_names_the_member_as_listed() -> None:
    """A directory's name ends in ``/`` once normalized; a report made while the
    member was typed names it the same way, so the two can be matched."""
    from archivey import DiagnosticCode

    def populate(iso: Any) -> None:
        iso.add_directory("/DDD", rr_name="ddd")

    data = _cut_after(_build_rr_iso(populate), b"ddd")
    with open_archive(io.BytesIO(data)) as ar:
        ddd = {m.name: m for m in ar.members()}["ddd/"]
        [diagnostic] = ddd.diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        assert diagnostic.context.member_name == "ddd/"
        assert "ddd/" in diagnostic.message


def test_an_empty_rock_ridge_name_falls_back_to_the_iso9660_name() -> None:
    """An ``NM`` entry that spells nothing would join into a path as an empty
    component, listing the directory's children one level up and the directory as a
    second copy of its parent. The ISO 9660 name stands in, as Linux's isofs does."""
    from archivey import DiagnosticCode

    def populate(iso: Any) -> None:
        iso.add_directory("/TOP", rr_name="top")
        iso.add_directory("/TOP/DDDD", rr_name="dddd")
        iso.add_fp(io.BytesIO(b"in"), 2, "/TOP/DDDD/IN.;1", rr_name="in")

    data = _build_rr_iso(populate)
    nm = b"NM\x09\x01\x00dddd"
    assert data.count(nm) == 1
    # The empty NM, then a 4-byte SUSP entry of no known type that pads the area back
    # to its old length, so nothing else moves.
    data = data.replace(nm, b"NM\x05\x01\x00" + b"XX\x04\x01")
    with open_archive(io.BytesIO(data)) as ar:
        members = ar.members()
        # A list, not a dict's keys: the directory listed as a second ``top/`` is
        # half of what this guards against.
        assert sorted(m.name for m in members) == ["top/", "top/DDDD/", "top/DDDD/in"]
        by_name = {m.name: m for m in members}
        assert ar.read("top/DDDD/in") == b"in"
        [diagnostic] = by_name["top/DDDD/"].diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        assert diagnostic.context.record == "NM"
        assert "listed under its ISO 9660 name" in diagnostic.message


def test_an_empty_nm_over_an_empty_iso9660_identifier_collapses_as_in_any_format() -> (
    None
):
    """With no name in either namespace there is nothing to fall back to: the empty
    component collapses, as ``a//b`` does in a ZIP, and both reports say so. The
    diagnostic does not claim an ISO 9660 name that is not there."""
    from archivey import DiagnosticCode

    def populate(iso: Any) -> None:
        iso.add_directory("/TOP", rr_name="top")
        iso.add_directory("/TOP/DDDD", rr_name="dddd")
        iso.add_fp(io.BytesIO(b"in"), 2, "/TOP/DDDD/IN.;1", rr_name="in")

    data = _build_rr_iso(populate)
    data = data.replace(b"NM\x09\x01\x00dddd", b"NM\x05\x01\x00XX\x04\x01")
    # The record's identifier length goes to 0. Its System Use area moves up to the
    # new offset (33, plus the pad byte an even length takes), and a 4-byte unknown
    # entry fills the tail, so the record keeps its length.
    at = data.index(b"\x04DDDD") - 32
    record = data[at : at + data[at]]
    moved = record[:32] + b"\x00\x00" + record[38:] + b"XX\x04\x01"
    assert len(moved) == len(record)
    data = data[:at] + moved + data[at + len(record) :]
    with open_archive(io.BytesIO(data)) as ar:
        assert sorted(m.name for m in ar.members()) == ["top/", "top/", "top/in"]
        codes = {d.code: d for d in ar.diagnostics.retained}
        assert (
            "no name is left"
            in codes[DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED].message
        )
        assert DiagnosticCode.MEMBER_NAME_NORMALIZED in codes


@pytest.mark.parametrize("flags", [3, 5, 6, 7])
def test_an_nm_entry_with_flags_pycdlib_refuses_costs_only_its_member(
    flags: int,
) -> None:
    """pycdlib refuses an ``NM`` with more than one of CONTINUE, CURRENT and PARENT,
    and with it the whole image; isofs ignores the entry. The filter ends the area at
    it, so the image lists and the member says what it lost."""
    from archivey import DiagnosticCode

    def populate(iso: Any) -> None:
        iso.add_directory("/TOP", rr_name="top")
        iso.add_directory("/TOP/DDDD", rr_name="dddd")
        iso.add_fp(io.BytesIO(b"in"), 2, "/TOP/DDDD/IN.;1", rr_name="in")

    data = _build_rr_iso(populate)
    nm = b"NM\x09\x01\x00dddd"
    assert data.count(nm) == 1
    data = data.replace(nm, b"NM\x09\x01" + bytes([flags]) + b"dddd")
    with open_archive(io.BytesIO(data)) as ar:
        members = ar.members()
        assert sorted(m.name for m in members) == ["top/", "top/DDDD/", "top/DDDD/in"]
        [diagnostic] = {m.name: m for m in members}["top/DDDD/"].diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        assert diagnostic.context.list_truncated


def test_a_directory_record_without_entries_is_named_as_listed() -> None:
    """The report for a record with no Rock Ridge entries names a directory with its
    ``/``, in the message as in the context."""
    from archivey import DiagnosticCode

    def populate(iso: Any) -> None:
        iso.add_directory("/DDD", rr_name="ddd")

    data = bytearray(_build_rr_iso(populate))
    # The directory record, not the path table entry: its identifier length sits
    # at offset 32 and the identifier at 33.
    at = next(
        i
        for i in range(len(data))
        if data.startswith(b"DDD", i)
        and i >= 33
        and data[i - 1] == 3
        and data[i - 33] >= 33 + 3
    )
    start = at - 33
    extent = int.from_bytes(data[start + 2 : start + 6], "little") * 2048
    # The directory's own ``.`` and ``..`` records lose their entries too, or pycdlib
    # refuses children with Rock Ridge under a parent without it.
    dot = extent
    dotdot = dot + data[dot]
    for record, ident_len in ((start, 3), (dot, 1), (dotdot, 1)):
        su = record + 33 + ident_len + (1 if ident_len % 2 == 0 else 0)
        data[su : record + data[record]] = bytes(record + data[record] - su)
    with open_archive(io.BytesIO(bytes(data))) as ar:
        ddd = {m.name: m for m in ar.members()}["DDD/"]
        [diagnostic] = ddd.diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        assert diagnostic.context.member_name == "DDD/"
        assert "'DDD/'" in diagnostic.message


def test_an_area_cut_before_its_nm_entry_lists_under_the_iso_name() -> None:
    """With no ``NM`` entry pycdlib names the record by its ISO 9660 identifier,
    ``;1`` included; the member lists under the identifier with that removed, as a
    record with no Rock Ridge entries at all does."""
    from archivey import DiagnosticCode

    data = bytearray(_build_rr_iso(_two_rr_files))
    nm = data.index(b"NM\x08\x01\x00aaa")
    rr = data.rindex(b"RR\x05\x01", 0, nm)
    data[rr + 3] = 99
    with open_archive(io.BytesIO(bytes(data))) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert set(by_name) == {"AAA", "bbb"}
        assert by_name["AAA"].raw_name == b"AAA"
        assert ar.read("AAA") == b"AAAA"
        assert [d.code for d in by_name["AAA"].diagnostics] == [
            DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        ]


def test_a_record_without_a_continuation_area_has_no_nm_name() -> None:
    """pycdlib leaves ``ce_entries`` as ``None`` until a continuation area is parsed; a
    record with neither an ``NM`` nor such an area has no ``NM`` name. The end-to-end
    case is the cut-area test above.
    """
    import pycdlib

    from archivey.internal.backends.iso_reader import _nm_name, _rr_entry_groups

    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(_build_rr_iso(_two_rr_files)))
    try:
        record = iso.get_record(rr_path="/aaa")
        rr = record.rock_ridge
        assert rr is not None
        assert rr.ce_entries is None
        assert _rr_entry_groups(rr) == (rr.dr_entries,)
        rr.dr_entries.nm_records = []
        assert _nm_name(record) is None
    finally:
        iso.close()


def test_a_symlink_whose_entries_are_cut_withholds_its_target() -> None:
    """The target may have run on past the malformed entry (genisoimage's long
    targets do), so it is not reported cut short."""
    from archivey import DiagnosticCode

    def populate(iso: Any) -> None:
        iso.add_fp(io.BytesIO(b"AAAA"), 4, "/AAA.;1", rr_name="aaa")
        iso.add_symlink("/LNK.;1", rr_symlink_name="lnk", rr_path="a/b/c")

    data = _cut_after(_build_rr_iso(populate), b"lnk")
    with open_archive(io.BytesIO(data)) as ar:
        lnk = {m.name: m for m in ar.members()}["lnk"]
        assert lnk.type is MemberType.SYMLINK
        assert lnk.link_target is None
        assert [d.code for d in lnk.diagnostics] == [
            DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
            DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE,
        ]


def test_a_strict_policy_refuses_a_cut_rock_ridge_area() -> None:
    from archivey import ArchiveyConfig, DiagnosticPolicy
    from archivey.exceptions import ArchiveyError

    data = _cut_after(_build_rr_iso(_two_rr_files), b"aaa")
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(ArchiveyError),
        open_archive(io.BytesIO(data), config=strict) as ar,
    ):
        ar.members()


# --- names that are not UTF-8 ----------------------------------------------------------


def _latin1_name_image() -> bytes:
    """A Rock Ridge name written in Latin-1, as ``genisoimage -input-charset
    iso8859-1`` stores ``caféé.txt``, beside a symlink pointing at it."""

    def populate(iso: Any) -> None:
        iso.add_fp(io.BytesIO(b"x"), 1, "/CAF.TXT;1", rr_name="cafXY.txt")
        iso.add_symlink("/LNK.;1", rr_symlink_name="lnk", rr_path="cafXY.txt")

    return _build_rr_iso(populate).replace(b"cafXY", b"caf\xe9\xe9")


def test_a_latin1_rock_ridge_name_decodes_with_encoding() -> None:
    """UTF-8 first, then ``encoding=`` for bytes that are not UTF-8, as TAR does;
    ``raw_name`` is the stored bytes either way."""
    from archivey import DiagnosticCode

    data = _latin1_name_image()
    with open_archive(io.BytesIO(data)) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert set(by_name) == {"caf\udce9\udce9.txt", "lnk"}
        assert by_name["caf\udce9\udce9.txt"].raw_name == b"caf\xe9\xe9.txt"
    with open_archive(io.BytesIO(data), encoding="latin-1") as ar:
        by_name = {m.name: m for m in ar.members()}
        member = by_name["caféé.txt"]
        assert member.raw_name == b"caf\xe9\xe9.txt"
        assert by_name["lnk"].link_target == "caféé.txt"
        assert ar.read("caféé.txt") == b"x"
        assert DiagnosticCode.ENCODING_ARGUMENT_UNUSED not in ar.diagnostics.counts


def _latin1_names_with_joliet_image() -> bytes:
    """Rock Ridge names in Latin-1 beside a Joliet tree that has them right, as
    ``genisoimage -R -J -input-charset iso8859-1`` writes. ``#`` stands for the
    Latin-1 byte in each Rock Ridge name, swapped in after pycdlib writes the image."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09", joliet=3)
    iso.add_directory("/REP", rr_name="r#pertoire", joliet_path="/répertoire")
    iso.add_fp(
        io.BytesIO(b"naive"),
        5,
        "/REP/NAIVE.TXT;1",
        rr_name="na#ve.txt",
        joliet_path="/répertoire/naïve.txt",
    )
    iso.add_directory("/ONLY", rr_name="only#", joliet_path="/onlyé")
    iso.add_directory("/ONLY/INNER", rr_name="inner", joliet_path="/onlyé/inner")
    iso.add_fp(
        io.BytesIO(b"f"),
        1,
        "/ONLY/INNER/F.TXT;1",
        rr_name="f.txt",
        joliet_path="/onlyé/inner/f.txt",
    )
    iso.add_fp(
        io.BytesIO(b"cafe"),
        4,
        "/CAFE.TXT;1",
        rr_name="caf#.txt",
        joliet_path="/café.txt",
    )
    iso.add_fp(io.BytesIO(b""), 0, "/EMPTY.;1", rr_name="empty#", joliet_path="/emptyé")
    iso.add_fp(io.BytesIO(b""), 0, "/OTHER.;1", rr_name="other", joliet_path="/other")
    iso.add_symlink("/LNK.;1", rr_symlink_name="lnk", rr_path="caf#.txt")
    iso.add_symlink("/REP/UP.;1", rr_symlink_name="up", rr_path="../caf#.txt")
    iso.add_symlink("/DOWN.;1", rr_symlink_name="down", rr_path="r#pertoire/na#ve.txt")
    iso.add_symlink("/ABS.;1", rr_symlink_name="abs", rr_path="/caf#.txt")
    # A Joliet name cut short, as writers cut them at 64 characters.
    iso.add_fp(
        io.BytesIO(b"long"),
        4,
        "/LONG.TXT;1",
        rr_name="long#name.txt",
        joliet_path="/longé",
    )
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    data = out.getvalue()
    for name in (b"r#pertoire", b"only#", b"caf#.txt", b"empty#", b"long#name"):
        data = data.replace(name, name.replace(b"#", b"\xe9"))
    return data.replace(b"na#ve.txt", b"na\xefve.txt")


def test_a_latin1_rock_ridge_name_takes_its_joliet_name() -> None:
    """Without ``encoding=``, a Rock Ridge name that is not UTF-8 takes the Joliet name
    of the same file or directory, and says so; ``raw_name`` stays the stored bytes."""
    from archivey import DiagnosticCode

    with open_archive(io.BytesIO(_latin1_names_with_joliet_image())) as ar:
        by_name = {m.name: m for m in ar.members()}
        assert set(by_name) == {
            "répertoire/",
            "répertoire/naïve.txt",
            "onlyé/",
            "onlyé/inner/",
            "onlyé/inner/f.txt",
            "café.txt",
            "emptyé",
            "other",
            "long\udce9name.txt",
            "lnk",
            "répertoire/up",
            "down",
            "abs",
        }
        inferred = {
            name
            for name, member in by_name.items()
            if any(
                d.code == DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED
                for d in member.diagnostics
            )
        }
        assert inferred == {
            "répertoire/",
            "répertoire/naïve.txt",
            "onlyé/",
            "café.txt",
            "emptyé",
        }
        assert by_name["café.txt"].raw_name == b"caf\xe9.txt"
        # A link names its target the way the target's member is named; an absolute
        # target points outside the image and stays escaped.
        assert by_name["lnk"].link_target == "café.txt"
        assert by_name["répertoire/up"].link_target == "../café.txt"
        assert by_name["down"].link_target == "répertoire/naïve.txt"
        assert by_name["abs"].link_target == "/caf\udce9.txt"
        # No decode of the stored bytes made the name, so no encoding is claimed.
        (diagnostic,) = by_name["café.txt"].diagnostics
        assert diagnostic.context.inferred_encoding == ""
        assert diagnostic.context.declared_encoding == ""
        assert by_name["répertoire/naïve.txt"].raw_name == b"r\xe9pertoire/na\xefve.txt"
        assert ar.read("répertoire/naïve.txt") == b"naive"


def _wide_latin1_links_image(count: int) -> bytes:
    """One directory of ``count`` Latin-1 files and ``count`` symlinks naming them,
    beside a Joliet tree, so every link target takes the Joliet walk."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09", joliet=3)
    iso.add_directory("/W", rr_name="w", joliet_path="/w")
    for i in range(count):
        iso.add_fp(
            io.BytesIO(b"x"),
            1,
            f"/W/F{i}.;1",
            rr_name=f"f#{i:03d}",
            joliet_path=f"/w/fé{i:03d}",
        )
        iso.add_symlink(f"/W/L{i}.;1", rr_symlink_name=f"l{i}", rr_path=f"f#{i:03d}")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue().replace(b"f#", b"f\xe9")


def test_following_link_targets_reads_each_directory_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Link targets are looked up through a per-directory index, so the number of
    directory walks does not grow with the number of links in a directory; a scan
    per target component made listing one wide directory quadratic."""
    from archivey.internal.backends import iso_reader

    real = iso_reader._yield_children
    calls = 0

    def counting(record: Any, rock_ridge: bool) -> Any:
        nonlocal calls
        calls += 1
        return real(record, rock_ridge)

    monkeypatch.setattr(iso_reader, "_yield_children", counting)
    walks = []
    for count in (4, 40):
        calls = 0
        with open_archive(io.BytesIO(_wide_latin1_links_image(count))) as ar:
            members = list(ar.members())
        assert {m.link_target for m in members if m.link_target} == {
            f"fé{i:03d}" for i in range(count)
        }
        walks.append(calls)
    assert walks[0] == walks[1], walks


def test_empty_files_sharing_an_extent_are_matched_in_linear_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every empty file can share one extent, so a Joliet name is looked up by extent
    and name together; matching each Rock Ridge name against every file at the extent
    made listing N empty Latin-1 files quadratic."""
    import pycdlib

    from archivey.internal.backends import iso_reader

    real = iso_reader._ascii_runs_match
    calls = 0

    def counting(raw: bytes, name: str) -> bool:
        nonlocal calls
        calls += 1
        return real(raw, name)

    monkeypatch.setattr(iso_reader, "_ascii_runs_match", counting)
    for count in (4, 40):
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=3, rock_ridge="1.09", joliet=3)
        for i in range(count):
            iso.add_fp(
                io.BytesIO(b""),
                0,
                f"/E{i}.;1",
                rr_name=f"e#{i:03d}",
                joliet_path=f"/eé{i:03d}",
            )
        out = io.BytesIO()
        iso.write_fp(out)
        iso.close()
        calls = 0
        data = out.getvalue().replace(b"e#", b"e\xe9")
        with open_archive(io.BytesIO(data)) as ar:
            names = {m.name for m in ar.members()}
        assert names == {f"eé{i:03d}" for i in range(count)}
        assert calls <= count, (count, calls)


def test_encoding_wins_over_the_joliet_name() -> None:
    with open_archive(
        io.BytesIO(_latin1_names_with_joliet_image()), encoding="cp1252"
    ) as ar:
        members = list(ar.members())
    assert {m.name for m in members} >= {"café.txt", "longéname.txt"}
    assert all(not m.diagnostics for m in members)


@pytest.mark.parametrize("encoding", ["utf-32", "idna"])
def test_an_encoding_that_cannot_decode_the_name_falls_back_to_escapes(
    encoding: str,
) -> None:
    """A text codec that fails on the bytes, or has no ``surrogateescape``, costs
    neither the listing nor the name: it decodes as with no ``encoding=``."""
    with open_archive(io.BytesIO(_latin1_name_image()), encoding=encoding) as ar:
        names = {m.name for m in ar.members()}
    assert "caf\udce9\udce9.txt" in names


def test_the_filter_knows_every_entry_pycdlib_parses() -> None:
    """``_PYCDLIB_SUSP_TAGS`` mirrors pycdlib's dispatch by hand. pycdlib names one
    ``RR<TAG>Record`` class per tag it parses, so a release that adds one fails here
    rather than having archivey drop the new entry before pycdlib sees it."""
    import re

    from pycdlib import rockridge

    from archivey.internal.backends.iso_reader import _PYCDLIB_SUSP_TAGS

    tags = {
        name[2:4].encode()
        for name in dir(rockridge)
        if re.fullmatch(r"RR[A-Z]{2}Record", name)
    }
    assert tags == _PYCDLIB_SUSP_TAGS


def test_a_utf8_rock_ridge_name_ignores_encoding() -> None:
    def populate(iso: Any) -> None:
        iso.add_fp(io.BytesIO(b"x"), 1, "/CAF.TXT;1", rr_name="café.txt")

    with open_archive(io.BytesIO(_build_rr_iso(populate)), encoding="latin-1") as ar:
        [member] = ar.members()
        assert member.name == "café.txt"
        assert member.raw_name == "café.txt".encode()


@pytest.mark.parametrize(
    ("name", "iso9660", "expected"),
    [
        ("FOO.;1", True, ("FOO", 1)),
        ("FOO.;1", False, ("FOO.", 1)),
        ("FOO;1", True, ("FOO", 1)),
        ("FOO;1", False, ("FOO", 1)),
        ("A.;12", True, ("A", 12)),
        ("A.;12", False, ("A.", 12)),
        # A bare ``;N`` is a plain ISO 9660 name; Joliet strips it to nothing.
        (";1", True, (";1", None)),
        (";1", False, ("", 1)),
        # A lone dot is kept: it is the whole stem, not an empty extension.
        (".;1", True, (".", 1)),
        (".;1", False, (".", 1)),
        ("..;3", True, (".", 3)),
        ("..;3", False, ("..", 3)),
        ("FOO.;", True, ("FOO.;", None)),
        ("FOO.;", False, ("FOO.;", None)),
        # A final newline is part of the name, so no version follows it.
        ("FOO;1\n", True, ("FOO;1\n", None)),
        ("FOO;1\n", False, ("FOO;1\n", None)),
        # A version is ASCII digits; an Arabic-Indic one is part of the name.
        ("FOO;\u0661", True, ("FOO;\u0661", None)),
        ("FOO;\u0661", False, ("FOO;\u0661", None)),
    ],
)
def test_strip_version_rules(
    name: str, iso9660: bool, expected: tuple[str, int | None]
) -> None:
    assert _strip_version(name, iso9660=iso9660) == expected
