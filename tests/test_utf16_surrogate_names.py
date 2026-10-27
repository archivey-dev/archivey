"""RAR 1.5-4 and Joliet member names that hold a lone UTF-16 surrogate.

Both formats store names as UTF-16 code units, as 7z does, so a name made on Windows
can carry a surrogate without its partner. The readers decode with ``surrogatepass``
and keep that unit in ``member.name``, as the 7z reader does
(``tests/test_sevenzip_surrogate_names.py``). What reaches disk is decided at
extraction, for every format alike, so each extraction test here compares the tree
with the one the same names give from a 7z.

The archives are built in the test: no tool writes a lone surrogate into either
format from a POSIX host.
"""

from __future__ import annotations

import io
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

import archivey
from archivey.config import ArchiveyConfig, RarDecompressor
from archivey.exceptions import UnsupportedFeatureError
from archivey.types import ExtractionPolicy, ExtractionStatus
from tests.conftest import requires, requires_binary
from tests.extract_util import open_and_extract
from tests.test_audit_rar_iso_dir import _fixture, _rar3_build, _rar3_parse
from tests.test_sevenzip_surrogate_names import _surrogate_7z, _tree

_BYTE_NAMES = sys.platform not in ("win32", "darwin")

_FILES = [
    ("hi\ud800.txt", b"high"),
    ("ok.txt", b"ok"),
    ("z\udfff", b"last"),
    ("dir\udbff/in.txt", b"nested"),
    ("lo\udc80.txt", b"low"),  # the surrogateescape range: one byte on disk
    ("pair\U0001f600.txt", b"pair"),  # a valid pair is one character
]
_NAMES = [name for name, _ in _FILES]


# --- RAR 1.5-4 ------------------------------------------------------------------


def _rar3_encode_unicode(name: str) -> bytes:
    """``name`` in the RAR 1.5-4 compressed UTF-16 form, every unit stored whole.

    The form is a high-byte seed, then a flags byte per four units; flag 2 means the
    unit's two bytes follow (unrar ``EncodeFileName::Decode``).
    """
    units = name.encode("utf-16le", "surrogatepass")
    out = bytearray(b"\x00")
    for start in range(0, len(units), 8):
        chunk = units[start : start + 8]
        out.append(0xAA)
        out += chunk
    return bytes(out)


def _rar4_unicode(
    tmp_path: Path, files: list[tuple[str, bytes]], *, std: bytes | None = None
) -> Path:
    """A nonsolid RAR 2.9 archive of stored members, each with a UTF-16 name field.

    The 8-bit field holds ``std`` when given, else the name with every non-ASCII
    character as ``_``, as a writer whose code page lacks it would.
    """
    blocks = _rar3_parse(_fixture("hostile_argv__rar4.rar").read_bytes())
    template = next(block for block in blocks if block["type"] == 0x74)
    head = [block for block in blocks if block["type"] == 0x73]
    tail = [block for block in blocks if block["type"] == 0x7B]
    members = []
    for name, data in files:
        stored = name.replace("/", "\\")
        eight_bit = std or "".join(c if c < "\x80" else "_" for c in stored).encode()
        field = eight_bit + b"\x00" + _rar3_encode_unicode(stored)
        header = bytearray(template["header"])
        flags = struct.unpack_from("<H", header, 3)[0]
        old_len = struct.unpack_from("<H", header, 26)[0]
        offset = 32 + (8 if flags & 0x100 else 0)
        header[offset : offset + old_len] = field
        struct.pack_into("<H", header, 26, len(field))
        # Unicode flag; not solid, not a directory; stored.
        struct.pack_into("<H", header, 3, (flags & ~0x02F0) | 0x0200)
        struct.pack_into("<II", header, 7, len(data), len(data))
        struct.pack_into("<I", header, 16, zlib.crc32(data))
        header[15] = 2  # Win32
        struct.pack_into("<I", header, 28, 0x20)  # FILE_ATTRIBUTE_ARCHIVE
        header[25] = 0x30
        struct.pack_into("<H", header, 5, len(header))
        members.append({"type": 0x74, "header": header, "data": data})
    path = tmp_path / "surrogate4.rar"
    path.write_bytes(_rar3_build(head + members + tail))
    return path


# --- Joliet ---------------------------------------------------------------------

# Each placeholder stands in for one unit of _FILES; the image is written with the
# placeholders and their UTF-16BE bytes are then swapped for the surrogate's.
# A list, not a dict: ruff takes every surrogate key for the same one (F601).
_PLACEHOLDERS = [
    ("\ud800", "\u4e00"),
    ("\udfff", "\u4e01"),
    ("\udbff", "\u4e02"),
    ("\udc80", "\u4e03"),
]


def _placeheld(text: str) -> str:
    for unit, placeholder in _PLACEHOLDERS:
        text = text.replace(unit, placeholder)
    return text


def _swap_placeholders(
    image: bytes, *, rock_ridge: dict[str, bytes], symlinks: tuple[tuple[str, str], ...]
) -> bytes:
    for unit, placeholder in _PLACEHOLDERS:
        old = placeholder.encode("utf-16_be")
        image = image.replace(old, unit.encode("utf-16_be", "surrogatepass"))
    for placeholder_name, stored in rock_ridge.items():
        old = placeholder_name.encode()
        # Its NM record, and the SL record of each symlink that targets it.
        expected = 1 + sum(target == placeholder_name for _, target in symlinks)
        assert len(old) == len(stored) and image.count(old) == expected
        image = image.replace(old, stored)
    return image


def _joliet_iso(
    files: list[tuple[str, bytes]],
    *,
    rock_ridge: dict[str, bytes] | None = None,
    symlinks: tuple[tuple[str, str], ...] = (),
) -> bytes:
    """A Joliet image (and Rock Ridge when ``rock_ridge`` maps names to NM bytes).

    ``symlinks`` are Rock Ridge ``(name, target)`` pairs in the root; a target that
    holds a ``rock_ridge`` placeholder name is swapped with it.
    """
    import pycdlib

    iso = pycdlib.PyCdlib()
    kwargs: dict[str, object] = {"joliet": 3}
    if rock_ridge is not None:
        kwargs["rock_ridge"] = "1.09"
    iso.new(interchange_level=3, **kwargs)
    made: set[str] = set()
    for index, (name, data) in enumerate(files):
        parts = _placeheld(name).split("/")
        iso_dir = ""
        for depth, part in enumerate(parts[:-1]):
            joliet_dir = "/" + "/".join(parts[: depth + 1])
            iso_dir += f"/D{index}{depth}"
            if joliet_dir not in made:
                made.add(joliet_dir)
                iso.add_directory(
                    iso_dir,
                    joliet_path=joliet_dir,
                    rr_name=part if rock_ridge is not None else None,
                )
        iso.add_fp(
            io.BytesIO(data),
            len(data),
            f"{iso_dir}/F{index}.;1",
            joliet_path="/" + "/".join(parts),
            rr_name=parts[-1] if rock_ridge is not None else None,
        )
    for index, (name, target) in enumerate(symlinks):
        iso.add_symlink(f"/L{index}.;1", rr_symlink_name=name, rr_path=target)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return _swap_placeholders(
        out.getvalue(), rock_ridge=rock_ridge or {}, symlinks=symlinks
    )


# --- listing --------------------------------------------------------------------


def test_rar4_unicode_name_keeps_its_surrogate(tmp_path: Path) -> None:
    archive = _rar4_unicode(tmp_path, _FILES)
    with archivey.open_archive(archive) as reader:
        members = reader.members()
        assert [m.name for m in members] == _NAMES
        # raw_name is the 8-bit field, as for every RAR 1.5-4 name.
        assert members[0].raw_name == b"hi_.txt"
        assert reader.read("hi\ud800.txt") == b"high"
        assert [(m.name, s.read()) for m, s in reader.stream_members()] == _FILES


def test_rar4_astral_cut_to_a_surrogate_unit_is_recovered(tmp_path: Path) -> None:
    """A truncated astral character that lands on a surrogate unit is recovered.

    RAR 2.9-4 keep only the low 16 bits of a character above U+FFFF, so U+1D800
    is stored as the unit U+D800. The 8-bit field holds the UTF-8 name, and the
    reader takes it when the units are exactly 0x10000 below. Under ``replace``
    the unit was U+FFFD and never matched.
    """
    archive = _rar4_unicode(
        tmp_path, [("x\ud800.txt", b"sign")], std="x\U0001d800.txt".encode()
    )
    with archivey.open_archive(archive) as reader:
        (entry,) = reader.members()
    assert entry.name == "x\U0001d800.txt"


@requires("pycdlib")
def test_joliet_name_keeps_its_surrogate(tmp_path: Path) -> None:
    archive = tmp_path / "surrogate.iso"
    archive.write_bytes(_joliet_iso(_FILES))
    with archivey.open_archive(archive) as reader:
        files = {m.name: m for m in reader.members() if m.is_file}
        assert sorted(files) == sorted(_NAMES)
        assert all("\ufffd" not in m.name for m in reader.members())
        assert "dir\udbff/" in {m.name for m in reader.members() if m.is_dir}
        assert reader.read("hi\ud800.txt") == b"high"
        # A Joliet raw_name is the UTF-8 of the name; a lone unit as its three bytes.
        assert files["hi\ud800.txt"].raw_name == b"hi\xed\xa0\x80.txt"


@requires("pycdlib")
def test_rock_ridge_name_takes_a_joliet_name_with_a_surrogate(
    tmp_path: Path,
) -> None:
    """A Rock Ridge name that is not UTF-8 takes its Joliet counterpart's name.

    Before, a Joliet name that held a lone surrogate failed its strict decode and
    the Rock Ridge bytes were escaped instead.
    """
    archive = tmp_path / "rr.iso"
    archive.write_bytes(
        _joliet_iso(
            [("hi\ud800.txt", b"high")],
            rock_ridge={"hi\u4e00.txt": b"hi\xed\xa0\x80.txt"},
        )
    )
    with archivey.open_archive(archive) as reader:
        (member,) = reader.members()
    assert member.name == "hi\ud800.txt"
    assert member.raw_name == b"hi\xed\xa0\x80.txt"


@requires("pycdlib")
def test_rock_ridge_link_target_takes_a_joliet_name_with_a_surrogate(
    tmp_path: Path,
) -> None:
    """A link target component that is not UTF-8 resolves to the name the file has."""
    archive = tmp_path / "rr_link.iso"
    archive.write_bytes(
        _joliet_iso(
            [("hi\ud800.txt", b"high")],
            rock_ridge={"hi\u4e00.txt": b"hi\xed\xa0\x80.txt"},
            symlinks=(("link", "hi\u4e00.txt"),),
        )
    )
    with archivey.open_archive(archive) as reader:
        link = next(m for m in reader.members() if m.name == "link")
    assert link.link_target == "hi\ud800.txt"


# --- extraction -----------------------------------------------------------------


@pytest.fixture(params=["rar4", pytest.param("joliet", marks=requires("pycdlib"))])
def archive(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    if request.param == "rar4":
        return _rar4_unicode(tmp_path, _FILES)
    path = tmp_path / "surrogate.iso"
    path.write_bytes(_joliet_iso(_FILES))
    return path


@pytest.mark.skipif(not _BYTE_NAMES, reason="needs a filesystem that takes any bytes")
@pytest.mark.parametrize("policy", list(ExtractionPolicy))
def test_extraction_writes_what_the_7z_gives(
    archive: Path, tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """The same names extract to the same tree from RAR or Joliet as from a 7z."""
    seven = tmp_path / "same.7z"
    seven.write_bytes(_surrogate_7z(_FILES))
    expected_dest = tmp_path / "from7z"
    expected = open_and_extract(seven, expected_dest, policy=policy)
    dest = tmp_path / "out"
    results = open_and_extract(archive, dest, policy=policy)
    files = [r for r in results if r.member.is_file]
    assert [r.status for r in files] == [ExtractionStatus.EXTRACTED] * len(_FILES)
    assert _tree(dest) == _tree(expected_dest)
    presented = {r.member.name: r.presented_name for r in files}
    assert presented == {r.member.name: r.presented_name for r in expected}


@pytest.mark.skipif(sys.platform != "win32", reason="Windows keeps the exact name")
def test_windows_extraction_uses_the_exact_name(archive: Path, tmp_path: Path) -> None:
    dest = tmp_path / "out"
    open_and_extract(archive, dest, policy=ExtractionPolicy.TRUSTED)
    assert (dest / "hi\ud800.txt").read_bytes() == b"high"
    assert (dest / "dir\udbff" / "in.txt").read_bytes() == b"nested"


# --- the reference tools --------------------------------------------------------


@pytest.mark.skipif(not _BYTE_NAMES, reason="needs a filesystem that takes any bytes")
@requires_binary("7z")
def test_trusted_extraction_matches_the_7z_tool(archive: Path, tmp_path: Path) -> None:
    """7-Zip 23.01 writes a lone unit in a RAR or Joliet name as its UTF-8 form.

    ``TRUSTED`` writes the same bytes. U+DC80-U+DCFF is left out: archivey writes it
    as the byte it stands for, where 7-Zip writes three (see the 7z tests).
    """
    files = [(name, data) for name, data in _FILES if "\udc80" not in name]
    if archive.suffix == ".rar":
        archive = _rar4_unicode(tmp_path, files)
    else:
        archive.write_bytes(_joliet_iso(files))
    seven_zip = shutil.which("7z")
    assert seven_zip is not None
    theirs = tmp_path / "theirs"
    theirs.mkdir()
    subprocess.run(
        [seven_zip, "x", "-y", str(archive)],
        cwd=theirs,
        check=True,
        capture_output=True,
    )
    ours = tmp_path / "ours"
    open_and_extract(archive, ours, policy=ExtractionPolicy.TRUSTED)
    assert _tree(ours) == _tree(theirs)


def _compressed_rar4_surrogate(
    tmp_path: Path, names: tuple[str, ...] = ("hi\ud800.txt",)
) -> tuple[Path, list[bytes]]:
    """The fixture's compressed members renamed to ``names``, in order; their bytes.

    A name with a non-ASCII character gets a UTF-16 field, with ``_`` for it in the
    8-bit field; an ASCII name is an 8-bit name only.
    """
    source = _fixture("hostile_argv__rar4.rar")
    with archivey.open_archive(source) as reader:
        expected = [reader.read(member) for member in reader.members()[: len(names)]]
    blocks = _rar3_parse(source.read_bytes())
    files = [block for block in blocks if block["type"] == 0x74]
    for block, name in zip(files, names, strict=False):
        header = block["header"]
        eight_bit = "".join(c if c < "\x80" else "_" for c in name).encode()
        flags = struct.unpack_from("<H", header, 3)[0]
        if name.isascii():
            field, flags = eight_bit, flags & ~0x0200
        else:
            field, flags = (
                eight_bit + b"\x00" + _rar3_encode_unicode(name),
                flags | 0x0200,
            )
        old_len = struct.unpack_from("<H", header, 26)[0]
        offset = 32 + (8 if flags & 0x100 else 0)
        header[offset : offset + old_len] = field
        struct.pack_into("<H", header, 26, len(field))
        struct.pack_into("<H", header, 3, flags)
        struct.pack_into("<H", header, 5, len(header))
    archive = tmp_path / "compressed4.rar"
    archive.write_bytes(_rar3_build(blocks))
    return archive, expected


_UNRAR = ArchiveyConfig(rar_decompressor=RarDecompressor.UNRAR)


@requires_binary("unrar")
@pytest.mark.parametrize("name", ["hi\ud800.txt", "pair\U0001f600.txt"])
def test_unrar_reads_a_compressed_rar4_name_with_a_surrogate_unit(
    tmp_path: Path, name: str
) -> None:
    """``unrar`` matches these names unit by unit; the mask sends each unit as ``?``.

    No argv encoding carries a surrogate unit to ``unrar``. Before, a lone unit was
    U+FFFD (the read selected nothing and reported a ``TruncatedError``), and a valid
    pair was sent as one character where ``unrar`` holds two.
    """
    archive, expected = _compressed_rar4_surrogate(tmp_path, (name,))
    with archivey.open_archive(archive, config=_UNRAR) as reader:
        assert reader.members()[0].name == name
        lone_unit = any("\ud800" <= char <= "\udfff" for char in name)
        if sys.platform == "win32" and lone_unit:
            # Windows argv carries a valid pair exactly; a lone unit is refused there
            # (what Windows unrar does with one is unmeasured).
            with pytest.raises(UnsupportedFeatureError, match="unar"):
                reader.read(name)
            return
        assert reader.read(name) == expected[0]


@requires_binary("unrar")
@pytest.mark.skipif(sys.platform == "win32", reason="Windows sends no `?` mask")
def test_unrar_sizes_a_read_past_a_surrogate_name_the_mask_also_selects(
    tmp_path: Path,
) -> None:
    """``hi?.txt`` selects ``hiX.txt`` too, so ``unrar`` pipes the earlier member first.

    The last member's 8-bit name ``hi`` is an exact mask that ``unrar`` does not match
    against ``hi`` U+D800 ``.txt`` before it, so that read has nothing to skip.
    """
    names = ("hiX.txt", "hi\ud800.txt", "hi")
    archive, expected = _compressed_rar4_surrogate(tmp_path, names)
    # Decoding an earlier member first is refused by default, as for any glob.
    with (
        archivey.open_archive(archive, config=_UNRAR) as reader,
        pytest.raises(UnsupportedFeatureError, match="earlier members"),
    ):
        reader.read(names[1])
    config = ArchiveyConfig(
        rar_decompressor=RarDecompressor.UNRAR,
        rar_allow_glob_member_concatenation=True,
    )
    with archivey.open_archive(archive, config=config) as reader:
        assert [reader.read(name) for name in names] == expected


@requires_binary("unrar")
@pytest.mark.skipif(sys.platform == "win32", reason="Windows argv carries the unit")
def test_unrar_refuses_a_surrogate_unit_in_a_directory_and_names_unar(
    tmp_path: Path,
) -> None:
    """The unit would reach ``unrar`` as a directory glob, which cannot be sized."""
    archive, _ = _compressed_rar4_surrogate(tmp_path, ("dir\ud800/f.txt",))
    with (
        archivey.open_archive(archive, config=_UNRAR) as reader,
        pytest.raises(UnsupportedFeatureError, match="surrogate unit.*unar"),
    ):
        reader.read("dir\ud800/f.txt")


@requires_binary("unar")
def test_unar_reads_a_compressed_rar4_surrogate_name(tmp_path: Path) -> None:
    archive, expected = _compressed_rar4_surrogate(tmp_path)
    config = ArchiveyConfig(rar_decompressor=RarDecompressor.UNAR)
    with archivey.open_archive(archive, config=config) as reader:
        assert reader.read("hi\ud800.txt") == expected[0]
