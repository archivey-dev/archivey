"""Member names ``unrar`` would read differently from archivey, and the reads of them.

``unrar`` is given a synthetic archive whose members have placeholder names, so no
stored name reaches it, or the original archive with a mask only for a name plain
enough to select its member alone (``RarReader._plain_mask``). These tests build
archives whose names ``unrar`` reads in surprising ways (a RAR5 name cut at a bad
byte, overlong UTF-8, a leading ``../``, a mask that names a directory prefix, a
trailing dot, a glob) and check that each member reads its own bytes, by either
route, and that only plain names take the mask.

The archives are derived from committed fixtures by rewriting headers, so only
``unrar`` is needed at runtime.
"""

from __future__ import annotations

import dataclasses
import struct
import zlib
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.internal.backends import rar_reader
from archivey.internal.backends.rar_reader import RarReader
from tests.conftest import requires_binary
from tests.test_audit_rar_iso_dir import (
    _fixture,
    _rar3_build,
    _rar3_parse,
    _rar5_build,
    _rar5_parse,
)

_UNRAR_ONLY = ArchiveyConfig(rar_decompressor="unrar")

# RAR5: (stored name, host OS as stored: 0 Windows, 1 Unix).
_RAR5_NAMES: list[tuple[bytes, int]] = [
    (b"ab", 1),
    (b"ab\xffcd.txt", 1),  # unrar reads "ab"
    (b"ab/x", 1),  # below "ab"
    (b"ab\\x", 1),  # a literal backslash on Unix, still below "ab"
    (b"ab.", 1),
    (b"ab..", 1),
    (b"AB", 1),
    (b"a", 1),
    (b"\xff", 1),  # unrar reads ""
    ("\ufffd".encode(), 1),
    (b"\xc1\x81", 1),  # overlong "A"
    (b"A", 1),
    (b"\xc0\x80zz", 1),  # overlong NUL: ""
    (b"../ab", 1),
    (b"x/../ab", 1),
    (b"./ab", 1),
    (b"\xed\xa0\x80q", 1),  # an encoded surrogate
    (b"\xf4\x90\x80\x80q", 1),  # above U+10FFFF: dropped, "q"
    (b"q", 1),
    (b"ab\xfe\xff", 1),  # "ab" again
    (b"w\\v", 0),  # Windows host: unrar on Unix reads "w_v"
    (b"w_v", 1),
    (b"a?b", 1),
    (b"aXb", 1),
    (b"d/ab", 1),
    ("\u00e9/ab".encode(), 1),
]


def _payload(index: int) -> bytes:
    return f"<{index:03d}>".encode()


def _build_rar5(tmp_path: Path, names: list[tuple[bytes, int]]) -> Path:
    """A nonsolid RAR5 archive of stored members, one per name, in order."""
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    template = next(block for block in blocks if block["type"] == 2)
    head = [block for block in blocks if block["type"] == 1]
    tail = [block for block in blocks if block["type"] == 5]
    files = []
    for index, (name, host) in enumerate(names):
        data = _payload(index)
        block = dict(template)
        block.update(
            name=name,
            host_os=host,
            cinfo=0,  # stored, not solid
            unpacked=len(data),
            crc=struct.pack("<I", zlib.crc32(data)),
            data=data,
        )
        files.append(block)
    path = tmp_path / "names5.rar"
    path.write_bytes(_rar5_build(head + files + tail))
    return path


def _nocrc_rar5(tmp_path: Path, names: list[tuple[bytes, int]]) -> Path:
    """:func:`_build_rar5` with no CRCs, so no digest check can catch a wrong member."""
    blocks = _rar5_parse(_build_rar5(tmp_path, names).read_bytes())
    for block in blocks:
        if block["type"] == 2:
            block["crc"] = None
    path = tmp_path / "nocrc.rar"
    path.write_bytes(_rar5_build(blocks))
    return path


@requires_binary("unrar")
@pytest.mark.parametrize("in_place", [False, True], ids=["synthetic", "in-place"])
def test_every_rar5_member_reads_its_own_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, in_place: bool
) -> None:
    """Whatever ``unrar`` would make of a name, each read returns the member's own
    bytes. The members are stored, which the reader would slice itself, so slicing
    is turned off to send each read through ``unrar``. With the in-place threshold
    at 0 every member is "large": the plain names read the original archive
    through a mask, the rest a synthetic archive."""
    monkeypatch.setattr(RarReader, "_is_directly_sliceable", lambda self, info: False)
    if in_place:
        monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    path = _nocrc_rar5(tmp_path, _RAR5_NAMES)
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        assert isinstance(reader, RarReader)
        for index, member in enumerate(reader.members()):
            assert not member.hashes
            assert reader.read(member) == _payload(index), (index, member.name)


@pytest.mark.parametrize("non_ascii", [True, False], ids=["utf8", "ascii-only"])
def test_only_a_plain_name_selects_its_member_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, non_ascii: bool
) -> None:
    monkeypatch.setattr(rar_reader, "unrar_mask_carries_non_ascii", lambda: non_ascii)
    path = _nocrc_rar5(tmp_path, _RAR5_NAMES)
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        assert isinstance(reader, RarReader)
        # Several names here do not decode cleanly, so no mask is trusted at all.
        assert [reader._plain_mask(m) for m in reader.members()] == [None] * len(
            _RAR5_NAMES
        )
    clean: list[tuple[bytes, int]] = [
        (b"ab", 1),
        (b"ab/x", 1),
        (b"AB.txt", 1),
        (b"ab.txt", 1),
        (b"note.", 1),
        (b"a?b", 1),
        (b"aXb", 1),
        (b"d/ab", 1),
        ("caf\u00e9.txt".encode(), 1),
        (b"plain.txt", 1),
    ]
    path = _nocrc_rar5(tmp_path, clean)
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        assert isinstance(reader, RarReader)
        masks = {m.name: reader._plain_mask(m) for m in reader.members()}
    # "ab" has "ab/x" below it; "AB.txt" and "ab.txt" fold together; "note." has
    # a trailing dot; "a?b" is a glob; "café.txt" is plain only where unrar reads
    # a non-ASCII mask back as the same text.
    assert masks == {
        "ab": None,
        "ab/x": "ab/x",
        "AB.txt": None,
        "ab.txt": None,
        "note.": None,
        "a?b": None,
        "aXb": "aXb",
        "d/ab": "d/ab",
        "café.txt": "café.txt" if non_ascii else None,
        "plain.txt": "plain.txt",
    }


@requires_binary("unrar")
def test_a_large_member_with_a_utf8_name_reads_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-ASCII name reaches ``unrar`` as its own mask and selects that member
    alone, on Windows (Unicode argv) and under a UTF-8 locale on POSIX."""
    if not rar_reader.unrar_mask_carries_non_ascii():
        pytest.skip("no UTF-8 locale for unrar on this system")
    monkeypatch.setattr(RarReader, "_is_directly_sliceable", lambda self, info: False)
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    names = [("café.txt".encode(), 1), ("日本/ß.txt".encode(), 1), (b"plain.txt", 1)]
    path = _nocrc_rar5(tmp_path, names)
    spawned: list[str | None] = []
    real = rar_reader.open_unrar_p

    def spawn(archive: object, *args: object, **kwargs: object) -> object:
        spawned.append(kwargs.get("member"))  # type: ignore[arg-type]
        return real(archive, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spawn)
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        got = [reader.read(member) for member in reader.members()]
    assert got == [_payload(i) for i in range(3)]
    assert spawned == ["café.txt", "日本/ß.txt", "plain.txt"]


@requires_binary("unrar")
def test_a_large_member_without_a_plain_name_is_copied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a source on disk, a "large" member reads in place only through a plain
    name; the glob ``a?b`` is copied to a synthetic archive like a small one."""
    monkeypatch.setattr(RarReader, "_is_directly_sliceable", lambda self, info: False)
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    names = [(b"a?b", 1), (b"aXb", 1), (b"plain.txt", 1)]
    path = _nocrc_rar5(tmp_path, names)
    spawned: list[str | None] = []
    real = rar_reader.open_unrar_p

    def spawn(archive: object, *args: object, **kwargs: object) -> object:
        spawned.append(kwargs.get("member"))  # type: ignore[arg-type]
        return real(archive, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spawn)
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        got = [reader.read(member) for member in reader.members()]
    assert got == [_payload(i) for i in range(3)]
    assert spawned == [None, "aXb", "plain.txt"]


def test_a_history_row_is_masked_with_its_version_suffix() -> None:
    """``unrar -ver`` names a history row ``name;n``; the live row keeps the bare
    name. Fails if the ``;n`` suffix is dropped (two rows would share ``file.txt``)
    or if history rows were counted against the current rows only (KeyError)."""
    with open_archive(_fixture("file_version__.rar"), config=_UNRAR_ONLY) as reader:
        assert isinstance(reader, RarReader)
        masks = [reader._plain_mask(m) for m in reader.members()]
    assert masks == ["file.txt;1", "file.txt;2", "file.txt"]


@requires_binary("unrar")
def test_a_history_row_reads_in_place_by_its_versioned_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An in-place read of a history row passes ``-n./file.txt;1`` with ``-ver``
    and gets that row alone, the same bytes as the synthetic read."""
    path = _fixture("file_version__.rar")
    monkeypatch.setattr(RarReader, "_is_directly_sliceable", lambda self, info: False)
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        expected = [reader.read(member) for member in reader.members()]
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    spawned: list[str | None] = []
    real = rar_reader.open_unrar_p

    def spawn(archive: object, *args: object, **kwargs: object) -> object:
        spawned.append(kwargs.get("member"))  # type: ignore[arg-type]
        return real(archive, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spawn)
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        got = [reader.read(member) for member in reader.members()]
    assert got == expected
    assert len(set(expected)) == len(expected)
    assert spawned == ["file.txt;1", "file.txt;2", "file.txt"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        # An ASCII 8-bit name is plain.
        (b"plain.txt", "plain.txt"),
        # A RAR 1.5-4 backslash is a separator, and the mask uses ``/``.
        (b"d\\x.txt", "d/x.txt"),
        # A non-ASCII 8-bit name has no code page unrar is known to share.
        (b"caf\xe9.txt", None),
    ],
)
def test_rar4_8bit_names_and_the_plain_rule(
    tmp_path: Path, name: bytes, expected: str | None
) -> None:
    """Fails if 8-bit names were decoded with a code page for the mask, or if a
    ``\\`` were kept (or refused) instead of read as ``/``."""
    path = _rar4_with_name(tmp_path, name)
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        assert isinstance(reader, RarReader)
        masks = [reader._plain_mask(m) for m in reader.members()]
    others = ["-inul", "@atfile"] if expected is not None else [None, None]
    assert masks == [expected, *others]


def test_a_rar4_unicode_name_with_a_lone_surrogate_is_not_plain(
    tmp_path: Path,
) -> None:
    """A UTF-16 field with a lone surrogate makes no name in the archive plain.
    Fails if the surrogate check were dropped."""
    path = _rar4_with_name(tmp_path, b"plain.txt")
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        assert isinstance(reader, RarReader)
        raw = reader.members()[0]._raw
        assert rar_reader._plain_unrar_text(raw, rar5=False) == "plain.txt"
        lone = dataclasses.replace(raw, rar3_unicode_name="hi\ud800.txt")
        assert rar_reader._plain_unrar_text(lone, rar5=False) is None
        pair = dataclasses.replace(raw, rar3_unicode_name="hi\U0001f600.txt")
        assert rar_reader._plain_unrar_text(pair, rar5=False) == "hi\U0001f600.txt"


def test_a_damaged_listing_reads_no_member_in_place(tmp_path: Path) -> None:
    """When a volume's walk stopped at a damaged header, ``unrar`` may find headers
    past it that the listing lacks, so no name is trusted to select one member."""
    path = _nocrc_rar5(tmp_path, [(b"plain.txt", 1), (b"other.txt", 1)])
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        assert isinstance(reader, RarReader)
        members = reader.members()
        reader._archive.damaged = "a damaged header"
        assert [reader._plain_mask(m) for m in members] == [None, None]


def _duplicate_names(tmp_path: Path, *, solid: bool) -> Path:
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    files = [block for block in blocks if block["type"] == 2]
    for block in files:
        block["name"] = b"same.txt"
        if solid and block is not files[0]:
            block["cinfo"] |= 0x40
    if solid:
        main = next(block for block in blocks if block["type"] == 1)
        main["body"] = bytes([main["body"][0] | 0x04]) + main["body"][1:]
    path = tmp_path / "dup.rar"
    path.write_bytes(_rar5_build(blocks))
    return path


@requires_binary("unrar")
@pytest.mark.parametrize("solid", [False, True], ids=["nonsolid", "solid"])
def test_duplicate_names_read_by_position(tmp_path: Path, solid: bool) -> None:
    """Three members with one name: each read returns its own bytes."""
    path = _duplicate_names(tmp_path, solid=solid)
    with open_archive(_fixture("hostile_argv__.rar"), config=_UNRAR_ONLY) as reader:
        expected = [reader.read(member) for member in reader.members()]
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        members = reader.members()
        assert [member.name for member in members] == ["same.txt"] * 3
        assert [reader.read(member) for member in reversed(members)] == list(
            reversed(expected)
        )


def _rar4_with_name(
    tmp_path: Path, name: bytes, *, host_os: int = 3, unicode_flag: bool = False
) -> Path:
    """``hostile_argv__rar4.rar`` with its first member renamed, header CRC fixed."""
    blocks = _rar3_parse(_fixture("hostile_argv__rar4.rar").read_bytes())
    first = next(block for block in blocks if block["type"] == 0x74)
    header = first["header"]
    flags = struct.unpack_from("<H", header, 3)[0]
    old_len = struct.unpack_from("<H", header, 26)[0]
    offset = 32 + (8 if flags & 0x100 else 0)
    header[offset : offset + old_len] = name
    struct.pack_into("<H", header, 26, len(name))
    flags = (flags & ~0x0200) | (0x0200 if unicode_flag else 0)
    struct.pack_into("<H", header, 3, flags)
    struct.pack_into("<H", header, 5, len(header))
    header[15] = host_os
    path = tmp_path / "named4.rar"
    path.write_bytes(_rar3_build(blocks))
    return path


@pytest.mark.parametrize(
    ("name", "host_os", "expected"),
    [
        # WinRAR on DOS and Windows writes the OEM code page: 0x82 is é in cp437.
        (b"caf\x82.txt", 2, "café.txt"),
        (b"caf\x82.txt", 0, "café.txt"),
        # rar on Unix writes the locale's bytes: 0xe9 is é in windows-1252.
        (b"caf\xe9.txt", 3, "café.txt"),
        # Valid UTF-8 is read as UTF-8 from any host.
        ("café.txt".encode(), 2, "café.txt"),
        ("café.txt".encode(), 3, "café.txt"),
    ],
)
def test_8bit_rar3_name_lists_in_its_writers_code_page(
    tmp_path: Path, name: bytes, host_os: int, expected: str
) -> None:
    path = _rar4_with_name(tmp_path, name, host_os=host_os)
    with open_archive(path) as reader:
        member = reader.members()[0]
        assert member.name == expected
        assert member.raw_name == name


def test_encoding_argument_decodes_an_8bit_rar3_name(tmp_path: Path) -> None:
    """``encoding=`` decodes bytes that are not valid UTF-8, in place of the host's
    code page, as it does for TAR and an unflagged ZIP name."""
    from archivey.diagnostics import DiagnosticCode

    stored = "привет.txt".encode("cp1251")
    path = _rar4_with_name(tmp_path, stored)
    with open_archive(path, encoding="cp1251") as reader:
        member = reader.members()[0]
        assert member.name == "привет.txt"
        assert member.raw_name == stored
        assert DiagnosticCode.ENCODING_ARGUMENT_UNUSED not in reader.diagnostics.counts


@pytest.mark.parametrize("unicode_flag", [False, True])
def test_valid_utf8_rar3_name_wins_over_the_encoding_argument(
    tmp_path: Path, unicode_flag: bool
) -> None:
    """The bytes ``c3 a9`` are UTF-8 ``é``; ``encoding="latin-1"`` does not make them
    ``Ã©``, whether or not the Unicode flag is set."""
    from archivey.diagnostics import DiagnosticCode

    stored = "é.txt".encode()
    path = _rar4_with_name(tmp_path, stored, unicode_flag=unicode_flag)
    with open_archive(path, encoding="latin-1") as reader:
        member = reader.members()[0]
        assert member.name == "é.txt"
        assert member.raw_name == stored
    inferred = [
        d
        for d in member.diagnostics
        if d.code == DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED
    ]
    if unicode_flag:
        # The flag declares UTF-8: nothing was inferred.
        assert inferred == []
    else:
        # Reported as ZIP and TAR report it, naming the codec passed over.
        (diag,) = inferred
        assert diag.context.inferred_encoding == "utf-8"
        assert diag.context.declared_encoding == "latin-1"


@requires_binary("unrar")
def test_8bit_rar3_name_decoded_with_encoding_still_reads(tmp_path: Path) -> None:
    """No stored name reaches ``unrar``, so a name it would read differently (on
    macOS, cp1251 ``привет.txt`` reads as empty) still reads on every OS."""
    with open_archive(_fixture("hostile_argv__rar4.rar"), config=_UNRAR_ONLY) as ar:
        expected = ar.read("canary.txt")
    path = _rar4_with_name(tmp_path, "привет.txt".encode("cp1251"))
    with open_archive(path, encoding="cp1251", config=_UNRAR_ONLY) as reader:
        assert reader.read(reader.members()[0]) == expected


def test_unicode_flagged_rar3_name_without_a_utf16_field(tmp_path: Path) -> None:
    """The flag declares UTF-8: ``encoding=`` applies only when the bytes are not."""
    path = _rar4_with_name(tmp_path, "café.txt".encode(), unicode_flag=True)
    with open_archive(path, encoding="latin-1") as reader:
        assert reader.members()[0].name == "café.txt"
    path = _rar4_with_name(tmp_path, b"caf\xe9.txt", unicode_flag=True)
    with open_archive(path) as reader:
        assert reader.members()[0].name == "café.txt"
    with open_archive(path, encoding="cp437") as reader:
        assert reader.members()[0].name == "cafΘ.txt"


def test_encoding_argument_leaves_rar5_names_alone() -> None:
    """RAR5 stores UTF-8, so ``encoding=`` changes nothing there."""
    path = _fixture("hostile_argv__.rar")
    with open_archive(path) as reader:
        names = [member.name for member in reader.members()]
    with open_archive(path, encoding="cp500") as reader:
        assert [member.name for member in reader.members()] == names
