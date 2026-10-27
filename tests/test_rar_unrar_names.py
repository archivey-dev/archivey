"""How ``unrar`` reads member names, and which members an ``-n`` mask selects.

A named ``unrar p`` pipes every payload member its mask selects, in archive order,
so archivey sizes a skip past the ones before the target. That skip is only right
if archivey computes the same selection ``unrar`` does. These tests build archives
whose names exercise each step of ``unrar``'s reading (a RAR5 name cut at a bad
byte, overlong UTF-8, an 8-bit RAR3 name mapped to private-use characters, leading
``../``, a mask that names a directory prefix, a trailing dot) and compare the
selection archivey predicts with what ``unrar`` actually emits.

The archives are derived from committed fixtures by rewriting headers, so only
``unrar`` is needed at runtime.
"""

from __future__ import annotations

import struct
import subprocess
import sys
import zlib
from pathlib import Path
from typing import Any

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.exceptions import ArchiveyError, UnsupportedFeatureError
from archivey.internal.backends import rar_unrar
from archivey.internal.backends.rar_reader import RarReader
from archivey.internal.backends.rar_unrar import (
    _member_include_switch,
    _unrar_env,
    find_rarlab_unrar,
    unrar_mask_is_usable,
    unrar_mask_selects,
    unrar_mask_view,
    unrar_member_view,
)
from tests.conftest import requires_binary
from tests.test_audit_rar_iso_dir import (
    _fixture,
    _rar3_build,
    _rar3_parse,
    _rar5_build,
    _rar5_parse,
)

_UNRAR_ONLY = ArchiveyConfig(rar_decompressor="unrar")
_LINUX_ONLY = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the expected selections are measured against unrar on Linux",
)

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
    ("�".encode(), 1),
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
    ("é/ab".encode(), 1),
]

# RAR 1.5-4 names without the Unicode flag.
_RAR3_NAMES: list[bytes] = [
    b"caf\xe9.txt",
    b"caf\xe9.txt",  # a duplicate
    "café.txt".encode(),  # valid UTF-8: a different name to unrar
    b"caf\xc3.txt",  # a cut-off UTF-8 sequence: mapped
    b"caf",
    b"caf\xe9",
    b"d\\caf\xe9.txt",  # RAR3 backslash is a separator
    b"d/caf\xe9.txt",
    b"caf?.txt",
    b"cafX.txt",
    b"caf\xf8\x80\x80\x80\x80.txt",  # an overlong five-byte form: mapped
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


def _build_rar3(tmp_path: Path, names: list[bytes]) -> Path:
    """A nonsolid RAR 2.9 archive of stored members with 8-bit names."""
    blocks = _rar3_parse(_fixture("hostile_argv__rar4.rar").read_bytes())
    template = next(block for block in blocks if block["type"] == 0x74)
    head = [block for block in blocks if block["type"] == 0x73]
    tail = [block for block in blocks if block["type"] == 0x7B]
    files = []
    for index, name in enumerate(names):
        data = _payload(index)
        header = bytearray(template["header"])
        flags = struct.unpack_from("<H", header, 3)[0]
        old_len = struct.unpack_from("<H", header, 26)[0]
        offset = 32 + (8 if flags & 0x100 else 0)
        header[offset : offset + old_len] = name
        struct.pack_into("<H", header, 26, len(name))
        # No Unicode flag, not solid, not a directory; stored.
        struct.pack_into("<H", header, 3, flags & ~0x02F0)
        struct.pack_into("<II", header, 7, len(data), len(data))
        struct.pack_into("<I", header, 16, zlib.crc32(data))
        header[25] = 0x30
        struct.pack_into("<H", header, 5, len(header))
        files.append({"type": 0x74, "header": header, "data": data})
    path = tmp_path / "names3.rar"
    path.write_bytes(_rar3_build(head + files + tail))
    return path


def _unrar_selects(archive: Path, mask: str | bytes, count: int) -> list[int]:
    """Indexes of the members ``unrar p -n./<mask>`` emits, in pipe order."""
    completed = subprocess.run(
        [
            find_rarlab_unrar(),
            "p",
            "-inul",
            "-cfg-",
            _member_include_switch(mask),
            "--",
            str(archive),
        ],
        capture_output=True,
        env=_unrar_env(),
        timeout=30,
        check=False,
    )
    out = completed.stdout
    assert len(out) % 5 == 0, out
    indexes = [int(out[at + 1 : at + 4]) for at in range(0, len(out), 5)]
    assert all(0 <= index < count for index in indexes)
    return indexes


def _check_masks(
    archive: Path, views: list[str | None], masks: list[str | bytes]
) -> None:
    mismatches: list[tuple[Any, list[int], list[int]]] = []
    for mask in masks:
        mask_view = unrar_mask_view(mask)
        assert mask_view is not None
        if not unrar_mask_is_usable(mask_view):
            continue
        expected = [
            index
            for index, view in enumerate(views)
            if view is not None and unrar_mask_selects(mask_view, view)
        ]
        actual = _unrar_selects(archive, mask, len(views))
        if actual != expected:
            mismatches.append((mask, expected, actual))
    assert not mismatches


@requires_binary("unrar")
@_LINUX_ONLY
def test_rar5_mask_selection_is_the_one_unrar_makes(tmp_path: Path) -> None:
    archive = _build_rar5(tmp_path, _RAR5_NAMES)
    views = [
        unrar_member_view(
            rar5=True,
            stored=name,
            rar3_unicode_name=None,
            host_os=2 if host == 0 else 3,
            file_version=None,
        )
        for name, host in _RAR5_NAMES
    ]
    assert views[1] == "ab"
    assert views[8] == ""
    assert views[10] == "A"
    assert views[12] == ""
    assert views[16] == "\ud800q"
    assert views[17] == "q"
    assert views[20] == "w_v"
    masks: list[str | bytes] = [
        view.rstrip("/")
        for view in views
        if view is not None and not any(0xD800 <= ord(c) <= 0xDFFF for c in view)
    ]
    masks += ["ab.", "ab...", "a?", "?", "??", "a?b", "d/ab", "é", "x/../ab"]
    _check_masks(archive, views, masks)


@requires_binary("unrar")
@_LINUX_ONLY
def test_rar3_8bit_mask_selection_is_the_one_unrar_makes(tmp_path: Path) -> None:
    archive = _build_rar3(tmp_path, _RAR3_NAMES)
    views = [
        unrar_member_view(
            rar5=False,
            stored=name,
            rar3_unicode_name=None,
            host_os=3,
            file_version=None,
        )
        for name in _RAR3_NAMES
    ]
    # ``unrar lb`` shows the same private-use mapping.
    assert views[0] == "caf￾.txt"
    assert views[2] == "café.txt"
    masks: list[str | bytes] = [
        name.replace(b"\\", b"/").rstrip(b"/") for name in _RAR3_NAMES
    ]
    masks += ["café.txt", "caf￾.txt", "caf", b"caf\xe9.txt.", b"d"]
    _check_masks(archive, views, masks)


@requires_binary("unrar")
def test_every_rar5_member_reads_its_own_bytes_or_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever unrar selects alongside a member, the bytes returned are its own.

    No member has a CRC, so no digest check can catch a wrong member. The members
    are stored, which the reader would slice itself, so slicing is turned off to send
    each read through a named ``unrar p``.
    """
    monkeypatch.setattr(RarReader, "_is_directly_sliceable", lambda self, info: False)
    blocks = _rar5_parse(_build_rar5(tmp_path, _RAR5_NAMES).read_bytes())
    for block in blocks:
        if block["type"] == 2:
            block["crc"] = None
    path = tmp_path / "nocrc.rar"
    path.write_bytes(_rar5_build(blocks))
    outcomes: dict[int, str] = {}
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        for index, member in enumerate(reader.members()):
            assert not member.hashes
            try:
                data = reader.read(member)
            except UnsupportedFeatureError as exc:
                outcomes[index] = f"refused: {exc}"
                continue
            assert data == _payload(index), (index, member.name)
            outcomes[index] = "read"
    refused = {index for index, outcome in outcomes.items() if outcome != "read"}
    # "\xff" and the overlong NUL read as empty; the encoded surrogate cannot be
    # passed back; unrar reads "ab\\x" with its backslash. "w\\v" has a
    # Windows host, so POSIX unrar reads it as "w_v" and it reads by position
    # beside the "w_v" after it; Windows still refuses a stored backslash. "a?b"
    # is a glob that also selects "aXb"... after it, so it reads.
    expected = {3, 8, 12, 16, 20} if sys.platform == "win32" else {3, 8, 12, 16}
    assert refused == expected, outcomes


@requires_binary("unrar")
@pytest.mark.parametrize("solid", [False, True], ids=["nonsolid", "solid"])
def test_duplicate_names_read_by_position(tmp_path: Path, solid: bool) -> None:
    """Three members with one name: each read returns its own bytes."""
    source = _fixture("hostile_argv__.rar")
    blocks = _rar5_parse(source.read_bytes())
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
    with open_archive(source, config=_UNRAR_ONLY) as reader:
        expected = [reader.read(member) for member in reader.members()]
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        members = reader.members()
        assert [member.name for member in members] == ["same.txt"] * 3
        assert [reader.read(member) for member in reversed(members)] == list(
            reversed(expected)
        )


@requires_binary("unrar")
def test_invalid_utf8_name_reads_through_the_prefix_unrar_sees(tmp_path: Path) -> None:
    """``ab\\xffcd.txt`` is ``ab`` to unrar; earlier members named ``ab`` are skipped."""
    source = _fixture("hostile_argv__.rar")
    with open_archive(source, config=_UNRAR_ONLY) as reader:
        expected = [reader.read(member) for member in reader.members()]
    blocks = _rar5_parse(source.read_bytes())
    files = [block for block in blocks if block["type"] == 2]
    files[0]["name"] = b"ab"
    files[1]["name"] = b"ab\xfe"
    files[2]["name"] = b"ab\xffcd.txt"
    for block in files:
        block["crc"] = None
    path = tmp_path / "prefix.rar"
    path.write_bytes(_rar5_build(blocks))
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        members = reader.members()
        assert [reader.read(member) for member in reversed(members)] == list(
            reversed(expected)
        )


@requires_binary("unrar")
def test_name_unrar_reads_as_empty_is_refused(tmp_path: Path) -> None:
    source = _fixture("hostile_argv__.rar")
    blocks = _rar5_parse(source.read_bytes())
    files = [block for block in blocks if block["type"] == 2]
    files[1]["name"] = b"\xc0\x80x"
    path = tmp_path / "empty.rar"
    path.write_bytes(_rar5_build(blocks))
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        member = reader.members()[1]
        with pytest.raises(UnsupportedFeatureError, match="unrar reads its name"):
            reader.read(member)
        # The other members still read.
        assert reader.read(reader.members()[2])


@requires_binary("unrar")
@_LINUX_ONLY
def test_earlier_name_unrar_cannot_be_modelled_refuses_later_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no UTF-8 locale, an 8-bit name's reading by unrar is unknown."""
    path = _rar4_with_name(tmp_path, b"caf\xe9")
    monkeypatch.setattr(rar_unrar, "_utf8_locale_name", lambda: None)
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        later = reader.members()[2]
        with pytest.raises(ArchiveyError, match="earlier member's name"):
            reader.read(later)


def test_five_and_six_byte_forms_are_modelled_as_glibc_reads_them() -> None:
    """glibc's ``mbrtowc`` decodes five- and six-byte forms above U+10FFFF and
    rejects their overlong spellings. A rejected form is mapped byte by byte like
    any invalid byte, which is modelled; an accepted one is not."""
    if not sys.platform.startswith("linux") or rar_unrar._utf8_locale_name() is None:
        pytest.skip("the glibc reading needs Linux and a UTF-8 locale")

    def view(stored: bytes) -> str | None:
        return unrar_member_view(
            rar5=False,
            stored=stored,
            rar3_unicode_name=None,
            host_os=3,
            file_version=None,
        )

    assert view(b"caf\xf8\x80\x80\x80\x80.txt") == (
        "caf\ufffe" + "".join(chr(0xE000 + b) for b in b"\xf8\x80\x80\x80\x80") + ".txt"
    )
    assert view(b"caf\xfc\x80\x80\x80\x80\x80.txt") is not None
    assert view(b"caf\xf8\x88\x80\x80\x80.txt") is None  # U+200000
    assert view(b"caf\xfc\x84\x80\x80\x80\x80.txt") is None  # U+4000000


@requires_binary("unrar")
@_LINUX_ONLY
def test_overlong_five_byte_name_does_not_refuse_later_reads(tmp_path: Path) -> None:
    """unrar maps an overlong form, so the earlier name is known and later
    members read; the accepted form is not modelled and refuses them."""
    with open_archive(_fixture("hostile_argv__rar4.rar"), config=_UNRAR_ONLY) as ar:
        expected = {m.name: ar.read(m) for m in ar.members()[1:] if m.is_file}
    path = _rar4_with_name(tmp_path, b"caf\xf8\x80\x80\x80\x80")
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        later = [m for m in reader.members()[1:] if m.is_file]
        assert later
        for member in later:
            assert reader.read(member) == expected[member.name]
    path = _rar4_with_name(tmp_path, b"caf\xf8\x88\x80\x80\x80")
    with (
        open_archive(path, config=_UNRAR_ONLY) as reader,
        pytest.raises(ArchiveyError, match="earlier member's name"),
    ):
        reader.read(next(m for m in reader.members()[1:] if m.is_file))


# --- listing an 8-bit RAR 1.5-4 name -------------------------------------------


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
    """The mask is the stored bytes, whatever the name was decoded with."""
    with open_archive(_fixture("hostile_argv__rar4.rar"), config=_UNRAR_ONLY) as ar:
        expected = ar.read("canary.txt")
    path = _rar4_with_name(tmp_path, "привет.txt".encode("cp1251"))
    with open_archive(path, encoding="cp1251", config=_UNRAR_ONLY) as reader:
        if sys.platform == "darwin":
            # macOS unrar reads this name as empty; see the test below.
            with pytest.raises(UnsupportedFeatureError, match="unar"):
                reader.read(reader.members()[0])
        else:
            assert reader.read(reader.members()[0]) == expected


@requires_binary("unrar")
def test_8bit_name_macos_unrar_reads_as_empty_is_refused_before_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """macOS ``unrar`` converts an 8-bit name, and the argv mask, with ``UtfToWide``
    (``unicode.cpp``, ``CharToWide`` under ``_APPLE``), which stops at the first
    byte that is not UTF-8. cp1251 ``привет.txt`` starts with such a byte, so the
    name ``unrar`` reads is empty and no mask can select only this member. The read
    is refused before ``unrar`` is spawned. A name cut later (``caf\\xe9.txt`` is
    ``caf``) still has a mask and reads through it.
    """
    from archivey.internal.backends import rar_unrar

    path = _rar4_with_name(tmp_path, "привет.txt".encode("cp1251"))
    with open_archive(path, encoding="cp1251", config=_UNRAR_ONLY) as reader:
        member = reader.members()[0]
        monkeypatch.setattr(rar_unrar.sys, "platform", "darwin")

        def no_spawn(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("unrar was spawned")

        monkeypatch.setattr(rar_unrar.subprocess, "Popen", no_spawn)
        with pytest.raises(UnsupportedFeatureError, match="unar"):
            reader.read(member)
    assert (
        unrar_member_view(
            rar5=False,
            stored=b"caf\xe9.txt",
            rar3_unicode_name=None,
            host_os=3,
            file_version=None,
        )
        == "caf"
    )


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
