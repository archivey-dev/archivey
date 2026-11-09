"""Raw CD sector images (a ``.bin`` from a ``.bin``/``.cue`` pair).

Mode 1 and Mode 2 Form 1 images are read: every sector is stripped to its 2048 bytes of
user data, which is a byte-identical ``.iso``. Layouts that hold no filesystem (Mode 2
Form 2) or that are not understood are refused by name; such a file used to fail
detection with "no magic-byte match", which sends a user looking for a corrupt file.
The refusals need no pycdlib: they come before the reader.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    CorruptionError,
    DiagnosticCode,
    TruncatedError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
)
from tests.conftest import requires

_SYNC = b"\x00" + b"\xff" * 10 + b"\x00"


def _sector(index: int, *, mode: int, form2: bool = False, size: int = 2352) -> bytes:
    """One raw sector: sync, BCD MSF address, mode byte, payload, zeroed EDC/ECC."""
    lba = index + 150  # the two-second pregap every MSF address counts from
    minute, rest = divmod(lba, 75 * 60)
    second, frame = divmod(rest, 75)
    msf = bytes(int(str(v), 16) for v in (minute, second, frame))
    header = _SYNC + msf + bytes([mode])
    if mode == 2:
        submode = 0x20 if form2 else 0x08
        body = bytes([0, 0, submode, 0]) * 2 + b"D" * (2324 if form2 else 2048)
    else:
        body = b"D" * 2048
    sector = header + body
    sector += b"\x00" * (2352 - len(sector))
    return sector + b"\x00" * (size - 2352)


def _image(
    *, mode: int, form2: bool = False, size: int = 2352, count: int = 4
) -> bytes:
    return b"".join(_sector(i, mode=mode, form2=form2, size=size) for i in range(count))


def to_raw(iso: bytes, *, mode: int = 1, size: int = 2352) -> bytes:
    """``iso`` written as a raw sector image: each 2048-byte block in a whole sector."""
    out = []
    for index in range(0, len(iso), 2048):
        sector = bytearray(_sector(index // 2048, mode=mode, size=size))
        offset = 16 if mode == 1 else 24
        sector[offset : offset + 2048] = iso[index : index + 2048].ljust(2048, b"\0")
        out.append(bytes(sector))
    return b"".join(out)


_CASES = [
    pytest.param(
        _image(mode=2, form2=True), "Mode 2 Form 2, 2352-byte sectors", id="mode2-form2"
    ),
    pytest.param(
        _image(mode=7), "unknown sector mode 7, 2352-byte sectors", id="mode7"
    ),
    pytest.param(_image(mode=1, count=1), "(Mode 1)", id="single-sector"),
]


@pytest.mark.parametrize(("data", "layout"), _CASES)
def test_raw_sector_image_is_refused_by_name(
    data: bytes, layout: str, tmp_path: Path
) -> None:
    path = tmp_path / "disc.bin"
    path.write_bytes(data)
    with pytest.raises(UnsupportedFeatureError, match="raw CD sector image") as ei:
        open_archive(path)
    assert layout in str(ei.value)
    assert ei.value.archive_name is not None
    with pytest.raises(UnsupportedFeatureError, match="raw CD sector image"):
        open_archive(io.BytesIO(data))


def test_form2_says_there_is_no_filesystem(tmp_path: Path) -> None:
    path = tmp_path / "video.bin"
    path.write_bytes(_image(mode=2, form2=True))
    with pytest.raises(UnsupportedFeatureError, match="not an ISO 9660 filesystem"):
        open_archive(path)


def test_unread_layouts_say_how_to_convert(tmp_path: Path) -> None:
    path = tmp_path / "disc.bin"
    path.write_bytes(_image(mode=7))
    with pytest.raises(UnsupportedFeatureError, match="convert it to a plain .iso"):
        open_archive(path)


def test_raw_sector_image_is_detected_as_iso(tmp_path: Path) -> None:
    # Detection claims it as ISO on the sync pattern, which is what lets the backend
    # refuse it by name instead of the file failing detection.
    path = tmp_path / "disc.bin"
    path.write_bytes(_image(mode=1))
    info = detect_format(path)
    assert info.format == ArchiveFormat.ISO
    assert info.detected_by == "magic"


def test_explicit_iso_format_refuses_too() -> None:
    data = _image(mode=7)
    with pytest.raises(UnsupportedFeatureError, match="raw CD sector image"):
        open_archive(io.BytesIO(data), format=ArchiveFormat.ISO)


def test_the_probe_restores_the_stream_position() -> None:
    from archivey.internal.backends.iso_reader import _describe_raw_sector_image

    stream = io.BytesIO(b"\x00" * 4096)
    assert _describe_raw_sector_image(stream) is None
    assert stream.tell() == 0


def test_the_refusal_does_not_need_pycdlib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without this ordering a caller lacking pycdlib is told to install it, and only
    # then learns the file cannot be read at all. The core-only CI leg has no pycdlib;
    # this pins the same answer in every leg.
    monkeypatch.setattr(
        "archivey.internal.registry._optional", lambda name: None, raising=True
    )
    path = tmp_path / "disc.bin"
    path.write_bytes(_image(mode=2, form2=True))
    with pytest.raises(UnsupportedFeatureError, match="raw CD sector image"):
        open_archive(path)


# --- reading Mode 1 and Mode 2 Form 1 images ---------------------------------------

_PAYLOAD = bytes(range(256)) * 80  # 20 480 bytes: ten sectors of user data


def _plain_iso() -> bytes:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    iso.add_directory("/SUB", rr_name="sub")
    iso.add_fp(io.BytesIO(_PAYLOAD), len(_PAYLOAD), "/SUB/BIG.DAT;1", rr_name="big.dat")
    iso.add_fp(io.BytesIO(b"hello\n"), 6, "/A.TXT;1", rr_name="a.txt")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _contents(source: Path | io.BytesIO) -> dict[str, bytes | None]:
    with open_archive(source) as archive:
        return {
            m.name: archive.open(m).read() if m.is_file else None
            for m in archive.members()
        }


@requires("pycdlib")
@pytest.mark.parametrize(
    ("mode", "size"),
    [
        pytest.param(1, 2352, id="mode1"),
        pytest.param(2, 2352, id="mode2-form1"),
        pytest.param(1, 2448, id="mode1-subchannel"),
    ],
)
def test_a_data_image_reads_like_the_plain_iso(
    mode: int, size: int, tmp_path: Path
) -> None:
    iso = _plain_iso()
    plain = tmp_path / "disc.iso"
    plain.write_bytes(iso)
    raw = tmp_path / "disc.bin"
    raw.write_bytes(to_raw(iso, mode=mode, size=size))
    expected = _contents(plain)
    assert expected["sub/big.dat"] == _PAYLOAD
    assert _contents(raw) == expected
    assert _contents(io.BytesIO(raw.read_bytes())) == expected
    with open_archive(raw) as archive:
        assert archive.format == ArchiveFormat.ISO
        assert archive.diagnostics.retained == ()


@requires("pycdlib")
def test_audio_after_the_data_track_is_not_trailing_data(tmp_path: Path) -> None:
    # A mixed-mode disc: the data track, then audio sectors, which carry no sync.
    audio = bytes(range(1, 256)) * 2352 * 2  # 510 sectors' worth, never zero
    path = tmp_path / "game.bin"
    path.write_bytes(to_raw(_plain_iso()) + audio[: 2352 * 20])
    with open_archive(path) as archive:
        assert archive.open("a.txt").read() == b"hello\n"
        assert archive.diagnostics.retained == ()


@requires("pycdlib")
def test_data_sectors_past_the_volume_are_trailing_data(tmp_path: Path) -> None:
    path = tmp_path / "disc.bin"
    path.write_bytes(to_raw(_plain_iso() + b"\x01" * 2048))
    with open_archive(path) as archive:
        codes = [d.code for d in archive.diagnostics.retained]
    assert codes == [DiagnosticCode.ARCHIVE_TRAILING_DATA]


@requires("pycdlib")
def test_a_damaged_sector_fails_the_member_that_reads_it(tmp_path: Path) -> None:
    iso = _plain_iso()
    raw = bytearray(to_raw(iso))
    sector = iso.index(_PAYLOAD) // 2048 + 3
    raw[sector * 2352 + 5] = 0x00  # break the sync
    path = tmp_path / "disc.bin"
    path.write_bytes(bytes(raw))
    with open_archive(path) as archive:
        assert archive.open("a.txt").read() == b"hello\n"
        with pytest.raises(CorruptionError, match=f"sector {sector} is not a Mode 1"):
            archive.open("sub/big.dat").read()


@requires("pycdlib")
def test_a_form2_sector_in_a_member_is_refused(tmp_path: Path) -> None:
    iso = _plain_iso()
    raw = bytearray(to_raw(iso, mode=2))
    sector = iso.index(_PAYLOAD) // 2048 + 1
    raw[sector * 2352 + 18] |= 0x20
    path = tmp_path / "disc.bin"
    path.write_bytes(bytes(raw))
    with (
        open_archive(path) as archive,
        pytest.raises(UnsupportedFeatureError, match="Mode 2 Form 2 sector"),
    ):
        archive.open("sub/big.dat").read()


@requires("pycdlib")
def test_a_cut_image_fails_the_member_at_the_cut(tmp_path: Path) -> None:
    iso = _plain_iso()
    start = iso.index(_PAYLOAD) // 2048
    raw = to_raw(iso)
    path = tmp_path / "disc.bin"
    path.write_bytes(raw[: (start + 4) * 2352 + 100])
    with open_archive(path) as archive, pytest.raises(TruncatedError):
        archive.open("sub/big.dat").read()


def test_raw_ranges_cover_whole_sectors() -> None:
    from archivey.internal.backends.cd_sectors import RawSectorLayout

    layout = RawSectorLayout(mode=1, form2=False, sector_size=2352)
    assert layout.raw_range(0, 1) == (0, 2352)
    assert layout.raw_range(2048, 4096) == (2352, 4704)
    assert layout.raw_range(2047, 2049) == (0, 4704)
    assert layout.raw_range(4096, 4096) == (4704, 4704)


def test_a_replacement_is_refused_a_readable_raw_image(tmp_path: Path) -> None:
    # Covered for the message in test_format_policy; this pins that the readable
    # layouts are among those refused, and why.
    from archivey.internal.backends.iso_reader import refuse_raw_sector_image

    with pytest.raises(UnsupportedFeatureError, match="replacement plugin is not"):
        refuse_raw_sector_image(
            io.BytesIO(_image(mode=1)), ArchiveFormat.ISO, None, replacement="Plugin"
        )
    refuse_raw_sector_image(io.BytesIO(_image(mode=1)), ArchiveFormat.ISO, None)
