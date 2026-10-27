"""Windows reparse points in a ZIP read from a pipe, against the same archive from a file.

Only the central directory, after the last member, says a member is a reparse point,
so the pass keeps the start of data over the link target cap as far as a reparse
buffer's parse reads it, whether or not the caller read the member.
"""

from __future__ import annotations

import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

import archivey
from archivey import ExtractionStatus
from archivey.config import ListingLimits
from archivey.diagnostics import DiagnosticCode
from archivey.internal.backends.zip_forward_reader import _MAX_REPARSE_PREFIX
from archivey.internal.base_reader import MAX_LINK_TARGET_BYTES
from archivey.internal.windows_reparse import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    IO_REPARSE_TAG_MOUNT_POINT,
    IO_REPARSE_TAG_SYMLINK,
)
from archivey.types import ArchiveMember, MemberType
from tests.memory_util import traced_peak
from tests.streams_util import NonSeekableBytesIO
from tests.test_windows_reparse import _reparse_buffer
from tests.test_zip_pipe import _streamed
from tests.zipcrypto import build_zipcrypto_zip

_FILE_ATTRIBUTE_DIRECTORY = 0x10


def _zip(entries: list[tuple[str, int, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, attributes, data in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 0
            info.external_attr = attributes
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return buf.getvalue()


def _from_file(data: bytes) -> dict[str, ArchiveMember]:
    with archivey.open_archive(io.BytesIO(data)) as reader:
        return {m.name: m for m in reader.members()}


def _from_pipe(data: bytes, *, read: bool) -> dict[str, ArchiveMember]:
    with archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        for _, stream in reader.stream_members():
            if read and stream is not None:
                stream.read()
        return {m.name: m for m in reader.members_report().members}


@pytest.mark.parametrize("bit3", [False, True], ids=["sized", "bit3"])
@pytest.mark.parametrize("read", [True, False], ids=["read", "unread"])
def test_a_reparse_target_at_the_cap_is_kept_from_data_over_it(
    read: bool, bit3: bool
) -> None:
    """The UTF-16 buffer of a target at the cap is about four times the cap, so the
    pass keeps the buffer's start past the cap, as far as the buffer declares. A bit-3
    member nobody read is decoded that far and no further."""
    at_cap = "a" * MAX_LINK_TARGET_BYTES
    over = "b" * (MAX_LINK_TARGET_BYTES + 1)
    attributes = 0x20 | FILE_ATTRIBUTE_REPARSE_POINT
    data = _zip(
        [
            (
                "at_cap",
                attributes,
                _reparse_buffer(IO_REPARSE_TAG_SYMLINK, at_cap, at_cap),
            ),
            ("over", attributes, _reparse_buffer(IO_REPARSE_TAG_SYMLINK, over, over)),
        ]
    )
    if bit3:
        data = _streamed(data)
    piped = _from_pipe(data, read=read)
    from_file = _from_file(data)
    for name in ("at_cap", "over"):
        assert piped[name].type is from_file[name].type is MemberType.SYMLINK
        assert piped[name].link_target == from_file[name].link_target
    assert piped["at_cap"].link_target == at_cap
    assert piped["over"].link_target is None


@pytest.mark.parametrize("read", [True, False], ids=["read", "unread"])
def test_a_large_reparse_member_with_another_tag_is_a_file(read: bool) -> None:
    """A tag that names no link (a deduplication stub, a cloud placeholder) makes the
    member a file again, whatever its length: its first bytes say so."""
    content = b"\x13\x00\x00\x80" + bytes(4) + b"content" * 1000
    data = _zip([("stub", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, content)])
    assert _from_file(data)["stub"].type is MemberType.FILE
    assert _from_pipe(data, read=read)["stub"].type is MemberType.FILE


@pytest.mark.parametrize("bit3", [False, True], ids=["sized", "bit3"])
def test_data_that_runs_on_past_a_link_buffer_is_a_file(bit3: bool) -> None:
    """Data longer than the buffer its header declares is not that buffer, so the
    member is a file, from a pipe as from a file. Neither keeps the bytes after the
    buffer's end. Past a bit-3 member's buffer the walk's scan finds where its data
    ends."""
    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "C:\\target", "C:\\target")
    data = _zip(
        [("link", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, buffer + bytes(1 << 20))]
    )
    if bit3:
        data = _streamed(data)
    for member in (_from_file(data)["link"], _from_pipe(data, read=False)["link"]):
        assert member.type is MemberType.FILE
        assert member.link_target is None


def test_a_folder_the_pass_meets_as_a_junction_is_never_made(tmp_path: Path) -> None:
    """The name makes the member a folder until the directory says it is a junction;
    the pass makes nothing for it, and the junction is refused at placement, so
    neither the folder nor its parent is made, as from a file."""
    buffer = _reparse_buffer(
        IO_REPARSE_TAG_MOUNT_POINT, "\\??\\C:\\tree\\target", "C:\\tree\\target"
    )
    attributes = _FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
    data = _zip([("tree/junction_dir/", attributes, buffer)])
    trees = []
    for piped in (False, True):
        out = tmp_path / ("pipe" if piped else "file")
        source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
        with archivey.open_archive(source, streaming=piped) as reader:
            report = reader.extract_all(out)
        assert [r.status for r in report.results] == [ExtractionStatus.BLOCKED]
        trees.append(sorted(p.relative_to(out) for p in out.rglob("*")))
    assert trees == [[], []]


def test_a_member_declaring_a_huge_link_buffer_costs_the_pass_nothing() -> None:
    """Data over the cap that opens like a symlink buffer declaring 64 KiB keeps
    nothing: no target within the cap needs that much, and the directory never said
    these are reparse points. Kept, 40 of them would pass this listing limit."""
    content = struct.pack("<IHH", IO_REPARSE_TAG_SYMLINK, 0xFFFF, 0) + bytes(70_000)
    data = _zip([(f"{i}.bin", 0x20, content) for i in range(40)])
    config = archivey.ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=1 << 20)
    )
    with archivey.open_archive(io.BytesIO(data), config=config) as reader:
        from_file = [m.name for m in reader.members()]
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, config=config
    ) as reader:
        for _ in reader.stream_members():
            pass
        piped = [m.name for m in reader.members_report().members]
    assert piped == from_file


def _target_messages(source: io.BytesIO, *, streaming: bool) -> list[str]:
    with archivey.open_archive(source, streaming=streaming) as reader:
        if streaming:
            for _ in reader.stream_members():
                pass
        else:
            reader.members()
        return [
            d.message
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]


def test_a_damaged_reparse_buffer_over_the_cap_says_why_as_from_a_file() -> None:
    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "t" * 1990, "t" * 1990)
    assert len(buffer) > MAX_LINK_TARGET_BYTES
    raw = bytearray(_zip([("link", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, buffer)]))
    name_len, extra_len = struct.unpack_from("<HH", raw, 26)
    start = 30 + name_len + extra_len
    raw[start + 2] ^= 0xFF
    raw[start + 3] ^= 0xFF
    from_file = _target_messages(io.BytesIO(bytes(raw)), streaming=False)
    piped = _target_messages(NonSeekableBytesIO(bytes(raw)), streaming=True)
    assert len(piped) == len(from_file) == 1
    assert "over 4096 bytes" not in piped[0]
    assert "deflate" in piped[0] and "deflate" in from_file[0]


def test_parent_folders_of_a_link_refused_at_placement_are_never_made(
    tmp_path: Path,
) -> None:
    """The pass stages ``d/f`` as a file; the directory makes it a link to an
    absolute target, which placement refuses, so neither ``d`` nor ``d/f`` is made,
    as the file read never makes them."""
    buffer = _reparse_buffer(
        IO_REPARSE_TAG_SYMLINK, "C:\\tree\\target", "C:\\tree\\target"
    )
    data = _zip([("d/f", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, buffer)])
    trees = []
    for piped in (False, True):
        out = tmp_path / ("pipe" if piped else "file")
        source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
        with archivey.open_archive(source, streaming=piped) as reader:
            report = reader.extract_all(out)
        assert [r.status for r in report.results] == [ExtractionStatus.BLOCKED]
        trees.append(sorted(p.relative_to(out) for p in out.rglob("*")))
    assert trees == [[], []]


def _extracted(
    data: bytes, out: Path, *, piped: bool, config: archivey.ArchiveyConfig
) -> tuple[list[ExtractionStatus], list[tuple[Path, bool]]]:
    source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
    with archivey.open_archive(source, streaming=piped, config=config) as reader:
        report = reader.extract_all(out)
    tree = sorted((p.relative_to(out), p.is_symlink()) for p in out.rglob("*"))
    return [r.status for r in report.results], tree


@pytest.mark.parametrize("read_link_targets", [True, False])
def test_a_reparse_link_over_the_cap_is_written_from_a_pipe_as_from_a_file(
    tmp_path: Path, read_link_targets: bool
) -> None:
    """Nobody reads a folder-named member's data, so the pass keeps its buffer's
    start while draining it, whatever ``read_link_targets`` says: a file read still
    reads the target extraction asks for. The long name is the substitute one, so
    the target written stays within what macOS takes."""
    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "t" * 2100, "target")
    assert len(buffer) > MAX_LINK_TARGET_BYTES
    attributes = _FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
    data = _zip([("linkdir/", attributes, buffer)])
    config = archivey.ArchiveyConfig(read_link_targets=read_link_targets)
    from_file = _extracted(data, tmp_path / "file", piped=False, config=config)
    piped = _extracted(data, tmp_path / "pipe", piped=True, config=config)
    assert piped == from_file
    if not sys.platform.startswith("win"):
        assert from_file == ([ExtractionStatus.EXTRACTED], [(Path("linkdir"), True)])


def _padded_link() -> bytes:
    """A symlink buffer whose payload declares 20 000 bytes of padding past its names:
    longer than Windows writes, and well formed."""
    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "tree\\target", "tree\\target")
    tag, length, reserved = struct.unpack_from("<IHH", buffer)
    padded = struct.pack("<IHH", tag, length + 20_000, reserved) + buffer[8:]
    return padded + bytes(20_000)


def test_a_link_buffer_padded_past_the_bound_is_read_only_from_a_file() -> None:
    """The stated exception: the pass keeps no buffer over the bound, so the target a
    file read reports is unavailable from a pipe, and says why."""
    content = _padded_link()
    assert len(content) > _MAX_REPARSE_PREFIX
    data = _zip([("link", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, content)])
    assert _from_file(data)["link"].link_target == "tree/target"
    assert _target_messages(io.BytesIO(data), streaming=False) == []
    assert _from_pipe(data, read=False)["link"].link_target is None
    (message,) = _target_messages(NonSeekableBytesIO(data), streaming=True)
    assert f"reparse buffer of {len(content)} bytes" in message
    assert f"over the {_MAX_REPARSE_PREFIX}" in message


@pytest.mark.parametrize("bit3", [False, True], ids=["sized", "bit3"])
def test_data_past_a_buffer_over_the_bound_is_a_file_from_a_pipe_too(
    bit3: bool,
) -> None:
    """The pass keeps nothing of a buffer over its bound, but the directory gives the
    member's size. Data longer than the buffer declares is not that buffer, so the
    member is a file from a pipe, as from a file, with the same report."""
    content = _padded_link() + b"x"
    data = _zip([("link", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, content)])
    if bit3:
        data = _streamed(data)
    assert _from_file(data)["link"].type is MemberType.FILE
    for read in (False, True):
        piped = _from_pipe(data, read=read)["link"]
        assert piped.type is MemberType.FILE
        assert piped.link_target is None
    from_file = _target_messages(io.BytesIO(data), streaming=False)
    assert from_file == _target_messages(NonSeekableBytesIO(data), streaming=True)
    (message,) = from_file
    assert f"its {len(content)} bytes of data are not a symlink" in message


def test_members_refused_a_reparse_prefix_keep_no_message_while_the_pass_runs() -> None:
    """A member whose data declares a buffer over the bound costs the pass what one
    declaring none does; the message is built only for a link."""

    def archive(tag: int) -> bytes:
        content = struct.pack("<IHH", tag, 0xFFFF, 0) + bytes(4100)
        return _zip([(f"{i}.bin", 0x20, content) for i in range(3000)])

    def listing(data: bytes) -> None:
        with archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
            for _ in reader.stream_members():
                pass

    refused, control = archive(IO_REPARSE_TAG_SYMLINK), archive(0x80000013)
    listing(control)
    refused_peak = traced_peak(lambda: listing(refused))
    control_peak = traced_peak(lambda: listing(control))
    assert refused_peak < control_peak + 3000 * 100


def _long_link_buffer() -> bytes:
    """A symlink buffer over the target cap whose target is short."""
    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "t" * 2100, "target")
    assert len(buffer) > MAX_LINK_TARGET_BYTES
    return buffer


def test_a_reparse_buffer_that_is_all_the_data_has_its_crc_checked(
    tmp_path: Path,
) -> None:
    """The file read reads one byte past the buffer, reaches the data's end and checks
    it; so does the pass, and a damaged one is no link from either."""
    attributes = _FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
    raw = bytearray(_zip([("linkdir/", attributes, _long_link_buffer())]))
    central = raw.rindex(b"PK\x01\x02")
    for crc_at in (14, central + 16):
        raw[crc_at] ^= 0xFF
    data = bytes(raw)
    from_file = _from_file(data)["linkdir"]
    piped = _from_pipe(data, read=False)["linkdir"]
    assert from_file.link_target is piped.link_target is None
    assert len(_target_messages(io.BytesIO(data), streaming=False)) == 1
    (message,) = _target_messages(NonSeekableBytesIO(data), streaming=True)
    assert "CRC" in message
    results = []
    for streaming in (False, True):
        source = NonSeekableBytesIO(data) if streaming else io.BytesIO(data)
        with archivey.open_archive(source, streaming=streaming) as reader:
            report = reader.extract_all(tmp_path / str(streaming), on_error="continue")
        results.append([r.status for r in report.results])
    assert results == [[ExtractionStatus.FAILED]] * 2


def test_an_unread_encrypted_reparse_buffer_over_the_cap_says_why_from_a_pipe() -> None:
    """The stated exception: the pass derives no key for a member nobody read and
    keeps no ciphertext of data that decodes past the cap, so the target a file read
    reports is unavailable from a pipe, and the reason says the pass did not decrypt
    it."""
    raw = bytearray(build_zipcrypto_zip(b"secret", b"linkdir/", _long_link_buffer()))
    central = raw.rindex(b"PK\x01\x02")
    attributes = _FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
    struct.pack_into("<I", raw, central + 38, attributes)
    data = bytes(raw)
    with archivey.open_archive(io.BytesIO(data), password="secret") as reader:
        assert reader.members()[0].link_target == "target"
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password="secret"
    ) as reader:
        for _ in reader.stream_members():
            pass
        assert reader.members_report().members[0].link_target is None
        (message,) = [
            d.message
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
    assert "did not decrypt" in message
    assert "decodes to more than the 4096-byte symlink target cap" in message


def test_a_reparse_buffer_the_caller_read_to_a_failed_crc_is_no_link() -> None:
    raw = bytearray(
        _zip([("link", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, _long_link_buffer())])
    )
    central = raw.rindex(b"PK\x01\x02")
    for crc_at in (14, central + 16):
        raw[crc_at] ^= 0xFF
    with archivey.open_archive(
        NonSeekableBytesIO(bytes(raw)), streaming=True
    ) as reader:
        for _, stream in reader.stream_members():
            assert stream is not None
            with pytest.raises(archivey.CorruptionError):
                stream.read()
        assert reader.members_report().members[0].link_target is None


class _PipeSink(io.RawIOBase):
    """Somewhere ``zipfile`` writes as to a pipe: each member gets a data descriptor."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, b: bytes | bytearray | memoryview) -> int:  # type: ignore[override]
        self.data += b
        return len(b)

    def tell(self) -> int:
        return len(self.data)


@pytest.mark.parametrize("bit3", [False, True], ids=["sized", "bit3"])
@pytest.mark.parametrize("read", [True, False], ids=["read", "unread"])
def test_short_damaged_data_past_a_link_buffer_is_a_file_from_a_pipe_too(
    read: bool, bit3: bool
) -> None:
    """Data within the target cap that runs on past its buffer, with a damaged byte
    after the buffer. The file read stops one byte past the buffer, so it never meets
    the damage, and the data is not the buffer: a file. The pass decodes all of such
    data and finds the failed CRC, but the CRC is not what decides here: it gives the
    file read's answer, and the damage is raised when the file is read."""
    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "C:\\target", "C:\\target")
    content = buffer + b"P" * 100
    assert len(content) <= MAX_LINK_TARGET_BYTES
    sink: io.BytesIO | _PipeSink = _PipeSink() if bit3 else io.BytesIO()
    with zipfile.ZipFile(sink, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 0
        info.external_attr = 0x20 | FILE_ATTRIBUTE_REPARSE_POINT
        # Level 0 stores the bytes as they are, so one padding byte can be changed.
        zf.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=0)
        zf.writestr("z", b"zz")
    raw = bytearray(sink.data if isinstance(sink, _PipeSink) else sink.getvalue())
    raw[raw.index(b"P" * 100) + 50] = ord("Q")
    data = bytes(raw)
    with archivey.open_archive(io.BytesIO(data)) as reader:
        from_file = reader.members()[0]
        assert from_file.type is MemberType.FILE
        with pytest.raises(archivey.CorruptionError), reader.open(from_file) as stream:
            stream.read()
    with archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        for member, stream in reader.stream_members():
            if read and member.name == "link":
                assert stream is not None
                with pytest.raises(archivey.CorruptionError):
                    stream.read()
        piped = {m.name: m for m in reader.members_report().members}
    assert piped["link"].type is MemberType.FILE
    assert piped["link"].link_target is None
    assert list(piped) == ["link", "z"]
    source = NonSeekableBytesIO(data)
    assert _target_messages(io.BytesIO(data), streaming=False) == _target_messages(
        source, streaming=True
    )


@pytest.mark.parametrize("damaged", [True, False], ids=["damaged", "intact"])
@pytest.mark.parametrize("after", [0, 1, 2])
def test_a_damaged_bit3_reparse_buffer_is_a_link_only_where_the_file_read_says(
    after: int, damaged: bool
) -> None:
    """The file read reads the buffer and one byte. Data that ends within that has
    its CRC checked, and a damaged one is a link with no target. Longer data is not
    the buffer, so it is a file, damaged or not, and its CRC is checked when it is
    read. The pass decodes a
    bit-3 member nobody read one byte further, since only a decode that returns
    nothing tells it the data ended there, and says the same. The member after it
    lists."""
    target = "C:\\" + "t" * 1990
    content = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, target, target) + bytes(after)
    sink = _PipeSink()
    with zipfile.ZipFile(sink, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 0
        info.external_attr = 0x20 | FILE_ATTRIBUTE_REPARSE_POINT
        # Level 0 stores the bytes as they are, so one target byte can be changed.
        zf.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=0)
        zf.writestr("z", b"zz")
    raw = bytearray(sink.data)
    if damaged:
        raw[raw.index(b"t\x00" * 4) + 100] = ord("u")
    data = bytes(raw)
    from_file = _from_file(data)["link"]
    # One byte past the buffer is where the file read ends: a failed CRC there is
    # damage, which leaves the member the link its flag says, with no target.
    damage_found = damaged and after <= 1
    expected_type = (
        MemberType.SYMLINK if after == 0 or damage_found else MemberType.FILE
    )
    assert from_file.type is expected_type
    assert (from_file.link_target is None) == (damaged or after > 0)
    piped = _from_pipe(data, read=False)
    assert piped["link"].type is from_file.type
    assert piped["link"].link_target == from_file.link_target
    assert list(piped) == ["link", "z"]


def _bit3_deflate_zip(name: str, attributes: int, deflated: bytes, size: int) -> bytes:
    """One bit-3 DEFLATE member holding ``deflated`` as it is, with a signed data
    descriptor stating ``size``, and its directory."""
    raw_name = name.encode()
    crc = 0
    local = struct.pack(
        "<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0x08, 8, 0, 0x21, 0, 0, 0, len(raw_name), 0
    )
    descriptor = struct.pack("<4sIII", b"PK\x07\x08", crc, len(deflated), size)
    members = local + raw_name + deflated + descriptor
    central = (
        struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            20,
            20,
            0x08,
            8,
            0,
            0x21,
            crc,
            len(deflated),
            size,
            len(raw_name),
            0,
            0,
            0,
            0,
            attributes,
            0,
        )
        + raw_name
    )
    end = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(members), 0
    )
    return members + central + end


@pytest.mark.parametrize("after", [0, 1, 2, 3])
def test_a_bit3_reparse_buffer_whose_decode_fails_past_it(after: int) -> None:
    """Decoded data that stops with a codec error ``after`` bytes past the buffer.
    Up to one byte past it, neither read gives a target: the file read's byte past
    the buffer meets the error. Further on, the file read's bounded read stops before
    the error with a byte past the buffer, so the data is not the buffer and the
    member is a file; reading it meets the error. The pass decodes one byte past that
    read, so two bytes past the buffer its own decode still meets the error, but the
    kept prefix filled before it did, and the pass says the same."""
    target = "C:\\" + "t" * 1990
    content = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, target, target) + bytes(after)
    stage = zlib.compressobj(0, zlib.DEFLATED, -15)
    # Stored blocks that are not the last, then a block of the reserved type 3.
    deflated = stage.compress(content) + stage.flush(zlib.Z_FULL_FLUSH) + b"\x07"
    data = _bit3_deflate_zip(
        "link", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, deflated, len(content)
    )
    from_file = _from_file(data)["link"]
    assert from_file.link_target is None
    assert from_file.type is (MemberType.SYMLINK if after <= 1 else MemberType.FILE)
    piped = _from_pipe(data, read=False)["link"]
    assert piped.type is from_file.type
    assert piped.link_target is None


def _listed_under(data: bytes, *, budget: int, pipe: bool) -> tuple[MemberType, str]:
    config = archivey.ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=budget)
    )
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with archivey.open_archive(source, streaming=pipe, config=config) as reader:
        if pipe:
            for _ in reader.stream_members():
                pass
            members = reader.members_report().members
        else:
            members = reader.members()
        (reason,) = [
            str(d.context.reason)
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
        return members[0].type, reason


@pytest.mark.parametrize("shape", ["damaged", "intact", "over-cap"], ids=lambda s: s)
def test_data_past_a_link_buffer_the_pass_dropped_is_a_file_from_a_pipe_too(
    shape: str,
) -> None:
    """``max_metadata_bytes`` makes the pass drop the longest data it keeps for link
    targets. Data that runs on past its buffer is no buffer as the file read reads it,
    so a member whose data the pass dropped is a file from a pipe as from a file,
    damaged or not, and whether it kept the whole data or a buffer's start."""
    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "C:\\target", "C:\\target")
    if shape == "over-cap":
        # Over the target cap, the pass keeps the buffer's start, here one declaring
        # 6000 bytes of padding past its names: within the bound on that start, over
        # this listing's ``max_metadata_bytes``.
        tag, length, reserved = struct.unpack_from("<IHH", buffer)
        content = struct.pack("<IHH", tag, length + 6000, reserved) + buffer[8:]
        content += bytes(6000) + b"P" * 100
        assert len(content) < _MAX_REPARSE_PREFIX
    else:
        content = buffer + b"P" * (MAX_LINK_TARGET_BYTES - len(buffer))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 0
        info.external_attr = 0x20 | FILE_ATTRIBUTE_REPARSE_POINT
        # Level 0 stores the bytes as they are, so one padding byte can be changed.
        zf.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=0)
        zf.writestr("z", b"z" * 100)
    raw = bytearray(buf.getvalue())
    if shape == "damaged":
        raw[raw.index(b"P" * 100) + 50] = ord("Q")
    data = bytes(raw)
    budget = MAX_LINK_TARGET_BYTES
    from_file = _listed_under(data, budget=budget, pipe=False)
    assert from_file == (MemberType.FILE, "reparse_data_unrecognized")
    assert _listed_under(data, budget=budget, pipe=True) == from_file


def test_a_link_buffer_the_pass_dropped_stays_a_link_without_its_target() -> None:
    """The stated exception, for a buffer that is one: dropped, it stays the link
    the file read lists, without the target the file read reads."""
    target = "C:\\" + "t" * 1000
    content = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, target, target)
    assert len(content) <= MAX_LINK_TARGET_BYTES
    data = _zip(
        [
            ("link", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, content),
            ("z", 0x20, b"z" * 100),
        ]
    )
    budget = MAX_LINK_TARGET_BYTES
    config = archivey.ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=budget)
    )
    with archivey.open_archive(io.BytesIO(data), config=config) as reader:
        from_file = reader.members()[0]
    assert from_file.type is MemberType.SYMLINK
    assert from_file.link_target == "C:/" + "t" * 1000
    assert _listed_under(data, budget=budget, pipe=True) == (
        MemberType.SYMLINK,
        "target_data_dropped",
    )


def test_dropped_ciphertext_of_an_unread_reparse_point_stays_a_link_from_a_pipe() -> (
    None
):
    """The stated exception: the pass does not decrypt kept ciphertext to decide, so
    an unread encrypted reparse point whose data runs past its buffer stays a link
    with no target when the bound drops that ciphertext, where a file read with the
    password reads it and makes it a file."""
    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "C:\\target", "C:\\target")
    content = buffer + b"P" * 3000
    raw = bytearray(
        build_zipcrypto_zip(b"secret", b"link", content, compression=zipfile.ZIP_STORED)
    )
    central = raw.rindex(b"PK\x01\x02")
    struct.pack_into("<I", raw, central + 38, 0x20 | FILE_ATTRIBUTE_REPARSE_POINT)
    data = bytes(raw)
    config = archivey.ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=2048)
    )
    with archivey.open_archive(
        io.BytesIO(data), password="secret", config=config
    ) as reader:
        assert reader.members()[0].type is MemberType.FILE
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password="secret", config=config
    ) as reader:
        for _ in reader.stream_members():
            pass
        (member,) = reader.members_report().members
        reasons = [
            str(d.context.reason)
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
    assert member.type is MemberType.SYMLINK
    assert member.link_target is None
    assert reasons == ["target_data_dropped"]
