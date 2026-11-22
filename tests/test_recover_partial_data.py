"""``ArchiveyConfig.recover_partial_data``: whether a read that meets damage first
hands back the bytes before it.

Off, a member stream does no second decode, so the bytes the failing decoder call
gave are lost. A compressed TAR's own stream recovers its bytes either way, so every
member that ends before the damage reads whole under both settings.
"""

from __future__ import annotations

import gzip
import io
import lzma
import random
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from typing import Any

import pytest

from archivey import ArchiveyConfig, PartialDataRecovery, Verification, open_archive
from archivey.config import PartialDataRecoveryStr
from archivey.exceptions import ArchiveyError, ArchiveyUsageError, CorruptionError
from tests.streams_util import NonSeekableBytesIO

_OFF = ArchiveyConfig(recover_partial_data=PartialDataRecovery.OFF)


def _damage(data: bytes, at: float) -> bytes:
    pos = int(len(data) * at)
    return data[:pos] + random.Random(7).randbytes(64) + data[pos + 64 :]


def _text(size: int, seed: int) -> bytes:
    rng = random.Random(seed)
    words = [bytes(rng.choice(b"abcdefgh") for _ in range(5)) for _ in range(300)]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words) + b" "
    return bytes(out[:size])


def _members(source: Any, config: ArchiveyConfig, **kwargs: Any) -> list[Any]:
    """Each member's name and data, or the error type its read raised; then the
    pass's own error, if it raised one."""
    out: list[Any] = []
    try:
        with open_archive(source, config=config, **kwargs) as archive:
            for member, stream in archive.stream_members():
                try:
                    out.append((member.name, stream.read()))
                except ArchiveyError as exc:
                    out.append((member.name, type(exc).__name__))
    except ArchiveyError as exc:
        out.append(type(exc).__name__)
    return out


def test_a_bare_gz_loses_the_failing_call_and_raises_the_same_error() -> None:
    damaged = _damage(gzip.compress(_text(3_000_000, 1), mtime=0), 0.5)

    def prefix(config: ArchiveyConfig) -> tuple[int, str | None]:
        got = 0
        with open_archive(io.BytesIO(damaged), config=config) as archive:
            stream = archive.open(archive.members()[0])
            try:
                while chunk := stream.read(1 << 20):
                    got += len(chunk)
            except ArchiveyError as exc:
                return got, type(exc).__name__
        return got, None

    on = prefix(ArchiveyConfig())
    off = prefix(_OFF)
    assert on[1] is not None
    assert off[1] == on[1]
    assert off[0] < on[0]


@pytest.mark.parametrize(
    ("count", "size"), [(80, 20), (12, 200_000)], ids=["small", "large"]
)
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_damaged_tar_xz_reads_every_whole_member_either_way(
    pipe: bool, count: int, size: int
) -> None:
    """The same members either way. Small members fit several to one read of the
    outer stream (the TAR walk reads ahead), so without the outer stream's override
    the failing call would take whole members with it: the ``small`` cases fail
    then. Large members only lose bytes of the member the damage cuts."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for i in range(count):
            data = _text(size, i)
            info = tarfile.TarInfo(f"m{i}.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    damaged = _damage(lzma.compress(buf.getvalue(), format=lzma.FORMAT_XZ), 0.55)

    def source() -> Any:
        return NonSeekableBytesIO(damaged) if pipe else io.BytesIO(damaged)

    kwargs = {"streaming": True} if pipe else {}
    on = _members(source(), ArchiveyConfig(), **kwargs)
    whole = [e for e in on if isinstance(e, tuple) and isinstance(e[1], bytes)]
    assert len(whole) >= 5, "the damage must come after several whole members"
    assert any(isinstance(e, str) or isinstance(e[1], str) for e in on)
    assert _members(source(), _OFF, **kwargs) == on


def test_a_compressed_tar_stream_recovers_whatever_the_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every stream a compressed TAR builds keeps recovering under ``False``: the
    outer stream's override, checked directly."""
    from archivey.internal.streams.decompressor_stream import DecompressorStream

    built: list[DecompressorStream] = []
    real = DecompressorStream.__init__

    def recording(self: DecompressorStream, *args: Any, **kwargs: Any) -> None:
        real(self, *args, **kwargs)
        built.append(self)

    monkeypatch.setattr(DecompressorStream, "__init__", recording)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("a.txt")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"abc"))
    packed = lzma.compress(buf.getvalue(), format=lzma.FORMAT_XZ)
    with open_archive(io.BytesIO(packed), config=_OFF) as archive:
        assert [m.name for m in archive.members()] == ["a.txt"]
    assert built
    assert all(stream._recover for stream in built)


def test_a_plugin_container_stream_recovers_whatever_the_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same override for a container a format adapter decompresses (an RPM's
    payload): every stream it builds keeps recovering under ``False``."""
    from pathlib import Path

    from archivey.internal.streams.decompressor_stream import DecompressorStream

    built: list[DecompressorStream] = []
    real = DecompressorStream.__init__

    def recording(self: DecompressorStream, *args: Any, **kwargs: Any) -> None:
        real(self, *args, **kwargs)
        built.append(self)

    monkeypatch.setattr(DecompressorStream, "__init__", recording)
    rpm = Path(__file__).parent / "fixtures" / "rpm" / "payload-xz.rpm"
    with open_archive(rpm, config=_OFF) as archive:
        assert archive.members()
    assert built
    assert all(stream._recover for stream in built)


def test_the_accelerator_fallback_keeps_the_setting(monkeypatch: Any) -> None:
    """rapidgzip's standard-library fallback is built at the read that meets the
    damage, after the stream was opened: it still does no second decode when the
    setting is off."""
    pytest.importorskip("rapidgzip")
    from archivey import AcceleratorMode
    from archivey.internal.streams.decompressor_stream import DecompressorStream

    built: list[DecompressorStream] = []
    real_init = DecompressorStream.__init__

    def record(self: DecompressorStream, *args: Any, **kwargs: Any) -> None:
        real_init(self, *args, **kwargs)
        built.append(self)

    monkeypatch.setattr(DecompressorStream, "__init__", record)
    damaged = _damage(gzip.compress(_text(3_000_000, 1), mtime=0), 0.5)
    config = ArchiveyConfig(
        use_rapidgzip=AcceleratorMode.ON, recover_partial_data=PartialDataRecovery.OFF
    )
    with open_archive(io.BytesIO(damaged), config=config) as archive:
        stream = archive.open(archive.members()[0])
        # Detection's probe streams and the first open are built under the setting;
        # only what the reads build is the fallback.
        built.clear()
        with pytest.raises(ArchiveyError):
            while stream.read(1 << 20):
                pass
    assert built, "the damage should reach the standard-library fallback"
    assert not any(s._recover for s in built)


@pytest.mark.parametrize("bad", [True, False])
def test_a_bool_is_refused_naming_the_level_that_does_what_it_did(bad: bool) -> None:
    """The field was a bool before it became ``PartialDataRecovery``: a bool raises,
    naming the level that does what it did."""
    level = "BEFORE_DAMAGE" if bad else "OFF"
    with pytest.raises(ArchiveyUsageError, match=f"PartialDataRecovery.{level}"):
        ArchiveyConfig(recover_partial_data=bad)


@pytest.mark.parametrize(
    ("spelling", "level"),
    [
        ("off", PartialDataRecovery.OFF),
        ("before-damage", PartialDataRecovery.BEFORE_DAMAGE),
        ("before_damage", PartialDataRecovery.BEFORE_DAMAGE),
        ("all", PartialDataRecovery.ALL),
    ],
)
def test_the_level_takes_its_string_spellings(
    spelling: PartialDataRecoveryStr, level: PartialDataRecovery
) -> None:
    assert ArchiveyConfig(recover_partial_data=spelling).recover_partial_data is level


_ALL = ArchiveyConfig(recover_partial_data=PartialDataRecovery.ALL)
# More than one read of 64 KiB, and not a multiple of it.
_CRC_PAYLOAD = _text(200_003, 3)


def _zip_with_a_bad_crc(method: int) -> bytes:
    """A ZIP of ``bad.bin`` whose CRC is wrong in both headers, so only the check
    fails (the data itself decodes), then ``good.txt``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=method) as zf:
        zf.writestr("bad.bin", _CRC_PAYLOAD)
        zf.writestr("good.txt", b"good")
    data = bytearray(buf.getvalue())
    crc = zipfile.crc32(_CRC_PAYLOAD).to_bytes(4, "little")
    wrong = (zipfile.crc32(_CRC_PAYLOAD) ^ 1).to_bytes(4, "little")
    count = data.count(crc)
    assert count == 2, "the CRC is in the local header and the central directory"
    return bytes(data.replace(crc, wrong))


def _read_in_chunks(stream: Any, n: int) -> tuple[bytes, type[BaseException] | None]:
    got = bytearray()
    try:
        while chunk := stream.read(n):
            got += chunk
    except ArchiveyError as exc:
        return bytes(got), type(exc)
    return bytes(got), None


_SOURCES = ["file", "streaming", "pipe"]


def _open(data: bytes, how: str, config: ArchiveyConfig) -> Any:
    if how == "pipe":
        return open_archive(NonSeekableBytesIO(data), config=config, streaming=True)
    return open_archive(io.BytesIO(data), config=config, streaming=how == "streaming")


def _bad_member(archive: Any, how: str) -> Iterator[Any]:
    """``bad.bin``'s stream: from ``open()`` on a file, else from ``stream_members()``."""
    if how == "file":
        with archive.open("bad.bin") as stream:
            yield stream
        return
    for member, stream in archive.stream_members():
        if member.name == "bad.bin":
            yield stream
            return


@pytest.mark.parametrize("how", _SOURCES)
@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@pytest.mark.parametrize("n", [1 << 16, -1], ids=["sized", "to_end"])
def test_all_returns_the_bytes_of_the_failing_read_and_the_next_read_raises(
    how: str, method: int, n: int
) -> None:
    """``ALL``: reading a member whose CRC fails gives every byte, then the check's
    error. The default raises the same error and, where the check runs as the read
    reaches the end, keeps back the failing read's bytes (a ZIP pass from a pipe
    checks the member only once its data has all been handed out)."""
    data = _zip_with_a_bad_crc(method)
    results = {}
    for name, config in (("default", ArchiveyConfig()), ("all", _ALL)):
        with _open(data, how, config) as archive:
            for stream in _bad_member(archive, how):
                results[name] = _read_in_chunks(stream, n)
    got, error = results["all"]
    assert got == _CRC_PAYLOAD
    assert error is CorruptionError
    default_got, default_error = results["default"]
    assert default_error is CorruptionError
    assert _CRC_PAYLOAD.startswith(default_got)
    if how != "pipe":
        assert len(default_got) < len(_CRC_PAYLOAD)


def test_all_raises_once_and_a_rewind_checks_again() -> None:
    """After the deferred error, a seek back to the start reads and checks the member
    again, so the same bytes and the same error come back."""
    data = _zip_with_a_bad_crc(zipfile.ZIP_DEFLATED)
    with (
        open_archive(io.BytesIO(data), config=_ALL, seekable_members=True) as archive,
        archive.open("bad.bin") as stream,
    ):
        assert stream.read() == _CRC_PAYLOAD
        with pytest.raises(CorruptionError):
            stream.read()
        stream.seek(0)
        assert _read_in_chunks(stream, 1 << 16) == (_CRC_PAYLOAD, CorruptionError)


@pytest.mark.parametrize("how", _SOURCES)
@pytest.mark.parametrize("n", [1 << 16, -1], ids=["sized", "to_end"])
def test_a_waiting_error_survives_read_zero_and_close_comes_first(
    how: str, n: int
) -> None:
    """``read(0)`` stays a no-op that leaves the waiting error for the next read
    that asks for bytes, and a closed stream raises its ``ValueError``, not it."""
    data = _zip_with_a_bad_crc(zipfile.ZIP_DEFLATED)
    for closes in (False, True):
        with _open(data, how, _ALL) as archive:
            for stream in _bad_member(archive, how):
                got = b""
                while len(got) < len(_CRC_PAYLOAD):
                    got += stream.read(n)
                assert stream.read(0) == b""
                if closes:
                    stream.close()
                    with pytest.raises(ValueError, match="closed"):
                        stream.read(1)
                else:
                    with pytest.raises(CorruptionError):
                        stream.read(1)


def test_all_reads_an_undamaged_member_as_the_default_does() -> None:
    data = _zip_with_a_bad_crc(zipfile.ZIP_DEFLATED)
    with open_archive(io.BytesIO(data), config=_ALL) as archive:
        assert archive.open("good.txt").read() == b"good"


def test_reader_read_raises_at_all() -> None:
    """``ArchiveReader.read()`` raises for a damaged member at every level: at ALL it
    reads once more after reading to the end, to meet the deferred error."""
    data = _zip_with_a_bad_crc(zipfile.ZIP_DEFLATED)
    for config in (ArchiveyConfig(), _ALL):
        with open_archive(io.BytesIO(data), config=config) as archive:
            with pytest.raises(CorruptionError):
                archive.read("bad.bin")
            assert archive.read("good.txt") == b"good"


def _zip_longer_than_declared() -> bytes:
    """A STORED ZIP whose ``big.bin`` holds 1 024 000 bytes and declares 1000 in both
    headers, then ``good.txt``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", bytes(range(256)) * 4000)
        zf.writestr("good.txt", b"good")
    data = bytearray(buf.getvalue())
    struct.pack_into("<I", data, 22, 1000)
    struct.pack_into("<I", data, data.index(b"PK\x01\x02") + 24, 1000)
    return bytes(data)


def _zip_one_byte_past_declared() -> bytes:
    """A STORED ZIP whose ``big.bin`` holds 1001 bytes and declares 1000, with the
    stored CRC that of the 1000 declared bytes: only the size check catches the extra
    byte, and the read that finds it reaches the end of the data."""
    payload = (bytes(range(256)) * 4)[:1001]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", payload)
        zf.writestr("good.txt", b"good")
    data = bytearray(buf.getvalue())
    central = data.index(b"PK\x01\x02")
    crc = zlib.crc32(payload[:1000])
    for crc_at, size_at in ((14, 22), (central + 16, central + 24)):
        struct.pack_into("<I", data, crc_at, crc)
        struct.pack_into("<I", data, size_at, 1000)
    return bytes(data)


@pytest.mark.parametrize("reads_again", [True, False])
def test_a_trimmed_overrun_never_verifies_the_member(reads_again: bool) -> None:
    """At ALL a pipe's read returns the declared bytes of a member that runs past
    them. Whether the caller then reads the error or moves on without reading again,
    the pass that drains the member keeps the size verdict: the bytes it counted stop
    at the declared size, and the CRC of those bytes matches."""
    data = _zip_one_byte_past_declared()
    with _open(data, "pipe", _ALL) as archive:
        for member, stream in archive.stream_members():
            if member.name != "big.bin":
                continue
            assert len(stream.read(4096)) == 1000
            if reads_again:
                with pytest.raises(CorruptionError):
                    stream.read(4096)
            big = member
        assert big.verified is not Verification.CHECKSUM


@pytest.mark.parametrize("how", _SOURCES)
def test_an_overrun_read_returns_its_declared_bytes_only_at_all(how: str) -> None:
    """A read past a member's declared size raises at the default level and returns
    nothing; at ALL it returns the declared bytes and the next read raises. From a
    pipe the pass checks the size itself, below the handle's verifier."""
    data = _zip_longer_than_declared()
    expected = (bytes(range(256)) * 4)[:1000]
    for config in (ArchiveyConfig(), _ALL):
        with _open(data, how, config) as archive:
            for member, stream in archive.stream_members():
                if member.name != "big.bin":
                    continue
                if config is _ALL:
                    assert stream.read(4096) == expected
                with pytest.raises(CorruptionError):
                    stream.read(4096)
                break


def test_an_on_source_read_stop_is_never_deferred_at_all(tmp_path: Any) -> None:
    """At ALL a read to the end that fails after some steps returns their bytes and
    keeps the error. The caller's own ``on_source_read`` exception is a stop, not the
    member's verdict: it comes out of that first read."""
    payload = _text(3 * 2**20 + 5, 7)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", payload)
    path = tmp_path / "a.zip"
    path.write_bytes(buf.getvalue())
    stop = CorruptionError("stop from callback")
    armed: list[int] = []

    def callback(progress: object) -> None:
        if armed:
            armed.append(1)
            if len(armed) == 3:
                raise stop

    config = ArchiveyConfig(
        recover_partial_data=PartialDataRecovery.ALL,
        on_source_read=callback,
        source_read_step=0,
    )
    with open_archive(path, config=config) as archive, archive.open("big.bin") as f:
        armed.append(0)
        with pytest.raises(CorruptionError) as caught:
            f.read()
    assert caught.value is stop


@pytest.mark.parametrize("n", [len(_CRC_PAYLOAD), 1 << 16], ids=["sized", "chunks"])
def test_a_deferred_check_is_reported_when_found(n: int) -> None:
    """At ALL the read whose check fails returns its bytes and the next read raises.
    The layers that watch a member's errors (a RAR pipe whose output may stop lining up
    after a failed member) hear of it when the check fails, not only on that next read:
    a caller can move on to the next member without making it."""
    from archivey.internal.hashing import crc32_digest
    from archivey.internal.streams.archive_stream import ArchiveStreamImpl
    from archivey.types import HashAlgorithm

    bad = crc32_digest(zlib.crc32(_CRC_PAYLOAD) ^ 0xFFFF)
    seen: list[BaseException] = []
    stream = ArchiveStreamImpl(
        lambda: io.BytesIO(_CRC_PAYLOAD),
        translate=lambda _exc: None,
        stamp=seen.append,
        expected_hashes={HashAlgorithm.CRC32: bad},
        expected_size=len(_CRC_PAYLOAD),
    )
    stream.return_failed_chunks()
    got = b""
    while len(got) < len(_CRC_PAYLOAD):
        got += stream.read(n)
    assert got == _CRC_PAYLOAD
    assert [type(e) for e in seen] == [CorruptionError]
    with pytest.raises(CorruptionError):
        stream.read(1)
    stream.close()
