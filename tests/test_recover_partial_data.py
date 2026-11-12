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
import tarfile
from typing import Any

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.exceptions import ArchiveyError
from tests.streams_util import NonSeekableBytesIO

_OFF = ArchiveyConfig(recover_partial_data=False)


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
        use_rapidgzip=AcceleratorMode.ON, recover_partial_data=False
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
