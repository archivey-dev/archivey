"""Detection probes are held to the caller's ``DecoderLimits.max_decoder_memory``.

A probe that reserved more than the cap would let detection allocate what the caller
ruled out, and the read that follows would refuse it anyway. Where the codec can size
its decoder to the probe's read (the LZMA family), the cap is checked against that
size, so the format is still found and the open refuses it. Where it cannot (a zstd
window, an lzop block), a probe over the cap is "can't tell": the tier is recorded as
``CAPABILITY_UNAVAILABLE``, an INFO log names the limit, and the source is read as the
bare compressed stream.
"""

from __future__ import annotations

import io
import logging
import lzma
import tarfile
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    DecoderLimits,
    detect_format,
    open_archive,
)
from archivey.detection_cost import TierSkip, TierSkipReason
from archivey.exceptions import ResourceLimitError
from archivey.internal.detection import probe_config
from archivey.types import ContainerFormat, StreamFormat
from tests.conftest import requires_zstd, zstd_backend
from tests.streams_util import lzma_alone_with_filter

_MIB = 2**20
_FIXTURES = Path(__file__).parent / "fixtures" / "external"


def _capped(cap: int | None) -> ArchiveyConfig:
    return ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=cap))


def _tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        payload = b"detection under a memory cap\n" * 100
        info = tarfile.TarInfo("member.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


_TARBALL = _tarball()


def _tar_zst(window_log: int) -> bytes:
    """A ``.tar.zst`` whose frame declares a ``2**window_log`` window (no content size)."""
    zstd = zstd_backend()
    compressor = zstd.ZstdCompressor(
        options={zstd.CompressionParameter.window_log: window_log}
    )
    frame = compressor.compress(_TARBALL) + compressor.flush()
    assert frame[4] == 0x00  # no single-segment flag: the window descriptor follows
    assert frame[5] == (window_log - 10) << 3
    return frame


def _refusal_logs(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "archivey.detection" and r.levelno == logging.INFO
    ]


@requires_zstd()
def test_a_zstd_window_over_the_cap_is_cant_tell(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    data = _tar_zst(23)  # 8 MiB
    path = tmp_path / "a.tar.zst"
    path.write_bytes(data)

    tar_zst = ArchiveFormat(ContainerFormat.TAR, StreamFormat.ZSTD)
    assert detect_format(path).format == tar_zst
    assert detect_format(path, config=_capped(8 * _MIB)).format == tar_zst

    config = _capped(4 * _MIB)
    with caplog.at_level(logging.INFO, logger="archivey.detection"):
        info = detect_format(path, config=config)
    assert info.format == ArchiveFormat.ZST
    assert TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE) in (
        info.unavailable_tiers
    )
    (message,) = _refusal_logs(caplog)
    assert "ZSTD" in message
    assert f"max_decoder_memory={4 * _MIB}" in message

    # The read of the bare stream refuses the same window, naming the same cap.
    with (
        pytest.raises(ResourceLimitError, match=f"max_decoder_memory={4 * _MIB}"),
        open_archive(path, config=config) as reader,
    ):
        (member,) = reader.members()
        reader.read(member)


@requires_zstd()
def test_a_zstd_window_over_libzstd_s_default_says_no_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Over 128 MiB, the probe's own ceiling refuses it, not the caller's cap: no log."""
    data = _tar_zst(28)
    with caplog.at_level(logging.INFO, logger="archivey.detection"):
        info = detect_format(io.BytesIO(data), config=_capped(None))
    assert info.format == ArchiveFormat.ZST
    assert TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE) in (
        info.unavailable_tiers
    )
    assert _refusal_logs(caplog) == []


def test_an_xz_dictionary_over_the_cap_is_still_found(tmp_path: Path) -> None:
    """The probe reserves a 4 KiB dictionary, under the cap: the format is found and
    the open refuses the declared one."""
    data = lzma.compress(
        _TARBALL,
        format=lzma.FORMAT_XZ,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 64 * _MIB}],
    )
    path = tmp_path / "a.tar.xz"
    path.write_bytes(data)
    config = _capped(32 * _MIB)
    info = detect_format(path, config=config)
    assert info.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.XZ)
    assert info.unavailable_tiers == ()
    with (
        pytest.raises(ResourceLimitError, match=f"max_decoder_memory={32 * _MIB}"),
        open_archive(path, config=config) as reader,
    ):
        reader.members()


def test_a_probe_dictionary_over_the_cap_is_cant_tell(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Under a cap smaller than the probe's own dictionary, the LZMA Alone content
    probe answers "can't tell", not "not this format", and the extension decides."""
    data = lzma_alone_with_filter(
        _TARBALL, {"id": lzma.FILTER_LZMA1, "dict_size": _MIB}
    )
    path = tmp_path / "a.lzma"
    path.write_bytes(data)
    with caplog.at_level(logging.INFO, logger="archivey.detection"):
        info = detect_format(path, config=_capped(1024))
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.detected_by == "extension"
    assert TierSkip("content_probe", TierSkipReason.CAPABILITY_UNAVAILABLE) in (
        info.unavailable_tiers
    )
    assert any("max_decoder_memory=1024" in m for m in _refusal_logs(caplog))

    found = detect_format(path)
    assert found.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZMA_ALONE)
    assert found.detected_by == "content_probe"


def test_a_cap_between_the_window_and_the_whole_source_skips_completion(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The whole-source re-check reads up to 64 KiB, so its clamped dictionary is
    larger than the window's: a cap between the two refuses only the re-check, and
    the window's hit stands."""
    import random

    payload = random.Random(0).randbytes(20_000)
    data = lzma_alone_with_filter(payload, {"id": lzma.FILTER_LZMA1, "dict_size": _MIB})
    assert 4096 < len(data) < 64 * 1024  # past the window, within the re-check
    path = tmp_path / "a.lzma"
    path.write_bytes(data)
    assert TierSkip("probe_completion", TierSkipReason.CAPABILITY_UNAVAILABLE) not in (
        detect_format(path).unavailable_tiers
    )
    with caplog.at_level(logging.INFO, logger="archivey.detection"):
        info = detect_format(path, config=_capped(32 * 1024))
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.detected_by == "content_probe"
    assert TierSkip("probe_completion", TierSkipReason.CAPABILITY_UNAVAILABLE) in (
        info.unavailable_tiers
    )
    (message,) = _refusal_logs(caplog)
    assert "max_decoder_memory=32768" in message
    # The number refused is the probe's, and the message says where it comes from.
    assert f"counted from the {_MIB}-byte dictionary the header declares" in message


def test_a_gzip_probe_is_not_capped() -> None:
    """gzip's 32 KiB window is the format's: no cap applies to it."""
    import gzip

    data = gzip.compress(_TARBALL)
    info = detect_format(io.BytesIO(data), config=_capped(1024))
    assert info.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.GZIP)


def test_probe_config_keeps_the_caller_s_decoder_limits() -> None:
    limits = DecoderLimits(max_decoder_memory=4 * _MIB)
    config = ArchiveyConfig(decoder_limits=limits)
    assert probe_config(config).decoder_limits == limits
    assert probe_config(ArchiveyConfig()) is probe_config(None)


def test_an_lzop_block_over_the_cap_is_cant_tell(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Under its own 256 KiB probe ceiling, an lzop block is still held to the cap."""
    pytest.importorskip("lzo")
    data = (_FIXTURES / "lzop" / "files.tar.lzo").read_bytes()
    tar_lzop = ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZOP)
    assert detect_format(io.BytesIO(data)).format == tar_lzop
    with caplog.at_level(logging.INFO, logger="archivey.detection"):
        info = detect_format(io.BytesIO(data), config=_capped(1024))
    assert info.format == ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.LZOP)
    assert TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE) in (
        info.unavailable_tiers
    )
    assert any("max_decoder_memory=1024" in m for m in _refusal_logs(caplog))
