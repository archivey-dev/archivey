"""Detection probes are held to the caller's ``DecoderLimits.max_decoder_memory``.

A probe that reserved more than the cap would let detection allocate what the caller
ruled out, and the read that follows would refuse it anyway. Where the codec can size
its decoder to the probe's read (the LZMA family), the cap is checked against that
size, so the format is still found and the open refuses it. Where it cannot (a zstd
window, an lzop block), a probe over the cap is "can't tell": the tier is recorded as
``CAPABILITY_UNAVAILABLE``, the diagnostic ``DETECTION_DECODER_LIMITED`` names the
cap, and the source is read as the bare compressed stream. A refusal that is not the
caller's cap (a probe's own ceiling) is an INFO log only.
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
    DiagnosticPolicy,
    detect_format,
    open_archive,
)
from archivey.detection_cost import TierSkip, TierSkipReason
from archivey.diagnostics import (
    ARCHIVE_INTEGRITY_CODES,
    DetectionDecoderLimitContext,
    Diagnostic,
    DiagnosticCode,
    DiagnosticSummary,
)
from archivey.exceptions import DiagnosticRaisedError, ResourceLimitError
from archivey.internal.detection import probe_config
from archivey.types import ContainerFormat, StreamFormat
from tests.conftest import requires_zstd, zstd_backend
from tests.streams_util import lzma_alone_with_filter

_MIB = 2**20
_FIXTURES = Path(__file__).parent / "fixtures" / "external"


def _capped(cap: int | None, **kwargs: object) -> ArchiveyConfig:
    return ArchiveyConfig(
        decoder_limits=DecoderLimits(max_decoder_memory=cap),
        **kwargs,  # type: ignore[arg-type]
    )


def _limited(summary: DiagnosticSummary) -> list[Diagnostic]:
    return [
        d
        for d in summary.retained
        if d.code is DiagnosticCode.DETECTION_DECODER_LIMITED
    ]


def _context(diagnostic: Diagnostic) -> DetectionDecoderLimitContext:
    assert isinstance(diagnostic.context, DetectionDecoderLimitContext)
    return diagnostic.context


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
    """The INFO records for a refusal that is not the caller's cap."""
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "archivey.detection" and r.levelno == logging.INFO
    ]


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "archivey.detection" and r.levelno == logging.WARNING
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

    seen: list[Diagnostic] = []
    config = _capped(4 * _MIB, on_diagnostic=seen.append)
    with caplog.at_level(logging.INFO, logger="archivey.detection"):
        info = detect_format(path, config=config)
    assert info.format == ArchiveFormat.ZST
    assert TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE) in (
        info.unavailable_tiers
    )
    (diagnostic,) = _limited(info.diagnostics)
    assert seen == [diagnostic]
    assert _context(diagnostic) == DetectionDecoderLimitContext(
        archive_name=str(path),
        tier="inner_tar",
        stream_format="ZSTD",
        max_decoder_memory=4 * _MIB,
        needed=None,
    )
    assert "ZSTD" in diagnostic.message
    assert f"max_decoder_memory={4 * _MIB}" in diagnostic.message
    # Logged at WARNING by the default policy, and not twice as an INFO record.
    assert _warnings(caplog) == [diagnostic.message]
    assert _refusal_logs(caplog) == []

    # The open of the bare stream refuses the same window, naming the same cap, and
    # the caller's callback has heard why the stream is read bare.
    seen.clear()
    with (
        pytest.raises(ResourceLimitError, match=f"max_decoder_memory={4 * _MIB}"),
        open_archive(path, config=config) as reader,
    ):
        (member,) = reader.members()
        reader.read(member)
    (opened,) = seen
    assert opened.code is DiagnosticCode.DETECTION_DECODER_LIMITED
    assert _context(opened) == _context(diagnostic)


@requires_zstd()
def test_raise_on_turns_the_cap_refusal_into_an_error() -> None:
    """Advisory by default, out of ``STRICT``; a caller can still ask to raise."""
    assert DiagnosticCode.DETECTION_DECODER_LIMITED not in ARCHIVE_INTEGRITY_CODES
    data = _tar_zst(23)
    strict = _capped(4 * _MIB, diagnostic_policy=DiagnosticPolicy.STRICT)
    assert detect_format(io.BytesIO(data), config=strict).format == ArchiveFormat.ZST
    raising = _capped(
        4 * _MIB,
        diagnostic_policy=DiagnosticPolicy(raise_on=["detection_decoder_limited"]),
    )
    with pytest.raises(DiagnosticRaisedError):
        detect_format(io.BytesIO(data), config=raising)


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
    assert _limited(info.diagnostics) == []


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
    assert _limited(info.diagnostics) == []
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
    (diagnostic,) = _limited(info.diagnostics)
    context = _context(diagnostic)
    assert (context.tier, context.stream_format) == ("content_probe", "LZMA_ALONE")
    assert context.max_decoder_memory == 1024
    assert context.needed is not None
    assert context.needed > 1024
    assert "max_decoder_memory=1024" in diagnostic.message

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
    info = detect_format(path, config=_capped(32 * 1024))
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.detected_by == "content_probe"
    assert TierSkip("probe_completion", TierSkipReason.CAPABILITY_UNAVAILABLE) in (
        info.unavailable_tiers
    )
    # The hit stands, so the diagnostic is the only trace of the skipped re-check.
    (diagnostic,) = _limited(info.diagnostics)
    context = _context(diagnostic)
    assert (context.tier, context.stream_format) == ("probe_completion", "LZMA_ALONE")
    assert context.max_decoder_memory == 32 * 1024
    assert context.needed is not None
    assert 32 * 1024 < context.needed <= _MIB
    message = diagnostic.message
    assert "max_decoder_memory=32768" in message
    # The number refused is the probe's, and the message says where it comes from.
    assert f"counted from the {_MIB}-byte dictionary the header declares" in message


def test_a_gzip_probe_is_not_capped() -> None:
    """gzip's 32 KiB window is the format's: no cap applies to it."""
    import gzip

    data = gzip.compress(_TARBALL)
    info = detect_format(io.BytesIO(data), config=_capped(1024))
    assert info.format == ArchiveFormat(ContainerFormat.TAR, StreamFormat.GZIP)
    assert _limited(info.diagnostics) == []


def test_a_cap_refusal_keeps_its_numbers_through_a_pickle() -> None:
    """A decoder child's refusal is pickled back to the parent: the type stays the
    public ``ResourceLimitError`` and the numbers detection reports survive."""
    import pickle

    from archivey.internal.config import check_decoder_memory, decoder_cap_refusal

    with pytest.raises(ResourceLimitError) as caught:
        check_decoder_memory(
            2 * _MIB, limits=DecoderLimits(max_decoder_memory=_MIB), what="a test"
        )
    assert type(caught.value) is ResourceLimitError
    restored = pickle.loads(pickle.dumps(caught.value))
    assert type(restored) is ResourceLimitError
    assert decoder_cap_refusal(restored) == (_MIB, 2 * _MIB)
    assert decoder_cap_refusal(ResourceLimitError("a probe ceiling")) is None


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
    (diagnostic,) = _limited(info.diagnostics)
    assert (_context(diagnostic).tier, _context(diagnostic).stream_format) == (
        "inner_tar",
        "LZOP",
    )
    assert "max_decoder_memory=1024" in diagnostic.message


def test_a_bzip3_block_over_the_cap_is_cant_tell(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Under its own 16 MiB probe ceiling, a bzip3 block is still held to the cap."""
    pytest.importorskip("bz3")
    from archivey.internal.streams.codecs.bzip3_codec import decoder_memory

    data = (_FIXTURES / "bzip3" / "files.tar.bz3").read_bytes()
    block_size = int.from_bytes(data[5:9], "little")
    tar_bzip3 = ArchiveFormat(ContainerFormat.TAR, StreamFormat.BZIP3)
    assert detect_format(io.BytesIO(data)).format == tar_bzip3
    assert (
        detect_format(
            io.BytesIO(data), config=_capped(decoder_memory(block_size))
        ).format
        == tar_bzip3
    )
    cap = decoder_memory(block_size) - 1
    with caplog.at_level(logging.INFO, logger="archivey.detection"):
        info = detect_format(io.BytesIO(data), config=_capped(cap))
    assert info.format == ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.BZIP3)
    assert TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE) in (
        info.unavailable_tiers
    )
    (diagnostic,) = _limited(info.diagnostics)
    assert _context(diagnostic).needed == decoder_memory(block_size)
    assert f"max_decoder_memory={cap}" in diagnostic.message
