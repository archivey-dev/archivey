"""Provenance-based ``format_unconfirmed`` (probe-provenance-unconfirmed).

The honesty channel stamps a decode failure when a content probe was the *sole*
evidence — at any ``DetectionConfidence`` — and leaves corroborated hits alone.
"""

from __future__ import annotations

import io
import lzma
import random
import sys
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    DecoderLimits,
    DetectionConfidence,
    DiagnosticPolicy,
    ProcessIsolation,
    detect_format,
    open_archive,
)
from archivey.detection_cost import BALANCED_BUDGET
from archivey.diagnostics import Diagnostic, DiagnosticCode
from archivey.exceptions import (
    CorruptionError,
    DiagnosticRaisedError,
    ResourceLimitError,
    ResourceUnavailableError,
)
from archivey.internal.detection import _extension_corroborates
from archivey.internal.streams.codecs.brotli_framing import BrotliBlock, parse_metablock
from archivey.types import ContainerFormat, StreamFormat
from tests.conftest import requires
from tests.corruption_util import raises_corruption_not_truncation
from tests.streams_util import truncated_brotli

TAR_BROTLI = ArchiveFormat(ContainerFormat.TAR, StreamFormat.BROTLI)

# Most sources below are unnamed or carry a name of another format, and detection runs
# a content probe on such a source only when the config asks for all of them.
PROBE_ALL = ArchiveyConfig(always_probe_content=True)


def _open_and_read(
    source: Path | io.BytesIO,
    diagnostics: list[Diagnostic] | None = None,
    *,
    config: ArchiveyConfig | None = None,
) -> None:
    """Open ``source`` and read its first member, collecting every diagnostic.

    A single-file source that does not decode raises from ``open_archive`` itself, so
    there is no reader left to ask for ``diagnostics``; ``on_diagnostic`` sees them
    wherever the failure lands.
    """
    config = config or ArchiveyConfig()
    if diagnostics is not None:
        config = replace(config, on_diagnostic=diagnostics.append)
    with open_archive(source, config=config) as reader:
        reader.open(next(iter(reader))).read()


def _probable_brotli_probe_only_residual() -> bytes:
    """A real Brotli stream cut short, larger than the completion window, no extension cue.

    The probe sees a valid compressed-first stream in its window and reports
    ``BROTLI`` / ``PROBABLE`` / ``content_probe``; the source is too large for the
    whole-source completion check, so only the read finds the truncation. Text that
    merely decodes for a while no longer serves: the 4 KiB probe sample and the
    completion check both reject it.
    """
    blob = truncated_brotli(BALANCED_BUDGET.completion_window_bytes + 4096)
    assert parse_metablock(blob).outcome is BrotliBlock.COMPRESSED
    return blob


def _lzma_alone_probe_only_residual() -> bytes:
    """An LZMA Alone claim that turns corrupt past the detection window — ``PROBABLE``.

    The header is the first five bytes of an OLE header (the full OLE signature is not
    used, because it stops the content probes): properties ``0xD0`` are legal (lc=1,
    lp=3, pb=4) and bytes 1-4 declare a 2.5 GiB dictionary. Under it is a real LZMA1
    stream with those properties, which the probe's window decodes, cut at 80 000 bytes
    and followed by ``ff`` bytes, which the full read fails on. A zero run after the
    header would be shorter, but the probe refuses one.

    The blob must stay over the 64 KiB probe-completion window
    (``completion_window_bytes`` under ``BALANCED``). A shorter one is re-probed whole,
    the re-probe reaches the ``ff`` tail, and the claim the tests need is gone.
    """
    data = random.Random(5).randbytes(100_000)
    lzma1 = {"id": lzma.FILTER_LZMA1, "lc": 1, "lp": 3, "pb": 4, "dict_size": 1 << 16}
    raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[lzma1])
    header = bytes.fromhex("D0CF11E0A1") + (1 << 20).to_bytes(8, "little")
    return header + raw[:80_000] + b"\xff" * 20_000


def _chain_surviving_guess_residual() -> bytes:
    """Uncompressed-first fabrication every probe check accepts (a chain past the cap)."""
    from tests.streams_util import brotli_link_cap_residual

    return brotli_link_cap_residual()


@requires("brotli")
def test_compressed_first_probable_failure_sets_format_unconfirmed() -> None:
    blob = _probable_brotli_probe_only_residual()
    info = detect_format(io.BytesIO(blob), config=PROBE_ALL)
    assert info.format == ArchiveFormat.BROTLI
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.detected_by == "content_probe"
    assert info.corroborated is False

    diagnostics: list[Diagnostic] = []
    with pytest.raises(CorruptionError) as caught:
        _open_and_read(io.BytesIO(blob), diagnostics, config=PROBE_ALL)
    exc = caught.value
    assert exc.format_unconfirmed is True
    assert "unconfirmed" in exc.message.lower()
    assert "Partial output may already have been produced" in exc.raw_message
    assert "GUESS" not in exc.raw_message
    messages = " ".join(d.message for d in diagnostics)
    assert "GUESS" not in messages
    assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED in {d.code for d in diagnostics}


def test_lzma_alone_probable_failure_sets_format_unconfirmed() -> None:
    blob = _lzma_alone_probe_only_residual()
    info = detect_format(io.BytesIO(blob), config=PROBE_ALL)
    assert info.format == ArchiveFormat.LZMA_ALONE
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.detected_by == "content_probe"
    assert info.corroborated is False

    # Bytes 1-4 declare a 2.5 GiB dictionary, over the default cap;
    # this case lifts the cap to reach the decode failure, and the next one keeps it.
    config = replace(PROBE_ALL, decoder_limits=DecoderLimits.UNLIMITED)
    diagnostics: list[Diagnostic] = []
    with pytest.raises(CorruptionError) as caught:
        _open_and_read(io.BytesIO(blob), diagnostics, config=config)
    assert caught.value.format_unconfirmed is True
    codes = {d.code for d in diagnostics}
    assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED in codes
    assert DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED not in codes


def test_lzma_alone_probable_limit_refusal_sets_format_unconfirmed() -> None:
    """A decoder-limit refusal on probe-only evidence is stamped like a decode failure.

    The dictionary the refusal names is four bytes of a fabrication, so the ordinary
    "raise the cap if the archive is trusted" advice would be about a file that was
    never ``.lzma``.
    """
    blob = _lzma_alone_probe_only_residual()
    diagnostics: list[Diagnostic] = []
    with pytest.raises(ResourceLimitError) as caught:
        _open_and_read(io.BytesIO(blob), diagnostics, config=PROBE_ALL)
    assert caught.value.format_unconfirmed is True
    message = str(caught.value)
    assert "unconfirmed" in message
    # Nothing was decoded: liblzma refuses the header before it allocates the
    # dictionary.
    assert "stopped by a limit" in message
    assert "Decode failed" not in message
    assert "Partial output" not in message
    codes = {d.code for d in diagnostics}
    assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED in codes


def test_a_shortage_on_unconfirmed_evidence_is_not_called_a_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``ResourceUnavailableError`` is stamped as the system running short, not as a
    limit: no limit was set, and a decoder killed part-way may have produced output."""
    # ``.lzma`` has no signature: the name is the only evidence.
    path = tmp_path / "data.lzma"
    path.write_bytes(lzma.compress(b"x" * 10_000, format=lzma.FORMAT_ALONE))
    monkeypatch.setattr(sys, "executable", str(tmp_path / "no-such-python"))
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    with pytest.raises(ResourceUnavailableError) as caught:
        _open_and_read(path, config=config)
    assert caught.value.format_unconfirmed is True
    message = str(caught.value)
    assert "system ran short" in message
    assert "stopped by a limit" not in message
    assert "Partial output may already have been produced" in message


def test_lzma_alone_limit_refusal_with_extension_is_not_stamped(
    tmp_path: Path,
) -> None:
    path = tmp_path / "x.lzma"
    path.write_bytes(_lzma_alone_probe_only_residual())
    with pytest.raises(ResourceLimitError) as caught:
        _open_and_read(path)
    assert caught.value.format_unconfirmed is False


@requires("brotli")
def test_br_extension_failure_does_not_stamp(tmp_path: Path) -> None:
    # Same residual as the probe-only case, but ``.br`` corroborates the claim.
    path = tmp_path / "x.br"
    path.write_bytes(_probable_brotli_probe_only_residual())
    info = detect_format(path)
    assert info.format == ArchiveFormat.BROTLI
    assert info.detected_by == "content_probe"
    assert info.corroborated is True
    diagnostics: list[Diagnostic] = []
    with pytest.raises(CorruptionError) as caught:
        _open_and_read(path, diagnostics)
    assert caught.value.format_unconfirmed is False
    assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED not in {d.code for d in diagnostics}


@requires("brotli")
def test_deferred_tar_br_extension_corroborates(tmp_path: Path) -> None:
    """``foo.tar.br`` over a bare-Brotli payload: the extension still agrees on the codec.

    The inner-TAR probe finds no tar, so detection reports bare ``BROTLI`` while the
    extension says ``TAR_BROTLI`` — the documented deferred case, not a conflict.
    """
    path = tmp_path / "x.tar.br"
    path.write_bytes(_probable_brotli_probe_only_residual())
    info = detect_format(path)
    assert info.format == ArchiveFormat.BROTLI
    assert info.detected_by == "content_probe"
    assert info.corroborated is True

    with pytest.raises(CorruptionError) as caught:
        _open_and_read(path)
    assert caught.value.format_unconfirmed is False


@requires("brotli")
@pytest.mark.parametrize("name", ["y.zip", "z.tar", "w.gz"])
def test_disagreeing_extension_does_not_corroborate(tmp_path: Path, name: str) -> None:
    """A name that disagrees must not corroborate — including across containers.

    ``z.tar`` is the case a bare ``stream``-only comparison got wrong: every container
    shares ``StreamFormat.UNCOMPRESSED``, so ``.tar``/``.zip`` would have "agreed" with any
    other container result. Pinned so ``ReadBackend.CONTENT_PROBES`` gaining a container
    probe cannot silently suppress the stamp.
    """
    path = tmp_path / name
    path.write_bytes(_probable_brotli_probe_only_residual())
    # The name points away from Brotli, so only probing everything reaches the probe.
    info = detect_format(path, config=PROBE_ALL)
    assert info.format == ArchiveFormat.BROTLI
    assert info.detected_by == "content_probe"
    assert info.corroborated is False

    with pytest.raises(CorruptionError) as caught:
        _open_and_read(path, config=PROBE_ALL)
    assert caught.value.format_unconfirmed is True


def test_extension_corroborates_rejects_cross_container_stream_match() -> None:
    """Unit pin on the predicate itself, for pairs no probe can produce today."""
    assert (
        _extension_corroborates((ArchiveFormat.ZIP, "zip"), ArchiveFormat.TAR) is False
    )
    assert (
        _extension_corroborates((ArchiveFormat.TAR, "tar"), ArchiveFormat.ZIP) is False
    )
    assert (
        _extension_corroborates((ArchiveFormat.RAR, "rar"), ArchiveFormat.ISO) is False
    )
    # Still true for what it is for.
    assert (
        _extension_corroborates((ArchiveFormat.BROTLI, "br"), ArchiveFormat.BROTLI)
        is True
    )
    assert _extension_corroborates((TAR_BROTLI, "tar.br"), ArchiveFormat.BROTLI) is True


@requires("brotli")
def test_inner_tar_upgrade_is_corroborated_and_probable() -> None:
    import brotli

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("a.txt")
        payload = b"hi"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    full = brotli.compress(buf.getvalue())
    info = detect_format(io.BytesIO(full), config=PROBE_ALL)
    assert info.format == TAR_BROTLI
    assert info.confidence == DetectionConfidence.PROBABLE
    assert info.detected_by == "content_probe"
    assert info.corroborated is True

    with open_archive(io.BytesIO(full), config=PROBE_ALL) as reader:
        members = list(reader)
        assert members
        assert reader.open(members[0]).read() == b"hi"
        assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED not in {
            d.code for d in reader.diagnostics.retained
        }


@requires("brotli")
def test_inner_tar_decode_failure_does_not_stamp() -> None:
    import brotli

    # Truncate the *tar* after the ustar header region, then Brotli-compress: detection
    # still sees the inner TAR (corroboration), but listing/reading fails.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("a.txt")
        payload = b"x" * 50_000
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    truncated_tar = buf.getvalue()[:1024]
    assert truncated_tar[257:262] == b"ustar"
    blob = brotli.compress(truncated_tar)
    info = detect_format(io.BytesIO(blob), config=PROBE_ALL)
    assert info.format == TAR_BROTLI
    assert info.corroborated is True
    with open_archive(io.BytesIO(blob), config=PROBE_ALL) as reader:
        with pytest.raises(CorruptionError) as caught:
            list(reader)
        assert caught.value.format_unconfirmed is False
        assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED not in {
            d.code for d in reader.diagnostics.retained
        }


@requires("brotli")
def test_probe_only_clean_read_stays_success() -> None:
    import brotli

    data = brotli.compress(b"payload " * 40)
    info = detect_format(io.BytesIO(data), config=PROBE_ALL)
    assert info.format == ArchiveFormat.BROTLI
    assert info.detected_by == "content_probe"
    assert info.corroborated is False
    with open_archive(io.BytesIO(data), config=PROBE_ALL) as reader:
        assert reader.open(next(iter(reader))).read() == b"payload " * 40
        assert not reader.diagnostics.retained


@requires("brotli")
def test_pedantic_probable_probe_keeps_typed_error() -> None:
    blob = _probable_brotli_probe_only_residual()
    cfg = replace(PROBE_ALL, diagnostic_policy=DiagnosticPolicy.PEDANTIC)
    diagnostics: list[Diagnostic] = []
    with pytest.raises(CorruptionError) as caught:
        _open_and_read(io.BytesIO(blob), diagnostics, config=cfg)
    assert not isinstance(caught.value, DiagnosticRaisedError)
    assert caught.value.format_unconfirmed is True
    assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED in {d.code for d in diagnostics}


@requires("brotli")
def test_confidence_matrix_unchanged_by_provenance() -> None:
    """Pin GUESS/PROBABLE so this change is not mistaken for a confidence retune."""
    import brotli

    guess = detect_format(
        io.BytesIO(_chain_surviving_guess_residual()), config=PROBE_ALL
    )
    assert guess.confidence == DetectionConfidence.GUESS

    compressed = brotli.compress(b"payload " * 40)
    assert parse_metablock(compressed).outcome is BrotliBlock.COMPRESSED
    probable = detect_format(io.BytesIO(compressed), config=PROBE_ALL)
    assert probable.confidence == DetectionConfidence.PROBABLE

    residual = detect_format(
        io.BytesIO(_probable_brotli_probe_only_residual()), config=PROBE_ALL
    )
    assert residual.confidence == DetectionConfidence.PROBABLE


def test_exact_magic_failure_untouched_by_probe_channel(tmp_path: Path) -> None:
    # Truncated gzip (exact magic) must not grow a probe-unconfirmed stamp.
    import gzip

    path = tmp_path / "x.gz"
    path.write_bytes(gzip.compress(b"hello world")[:8])
    info = detect_format(path)
    assert info.detected_by == "magic"
    assert info.corroborated is False
    diagnostics: list[Diagnostic] = []
    with pytest.raises(CorruptionError) as caught:
        _open_and_read(path, diagnostics)
    assert caught.value.format_unconfirmed is False
    assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED not in {d.code for d in diagnostics}


_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


def test_argument_provenance_records_the_resolved_volume() -> None:
    """``format=`` with a later RAR part records the first volume that was opened.

    The empty-listing check re-detects ``provenance.source`` by name, so it must be the
    file the reader read, not the name the caller passed.
    """
    later_part = _RAR_FIXTURES / "tinyvol_rnn.r00"
    with open_archive(later_part, format=ArchiveFormat.RAR) as archive:
        provenance = archive._format_provenance  # type: ignore[attr-defined]
        assert provenance is not None
        assert provenance.chosen_by == "argument"
        assert provenance.source == _RAR_FIXTURES / "tinyvol_rnn.rar"


def test_argument_provenance_of_a_stream_has_no_source() -> None:
    """A regression guard, not a red-green repro: ``main`` already passed this.

    It fails if the provenance falls back to the caller's argument for a source that
    has no single path, which would make the empty-listing check reach into a stream.
    """
    blob = (_RAR_FIXTURES / "stored_m0.rar").read_bytes()
    with open_archive(io.BytesIO(blob), format=ArchiveFormat.RAR) as archive:
        provenance = archive._format_provenance  # type: ignore[attr-defined]
        assert provenance is not None
        assert provenance.chosen_by == "argument"
        assert provenance.source is None


def test_empty_directory_with_format_directory_is_not_unconfirmed(
    tmp_path: Path,
) -> None:
    """``format=DIRECTORY`` on a directory is confirmed by the filesystem, not asserted."""
    with open_archive(tmp_path, format=ArchiveFormat.DIRECTORY) as archive:
        assert archive.members() == []
        codes = [d.code for d in archive.diagnostics.retained]
    assert codes == [DiagnosticCode.EMPTY_ARCHIVE]


# ---------------------------------------------------------------------------
# Extension-only guesses: the filename decided because every content signal declined.
# ---------------------------------------------------------------------------


def test_extension_only_failure_sets_format_unconfirmed(tmp_path: Path) -> None:
    path = tmp_path / "backup.gz"
    path.write_bytes(b"\x00" * 40_000)
    info = detect_format(path)
    assert info.format == ArchiveFormat.GZ
    assert info.detected_by == "extension"

    diagnostics: list[Diagnostic] = []
    with raises_corruption_not_truncation() as caught:
        _open_and_read(path, diagnostics)
    exc = caught.value
    assert exc.format_unconfirmed is True
    assert "extension only" in exc.message
    codes = [d.code for d in diagnostics]
    assert codes.count(DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED) == 1
    assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED not in codes
    (diag,) = [
        d for d in diagnostics if d.code is DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED
    ]
    assert diag.context.chosen_by == "extension"
    assert diag.context.detected_format is None
    assert "file extension" in diag.message


def test_strict_extension_only_failure_keeps_typed_error(tmp_path: Path) -> None:
    # EXTENSION_FORMAT_UNCONFIRMED is in the strict set, so STRICT resolves it to
    # RAISE: the emit must surface the typed error, not DiagnosticRaisedError.
    path = tmp_path / "backup.gz"
    path.write_bytes(b"\x00" * 40_000)
    cfg = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with raises_corruption_not_truncation() as caught:
        _open_and_read(path, config=cfg)
    assert not isinstance(caught.value, DiagnosticRaisedError)
    assert caught.value.format_unconfirmed is True


def test_magic_confirmed_failure_is_not_stamped_as_extension_only(
    tmp_path: Path,
) -> None:
    import gzip

    path = tmp_path / "x.gz"
    path.write_bytes(gzip.compress(b"hello world" * 100)[:30])
    diagnostics: list[Diagnostic] = []
    with pytest.raises(CorruptionError) as caught:
        _open_and_read(path, diagnostics)
    assert caught.value.format_unconfirmed is False
    assert DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED not in {
        d.code for d in diagnostics
    }
