"""What ``open_archive`` tells a caller who hands it a pipe.

The refusal is one typed error (``StreamNotSeekableError``) for every format, but the
*next step* it names depends on the backend rather than on the mode that was asked for.
TAR, ZIP, RAR and the single-file compressors read forward-only, so ``pipe=True``
really is the fix; ISO and 7z cannot be read as a pipe, so for those the only fix is a
seekable source. Suggesting ``pipe=True`` there would send callers into a second refusal
that explained the retry could never have worked, which is what these tests pin shut.

Every case names ``format=`` explicitly, so the refusal is reached before a byte is
read and no fixture archive is needed.
"""

from __future__ import annotations

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
    DiagnosticRaisedError,
    FormatSupport,
    PackageNotInstalledError,
    StreamNotSeekableError,
    format_availability,
    open_archive,
)
from tests.streams_util import NonSeekableBytesIO

# Trailing index or offset-addressed: no forward-only pass exists for these.
_NEEDS_SEEK = (
    ArchiveFormat.ISO,
    ArchiveFormat.SEVEN_Z,
)

# Read front to back, so a pipe is fine once the caller asks for pipe mode. The
# single-file compressors share one backend and one SUPPORTS_STREAMING_NON_SEEKABLE, so
# sampling only GZ would miss a per-codec regression; the ones whose package is absent
# skip through _skip_unless_registered rather than being left out of the list.
_READS_FORWARD = (
    ArchiveFormat.TAR,
    ArchiveFormat.ZIP,
    # With RARLAB unrar 7.00 or later; the refusal of random access comes first.
    ArchiveFormat.RAR,
    ArchiveFormat.TAR_GZ,
    ArchiveFormat.GZ,
    ArchiveFormat.BZ2,
    ArchiveFormat.XZ,
    ArchiveFormat.ZST,
    ArchiveFormat.LZ4,
    ArchiveFormat.LZIP,
    ArchiveFormat.ZLIB,
    ArchiveFormat.BROTLI,
)


def _skip_unless_registered(fmt: ArchiveFormat) -> None:
    # Only the forward-reading formats need this. Their refusal without pipe=True comes
    # after the availability check, so `.lz4` or `.zst` without its package fails as
    # PackageNotInstalledError first. The seek-only formats are refused before that
    # check, so their tests run in a core-only install too.
    availability = format_availability(fmt)
    if availability.support is FormatSupport.NONE:
        pytest.skip(f"{fmt.display_name} has no usable backend here")


@pytest.mark.parametrize("fmt", _NEEDS_SEEK, ids=lambda f: f.display_name)
@pytest.mark.parametrize(
    "mode",
    [{}, {"streaming": True}, {"pipe": True}],
    ids=["random", "streaming", "pipe"],
)
def test_seek_only_format_never_proposes_pipe(
    fmt: ArchiveFormat, mode: dict[str, bool]
) -> None:
    with pytest.raises(StreamNotSeekableError) as excinfo:
        open_archive(NonSeekableBytesIO(b""), format=fmt, **mode)

    message = str(excinfo.value)
    assert "streaming=True" not in message
    assert "Pass pipe=True" not in message, (
        f"{fmt.display_name} refuses pipe=True as well, so proposing it is a "
        f"dead end: {message}"
    )
    assert "BytesIO" in message  # the step that does work
    assert excinfo.value.source_format is fmt


@pytest.mark.parametrize("fmt", _NEEDS_SEEK, ids=lambda f: f.display_name)
def test_seek_only_format_refuses_both_modes_alike(fmt: ArchiveFormat) -> None:
    """Same source, either access mode, same answer — the mode was never the problem."""
    messages = set()
    for streaming in (False, True):
        with pytest.raises(StreamNotSeekableError) as excinfo:
            open_archive(NonSeekableBytesIO(b""), format=fmt, streaming=streaming)
        messages.add(str(excinfo.value))
    assert len(messages) == 1, messages


@pytest.mark.parametrize("fmt", _READS_FORWARD, ids=lambda f: f.display_name)
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_forward_only_format_proposes_pipe(fmt: ArchiveFormat, streaming: bool) -> None:
    _skip_unless_registered(fmt)
    with pytest.raises(StreamNotSeekableError) as excinfo:
        open_archive(NonSeekableBytesIO(b""), format=fmt, streaming=streaming)

    assert "Pass pipe=True" in str(excinfo.value)
    assert "streaming=True" not in str(excinfo.value)
    assert excinfo.value.source_format is fmt


_PEDANTIC = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.PEDANTIC)


def test_seek_only_refusal_reports_an_unused_password_first() -> None:
    """Both refusal halves emit the argument diagnostics before they refuse.

    ISO carries no encryption, so ``password=`` is ``PASSWORD_ARGUMENT_UNUSED``, which
    the pedantic preset raises. The capability refusal runs before the availability
    check, and the diagnostic comes first.
    """
    with pytest.raises(DiagnosticRaisedError) as excinfo:
        open_archive(
            NonSeekableBytesIO(b""),
            format=ArchiveFormat.ISO,
            password="x",
            config=_PEDANTIC,
        )
    assert excinfo.value.diagnostic.code is DiagnosticCode.PASSWORD_ARGUMENT_UNUSED


def test_mode_refusal_reports_an_unused_password_first() -> None:
    """The mode half keeps the same order: the diagnostic, then the refusal."""
    with pytest.raises(DiagnosticRaisedError) as excinfo:
        open_archive(
            NonSeekableBytesIO(b""),
            format=ArchiveFormat.TAR,
            streaming=False,
            password="x",
            config=_PEDANTIC,
        )
    assert excinfo.value.diagnostic.code is DiagnosticCode.PASSWORD_ARGUMENT_UNUSED


def test_availability_refusal_emits_no_argument_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The availability refusal comes before the argument diagnostics, so none is emitted.

    ``.tar.lz4`` without ``lz4`` is refused as ``PackageNotInstalledError`` while the
    reader is being chosen, before ``password=`` is checked. Under the pedantic preset
    an emitted ``PASSWORD_ARGUMENT_UNUSED`` would raise ``DiagnosticRaisedError``
    instead, so the error type is the proof. ``lz4`` is hidden the way the codec tests
    hide it (``codecs.deps.lz4_frame = None``), so the case runs with or without it.
    """
    from archivey.internal.streams import codecs as codecs_module

    monkeypatch.setattr(codecs_module.deps, "lz4_frame", None)
    assert format_availability(ArchiveFormat.TAR_LZ4).support is FormatSupport.NONE

    with pytest.raises(PackageNotInstalledError):
        open_archive(
            NonSeekableBytesIO(b""),
            format=ArchiveFormat.TAR_LZ4,
            streaming=False,
            password="x",
            config=_PEDANTIC,
        )
