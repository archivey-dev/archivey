"""A wrong-typed ``format=`` argument is a usage error, on every public entry point.

Four public functions took a format argument, and three of them accepted a
``StreamFormat`` — the codec half of an ``ArchiveFormat``'s ``(container, stream)``
pair — without noticing: ``format_availability()`` fabricated a ``FormatAvailability``
whose ``format`` field violated its own declared type, and ``open_archive()`` /
``extract()`` (since removed, ADR 0019) let an ``AttributeError`` naming a private
attribute cross the public boundary. ``open_stream()`` accepts both types by design,
but silently *ignored* a value that was neither and auto-detected instead.

The type checkers already reject all four calls (both run over ``src/`` only, so an
untyped caller is the exposure). These tests cover what happens when the call is made
anyway: ``ArchiveyUsageError``, outside the ``ArchiveyError`` tree per ADR 0012.

A format spelled as a **string** is the one wrong type that is not wrong: it is
converted, like the enum arguments beside it (see ``test_enum_arguments.py``). The
collision guard at the end of this file is what makes that safe to offer — it fails on
the day two formats come to share a spelling, rather than letting one of them become
unreachable.
"""

from __future__ import annotations

import gzip
import io
import zipfile
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyError,
    ArchiveyUsageError,
    FormatSupport,
    StreamFormat,
    format_availability,
    open_archive,
    open_stream,
)
from archivey.config import DEFAULT_ARCHIVEY_CONFIG
from archivey.core import _resolve_stream_format
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.enum_args import normalize_spelling
from archivey.internal.format_args import (
    _accepted_archive_formats,
    _accepted_stream_formats,
    coerce_archive_format,
    coerce_stream_or_archive_format,
)
from archivey.types import _FORMAT_NAMES, ContainerFormat

CONTENT = b"the quick brown fox jumps over the lazy dog\n"


@pytest.fixture
def zip_path(tmp_path: Path) -> Path:
    path = tmp_path / "archive.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("member.txt", CONTENT)
    return path


@pytest.fixture
def gz_path(tmp_path: Path) -> Path:
    path = tmp_path / "member.txt.gz"
    path.write_bytes(gzip.compress(CONTENT))
    return path


# --- format_availability ----------------------------------------------------------


def test_format_availability_rejects_a_stream_format() -> None:
    with pytest.raises(ArchiveyUsageError) as exc_info:
        format_availability(StreamFormat.ZSTD)  # type: ignore[arg-type]

    message = str(exc_info.value)
    assert "StreamFormat.ZSTD" in message
    assert "ArchiveFormat" in message


def test_format_availability_names_the_formats_that_contain_the_codec() -> None:
    """The message ends the mistake: a raw ``.zst`` stream, or a tar compressed with it."""
    with pytest.raises(ArchiveyUsageError) as exc_info:
        format_availability(StreamFormat.ZSTD)  # type: ignore[arg-type]

    message = str(exc_info.value)
    assert "ArchiveFormat.ZST" in message
    assert "ArchiveFormat.TAR_ZST" in message


@pytest.mark.parametrize("value", [None, 7, StreamFormat.UNCOMPRESSED])
def test_format_availability_rejects_any_non_archive_format(value: object) -> None:
    with pytest.raises(ArchiveyUsageError) as exc_info:
        format_availability(value)  # type: ignore[arg-type]

    assert "ArchiveFormat" in str(exc_info.value)


def test_format_availability_usage_error_escapes_archiveyerror_handlers() -> None:
    """ADR 0012: a caller mistake sits outside the tree, so this handler must not catch."""
    with pytest.raises(ArchiveyUsageError):
        try:
            format_availability(StreamFormat.ZSTD)  # type: ignore[arg-type]
        except ArchiveyError:  # pragma: no cover - the point is that it does not fire
            pytest.fail("ArchiveyUsageError was swallowed by `except ArchiveyError`")


def test_unknown_format_is_still_a_legitimate_hintless_none() -> None:
    """A real ``ArchiveFormat`` answering NONE with an empty ``missing`` is an answer.

    The fix keys on the argument's *type*, not on the shape of the verdict, so this
    genuine hintless NONE must survive it.
    """
    availability = format_availability(ArchiveFormat.UNKNOWN)

    assert availability.format is ArchiveFormat.UNKNOWN
    assert availability.support is FormatSupport.NONE
    assert availability.missing == ()


def test_every_archive_format_still_answers() -> None:
    for fmt in (ArchiveFormat.ZIP, ArchiveFormat.TAR_GZ, ArchiveFormat.ZST):
        assert format_availability(fmt).format is fmt


# --- open_archive -----------------------------------------------------------------


def test_open_archive_rejects_a_stream_format(zip_path: Path) -> None:
    with pytest.raises(ArchiveyUsageError) as exc_info:
        open_archive(zip_path, format=StreamFormat.ZSTD)  # type: ignore[arg-type]

    message = str(exc_info.value)
    assert "StreamFormat.ZSTD" in message
    assert "ArchiveFormat.ZST" in message


def test_open_archive_does_not_leak_an_attribute_error(zip_path: Path) -> None:
    """The old failure was ``'StreamFormat' object has no attribute 'container'``."""
    with pytest.raises(ArchiveyUsageError) as exc_info:
        open_archive(zip_path, format=StreamFormat.ZSTD)  # type: ignore[arg-type]

    assert not isinstance(exc_info.value, AttributeError)
    assert "has no attribute" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_open_archive_rejects_before_it_reads_the_source() -> None:
    """The spec requires the refusal before the source is resolved, peeked or read."""
    source = io.BytesIO(b"PK\x03\x04not really a zip")
    with pytest.raises(ArchiveyUsageError):
        open_archive(source, format=StreamFormat.ZSTD)  # type: ignore[arg-type]

    assert source.tell() == 0


@pytest.mark.parametrize("value", [7, object()])
def test_open_archive_rejects_any_non_archive_format(
    value: object, zip_path: Path
) -> None:
    with pytest.raises(ArchiveyUsageError) as exc_info:
        open_archive(zip_path, format=value)  # type: ignore[arg-type]

    assert "ArchiveFormat" in str(exc_info.value)


@pytest.mark.parametrize("value", [ArchiveFormat.UNKNOWN, "unknown"])
def test_open_archive_refuses_the_unknown_format_before_reading(value: object) -> None:
    """``UNKNOWN`` is what detection answers, not a format a caller can assert.

    It used to reach the registry and fail as ``UnsupportedFeatureError`` ("No read
    backend registered"), an ``ArchiveyError`` reporting a caller's mistake as a
    missing feature. ``format_availability(UNKNOWN)`` keeps answering (see above).
    """
    source = io.BytesIO(b"PK\x03\x04not really a zip")
    with pytest.raises(ArchiveyUsageError, match="UNKNOWN"):
        open_archive(source, format=value)  # type: ignore[call-overload]

    assert source.tell() == 0


def test_open_archive_refuses_any_pair_with_an_unknown_container() -> None:
    """The check is on the container: an unnamed UNKNOWN pair is refused the same way."""
    fmt = ArchiveFormat(ContainerFormat.UNKNOWN, StreamFormat.GZIP)
    with pytest.raises(ArchiveyUsageError, match="UNKNOWN"):
        open_archive(io.BytesIO(b"x"), format=fmt)


@pytest.mark.parametrize(
    "value",
    [
        ArchiveFormat.UNKNOWN,
        "unknown",
        ArchiveFormat(ContainerFormat.UNKNOWN, StreamFormat.GZIP),
    ],
)
def test_open_stream_refuses_unknown_without_sending_the_caller_to_open_archive(
    value: object, gz_path: Path
) -> None:
    """``open_archive`` refuses UNKNOWN too, so naming it would be a second failure."""
    with pytest.raises(ArchiveyUsageError) as exc_info:
        open_stream(gz_path, format=value)  # type: ignore[arg-type]

    message = str(exc_info.value)
    assert "UNKNOWN" in message
    assert "open_archive" not in message
    assert "container format" not in message


@pytest.mark.parametrize("kind", ["missing", "directory", "unread stream"])
def test_open_stream_refuses_unknown_before_any_io(kind: str, tmp_path: Path) -> None:
    """The argument bug is reported first, as ``open_archive`` reports it.

    Checked after the source probe, a missing path said "not found" and a directory said
    "use open_archive()", which refuses the same ``format=``.
    """
    source: object
    if kind == "missing":
        source = tmp_path / "absent.gz"
    elif kind == "directory":
        source = tmp_path
    else:
        source = io.BytesIO(gzip.compress(CONTENT))
    with pytest.raises(ArchiveyUsageError, match="names no format"):
        open_stream(source, format="unknown")  # type: ignore[arg-type]
    if isinstance(source, io.BytesIO):
        assert source.tell() == 0


def test_open_archive_still_accepts_an_archive_format_and_none(zip_path: Path) -> None:
    for fmt in (None, ArchiveFormat.ZIP):
        with open_archive(zip_path, format=fmt) as reader:
            assert [m.name for m in reader.members()] == ["member.txt"]


# --- open_stream: the deliberate exception ----------------------------------------


def test_open_stream_keeps_accepting_both_format_types(gz_path: Path) -> None:
    """A raw stream has no container, so ``StreamFormat`` is a first-class argument here."""
    for fmt in (StreamFormat.GZIP, ArchiveFormat.GZ, None):
        with open_stream(gz_path, format=fmt) as stream:
            assert stream.read() == CONTENT


def test_open_stream_rejects_a_format_of_neither_type(gz_path: Path) -> None:
    """It used to ignore the argument and auto-detect, which is the same dishonesty."""
    with pytest.raises(ArchiveyUsageError) as exc_info:
        open_stream(gz_path, format=object())  # type: ignore[arg-type]

    message = str(exc_info.value)
    assert "StreamFormat" in message
    assert "ArchiveFormat" in message


def test_open_stream_rejects_a_format_of_neither_type_before_reading() -> None:
    source = io.BytesIO(gzip.compress(CONTENT))
    with pytest.raises(ArchiveyUsageError):
        open_stream(source, format=7)  # type: ignore[arg-type]

    assert source.tell() == 0


# --- the string spellings ----------------------------------------------------------


def test_no_two_formats_share_a_spelling() -> None:
    """The guard the coercion rests on, and which ``format_args`` says lives here.

    If this fails, a newly declared format's extension or name collides with another's
    under ``normalize_spelling`` and one of the two has become unspellable. Change the
    new format, not the normalization — callers are already using the old spelling.
    """
    seen: dict[str, str] = {}
    for fmt, name in _FORMAT_NAMES.items():
        for spelling in {normalize_spelling(name)} | {
            normalize_spelling(fmt.file_extension() or "")
        } - {""}:
            clash = seen.get(spelling)
            assert clash is None or clash == name, (
                f"{spelling!r} spells both {clash} and {name}"
            )
            seen[spelling] = name


def test_every_format_is_reachable_by_its_name_and_its_extension() -> None:
    for fmt, name in _FORMAT_NAMES.items():
        spellings = [name, name.lower(), name.replace("_", "-")]
        extension = fmt.file_extension()
        if extension:
            spellings += [extension, extension.upper(), f"  {extension}  "]
        for spelling in spellings:
            assert coerce_archive_format(spelling, call="t()") is fmt, (
                f"{spelling!r} did not resolve to {name}"
            )


def test_open_archive_accepts_the_format_spelled_as_a_string(zip_path: Path) -> None:
    with open_archive(zip_path, format="zip") as reader:
        assert reader.format is ArchiveFormat.ZIP


def test_format_availability_accepts_a_string() -> None:
    assert format_availability("zip") == format_availability(ArchiveFormat.ZIP)


def test_open_stream_resolves_a_shared_spelling_the_way_open_archive_would(
    gz_path: Path,
) -> None:
    """``"gz"`` names both an ``ArchiveFormat`` and a ``StreamFormat``.

    They are the same format at two levels, so the order picks a representation, not a
    meaning — and it picks the one ``open_archive`` would.
    """
    assert coerce_stream_or_archive_format("gz", call="t()") is ArchiveFormat.GZ
    with open_stream(gz_path, format="gz") as stream:
        assert stream.read() == CONTENT


def test_open_stream_accepts_a_stream_only_spelling(gz_path: Path) -> None:
    """``"gzip"`` is ``StreamFormat.GZIP``'s value and no ``ArchiveFormat``'s spelling."""
    assert coerce_stream_or_archive_format("gzip", call="t()") is StreamFormat.GZIP


@pytest.mark.parametrize(
    ("call", "expected", "not_expected"),
    [
        (
            lambda: coerce_archive_format("not-a-format", call="t()"),
            "'zip'",
            "'gzip'",
        ),
        # ``open_stream`` refuses a container format, so naming ``zip`` here would send
        # the caller into a second refusal — the defect the two accepted-list tests
        # below pin as a property.
        (
            lambda: coerce_stream_or_archive_format("not-a-format", call="t()"),
            "'gz'",
            "'zip'",
        ),
    ],
    ids=["archive", "stream_or_archive"],
)
def test_an_unknown_spelling_names_the_ones_that_work(  # type: ignore[no-untyped-def]
    call, expected: str, not_expected: str
) -> None:
    with pytest.raises(ArchiveyUsageError) as exc_info:
        call()

    message = str(exc_info.value)
    assert expected in message
    assert not_expected not in message


@pytest.mark.parametrize(
    "container",
    list(ContainerFormat),
    ids=lambda c: c.name,
)
def test_a_container_format_object_is_refused_rather_than_completed(
    container: ContainerFormat,
) -> None:
    """The other half of the pair, and the one the string branch used to swallow.

    ``ContainerFormat`` mixes in ``str`` and its values are the extension spellings, so
    before the wrong-enum check every member coerced to the ``ArchiveFormat`` of the
    same name — silently completing the caller's half-specified assertion with an
    ``UNCOMPRESSED`` stream. ``open_archive("a.tar.gz", format=ContainerFormat.TAR)``
    then failed as ``TruncatedError`` on a healthy archive: a caller bug reported as
    damaged input, inside the tree ``except ArchiveyError`` catches.
    """
    with pytest.raises(ArchiveyUsageError) as exc_info:
        coerce_archive_format(container, call="t()")

    message = str(exc_info.value)
    assert f"ContainerFormat.{container.name}" in message

    with pytest.raises(ArchiveyUsageError):
        coerce_stream_or_archive_format(container, call="t()")


def test_a_container_format_does_not_reach_the_backend(tmp_path: Path) -> None:
    """End-to-end: the refusal happens at the call, not as a decode failure later."""
    import gzip
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("hello.txt")
        info.size = len(CONTENT)
        tf.addfile(info, io.BytesIO(CONTENT))
    path = tmp_path / "a.tar.gz"
    path.write_bytes(gzip.compress(buf.getvalue()))

    with pytest.raises(ArchiveyUsageError):
        open_archive(path, format=ContainerFormat.TAR)  # type: ignore[arg-type]


def _quoted(accepted: str) -> list[str]:
    """The spellings out of an ``Accepted: ...`` fragment, unquoted."""
    return [part.strip().strip("'") for part in accepted.split(",")]


def test_the_archive_accepted_list_only_recommends_spellings_open_archive_takes() -> (
    None
):
    """Every spelling the refusal recommends resolves to a format that opens something.

    The list is repair advice appended to every ``coerce_archive_format`` refusal, so a
    spelling on it that leads somewhere worse — ``format="unknown"`` is refused,
    ``format="directory"`` opens only a directory path — is a message sending the caller
    into a second failure. Asserted as the property rather than as the absence of the
    names that prompted it, so another format that opens nothing cannot arrive
    unnoticed.
    """
    accepted = _accepted_archive_formats()
    assert accepted == accepted.lower(), "mixed case implies case is significant"

    for spelling in _quoted(accepted):
        fmt = coerce_archive_format(spelling, call="open_archive", allow_none=False)
        assert fmt.container not in (
            ContainerFormat.DIRECTORY,
            ContainerFormat.UNKNOWN,
        ), f"{spelling!r} is recommended but opens nothing"


def test_the_stream_accepted_list_only_recommends_spellings_open_stream_takes() -> None:
    """Same property for ``open_stream``, whose accepted set is the narrower one.

    This is the half that was wrong: the message borrowed ``coerce_archive_format``'s
    list, so a mistyped ``format=`` on ``open_stream`` was told to try ``zip``, ``tar``
    and eight other container spellings that the very next frame refuses.
    """
    accepted = _accepted_stream_formats()
    assert accepted == accepted.lower()

    for spelling in _quoted(accepted):
        resolved = coerce_stream_or_archive_format(spelling, call="open_stream")
        stream = _resolve_stream_format(
            resolved, io.BytesIO(), DiagnosticCollector(), DEFAULT_ARCHIVEY_CONFIG
        )
        assert stream is not StreamFormat.UNCOMPRESSED, (
            f"{spelling!r} is recommended but open_stream refuses it"
        )


def test_a_stream_format_object_is_still_refused_rather_than_widened() -> None:
    """Accepting ``"gz"`` did not make a ``StreamFormat`` *object* an ``ArchiveFormat``.

    It still earns the message naming the pairs built on it, which is the useful answer
    for the caller who reached there.
    """
    with pytest.raises(ArchiveyUsageError) as exc_info:
        coerce_archive_format(StreamFormat.GZIP, call="t()")

    message = str(exc_info.value)
    assert "StreamFormat.GZIP" in message
    assert "ArchiveFormat.GZ" in message
