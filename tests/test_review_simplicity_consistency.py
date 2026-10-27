"""Guardrails for the simplicity & consistency review (`review/archive/2026-08-15-simplicity-consistency/`).

The file started as two kinds of test: **guardrails** (plain assertions pinning a rule
the review classified as *format law* or *settled*) and **red halves**
(``@pytest.mark.xfail(strict=True)`` assertions of the behaviour the review argued was
correct, failing on purpose until a fix landed).

**All sixteen red halves have now landed** (W1–W8), so what remains is one regression
net, and it is deliberately kept in one file: each test names the finding it came from,
so a future change that reintroduces a divergence fails against the argument that
removed it rather than against a bare assertion. Where a fix went a different way than
the review recommended — Q2 and Q7 chose a diagnostic over the refusal the red halves
asserted — the test says so, because the *rejected* option is the one someone will
propose again.

Several tests also pin the half of a fix that is easy to lose: a pipe still reports no
cheap metadata (F1), a genuinely missing path still says "not found" (F11), a corrupt
member offset is still corruption (F4), a *small* rewind still stays quiet (F19), and a
directional bidi mark still extracts (O7).

Every test names the merged finding id from
`review/archive/2026-08-15-simplicity-consistency/SUMMARY.md` so the two stay linked. The review was
delivered twice independently (PR #230 and PR #231) and merged; findings carried over
from the second pass are marked in the SUMMARY's provenance column and their guardrails
were moved here from `review/simplicity-consistency/tests/` (pre-archive path), which
`testpaths = ["tests"]` never collected — a guardrail CI does not run guards nothing.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyError,
    ArchiveyUsageError,
    DiagnosticPolicy,
    StreamNotSeekableError,
    open_archive,
    open_stream,
)
from archivey.types import HashAlgorithm, MemberType
from tests.corruption_util import raises_corruption_not_truncation
from tests.sample_archives import (
    CORPUS,
    CorpusEntry,
    corpus_archive_path,
    skip_unless_runnable,
)

_FILE = MemberType.FILE

_BY_ID: dict[str, CorpusEntry] = {e.id: e for e in CORPUS}


def _entry(entry_id: str) -> CorpusEntry:
    return _BY_ID[entry_id]


def _archive(entry_id: str, key: str, tmp_path: Path) -> Path:
    """Build one corpus archive, skipping cleanly when this env cannot make it.

    Uses the shared ``skip_unless_runnable`` gate rather than a local copy: a missing
    reader *or a missing builder* is an **unmeasured** cell, not a pass. An earlier
    hand-rolled version of this checked only reader availability, which is exactly
    wrong for 7z — the reader is native, so it looked fine, while the corpus builder
    needs ``py7zr`` and the ``core-only`` CI leg died on ``ModuleNotFoundError``.
    """
    entry = _entry(entry_id)
    if key not in entry.formats:
        pytest.skip(f"corpus entry {entry_id!r} is not built as {key!r}")
    skip_unless_runnable(entry, key)
    try:
        return corpus_archive_path(entry, key, tmp_path)
    except FileNotFoundError as exc:  # a builder binary the tables do not name
        pytest.skip(f"builder for {key!r} unavailable: {exc}")


class _NonSeekable(io.RawIOBase):
    """Forward-only byte source — the pipe shape."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1, /) -> bytes:
        return self._inner.read(n)

    def readinto(self, b) -> int:  # type: ignore[override]
        return self._inner.readinto(b)

    def seekable(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# F1 — declared member-stream seekability leaks into member *metadata*
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["lz", "xz"])
@pytest.mark.parametrize("as_stream", [False, True], ids=["path", "bytesio"])
def test_member_size_does_not_depend_on_declared_seekability(
    key: str, as_stream: bool, tmp_path: Path
) -> None:
    """F1 (fixed): the same archive reports the same ``size`` either way.

    The size comes from the xz index / lzip trailer — a bounded peek over a source that
    is already seekable. Nothing about it needs the caller to want ``seek()``, and
    ``seekable_members`` is documented as a *member-stream* capability. Both source
    shapes are checked because the divergence held for a `Path` and a `BytesIO` alike.
    """
    path = _archive("single-file", key, tmp_path)

    def _size(**kwargs: object) -> int | None:
        source = io.BytesIO(path.read_bytes()) if as_stream else path
        with open_archive(source, **kwargs) as reader:  # type: ignore[arg-type]
            return reader.members()[0].size

    assert _size() == _size(seekable_members=True)
    assert isinstance(_size(), int)


def test_lzip_surfaces_crc32_without_declaring_seekable_members(
    tmp_path: Path,
) -> None:
    """F1 (fixed): a dedupe caller doing a plain ``open_archive`` gets the CRC-32.

    ``format-single-file-compressors`` promises the lzip CRC-32 from the index on a
    seekable source; the gate used to be the caller's ``seekable_members`` flag, so the
    founding dedupe use case (`VISION.md` "hashes without decompression") missed it on
    the default open.
    """
    from archivey.types import HashAlgorithm

    path = _archive("single-file", "lz", tmp_path)
    with open_archive(path) as reader:
        assert HashAlgorithm.CRC32 in reader.members()[0].hashes


@pytest.mark.parametrize("key", ["lz", "xz"])
def test_pipe_metadata_stays_absent_and_costs_no_decode(
    key: str, tmp_path: Path
) -> None:
    """F1 (guardrail): the gate moved to the *source's* shape, not away entirely.

    A non-seekable source has no cheap index read, so ``size`` stays ``None`` and no
    digest appears — the fix must not turn the harvest into a decompression pass.
    """
    from archivey.types import HashAlgorithm

    path = _archive("single-file", key, tmp_path)
    with open_archive(_NonSeekable(path.read_bytes()), streaming=True) as reader:
        member = next(iter(reader))
        assert member.size is None
        assert HashAlgorithm.CRC32 not in member.hashes


def test_gzip_reports_no_crc32_on_either_decoder(tmp_path: Path) -> None:
    """F1 (guardrail), narrowed to absence by PR 441: gzip reports no CRC at all.

    F1 said declared seekability must not leak into member metadata. PR 441's ruling
    then removed the gzip digest outright (a trailer CRC covers only the last member,
    and a read already verifies every member), so the assertion is absence on every
    path: listing and full read, with and without ``seekable_members``, on either
    decoder (the accelerator is pinned ON and OFF so the legs really differ).
    """
    from archivey.config import AcceleratorMode
    from archivey.types import HashAlgorithm

    path = _archive("single-file", "gz", tmp_path)
    modes = [AcceleratorMode.OFF]
    try:
        import rapidgzip  # noqa: F401

        modes.append(AcceleratorMode.ON)
    except ImportError:
        pass
    for mode in modes:
        config = ArchiveyConfig(use_rapidgzip=mode)
        for kwargs in ({}, {"seekable_members": True}):
            with open_archive(path, config=config, **kwargs) as reader:  # type: ignore[arg-type]
                member = reader.members()[0]
                reader.read(member)
                assert HashAlgorithm.CRC32 not in member.hashes


# ---------------------------------------------------------------------------
# F6 — index-topology table vs the directory backend
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("streaming", [False, True])
def test_directory_report_peek_returns_none(streaming: bool, tmp_path: Path) -> None:
    """F6 (fixed, spec side): the directory backend has no upfront index to peek at.

    `access-mode-and-cost` used to list "Leading (directory, ISO)" as offering a complete
    report in both modes, which the directory backend never did. The **spec** was the
    thing that was wrong: the filesystem walk is lazy, so before it there is nothing to
    peek at. The table now has a scan-based row.
    """
    from archivey.cost import ListingCost

    path = _archive("basic", "dir", tmp_path)
    with open_archive(path, streaming=streaming) as reader:
        assert reader.members_report_if_available() is None
        # The receipt the spec now agrees with.
        assert reader.cost.listing_cost is ListingCost.REQUIRES_SCANNING


@pytest.mark.parametrize("streaming", [False, True])
def test_rar_scan_at_open_offers_a_report_peek(streaming: bool, tmp_path: Path) -> None:
    """F6 (guardrail): the "Scan at open (RAR)" row. The peek follows the list held after
    open, not `listing_cost`: RAR scans, but inside `open_archive`."""
    from archivey.cost import ListingCost

    path = _archive("basic", "rar", tmp_path)
    with open_archive(path, streaming=streaming) as reader:
        assert reader.cost.listing_cost is ListingCost.REQUIRES_SCANNING
        report = reader.members_report_if_available()
        assert report is not None
        assert report.error is None
        assert len(report.members) > 0


@pytest.mark.parametrize("key", ["iso", "zip", "7z"])
def test_leading_and_trailing_index_backends_do_offer_a_report_peek(
    key: str, tmp_path: Path
) -> None:
    """F6 (guardrail): the backends the topology table covers correctly still do."""
    path = _archive("basic", key, tmp_path)
    with open_archive(path) as reader:
        report = reader.members_report_if_available()
        assert report is not None
        assert report.error is None
        assert len(report.members) > 0


def test_tar_has_no_report_peek_before_a_pass(tmp_path: Path) -> None:
    """F6 (guardrail): the no-index row of the topology table — format law, pinned."""
    path = _archive("basic", "tar", tmp_path)
    with open_archive(path) as reader:
        assert reader.members_report_if_available() is None


# ---------------------------------------------------------------------------
# F7 — an explicit wrong format= can succeed with an empty listing
# ---------------------------------------------------------------------------


def test_wrong_explicit_format_on_iso_yields_an_empty_listing(tmp_path: Path) -> None:
    """F7 (pin): ``format=TAR`` over an ISO opens and lists zero members.

    An ISO's first 32 KiB system area is zero-filled, which is byte-identical to a TAR
    end-of-archive marker, so the TAR reader sees a valid empty archive. It still opens
    — `format=` is an override — and the disagreement is now reported as data rather
    than nothing (see `test_wrong_explicit_format_does_not_silently_succeed`).

    The trailing-data half is pinned in
    `test_wrong_explicit_format_on_iso_reports_trailing_data`.
    """
    path = _archive("basic", "iso", tmp_path)
    with open_archive(path, format=ArchiveFormat.TAR) as reader:
        assert reader.format == ArchiveFormat.TAR
        assert reader.members() == []


def test_wrong_explicit_format_does_not_silently_succeed(tmp_path: Path) -> None:
    """F7 (fixed): the empty reader is still returned, but the disagreement is data.

    `format=` stays an override — wrong extensions are normal (`VISION.md`) and some
    callers use `format=` precisely to overrule them, so refusing here would take away
    the thing the argument is for. What was wrong was the *silence*: a clean empty
    listing under an asserted format that the bytes contradict.
    """
    from archivey.diagnostics import DiagnosticCode

    path = _archive("basic", "iso", tmp_path)
    with open_archive(path, format=ArchiveFormat.TAR) as reader:
        assert reader.members() == []
        counts = reader.diagnostics.counts
        assert counts[DiagnosticCode.EMPTY_ARCHIVE] == 1
        assert counts[DiagnosticCode.EXPLICIT_FORMAT_LISTED_EMPTY] == 1
        (record,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.EXPLICIT_FORMAT_LISTED_EMPTY
        ]
        assert record.context.detected_format == "ISO"  # type: ignore[union-attr]


def test_right_explicit_format_stays_silent(tmp_path: Path) -> None:
    """F7 (guardrail): the check must cost nothing and say nothing on a real archive."""
    from archivey.diagnostics import DiagnosticCode

    path = _archive("basic", "tar", tmp_path)
    with open_archive(path, format=ArchiveFormat.TAR) as reader:
        assert reader.members()
        assert DiagnosticCode.EMPTY_ARCHIVE not in reader.diagnostics.counts
        assert (
            DiagnosticCode.EXPLICIT_FORMAT_LISTED_EMPTY not in reader.diagnostics.counts
        )


def test_wrong_explicit_format_is_loud_for_most_formats(tmp_path: Path) -> None:
    """F7 (guardrail): the non-zero-prefixed formats do fail loudly — keep them loud."""
    path = _archive("basic", "zip", tmp_path)
    with (
        pytest.raises(ArchiveyError),
        open_archive(path, format=ArchiveFormat.TAR) as reader,
    ):
        reader.members()


@pytest.mark.parametrize(
    "raised",
    [FileNotFoundError("gone"), PermissionError("denied"), ValueError("odd")],
    ids=["missing", "unreadable", "valueerror"],
)
def test_empty_listing_check_never_decides_whether_listing_succeeded(
    raised: Exception, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F7 (guardrail): the re-detection probe is an advisory, not a failure mode.

    The explicit-`format=` arm is the only code that reopens the archive **by name**;
    everything else works off the handle opened at `open_archive`, which is why a path
    that vanishes mid-read is otherwise survivable. Reported by an automated review pass
    and confirmed: the probe caught only `ArchiveyError`, so a deleted path turned a
    *successful* empty listing into `FileNotFoundError` — a diagnostic deciding whether
    listing worked.

    The real-world trigger is `path.unlink()` (or a stale mount, or a caller that stages
    then deletes) between `open_archive` and the listing. This raises from the probe
    directly instead, for two reasons: it is portable — Windows refuses to unlink a file
    the reader still holds open, so the natural repro cannot run there — and it states
    the invariant rather than one route to it. Whatever the probe cannot answer, it
    degrades to "unconfirmed" and the listing still succeeds.
    """
    import tarfile

    from archivey.internal import detection

    path = tmp_path / "empty.tar"
    with tarfile.open(path, "w"):
        pass

    def _boom(*args: object, **kwargs: object) -> None:
        raise raised

    with open_archive(path, format=ArchiveFormat.TAR) as reader:
        monkeypatch.setattr(detection, "detect_format", _boom)
        assert reader.members() == []


# ---------------------------------------------------------------------------
# F2 — encoding= is honoured by some backends and silently discarded by others
# ---------------------------------------------------------------------------


def _names_with_and_without_encoding(path: Path) -> tuple[list[str], list[str]]:
    with open_archive(path) as reader:
        base = [m.name for m in reader.members()]
    # No backend applies ``encoding=`` to a valid UTF-8 name, ASCII included, so a
    # difference here needs a name whose bytes are not valid UTF-8.
    with open_archive(path, encoding="cp500") as reader:
        alt = [m.name for m in reader.members()]
    return base, alt


def _legacy_name_archive(key: str, tmp_path: Path) -> Path:
    """A one-member archive whose name ``café.txt`` is stored in a legacy code page,
    so its bytes are not valid UTF-8 and ``encoding=`` decides how it decodes."""
    import tarfile
    import zipfile

    path = tmp_path / f"legacy.{key}"
    if key == "zip":
        # zipfile writes a non-ASCII name as flagged UTF-8, so an ASCII name is
        # written and its bytes swapped for cp437 ones (0x82 = é), unflagged.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("cafX.txt", b"x")
        path.write_bytes(buf.getvalue().replace(b"cafX.txt", b"caf\x82.txt"))
    else:
        with tarfile.open(
            path, "w", format=tarfile.USTAR_FORMAT, encoding="latin-1"
        ) as tf:
            info = tarfile.TarInfo("café.txt")
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
    return path


@pytest.mark.parametrize("key", ["zip", "tar"])
def test_encoding_argument_is_applied(key: str, tmp_path: Path) -> None:
    """F2 (guardrail): the backends that consume ``encoding=`` still consume it, for a
    name whose bytes are not valid UTF-8 (a valid UTF-8 name, ASCII included, is
    UTF-8 whatever ``encoding=`` says)."""
    base, alt = _names_with_and_without_encoding(_legacy_name_archive(key, tmp_path))
    assert base != alt


@pytest.mark.parametrize("key", ["7z", "dir"])
def test_unusable_encoding_argument_is_recorded(key: str, tmp_path: Path) -> None:
    """F2 (fixed): the discard is queryable — but the entry point stays permissive.

    The review recommended refusing (the `#225`/P8 rule generalised). The maintainer
    chose the softer option, and O5 then supplied the principle behind it: `encoding=`
    is a **resource offered for use if needed**, not an assertion about this archive,
    and the batch caller who passes one configuration across heterogeneous input should
    not have it fail on the ISO in the middle.

    The names come out unchanged, but that alone cannot show the argument was
    discarded: no backend applies ``encoding=`` to a valid UTF-8 name, and these
    formats cannot portably hold one that is not (7z names are UTF-16). The
    diagnostic is what tells "discarded" from "applied to nothing".
    """
    from archivey.diagnostics import DiagnosticCode

    path = _archive("basic", key, tmp_path)
    with open_archive(path) as reader:
        base = [m.name for m in reader.members()]
    with open_archive(path, encoding="cp500") as reader:
        assert [m.name for m in reader.members()] == base
        assert reader.diagnostics.counts[DiagnosticCode.ENCODING_ARGUMENT_UNUSED] == 1


@pytest.mark.parametrize("key", ["zip", "tar", "iso"])
def test_usable_encoding_argument_is_not_recorded(key: str, tmp_path: Path) -> None:
    """F2 (guardrail): a backend that consumes `encoding=` must stay silent about it."""
    from archivey.diagnostics import DiagnosticCode

    path = _archive("basic", key, tmp_path)
    with open_archive(path, encoding="cp500") as reader:
        reader.members()
        assert DiagnosticCode.ENCODING_ARGUMENT_UNUSED not in reader.diagnostics.counts


# ---------------------------------------------------------------------------
# F8 — pipe support: loud and uniform (good), but not queryable (the finding)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["iso", "7z"])
def test_trailing_index_formats_refuse_a_pipe_loudly(key: str, tmp_path: Path) -> None:
    """F8 (guardrail): the refusal is one typed error with one message shape.

    This half of the seed turned out to be **fine**, and pinning it is what keeps it
    fine: a backend that started failing softly here would be a regression.
    """
    path = _archive("basic", key, tmp_path)
    data = path.read_bytes()
    with pytest.raises(StreamNotSeekableError):
        open_archive(_NonSeekable(data), streaming=True)


@pytest.mark.parametrize("key", ["tar", "tar.gz", "zip"])
def test_front_indexed_formats_accept_a_pipe(key: str, tmp_path: Path) -> None:
    """F8 (guardrail): the other side of the same rule."""
    path = _archive("basic", key, tmp_path)
    with open_archive(_NonSeekable(path.read_bytes()), streaming=True) as reader:
        assert sum(1 for _ in reader) > 0


# ---------------------------------------------------------------------------
# F11 — the two entry points disagree about what a directory is
# ---------------------------------------------------------------------------


def test_open_stream_missing_path_is_still_not_found(tmp_path: Path) -> None:
    """F11 (guardrail): the genuinely-absent case keeps its ``FileNotFoundError``.

    The fix below splits the old ``is_file()`` predicate; this pins the half that was
    always right, so the split cannot swallow it.
    """
    with pytest.raises(FileNotFoundError, match="Compressed stream not found"):
        open_stream(tmp_path / "nothing-here.gz")


def test_open_stream_directory_error_names_the_real_problem(tmp_path: Path) -> None:
    """F11 (fixed): the message must not claim the path is absent.

    Asserted as the *absence* of "not found" rather than the presence of "directory":
    the message interpolates the path, and a pytest tmp dir carries the test's own name,
    so a positive substring check would pass for the wrong reason.
    """
    d = tmp_path / "tree"
    d.mkdir()
    with pytest.raises(ArchiveyUsageError) as excinfo:
        open_stream(d)
    message = str(excinfo.value).replace(str(d), "<path>").lower()
    assert "not found" not in message


def test_open_archive_opens_the_directory_open_stream_rejects(tmp_path: Path) -> None:
    """F11 (guardrail): the asymmetry itself, pinned so a fix has to address both sides."""
    d = tmp_path / "tree"
    d.mkdir()
    (d / "a.txt").write_bytes(b"hello")
    with open_archive(d) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]


# ---------------------------------------------------------------------------
# The uniform surface that *is* uniform — pinned so it stays that way
# ---------------------------------------------------------------------------

_UNIFORM_KEYS = ["zip", "tar", "tar.gz", "iso", "7z", "dir", "gz"]


@pytest.mark.parametrize("key", _UNIFORM_KEYS)
def test_reader_surface_is_uniform_across_formats(key: str, tmp_path: Path) -> None:
    """The review's main negative result: these rows agree on every measured backend.

    The probe found no format that diverges on any of them. Pinning them here is the
    cheap half of the review — a future backend that gets one wrong fails a test rather
    than becoming a Gotchas bullet.
    """
    entry_id = "single-file" if key == "gz" else "basic"
    path = _archive(entry_id, key, tmp_path)

    with open_archive(path) as reader:
        with pytest.raises(TypeError):
            len(reader)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            _ = "some-name" in reader  # type: ignore[operator]
        assert reader.get("no-such-member") is None
        with pytest.raises(KeyError):
            reader.read("no-such-member")

        member = next(m for m in reader.members() if m.type.name == "FILE")
        stream = reader.open(member)
        try:
            with pytest.raises(ArchiveyUsageError):
                reader.open(member)
            with pytest.raises(io.UnsupportedOperation):
                stream.seek(0)
        finally:
            stream.close()

    with pytest.raises(ArchiveyUsageError):
        reader.format  # noqa: B018 - property access after close must raise
    with pytest.raises(ArchiveyUsageError):
        member in reader  # noqa: B015 - membership test after close must raise


@pytest.mark.parametrize("key", _UNIFORM_KEYS)
def test_streaming_mode_is_uniform_across_formats(key: str, tmp_path: Path) -> None:
    """Streaming enforcement agrees on every backend that can stream from a path."""
    entry_id = "single-file" if key == "gz" else "basic"
    path = _archive(entry_id, key, tmp_path)

    from archivey import ArchiveyUsageError

    with open_archive(path, streaming=True) as reader:
        for op in (
            lambda: reader.members(),
            lambda: reader.get("x"),
            lambda: reader.open("x"),
            lambda: reader.read("x"),
        ):
            with pytest.raises(ArchiveyUsageError):
                op()

        assert sum(1 for _ in reader) >= 0
        with pytest.raises(ArchiveyUsageError):
            for _ in reader:
                pass


# ---------------------------------------------------------------------------
# F3 — raw ValueError crosses open_archive for volume-sequence misuse
# (merged from the second review pass; verified independently here)
# ---------------------------------------------------------------------------


def test_empty_source_sequence_is_a_usage_error() -> None:
    """F3 (fixed): an empty sequence is caller misuse, so `ArchiveyUsageError`.

    `resolve_source` runs before any backend translator exists, so this had to be typed
    at the raise site rather than by a translator.
    """
    with pytest.raises(ArchiveyUsageError):
        open_archive([])


def test_non_seekable_volume_sequence_is_a_stream_error() -> None:
    """F3 (fixed): match the single-source spelling of the same refusal.

    The *single*-source version of this refusal is already `StreamNotSeekableError`
    (see the pipe guardrails above); a volume sequence is the same refusal.
    """
    with pytest.raises(StreamNotSeekableError):
        open_archive([_NonSeekable(b"x" * 100), _NonSeekable(b"y" * 100)])


# ---------------------------------------------------------------------------
# F4 — ZIP maps every ValueError to CorruptionError, including "already closed"
# ---------------------------------------------------------------------------


def _zip_bytes() -> bytes:
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hello")
    return buf.getvalue()


def test_zip_underlying_close_is_a_usage_error() -> None:
    """F4 (fixed): the archive bytes are fine — the handle is not.

    Distinct from the settled `#225` behaviour: a normal `reader.close()` followed by
    `open()` already raises `ArchiveyUsageError` (pinned by the uniform-surface test
    above). This path — the underlying handle closed while the reader still believes it
    is open — used to land in the ZIP translator's blanket `ValueError` arm and report
    `CorruptionError`, sending a caller hunting a bad file.
    """
    with open_archive(io.BytesIO(_zip_bytes())) as reader:
        member = next(m for m in reader.members() if m.type is _FILE)
        reader._fp.close()  # type: ignore[attr-defined]  # deliberate: simulate the fault
        with pytest.raises(ArchiveyUsageError):
            reader.open(member)


def test_zip_corrupt_member_offset_is_still_corruption(tmp_path: Path) -> None:
    """F4 (guardrail): the blanket `ValueError` arm still means damage for real damage.

    The closed-handle carve-out must not take the corrupt-local-header-offset case with
    it — that one really is a bad file, and `CorruptionError` is the right answer.
    """

    data = bytearray(_zip_bytes())
    # The central directory's local-header offset field, clobbered so the member's open
    # reads its local header from a nonsense position past the end of the file.
    cd_start = data.rindex(b"PK\x01\x02")
    data[cd_start + 42 : cd_start + 46] = (0xFFFFFFF0).to_bytes(4, "little")

    with open_archive(io.BytesIO(bytes(data))) as reader:
        member = next(m for m in reader.members() if m.type is _FILE)
        with raises_corruption_not_truncation():
            reader.open(member)


# ---------------------------------------------------------------------------
# F5 — single-file compressed_size is still Path-gated
# ---------------------------------------------------------------------------

_SINGLE_FILE_KEYS = ["gz", "bz2", "xz", "zst", "lz4", "lz", "zz", "br"]
# zlib and Brotli have no magic: the nameless stream reaches them only with every content
# probe on. Both shapes get the same config so only the shape differs.
_ALWAYS_PROBE = ArchiveyConfig(always_probe_content=True)


@pytest.mark.parametrize("key", _SINGLE_FILE_KEYS)
def test_single_file_compressed_size_is_not_path_gated(
    key: str, tmp_path: Path
) -> None:
    """F5 (fixed): source shape must not decide whether the field exists.

    This was the residual the `#225` Path/seekable sweep did not reach, and it held for
    **every** single-file codec, not just gzip: `_build_member` used `os.path.getsize`
    behind an `isinstance(..., Path)` check with no seekable-stream fallback, while the
    trailer/CRC probes beside it already handled both. Parametrized over all nine codecs
    because the bug was in the shared shell, not in any one codec.
    """
    path = _archive("single-file", key, tmp_path)
    with open_archive(path, config=_ALWAYS_PROBE) as reader:
        from_path = reader.members()[0].compressed_size
    with open_archive(io.BytesIO(path.read_bytes()), config=_ALWAYS_PROBE) as reader:
        from_stream = reader.members()[0].compressed_size

    assert from_path == from_stream == path.stat().st_size


def test_single_file_compressed_size_is_absent_for_a_pipe(tmp_path: Path) -> None:
    """F5 (guardrail): a non-seekable source still reports `None` — no forced scan.

    The fix widens the gate from "is a Path" to "is seekable", not to "read it and
    count", which would cost a whole pass at open on a pipe.
    """
    path = _archive("single-file", "gz", tmp_path)
    with open_archive(_NonSeekable(path.read_bytes()), streaming=True) as reader:
        assert next(iter(reader)).compressed_size is None


def test_container_formats_report_compressed_size_from_either_shape(
    tmp_path: Path,
) -> None:
    """F5 (guardrail): the container backends already do it right — keep them there."""
    path = _archive("basic", "zip", tmp_path)
    with open_archive(path) as reader:
        from_path = next(m for m in reader.members() if m.type is _FILE).compressed_size
    with open_archive(io.BytesIO(path.read_bytes())) as reader:
        from_stream = next(
            m for m in reader.members() if m.type is _FILE
        ).compressed_size
    assert from_path == from_stream and from_path is not None


# ---------------------------------------------------------------------------
# F9 — header encryption needs the password at open (format law)
# ---------------------------------------------------------------------------


def test_header_encrypted_7z_needs_the_password_at_open(tmp_path: Path) -> None:
    """F9 (guardrail): format law — the listing itself is ciphertext.

    Pinned because it bounds the `#225` laziness fix: *data* encryption stays lazy,
    *header* encryption cannot (finding F11).
    """
    from archivey import EncryptionError

    entry = _entry("encrypted-header")
    path = _archive("encrypted-header", "7z", tmp_path)

    with pytest.raises(EncryptionError):
        open_archive(path)
    with open_archive(path, password=entry.passwords[0]) as reader:
        assert len(reader.members()) > 0


def test_data_encrypted_members_still_list_without_a_password(tmp_path: Path) -> None:
    """F9 (guardrail): the other half — data encryption stays lazy, per `#225`."""
    entry = _entry("encrypted")
    key = next((k for k in ("zip", "7z") if k in entry.formats), None)
    if key is None:
        pytest.skip("no data-encrypted corpus entry in a measurable format")
    path = _archive("encrypted", key, tmp_path)

    with open_archive(path) as reader:  # no password at all
        assert len(reader.members()) > 0


# ---------------------------------------------------------------------------
# F10 — the bidi/RTL warning is ambient only
# ---------------------------------------------------------------------------


def test_bidi_name_warning_is_queryable_data(tmp_path: Path) -> None:
    """F10 (fixed): the RTL/bidi advisory is a diagnostic, not a bare `logger.warning`.

    `VISION.md`: "anything the library can only *warn* about should ideally also be
    queryable as data — a logging warning most applications never see is a surprise
    deferred, not avoided." This was the library's single ambient-only advisory, while
    its neighbour in the same helper (name normalization) already had a code.

    The context records *which* controls were found, because the override/isolate set
    (rejected during safe extraction) and the directional marks (legitimate in Arabic
    and Hebrew filenames) are not the same category.
    """
    import tarfile

    from archivey.diagnostics import DiagnosticCode

    name = "invoice\u202ecod.exe"
    path = tmp_path / "bidi.tar"
    with tarfile.open(path, "w") as tar:
        tar.addfile(tarfile.TarInfo(name), io.BytesIO(b""))

    with open_archive(path) as reader:
        assert [m.name for m in reader.members()] == [name]  # presented as stored
        summary = reader.diagnostics
        assert summary.counts[DiagnosticCode.MEMBER_NAME_BIDI_CONTROL] == 1
        (record,) = [
            d
            for d in summary.retained
            if d.code is DiagnosticCode.MEMBER_NAME_BIDI_CONTROL
        ]
        assert record.context.controls == "U+202E"  # type: ignore[union-attr]


@pytest.mark.parametrize("driver", ["members-twice", "extract_all"])
def test_bidi_diagnostic_is_emitted_once_per_presentation(
    driver: str, tmp_path: Path
) -> None:
    """F10 (guardrail): one member, one occurrence — however the list gets walked.

    The emission lives in `_register_member`, which runs when the base reader's one
    member walk first pulls a member, so neither a second listing call nor a backend
    that also normalizes the name can add a second.

    ``extract_all`` is the case that caught this out: it used to walk an upfront index
    twice, once for the extraction prep and once to materialize, building different
    ArchiveMember objects for the same members. One member with one deceptive name is
    one finding; counting it twice inflates the summary a caller queries, burns a second
    retention slot and fires their callback again.

    Deliberately a **ZIP**: only a backend with an upfront index answers
    ``members_report_if_available`` during extraction prep, which is the path that
    once walked twice.
    """
    import zipfile

    from archivey.diagnostics import DiagnosticCode

    path = tmp_path / "bidi.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a\u202eb.txt", b"x")

    with open_archive(path) as reader:
        if driver == "members-twice":
            reader.members()
            reader.members()
        else:
            reader.extract_all(tmp_path / "out")
        assert reader.diagnostics.counts[DiagnosticCode.MEMBER_NAME_BIDI_CONTROL] == 1


# ---------------------------------------------------------------------------
# F19 — the rewind diagnostic is silent for a degenerate seek index
# ---------------------------------------------------------------------------


def _single_block_xz(tmp_path: Path) -> Path:
    """A one-block .xz over incompressible data — what `lzma.compress` produces.

    `xz` without threading writes a single block too, so this is the common shape,
    not a contrived one.

    2 MB rather than the 1 MB the review used: the fix's threshold is
    `REWIND_REDECODE_WARN_BYTES` = 1 **MiB** (1 048 576), and 1 000 000 sits just under
    it, so the original payload would have measured the threshold rather than the
    blind spot.
    """
    import lzma
    import random

    path = tmp_path / "one_block.xz"
    path.write_bytes(lzma.compress(random.Random(7).randbytes(2_000_000)))
    return path


def test_full_rewind_emits_regardless_of_codec(tmp_path: Path) -> None:
    """F19 (fixed): the same work produces the same signal.

    A backward seek that throws away the whole decoded stream is the event the
    diagnostic exists for. Whether the codec *could* have carried a useful index is
    irrelevant when this particular file does not: a single-block xz has one seek point
    (the origin), so the rewind costs exactly what an index-less codec's does.

    The predicate used to be codec identity, decided once at open, and XZ returned
    ``None`` unconditionally because the *format* can carry a block index.
    """
    from archivey.diagnostics import DiagnosticCode

    path = _single_block_xz(tmp_path)
    with open_stream(path, seekable=True) as stream:
        stream.read()
        stream.seek(10)
        stream.read(4)
        assert DiagnosticCode.STREAM_REWIND_REDECOMPRESSES in dict(
            stream.diagnostics.counts
        )


def test_cheap_rewind_stays_silent(tmp_path: Path) -> None:
    """F19 (guardrail): the predicate is cost, so a *small* rewind must go quiet.

    The old codec-identity rule warned on any backward seek in an index-less stream,
    including a 1 KB one, which is noise. This is the other half of the same fix and the
    half a cost-based rule could regress by simply always warning.
    """
    import lzma

    from archivey.diagnostics import DiagnosticCode

    path = tmp_path / "small.lzma"
    path.write_bytes(lzma.compress(b"x" * 1000, format=lzma.FORMAT_ALONE))
    with open_stream(path, seekable=True) as stream:
        stream.read()
        stream.seek(0)
        stream.read(4)
        assert DiagnosticCode.STREAM_REWIND_REDECOMPRESSES not in dict(
            stream.diagnostics.counts
        )


def test_rewind_policy_escalates_on_every_qualifying_seek(tmp_path: Path) -> None:
    """F19 / O1: recorded once, escalated always.

    The tripwire is the diagnostic's real job — a `RAISE` policy so a batch job aborts
    instead of silently going quadratic — and a guard that disarms after firing once is
    not a guard. Deduplication is a presentation concern for the report; escalation is
    control flow for a caller who explicitly asked to be stopped.
    """
    from archivey import ArchiveyConfig, DiagnosticRaisedError
    from archivey.diagnostics import (
        DiagnosticCode,
        DiagnosticPolicy,
    )

    config = ArchiveyConfig(
        diagnostic_policy=DiagnosticPolicy(
            raise_on={DiagnosticCode.STREAM_REWIND_REDECOMPRESSES}
        )
    )
    path = _single_block_xz(tmp_path)
    with open_stream(path, seekable=True, config=config) as stream:
        stream.read()
        for _ in range(2):
            with pytest.raises(DiagnosticRaisedError):
                stream.seek(10)
            stream.read()
        # ...and the report still holds exactly one record, not one per seek.
        assert (
            stream.diagnostics.counts[DiagnosticCode.STREAM_REWIND_REDECOMPRESSES] == 1
        )


# ---------------------------------------------------------------------------
# F20 — a zero-filled file with a .tar extension opens as an empty archive
# ---------------------------------------------------------------------------


def test_content_detection_refuses_a_zero_filled_file(tmp_path: Path) -> None:
    """F20 (guardrail): magic-byte detection correctly declines to call zeros a TAR.

    This is the layer that behaves well, and it is pinned so a future detection change
    cannot quietly start accepting the shape the other two layers already accept.
    """
    from archivey import FormatDetectionError, detect_format

    path = tmp_path / "zeros.bin"
    path.write_bytes(b"\x00" * 32768)
    with pytest.raises(FormatDetectionError):
        detect_format(path)


def test_zero_filled_dot_tar_opens_empty_via_extension(tmp_path: Path) -> None:
    """F20 (pin): the *extension* path accepts what content detection refuses.

    32 KiB of zeros named ``z.tar`` opens as TAR with zero members, no error and no
    EOF diagnostic, because the two null trailer blocks really are present and nothing
    but zeros follows them.

    This is the realistic form of the wrong-format problem: a zero-truncated file with a
    plausible extension is exactly the shape `VISION.md`'s founding corpus is full of.
    The fix for an explicit ``format=`` does not reach this path, because there is no
    explicit format to disagree with — so this layer has its own code, keyed on the
    format having been chosen by the extension after every content signal declined.

    It still opens: a legitimately empty tar is byte-identical to this file, so no
    predicate over the bytes can refuse one without refusing the other (O8a).
    """
    from archivey.diagnostics import DiagnosticCode

    path = tmp_path / "z.tar"
    path.write_bytes(b"\x00" * 32768)
    with open_archive(path) as reader:
        assert reader.format == ArchiveFormat.TAR
        assert reader.members() == []
        assert dict(reader.diagnostics.counts) == {
            DiagnosticCode.EMPTY_ARCHIVE: 1,
            DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED: 1,
        }


def _one_member_tar() -> bytes:
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("a.txt")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"abc"))
    return buf.getvalue()


@pytest.mark.parametrize(
    ("tail", "tail_id"),
    [
        (b"JUNK" * 1024, "junk"),
        (b"\x00" * 4096 + b"X" + b"\x00" * 512, "buried-byte"),
        (_one_member_tar(), "concatenated"),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_trailing_data_is_reported(tail: bytes, tail_id: str, tmp_path: Path) -> None:
    """F20 (fixed): a non-zero byte past the trailer is reported, by default.

    The check used to look only for the second null trailer block, so 4 KiB of arbitrary
    appended bytes passed silently. It then ran only under ``strict_archive_eof``, which
    left ``DiagnosticPolicy.STRICT`` promising to raise on a code nothing emitted. Now
    the scan always runs, bounded, and the code follows the policy like any other.

    The concatenated case is deliberate: two tars really are two archives and the reader
    listed only the first.
    """
    from archivey import DiagnosticRaisedError
    from archivey.diagnostics import DiagnosticCode

    path = tmp_path / f"{tail_id}.tar"
    path.write_bytes(_one_member_tar() + tail)

    with open_archive(path, format=ArchiveFormat.TAR) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]
        assert dict(reader.diagnostics.counts) == {
            DiagnosticCode.ARCHIVE_TRAILING_DATA: 1
        }

    with (
        pytest.raises(DiagnosticRaisedError),
        open_archive(
            path,
            format=ArchiveFormat.TAR,
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
        ) as reader,
    ):
        reader.members()


def test_trailing_data_scan_is_bounded(tmp_path: Path) -> None:
    """The scan stops ``_MAX_TRAILING_SCAN`` bytes past the trailer, reporting nothing.

    It is an effort bound, not a ceiling: a byte beyond it goes unseen, which is the
    documented trade for not reading an arbitrarily long zero tail to EOF.
    """
    from archivey.internal.backends.tar_reader import _MAX_TRAILING_SCAN

    # Header, one data block and the two trailer blocks, without tarfile's record
    # padding, so the offsets below are measured from the end of the trailer.
    tar = _one_member_tar()[:2048]
    inside = tmp_path / "inside.tar"
    inside.write_bytes(tar + b"\x00" * (_MAX_TRAILING_SCAN - 1) + b"X")
    beyond = tmp_path / "beyond.tar"
    beyond.write_bytes(tar + b"\x00" * _MAX_TRAILING_SCAN + b"X")
    with open_archive(inside, format=ArchiveFormat.TAR) as reader:
        reader.members()
        assert reader.diagnostics.total_count == 1
    with open_archive(beyond, format=ArchiveFormat.TAR) as reader:
        reader.members()
        assert reader.diagnostics.total_count == 0


@pytest.mark.parametrize(
    ("damage", "expected"),
    [
        ("junk-inside-gzip", {"ARCHIVE_TRAILING_DATA": 1}),
        ("junk-after-gzip", {"ARCHIVE_TRAILING_DATA": 1}),
        ("gzip-footer-missing", {"DIGEST_UNVERIFIABLE": 1}),
    ],
)
def test_compressed_tail_that_will_not_decode_ends_the_scan_without_error(
    damage: str, expected: dict[str, int], tmp_path: Path
) -> None:
    """F20: on a ``.tar.gz``, a tail that fails to decode ends the scan without error.

    Bytes inside the gzip stream past the tar trailer are TAR's trailing data. Junk
    after the gzip stream is the codec's: the tail read reaches the stream's end, and
    the codec reports what follows it, once. A missing gzip footer makes the tail read
    fail as truncated; the tar itself was read whole, so the scan stops without an
    error, but the CRC-32 over it was never checked, and ``DIGEST_UNVERIFIABLE`` says
    so. Removing the ``except TruncatedError`` around the tail read makes that last
    case raise.
    """
    import gzip

    tar = _one_member_tar()
    data = {
        "junk-inside-gzip": gzip.compress(tar + b"JUNK" * 1024),
        "junk-after-gzip": gzip.compress(tar) + b"JUNKJUNK",
        "gzip-footer-missing": gzip.compress(tar)[:-4],
    }[damage]
    path = tmp_path / f"{damage}.tar.gz"
    path.write_bytes(data)

    with open_archive(path, format=ArchiveFormat.TAR_GZ) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]
        assert {
            code.name: count for code, count in reader.diagnostics.counts.items()
        } == expected


def test_zero_padding_after_the_trailer_still_passes(tmp_path: Path) -> None:
    """F20 (guardrail): the case the "nothing but zeros" rule exists to preserve.

    `tar` pads to 10 KiB records by default and other writers pad further, so "the file
    ends at the trailer" would reject what `tar(1)` itself produces.
    """
    path = tmp_path / "padded.tar"
    path.write_bytes(_one_member_tar() + b"\x00" * 4096)
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with open_archive(path, format=ArchiveFormat.TAR, config=config) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]
        assert dict(reader.diagnostics.counts) == {}


def test_wrong_explicit_format_on_iso_reports_trailing_data(tmp_path: Path) -> None:
    """F20: an ISO read as TAR reports trailing data — the review predicted otherwise.

    O8b listed "the ISO case still passes" as a deliberate consequence, on the grounds
    that its 32 KiB system area is zeros and therefore reads as a valid empty TAR with
    padding. Measured, that describes only the first 32768 bytes: the zeros stop exactly
    where the volume descriptors begin (``\\x01CD001``) and ~48 KiB of real data follows,
    so the file is not zeros to EOF.

    The outcome is the one a caller would want — someone who asserted `format=TAR` gets
    told the file continues past what was listed — but it is not what the review
    expected, so it is asserted here rather than left to be rediscovered.
    """
    from archivey.diagnostics import DiagnosticCode

    path = _archive("basic", "iso", tmp_path)
    data = path.read_bytes()
    first_nonzero = next(i for i, byte in enumerate(data) if byte)
    assert first_nonzero == 32768  # the system area ends; descriptors begin
    assert len(data) > first_nonzero  # ...and the file continues

    with open_archive(path, format=ArchiveFormat.TAR) as reader:
        assert reader.members() == []
        assert reader.diagnostics.counts[DiagnosticCode.ARCHIVE_TRAILING_DATA] == 1


def test_legitimately_empty_tar_stays_valid(tmp_path: Path) -> None:
    """F20 (guardrail): an empty TAR is legal, and any "zero members raises" rule breaks it.

    `tar cf empty.tar --files-from /dev/null` is a real thing and `tarfile` accepts it.
    Pinned so the cost of the strictest option in O8 stays visible.
    """
    import io
    import tarfile

    buf = io.BytesIO()
    tarfile.open(fileobj=buf, mode="w").close()
    path = tmp_path / "empty.tar"
    path.write_bytes(buf.getvalue())
    assert set(buf.getvalue()) == {0}  # all zeros — the whole reason no rule works
    with open_archive(path, format=ArchiveFormat.TAR) as reader:
        assert reader.members() == []


@pytest.mark.parametrize("blocks", [2, 5, 10, 20, 64, 128])
def test_every_block_aligned_zero_length_is_a_valid_empty_tar(
    blocks: int, tmp_path: Path
) -> None:
    """ADR 0015: no *length* rule works either, which is the third rejected fix.

    After "raise on zero members" and "raise when the file continues past the trailer"
    were both killed by an empty tar being all zeros, the surviving proposal was to
    accept only the canonical sizes — 1024 (Go `archive/tar`, hence the Docker/OCI empty
    layer) and 10240 (GNU tar default, Python `tarfile`) — and treat any other zero-filled
    length as suspect.

    GNU tar's `-b` blocking factor closes that door: each length below is exactly what
    `tar -b <blocks> -cf e.tar --files-from /dev/null` writes, and `tar -tvf` lists every
    one without error. The 64-block case is the punchline — 32768 zero bytes, *byte
    identical* to the junk file that prompted the finding.

    Constructed from bytes rather than by shelling out to `tar`, so the pin holds
    everywhere; the equivalence was verified against the real binary when ADR 0015 was
    written.
    """
    path = tmp_path / f"b{blocks}.tar"
    path.write_bytes(b"\x00" * (blocks * 512))
    with open_archive(path, format=ArchiveFormat.TAR) as reader:
        assert reader.members() == []


# ---------------------------------------------------------------------------
# O2a — a solid out-of-order open() deliberately says nothing
# ---------------------------------------------------------------------------


def test_solid_out_of_order_open_emits_nothing(tmp_path: Path) -> None:
    """O2a (guardrail): the silence is the decision, not an omission.

    Three separate reviews have proposed adding a warning here. The answer is no, and
    `access-mode-and-cost` now says so: `cost.access_cost == SOLID` is on the receipt at
    open, before the caller does anything — a *better* signal than the rewind case gets,
    and that one only emits because it has no open-time signal at all. Emitting per
    `open()` would also produce one occurrence per member on exactly the workload that
    provokes it.

    Pinned so a fourth review that adds one breaks a test instead of a decision.
    """
    from archivey.cost import AccessCost

    path = _archive("basic", "tar.gz", tmp_path)
    with open_archive(path) as reader:
        assert reader.cost.access_cost is AccessCost.SOLID  # the signal, at open
        members = [m for m in reader.members() if m.type is _FILE]
        for member in reversed(members):  # worst case: fully out of order
            reader.read(member)
        assert dict(reader.diagnostics.counts) == {}


# ---------------------------------------------------------------------------
# F16 follow-up — a stored digest must describe the member, in every format
# ---------------------------------------------------------------------------


def test_symlink_digests_describe_the_link_in_every_format(tmp_path: Path) -> None:
    """A `hashes` entry is a digest *of this member's content*, or it is absent.

    Found while auditing the RAR conformance sweep this review switched on (F16). The
    sweep's "links carry no digest" assertion was failing for RAR, and the first fix
    loosened it to "may or may not". The assertion was right: **RAR5 stores a symlink's
    target in a header field with no data stream**, so RARLAB writes ``crc32(b"") == 0``
    into the CRC field, and the reader was surfacing that. Every RAR5 symlink in
    existence therefore reported the same digest — one that neither describes the member
    (``size`` is the target's length, the digest covers zero bytes) nor distinguishes one
    link from another, in the field `VISION.md`'s "hashes without decompression" use case
    reads.

    So the rule is cross-format and this pins it: where a digest is present it equals the
    checksum of what the member actually holds; where the format stores nothing to
    checksum, the key is absent. Absence is the honest answer, not a zero.
    """
    import zlib

    entry_id, key_of_interest = "symlinks", "rar"
    expectations: dict[str, bool] = {  # format key -> does it store a link digest?
        "zip": True,  # target stored as member data
        "7z": True,  # target stored as member data
        "tar": False,  # target lives in the header; nothing to checksum
        key_of_interest: False,  # RAR5 redirect: header field, no data stream
    }
    for key, expects_digest in expectations.items():
        path = _archive(entry_id, key, tmp_path)
        with open_archive(path) as reader:
            links = [m for m in reader.members() if m.type is MemberType.SYMLINK]
            assert links, f"{key}: corpus entry should carry symlinks"
            for member in links:
                assert member.link_target is not None
                if not expects_digest:
                    assert not member.hashes, (
                        f"{key} {member.name!r} surfaced {dict(member.hashes)} for a "
                        f"link whose content is not stored as data"
                    )
                    continue
                digest = member.hashes.get(HashAlgorithm.CRC32)
                assert digest is not None, f"{key} {member.name!r} lost its digest"
                assert int.from_bytes(digest, "big") == zlib.crc32(
                    member.link_target.encode()
                ), f"{key} {member.name!r} digest is not the target's checksum"


def test_rar4_link_digests_survive_the_rar5_fix(tmp_path: Path) -> None:
    """The regression the RAR5 fix is most at risk of causing.

    RAR3/4 is the *opposite* of RAR5 here: it stores a symlink's target as the member's
    data, so ``compress_size`` is the target length and the CRC32 is a genuine digest of
    it — exactly what ZIP and 7z record. Keying the fix on the RAR5 *redirect* rather
    than on "is a link" is what keeps this working; a member-type check would have
    thrown away a meaningful value.
    """
    import zlib

    fixture = Path(__file__).parent / "fixtures" / "rar" / "symlinks_solid__rar4.rar"
    if not fixture.exists():  # pragma: no cover - fixture is committed
        pytest.skip("RAR4 symlink fixture missing")
    with open_archive(fixture) as reader:
        links = [m for m in reader.members() if m.type is MemberType.SYMLINK]
        assert links
        for member in links:
            assert member.link_target is not None
            digest = member.hashes.get(HashAlgorithm.CRC32)
            assert digest is not None, f"rar4 {member.name!r} lost its digest"
            assert int.from_bytes(digest, "big") == zlib.crc32(
                member.link_target.encode()
            )
