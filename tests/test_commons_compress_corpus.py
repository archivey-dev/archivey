"""Compare Archivey against Apache Commons Compress on Commons Compress's own test files.

Off by default. Point ``ARCHIVEY_COMMONS_COMPRESS_TEST_FILES`` at ``src/test/resources``
in a clone of https://github.com/apache/commons-compress::

    ARCHIVEY_COMMONS_COMPRESS_TEST_FILES=/path/to/commons-compress/src/test/resources \\
      uv run --no-sync pytest tests/test_commons_compress_corpus.py -q

Commons Compress (CC) is Java, so it is not run here. Its listing of every file was
recorded once with ``scripts/commons_compress/CcList.java`` and is pinned, with
Archivey's own result, in ``tests/fixtures/commons_compress/expected.json``. Each file
is read twice, from its path and as a non-seekable pipe with ``streaming=True``, and the
result must match the pin: the format, and every member's name, type, bytes read, CRC-32
and whether reading it raised, or the error class when the open fails. A pin records
only a count and a digest of the listing; a mismatch prints Archivey's full listing.
``scripts/gen_commons_compress_expected.py`` rewrites the pins, from a CC listing and a
run of this module's lister.

``test_every_divergence_from_commons_compress_is_triaged`` needs no clone and runs in the
normal suite: every file where Archivey and CC disagree must have a reason in
``_TRIAGE``, so a rewrite of the pins that brings a new divergence fails until someone
reads it.

The SquashFS plugin in ``packages/`` is registered when it is installed
(``uv pip install -e packages/archivey-squashfs``). The pins assume it, so without it
the comparison is skipped.

Triage (2026-10-28, CC master ``0c20ded``, 1.29.0-SNAPSHOT), in the report's groups:

* **MISSING FORMAT** CC reads LHA, dump, ARJ and Snappy, which Archivey does not
  implement. ZIP Implode and Shrink, once on this list, now read and match CC on all
  five of CC's archives (140 members).
* **POLICY** Archivey refuses, as the format's own tool does: a TAR header with a wrong
  checksum, bytes after a member's Deflate stream (DR-3), and two 7z headers 7-Zip
  calls Headers Error.
* **NAMES** CC's default name decoding: Archivey decodes valid UTF-8 names, keeps
  non-UTF-8 bytes as surrogate escapes, and names a nameless 7z member after the
  archive, as 7-Zip does.
* **NESTING** CC lists a JAR inside a gzip and a dump inside an LZ4; Archivey composes
  compressors only with TAR.
* **ARCHIVEY ONLY** PPMd 7z, split 7z, a UTF-8 cpio name, a ZIP behind a prefix, a tar
  CC reads only in lenient mode, Brotli, and a lone PAX header.
* **CC BUG** ``8.posix.tar.gz`` (master ignores a PAX ``size``). It and ``8.star.tar.gz``
  hold an 8 GiB member, so neither is pinned.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.types import ArchiveFormat, ContainerFormat
from tests.corpus_plugins import PLUGINS, installed_plugins

_ENV = "ARCHIVEY_COMMONS_COMPRESS_TEST_FILES"
EXPECTED_PATH = (
    Path(__file__).parent / "fixtures" / "commons_compress" / "expected.json"
)

# CC reads every file by its content, whatever its name, so Archivey runs every
# content probe too. CC's own tests use "foo" as the 7z password, and pass it only for
# 7z; given to other formats it only adds a warning.
CONFIG = ArchiveyConfig(always_probe_content=True)
PASSWORD = "foo"

# An 8 GiB member each: reading it takes minutes, so they have no pin.
SLOW = frozenset({"8.posix.tar.gz", "8.star.tar.gz"})


# Every file where Archivey's result from a path differs from CC's. A file both refuse
# without listing a member is agreement and needs no entry (see ``agrees_with_cc``).
_TRIAGE: dict[str, str] = {
    **dict.fromkeys(
        (
            "bla.lha",
            "test-amiga-l0-lh4.lha",
            "test-amiga-l2.lha",
            "test-macos-l0-lh5-rle.lha",
            "test-macos-l0-lh5.lha",
            "test-macos-l0-lh6.lha",
            "test-macos-l0-lh7.lha",
            "test-macos-l0.lha",
            "test-macos-l1.lha",
            "test-macos-l2.lha",
            "test-msdos-l0-lz4.lzs",
            "test-msdos-l0.lha",
            "test-msdos-l1.lha",
            "test-msdos-l2-attrib.lha",
            "test-msdos-l2.lha",
        ),
        "MISSING FORMAT: LHA",
    ),
    **dict.fromkeys(
        (
            "archive_with_trailer.dump",
            "bla.dump",
            "bla.z.dump",
            "dump/max-segment-length.dump",
            "synthetic/long-name/long-name-reversed.dump",
            "synthetic/long-name/long-name.dump",
            "org/apache/commons/compress/dump/looping_inodes-fail.dump",
        ),
        "MISSING FORMAT: dump",
    ),
    **dict.fromkeys(
        ("bla.arj", "bla.unix.arj", "synthetic/long-name/long-name.arj"),
        "MISSING FORMAT: ARJ",
    ),
    **dict.fromkeys(
        ("bla.tar.sz", "lorem-ipsum.txt.sz", "mixed.txt.sz"),
        "MISSING FORMAT: Snappy framed",
    ),
    "COMPRESS-356.tar": (
        "POLICY: header checksum is wrong; GNU tar also rejects the header"
    ),
    "archive_with_bytes_after_data.zip": (
        "POLICY: bytes after the Deflate stream inside a member (DR-3); 7-Zip "
        "also reports data after the payload"
    ),
    "COMPRESS-492.7z": (
        "POLICY: SUBSTREAMS_INFO before UNPACK_INFO; 7-Zip reports Headers Error, "
        "CC lists nothing without an error"
    ),
    "synthetic/long-name/long-name.7z": (
        "POLICY: a byte after the header's END; 7-Zip reports Headers Error"
    ),
    "COMPRESS-227.zip": (
        "POLICY: two directory entries share one local header; one forward pass "
        "(stream_members) yields its bytes once, then raises"
    ),
    **dict.fromkeys(
        (
            "COMPRESS-279-fail.tar",
            "COMPRESS-351.zip",
            "COMPRESS-529-fail.tar",
            "COMPRESS-544_truncated_in_content-fail.tar",
            "COMPRESS-544_truncated_in_padding-fail.tar",
            "COMPRESS-548.zip",
            "COMPRESS-647/test.zip",
            "bla-stored-dd-contradicts-actualsize.zip",
            "bla-stored-dd-nosig.zip",
            "bla-stored-dd-sizes-differ.zip",
            "bla-stored-dd.zip",
            "org/apache/commons/compress/fuzz/crash-f2efd9eaeb86cda597d07b5e3c3d81363633c2da",
            "org/apache/commons/compress/zip/ZipFile-method.zip",
            "org/apache/commons/compress/zip/decompressNextSymbol.bin",
        ),
        "BOTH FAIL: CC refuses the open; Archivey lists the members before the "
        "damage, then raises",
    ),
    "org/apache/commons/compress/zip/createBoundedInputStream.bin": (
        "BOTH FAIL: both fail to read the one member; CC types it OTHER"
    ),
    "COMPRESS-553-fail.tar": (
        "POLICY: a header that does not parse is CorruptionError; CC lists nothing "
        "and raises nothing"
    ),
    "utf8-7zip-test.zip": "NAMES: Archivey decodes the valid UTF-8 name",
    "COMPRESS-479.zip": "NAMES: Archivey decodes the valid UTF-8 name",
    "COMPRESS-114.tar": "NAMES: Archivey keeps non-UTF-8 bytes as surrogate escapes",
    "bla-nonames.7z": "NAMES: a nameless member is named after the archive, as 7-Zip does",
    "pack200/simple-E0.pack.gz": "NESTING: CC lists the JAR inside the gzip",
    "bla.dump.lz4": "NESTING: CC lists the dump inside the LZ4",
    "COMPRESS-320/PPMd.7z": "ARCHIVEY ONLY: CC has no PPMd",
    "COMPRESS-320/PPMd-solid.7z": "ARCHIVEY ONLY: CC has no PPMd",
    "bla-multi.7z.001": "ARCHIVEY ONLY: Archivey joins the split parts",
    "bla-multi.7z.002": "ARCHIVEY ONLY: Archivey joins the split parts",
    "COMPRESS-459.cpio": "ARCHIVEY ONLY: CC's US-ASCII default rejects the UTF-8 name",
    "COMPRESS-621.zip": "ARCHIVEY ONLY: a ZIP behind a prefix CC's detector misses",
    "org/apache/commons/compress/COMPRESS-707/COMPRESS-707-lenient.tar": (
        "ARCHIVEY ONLY: CC needs its lenient flag"
    ),
    "bla.tar.br": "ARCHIVEY ONLY: CC's detector has no Brotli probe",
    "brotli.testdata.compressed": "ARCHIVEY ONLY: CC's detector has no Brotli probe",
    "org/apache/commons/compress/tar/paxHeaders.bin": (
        "ARCHIVEY ONLY: a lone PAX header lists as empty, as GNU tar does"
    ),
}

# Every file whose pipe result differs from its path result, except a refusal with
# ``StreamNotSeekableError``: 7z needs to seek, and says so at open.
_PIPE_TRIAGE: dict[str, str] = {
    **dict.fromkeys(
        (
            "COMPRESS-554-fail.tar",
            "COMPRESS-569-fail.tar",
            "invalid-zip.zip",
            "synthetic/long-name/bin-big-endian.cpio",
            "synthetic/long-name/bin-little-endian.cpio",
            "COMPRESS-477/split_zip_created_by_winrar/split_zip_created_by_winrar.z02",
            "COMPRESS-477/split_zip_created_by_winrar/split_zip_created_by_winrar.zip",
            "COMPRESS-477/split_zip_created_by_zip/split_zip_created_by_zip.z02",
            "COMPRESS-477/split_zip_created_by_zip/split_zip_created_by_zip.zip",
            "COMPRESS-477/split_zip_created_by_zip/split_zip_created_by_zip_zip64.zip",
        ),
        "NO NAME: a damaged file the name points at from a path; from a pipe nothing matches",
    ),
    **dict.fromkeys(
        (
            "org/apache/commons/compress/COMPRESS-649/some-900kb-text.txt",
            "COMPRESS-477/split_zip_created_by_zip/split_zip_created_by_zip_zip64.z02",
            "test-macos-l0-lh6.lha",
        ),
        "BROTLI PROBE: accepted from a pipe, which has no length for the probe's completion check, then fails on read",
    ),
    **dict.fromkeys(
        (
            "COMPRESS-386",
            "COMPRESS-490/ArithmeticException.lz4",
            "COMPRESS-490/ArrayIndexOutOfBoundsException1.lz4",
            "COMPRESS-490/ArrayIndexOutOfBoundsException2.lz4",
            "org/apache/commons/compress/bzip2/hbCreateDecodeTables.bin",
        ),
        "WHOLE SOURCE: a damaged compressed stream refused at open from a path; from a pipe it opens and fails on read",
    ),
    **dict.fromkeys(
        (
            "COMPRESS-477/split_zip_created_by_winrar/split_zip_created_by_winrar.z01",
            "COMPRESS-477/split_zip_created_by_zip/split_zip_created_by_zip.z01",
            "COMPRESS-477/split_zip_created_by_zip/split_zip_created_by_zip_zip64.z01",
            "apache-maven-2.2.1.zip.001",
        ),
        "SPLIT ZIP: one piece; a path refuses it at the directory, a pipe lists members until the data runs out",
    ),
    **dict.fromkeys(
        (
            "COMPRESS-227.zip",
            "bla-stored-dd-contradicts-actualsize.zip",
            "bla-stored-dd-nosig.zip",
            "bla-stored-dd-sizes-differ.zip",
            "bla-stored-dd.zip",
            "org/apache/commons/compress/fuzz/crash-f2efd9eaeb86cda597d07b5e3c3d81363633c2da",
            "org/apache/commons/compress/zip/createBoundedInputStream.bin",
        ),
        "ONE PASS: a damaged ZIP read by its local headers, without the directory a path reads first, fails at a different point",
    ),
    "COMPRESS-621.zip": "PREFIX: a ZIP behind a prefix is found by its directory",
    "bla-multi.7z.002": "NO NAME: the second part of a split 7z, joined only by its name",
}


def _files_dir() -> Path | None:
    raw = os.environ.get(_ENV)
    if not raw:
        return None
    path = Path(raw).expanduser()
    return path if path.is_dir() else None


class _Pipe(io.RawIOBase):
    """A file that cannot seek, like a pipe."""

    def __init__(self, path: Path) -> None:
        super().__init__()
        self._file = path.open("rb")

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        return self._file.readinto(buffer)

    def close(self) -> None:
        self._file.close()
        super().close()


def normalize_name(name: str | None) -> str:
    if name is None:
        return "<none>"
    name = name.replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    return name.rstrip("/") or "."


def _format_label(fmt: ArchiveFormat) -> str:
    return f"{fmt.container.value}/{fmt.stream.value}"


def list_with_archivey(path: Path, *, pipe: bool) -> dict[str, Any]:
    """Archivey's reading of ``path``: format and members, or the error class.

    A member is ``[name, type, bytes read, CRC-32, whether reading it raised]``: the
    raise is a flag, not a class, so a listing compares with CC's Java one. A single
    compressed file (``RAW_STREAM``) has one member named ``<data>``, since its name is
    only derived from the file name.

    Name and type are taken when the pass ends, not when the member is yielded: a pipe
    pass over a ZIP learns them from the central directory and updates the members in
    place, and leaves out a local entry the directory does not list. Only a file's bytes are compared, since CC reads a symlink's target as its
    data and Archivey does not.
    """
    source: Any = io.BufferedReader(_Pipe(path)) if pipe else path
    seen: list[tuple[Any, list[Any]]] = []
    raw = False

    def rows() -> list[list[Any]]:
        return [
            [
                "<data>" if raw else normalize_name(member.name),
                member.type.name.lower(),
                *(data if member.is_file else [None, None, data[2]]),
            ]
            for member, data in seen
        ]

    try:
        with open_archive(
            source,
            password=PASSWORD if ".7z" in path.name else None,
            config=CONFIG,
            streaming=pipe,
        ) as archive:
            raw = archive.format.container is ContainerFormat.RAW_STREAM
            for member, stream in archive.stream_members():
                data: list[Any] = [None, None, None]
                # The type at yield time, on purpose: a member a pipe pass reads as a
                # file and the directory later calls a directory is read here, and
                # rows() then drops the bytes.
                if stream is not None and member.is_file:
                    crc, size = 0, 0
                    try:
                        while chunk := stream.read(1 << 16):
                            crc = zlib.crc32(chunk, crc)
                            size += len(chunk)
                        data[:2] = size, crc
                    except Exception:  # noqa: BLE001 — recorded, then compared
                        data[2] = True
                seen.append((member, data))
            # A pipe pass over a ZIP yields a local entry before it can know that the
            # directory does not list it, then drops it from the listing.
            report = archive.members_report_if_available()
            if report is not None:
                listed = {id(member) for member in report.members}
                seen[:] = [item for item in seen if id(item[0]) in listed]
            return {"format": _format_label(archive.format), "members": rows()}
    except Exception as exc:  # noqa: BLE001 — recorded, then compared
        return {"error": type(exc).__name__, "members": rows()}
    finally:
        if pipe:
            source.close()


def summarize(listing: dict[str, Any]) -> dict[str, Any]:
    """The pinned form of a listing: its format or error, member count and digest, and
    how many members raised when read."""
    if "error" in listing and not listing["members"]:
        return {"error": listing["error"]}
    rows = sorted(listing["members"], key=lambda row: json.dumps(row))
    digest = hashlib.sha256(json.dumps(rows).encode()).hexdigest()[:16]
    summary = {key: listing[key] for key in ("format", "error") if key in listing}
    summary.update(members=len(rows), digest=digest)
    if failed := sum(1 for row in rows if row[4]):
        summary["failed"] = failed
    return summary


def _fails(summary: dict[str, Any] | None) -> bool:
    return summary is None or "error" in summary or "failed" in summary


def agrees_with_cc(cc: dict[str, Any] | None, ours: dict[str, Any]) -> bool:
    """Whether Archivey's summary matches CC's.

    When either side listed members, the listings must match, member reads that
    raised included. When neither did, both refusing the file counts: CC's errors are
    Java's, so their classes are not compared.
    """
    if cc is not None and "digest" in cc and "digest" in ours:
        return (cc["members"], cc["digest"]) == (ours["members"], ours["digest"])
    if (cc is not None and "digest" in cc) or "digest" in ours:
        return False
    return _fails(cc) and _fails(ours)


def load_expected() -> dict[str, dict[str, Any]]:
    if not EXPECTED_PATH.exists():  # Only while the generator writes the first pins.
        return {}
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))["files"]


_ROOT = _files_dir()
_EXPECTED = load_expected()


def _params() -> Iterator[Any]:
    if _ROOT is None:  # Nothing to collect: 820 skips would only crowd the summary.
        return
    for name in sorted(_EXPECTED):
        for pipe in (False, True):
            mode = "pipe" if pipe else "path"
            yield pytest.param(name, pipe, id=f"{mode}:{name}")


@pytest.fixture(scope="module")
def _plugins() -> Iterator[frozenset[str]]:
    with installed_plugins() as installed:
        yield installed


@pytest.mark.skipif(
    _ROOT is None,
    reason=f"set {_ENV} to Commons Compress's src/test/resources to run this corpus",
)
@pytest.mark.parametrize(("name", "pipe"), list(_params()))
def test_archivey_matches_the_pinned_result(
    name: str, pipe: bool, _plugins: frozenset[str]
) -> None:
    assert _ROOT is not None
    entry = _EXPECTED[name]
    expected = entry.get("pipe", entry["path"]) if pipe else entry["path"]
    if missing := sorted({module for module, _ in PLUGINS} - _plugins):
        # A damaged ar file is a CorruptionError with the plugin and no format without.
        pytest.skip(f"the pins assume every plugin; not installed: {missing}")
    listing = list_with_archivey(_ROOT / name, pipe=pipe)
    assert summarize(listing) == expected, json.dumps(listing, indent=1)


@pytest.mark.skipif(_ROOT is None, reason=f"set {_ENV} to run")
def test_the_pins_cover_every_file() -> None:
    assert _ROOT is not None
    found = {p.relative_to(_ROOT).as_posix() for p in _ROOT.rglob("*") if p.is_file()}
    assert found - SLOW == set(_EXPECTED), (
        f"new: {sorted(found - SLOW - set(_EXPECTED))[:10]} "
        f"gone: {sorted(set(_EXPECTED) - found)[:10]}"
    )


def test_every_divergence_from_commons_compress_is_triaged() -> None:
    """Runs without a clone: the pins and the triage must agree."""
    untriaged = sorted(
        name
        for name, entry in _EXPECTED.items()
        if not agrees_with_cc(entry["cc"], entry["path"]) and name not in _TRIAGE
    )
    assert not untriaged, f"divergences with no reason in _TRIAGE: {untriaged}"
    stale = sorted(
        name
        for name in _TRIAGE
        if name not in _EXPECTED
        or agrees_with_cc(_EXPECTED[name]["cc"], _EXPECTED[name]["path"])
    )
    assert not stale, f"_TRIAGE entries that no longer diverge: {stale}"
    pipe_untriaged = sorted(
        name
        for name, entry in _EXPECTED.items()
        if "pipe" in entry
        and entry["pipe"] != {"error": "StreamNotSeekableError"}
        and name not in _PIPE_TRIAGE
    )
    assert not pipe_untriaged, f"pipe differences with no reason: {pipe_untriaged}"
    pipe_stale = sorted(
        name
        for name in _PIPE_TRIAGE
        if "pipe" not in _EXPECTED.get(name, {})
        or _EXPECTED[name]["pipe"] == {"error": "StreamNotSeekableError"}
    )
    assert not pipe_stale, f"_PIPE_TRIAGE entries with no pipe difference: {pipe_stale}"
