"""A solid pass decodes a RAR5 file copy's source once, however many copies follow.

``rar -oi`` stores every repeat of a file as a file copy (redirect type 5, no data of
its own). ``unrar p`` and ``unar`` emit nothing for one, so a solid pass used to serve
each copy from a named open of its source, which decodes the solid stream again from
the start up to the source: the cost was copies x solid prefix. The pass now keeps the
source's bytes as its pipe passes them (``rar_copy_sources.FileCopySources``).

The tests count decompressor spawns rather than time anything: one spawn for the whole
pass means the source was decoded once.
"""

from __future__ import annotations

import io
import random
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    DecoderLimits,
    ExtractionLimits,
    ExtractionProgress,
    SpoolLimits,
    open_archive,
)
from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    ResourceLimitError,
)
from archivey.internal.backends import rar_copy_sources, rar_reader
from tests.conftest import binary_refusal
from tests.extract_util import open_and_extract

_COPIES = 6
_COPY_NAMES = [f"d_copy{i}.txt" for i in range(_COPIES)]


def _text(seed: int, size: int) -> bytes:
    """Compressible but not trivial text. ``unar`` 1.10 fails to decode some solid RAR5
    archives of near-incompressible data, which would make its cases flaky."""
    rng = random.Random(seed)
    words = [b"alpha", b"beta", b"gamma", b"delta", b"omega", b"kappa", b"sigma"]
    out = bytearray()
    while len(out) < size:
        out += b" ".join(rng.choice(words) for _ in range(12)) + b"\n"
    return bytes(out[:size])


def _solid_with_copies(tmp_path: Path) -> tuple[Path, bytes]:
    """A solid RAR5 of ``a_prefix.txt``, ``b_source.txt``, ``c_other.txt``, then
    copies of ``b_source.txt``, in that order (``rar`` stores names sorted).

    Returns the archive and the source's bytes. Checked with ``rar lt``: every copy is
    a "File reference", so none of them has data in the solid stream.
    """
    src = tmp_path / "src"
    src.mkdir()
    payload = _text(1, 5000)
    (src / "a_prefix.txt").write_bytes(_text(2, 200_000))
    (src / "b_source.txt").write_bytes(payload)
    (src / "c_other.txt").write_bytes(b"other")
    for name in _COPY_NAMES:
        (src / name).write_bytes(payload)
    archive = tmp_path / "copies.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-ma5", "-s", "-oi:1000", str(archive)]
        + ["a_prefix.txt", "b_source.txt", "c_other.txt", *_COPY_NAMES],
        cwd=src,
        check=True,
        timeout=60,
    )
    listing = subprocess.run(
        ["rar", "lt", str(archive)], capture_output=True, check=True, timeout=60
    ).stdout
    assert listing.count(b"File reference") == _COPIES
    with open_archive(archive) as reader:
        members = reader.members()
    assert [m.name for m in members] == [
        "a_prefix.txt",
        "b_source.txt",
        "c_other.txt",
        *_COPY_NAMES,
    ]
    assert all(m.extra.get("is_file_copy") for m in members[3:])
    return archive, payload


def _config(
    decompressor: str, *, needs_decompressor: bool = True, **kwargs: object
) -> ArchiveyConfig:
    """Skip without ``rar``, and without a ``decompressor`` archivey will use.

    ``binary_refusal``, not ``shutil.which``: archivey refuses some binaries that are
    on PATH (a ``unar`` that fails its RAR5 check, a lookalike or pre-6.0 ``unrar``),
    and the rows would fail rather than skip. ``needs_decompressor=False`` is for a
    test that stops before any process starts; such a test asserts ``spawns == []``,
    which is what keeps the flag honest.
    """
    if shutil.which("rar") is None:
        pytest.skip("needs rar")
    if needs_decompressor and (refusal := binary_refusal(decompressor)) is not None:
        pytest.skip(f"needs a {decompressor} archivey will use: {refusal}")
    return ArchiveyConfig(rar_decompressor=decompressor, **kwargs)  # type: ignore[arg-type]


@pytest.fixture
def spawns(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Every ``unrar p`` / ``unar`` the reader starts, named opens included."""
    seen: list[str] = []
    real_unrar, real_unar = rar_reader.open_unrar_p, rar_reader.open_unar_stdout

    def unrar(*args: object, **kwargs: object) -> object:
        seen.append("unrar")
        return real_unrar(*args, **kwargs)  # type: ignore[arg-type]

    def unar(*args: object, **kwargs: object) -> object:
        seen.append("unar")
        return real_unar(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", unrar)
    monkeypatch.setattr(rar_reader, "open_unar_stdout", unar)
    yield seen


_DECOMPRESSORS = ["unrar", "unar"]


@pytest.mark.parametrize("decompressor", _DECOMPRESSORS)
def test_stream_members_serves_every_copy_from_one_decode(
    tmp_path: Path, decompressor: str, spawns: list[str]
) -> None:
    config = _config(decompressor)
    archive, payload = _solid_with_copies(tmp_path)
    seen: dict[str, bytes] = {}
    with open_archive(archive, config=config) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            seen[member.name] = stream.read()
    for name in ["b_source.txt", *_COPY_NAMES]:
        assert seen[name] == payload, name
    assert seen["c_other.txt"] == b"other"
    assert spawns == [decompressor]


@pytest.mark.parametrize("decompressor", _DECOMPRESSORS)
def test_copies_read_when_their_source_was_skipped(
    tmp_path: Path, decompressor: str, spawns: list[str]
) -> None:
    """The caller never reads the source: the pass moves through it for the first
    copy and keeps it on the way."""
    config = _config(decompressor)
    archive, payload = _solid_with_copies(tmp_path)
    with open_archive(archive, config=config) as reader:
        for member, stream in reader.stream_members():
            if member.name in _COPY_NAMES:
                assert stream is not None
                assert stream.read() == payload
    assert spawns == [decompressor]


@pytest.mark.parametrize("decompressor", _DECOMPRESSORS)
def test_extract_writes_every_copy_from_one_decode(
    tmp_path: Path, decompressor: str, spawns: list[str]
) -> None:
    config = _config(decompressor)
    archive, payload = _solid_with_copies(tmp_path)
    dest = tmp_path / "out"
    with open_archive(archive, config=config) as reader:
        reader.extract_all(dest)
    for name in ["b_source.txt", *_COPY_NAMES]:
        assert (dest / name).read_bytes() == payload, name
    assert spawns == [decompressor]


def test_extract_of_copies_only_still_decodes_once(
    tmp_path: Path, spawns: list[str]
) -> None:
    """A filter that drops the source: its copies are still served from the pass."""
    config = _config("unrar")
    archive, payload = _solid_with_copies(tmp_path)
    dest = tmp_path / "out"
    with open_archive(archive, config=config) as reader:
        reader.extract_all(dest, members=lambda m: m.name in _COPY_NAMES)
    assert not (dest / "b_source.txt").exists()
    for name in _COPY_NAMES:
        assert (dest / name).read_bytes() == payload, name
    assert spawns == ["unrar"]


def test_a_large_source_is_kept_in_the_spool(
    tmp_path: Path, spawns: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the in-memory allowance the source goes to the temporary file."""
    monkeypatch.setattr(rar_copy_sources, "_MEMORY_LIMIT", 0)
    config = _config("unrar")
    archive, payload = _solid_with_copies(tmp_path)
    # Through stream_members: under extract_all the copies are made from the written
    # file, so the source is never kept.
    with open_archive(archive, config=config) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            data = stream.read()
            if member.name in _COPY_NAMES:
                assert data == payload, member.name
        assert reader._resource_usage().spool_bytes == len(payload)
    assert spawns == ["unrar"]


def test_a_source_the_spool_limit_refuses_falls_back_to_named_opens(
    tmp_path: Path, spawns: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not kept: each copy opens its source by name, as before, and still reads right.
    The refused reservation does not refuse anything else."""
    monkeypatch.setattr(rar_copy_sources, "_MEMORY_LIMIT", 0)
    config = _config("unrar", spool_limits=SpoolLimits(max_bytes=0))
    archive, payload = _solid_with_copies(tmp_path)
    seen: dict[str, bytes] = {}
    with open_archive(archive, config=config) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            seen[member.name] = stream.read()
    for name in ["b_source.txt", *_COPY_NAMES]:
        assert seen[name] == payload, name
    assert spawns == ["unrar"] * (1 + _COPIES)


def test_extraction_limits_count_every_copy(tmp_path: Path) -> None:
    """A copy served from the kept source is written byte for byte, so the byte cap
    trips on the copies as it did when each one decoded its source again."""
    config = _config("unrar")
    archive, payload = _solid_with_copies(tmp_path)
    total_without_copies = 200_000 + len(payload) + len(b"other")
    limits = ExtractionLimits(
        max_extracted_bytes=total_without_copies + 2 * len(payload)
    )
    with pytest.raises(ResourceLimitError, match="max_extracted_bytes"):
        open_and_extract(archive, tmp_path / "out", config=config, limits=limits)


def test_a_kept_source_is_still_checked_against_its_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The kept bytes go through the source's CRC like the pipe's own bytes."""
    config = _config("unrar")
    archive, _payload = _solid_with_copies(tmp_path)
    real_open = rar_copy_sources.FileCopySources.open

    def tampered(self: rar_copy_sources.FileCopySources, *args: object) -> object:
        stream = real_open(self, *args)  # type: ignore[arg-type]
        assert stream is not None
        data = bytearray(stream.read())
        data[0] ^= 1
        return io.BytesIO(bytes(data))

    monkeypatch.setattr(rar_copy_sources.FileCopySources, "open", tampered)
    with open_archive(archive, config=config) as reader:
        for member, stream in reader.stream_members():
            if member.name == _COPY_NAMES[0]:
                assert stream is not None
                with pytest.raises(CorruptionError):
                    stream.read()
                break


def test_two_skipped_sources_in_the_spool_keep_their_own_bytes(
    tmp_path: Path, spawns: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both sources are pending in the temporary file at once when the caller skips
    them both; each must land in its own span."""
    monkeypatch.setattr(rar_copy_sources, "_MEMORY_LIMIT", 0)
    config = _config("unrar")
    src = tmp_path / "src"
    src.mkdir()
    first, second = _text(3, 4000), _text(4, 6000)
    (src / "a_prefix.txt").write_bytes(_text(2, 50_000))
    (src / "b_first.txt").write_bytes(first)
    (src / "b_second.txt").write_bytes(second)
    (src / "d_copy_b.txt").write_bytes(first)
    (src / "d_copy_a.txt").write_bytes(second)
    archive = tmp_path / "two.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-ma5", "-s", "-oi:1000", str(archive), "."],
        cwd=src,
        check=True,
        timeout=60,
    )
    seen: dict[str, bytes] = {}
    with open_archive(archive, config=config) as reader:
        assert reader.get("d_copy_b.txt").extra.get("is_file_copy")
        assert reader.get("d_copy_a.txt").extra.get("is_file_copy")
        for member, stream in reader.stream_members():
            if member.name.startswith("d_"):
                assert stream is not None
                seen[member.name] = stream.read()
    assert seen == {"d_copy_a.txt": second, "d_copy_b.txt": first}
    assert spawns == ["unrar"]


@pytest.mark.parametrize("decompressor", _DECOMPRESSORS)
def test_a_copy_read_checks_its_source_dictionary(
    tmp_path: Path, decompressor: str, spawns: list[str]
) -> None:
    """Serving a copy decodes through its source, so the source's dictionary is
    checked against ``max_decoder_memory`` before the pass's process starts, as the
    source's own read would be."""
    config = _config(
        decompressor,
        needs_decompressor=False,
        decoder_limits=DecoderLimits(max_decoder_memory=1),
    )
    archive, _ = _solid_with_copies(tmp_path)
    with open_archive(archive, config=config) as reader:
        for member, stream in reader.stream_members():
            if member.name == _COPY_NAMES[0]:
                assert stream is not None
                with pytest.raises(ResourceLimitError):
                    stream.read()
                break
    assert spawns == []


def test_each_pass_keeps_its_source_within_the_same_spool_limit(
    tmp_path: Path, spawns: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pass gives back the spool allowance its kept file held when it ends, so a
    second pass on the same reader can keep the source again."""
    monkeypatch.setattr(rar_copy_sources, "_MEMORY_LIMIT", 0)
    _config("unrar")  # skips without rar and unrar
    archive, payload = _solid_with_copies(tmp_path)
    # Room for the source once, not twice.
    config = _config(
        "unrar", spool_limits=SpoolLimits(max_bytes=len(payload) + len(payload) // 2)
    )
    with open_archive(archive, config=config) as reader:
        for _ in range(2):
            for member, stream in reader.stream_members():
                assert stream is not None
                data = stream.read()
                if member.name in _COPY_NAMES:
                    assert data == payload, member.name
        # The reader's private resource-usage record keeps the peak, not the sum.
        assert reader._resource_usage().spool_bytes == len(payload)
    assert spawns == ["unrar", "unrar"]


def test_a_kept_source_does_not_take_the_stream_copys_allowance(
    tmp_path: Path, spawns: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """From a stream source, ``unrar`` needs the archive copied to a temporary file.
    That copy is not optional; keeping a source is, so the source is kept only with
    what the copy left, and here it is declined and its copies decode it again."""
    monkeypatch.setattr(rar_copy_sources, "_MEMORY_LIMIT", 0)
    _config("unrar")  # skips without rar and unrar
    src = tmp_path / "src"
    src.mkdir()
    payload = _text(5, 200_000)
    copies = ["c_copy0.txt", "c_copy1.txt"]
    (src / "a_source.txt").write_bytes(payload)
    (src / "b_other.txt").write_bytes(b"other")
    for name in copies:
        (src / name).write_bytes(payload)
    archive = tmp_path / "first.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-ma5", "-s", "-oi:1000", str(archive)]
        + ["a_source.txt", "b_other.txt", *copies],
        cwd=src,
        check=True,
        timeout=60,
    )
    data = archive.read_bytes()
    # Either one fits on its own; the two together do not.
    limit = max(len(data), len(payload))
    config = _config("unrar", spool_limits=SpoolLimits(max_bytes=limit))
    seen: dict[str, bytes] = {}
    with open_archive(io.BytesIO(data), config=config) as reader:
        assert reader.members()[0].name == "a_source.txt"
        assert all(reader.get(name).extra.get("is_file_copy") for name in copies)
        for member, stream in reader.stream_members():
            assert stream is not None
            seen[member.name] = stream.read()
    assert seen == {
        "a_source.txt": payload,
        "b_other.txt": b"other",
        **dict.fromkeys(copies, payload),
    }
    assert spawns == ["unrar"] * (1 + len(copies))


# --- Extraction copies a copy from its written source; file_copy_streams=False ---


def _no_temp_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if the pass opens its temporary file for a kept source."""

    def refuse() -> object:
        raise AssertionError("a source was kept in the temporary file")

    monkeypatch.setattr(rar_copy_sources.tempfile, "TemporaryFile", refuse)


@pytest.mark.parametrize("decompressor", _DECOMPRESSORS)
@pytest.mark.parametrize("streaming", [False, True])
def test_extract_copies_each_copy_from_the_written_source(
    tmp_path: Path,
    decompressor: str,
    streaming: bool,
    spawns: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The source is written from the pass, so it is not kept: each copy is copied
    from the source's file. With no room in memory or in the spool, the copies still
    cost no second decode."""
    monkeypatch.setattr(rar_copy_sources, "_MEMORY_LIMIT", 0)
    _no_temp_file(monkeypatch)
    config = _config(decompressor, spool_limits=SpoolLimits(max_bytes=0))
    archive, payload = _solid_with_copies(tmp_path)
    dest = tmp_path / "out"
    with open_archive(archive, config=config, streaming=streaming) as reader:
        report = reader.extract_all(dest)
    assert all(r.status.value == "extracted" for r in report.results)
    for name in ["b_source.txt", *_COPY_NAMES]:
        assert (dest / name).read_bytes() == payload, name
    assert spawns == [decompressor]


def test_extract_copy_counts_toward_the_byte_cap_when_copied_from_disk(
    tmp_path: Path, spawns: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_temp_file(monkeypatch)
    config = _config("unrar")
    archive, payload = _solid_with_copies(tmp_path)
    total_without_copies = 200_000 + len(payload) + len(b"other")
    limits = ExtractionLimits(
        max_extracted_bytes=total_without_copies + 2 * len(payload)
    )
    with pytest.raises(ResourceLimitError, match="max_extracted_bytes"):
        open_and_extract(archive, tmp_path / "out", config=config, limits=limits)
    # The copies came from the source's file: a re-decode would spawn again.
    assert spawns == ["unrar"]


def test_extract_falls_back_when_the_written_source_was_replaced(
    tmp_path: Path, spawns: list[str]
) -> None:
    """Something else replaces the source's file before its copies are written. The
    copies do not take the new file's bytes: they read the source again from the
    archive."""
    config = _config("unrar")
    archive, payload = _solid_with_copies(tmp_path)
    dest = tmp_path / "out"
    swapped = []

    def swap(progress: ExtractionProgress) -> None:
        if progress.member.name == "c_other.txt" and not swapped:
            other = dest / "replacement"
            other.write_bytes(b"x" * len(payload))
            other.replace(dest / "b_source.txt")
            swapped.append(True)

    with open_archive(archive, config=config) as reader:
        reader.extract_all(dest, on_progress=swap)
    assert swapped
    for name in _COPY_NAMES:
        assert (dest / name).read_bytes() == payload, name
    # The pass did not keep the source, since it was writing it to disk; each copy
    # then decodes it again.
    assert spawns == ["unrar"] * (1 + _COPIES)


def test_extract_falls_back_when_a_later_member_took_the_source_path(
    tmp_path: Path,
) -> None:
    """A later member of the same size lands on the source's path (a filter renames
    it, REPLACE lets it in). The copies must not take that member's bytes.

    The later member is a copy source too (``e_copy_of_c.txt`` reads it), so its
    write records an identity as well; keyed by path alone, that identity would
    vouch for ``b_source.txt``'s copies."""
    config = _config("unrar")
    src = tmp_path / "src"
    src.mkdir()
    payload = _text(7, 4000)
    impostor = _text(8, 4000)
    copies = ["d_copy0.txt", "d_copy1.txt"]
    (src / "b_source.txt").write_bytes(payload)
    (src / "c_same.txt").write_bytes(impostor)
    for name in copies:
        (src / name).write_bytes(payload)
    (src / "e_copy_of_c.txt").write_bytes(impostor)
    archive = tmp_path / "clash.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-ma5", "-s", "-oi:1000", str(archive)]
        + ["b_source.txt", "c_same.txt", *copies, "e_copy_of_c.txt"],
        cwd=src,
        check=True,
        timeout=60,
    )
    dest = tmp_path / "out"
    with open_archive(archive, config=config) as reader:
        assert all(
            reader.get(name).extra.get("is_file_copy")
            for name in [*copies, "e_copy_of_c.txt"]
        )
        reader.extract_all(
            dest,
            filter=lambda m: (
                m.replace(name="b_source.txt") if m.name == "c_same.txt" else m
            ),
            overwrite="replace",
        )
    assert (dest / "b_source.txt").read_bytes() == impostor
    assert (dest / "e_copy_of_c.txt").read_bytes() == impostor
    for name in copies:
        assert (dest / name).read_bytes() == payload, name


def test_dry_run_still_serves_copies_from_one_decode(
    tmp_path: Path, spawns: list[str]
) -> None:
    """A dry run writes empty files, so it keeps the source and reads the copies from
    the pass."""
    config = _config("unrar")
    archive, _ = _solid_with_copies(tmp_path)
    dest = tmp_path / "out"
    with open_archive(archive, config=config) as reader:
        report = reader.extract_all(dest, dry_run=True)
    assert all(r.status.value == "extracted" for r in report.results)
    assert not dest.exists()
    assert spawns == ["unrar"]


@pytest.mark.parametrize("decompressor", _DECOMPRESSORS)
def test_stream_members_without_copy_streams_yields_none_for_copies(
    tmp_path: Path,
    decompressor: str,
    spawns: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``file_copy_streams=False``: each copy comes with no stream and the pass keeps
    nothing for it; the copy names its source, whose digest stands for it."""
    monkeypatch.setattr(rar_copy_sources, "_MEMORY_LIMIT", 0)
    _no_temp_file(monkeypatch)
    config = _config(decompressor)
    archive, payload = _solid_with_copies(tmp_path)
    seen: dict[str, bytes | None] = {}
    with open_archive(archive, config=config) as reader:
        for member, stream in reader.stream_members(file_copy_streams=False):
            seen[member.name] = None if stream is None else stream.read()
            if member.name in _COPY_NAMES:
                source = member.link_target_member
                assert source is not None and source.name == "b_source.txt"
                assert source.hashes
    assert seen["b_source.txt"] == payload
    assert all(seen[name] is None for name in _COPY_NAMES)
    assert spawns == [decompressor]


def test_stream_members_without_copy_streams_on_a_nonsolid_archive(
    tmp_path: Path,
) -> None:
    config = _config("unrar")
    src = tmp_path / "src"
    src.mkdir()
    payload = _text(6, 3000)
    (src / "a.txt").write_bytes(payload)
    (src / "b.txt").write_bytes(payload)
    archive = tmp_path / "nonsolid.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-ma5", "-oi:1000", str(archive), "a.txt", "b.txt"],
        cwd=src,
        check=True,
        timeout=60,
    )
    with open_archive(archive, config=config) as reader:
        assert reader.get("b.txt").extra.get("is_file_copy")
        pairs = [
            (m.name, None if s is None else s.read())
            for m, s in reader.stream_members(file_copy_streams=False)
        ]
        assert pairs == [("a.txt", payload), ("b.txt", None)]
        # The default still reads the copy's bytes.
        assert [
            s.read() if s is not None else None for _, s in reader.stream_members()
        ] == [payload, payload]


def test_file_copy_streams_takes_a_bool(tmp_path: Path) -> None:
    config = _config("unrar")
    archive, _ = _solid_with_copies(tmp_path)
    with (
        open_archive(archive, config=config) as reader,
        pytest.raises(ArchiveyUsageError, match="file_copy_streams"),
    ):
        reader.stream_members(file_copy_streams=0)  # type: ignore[arg-type]
