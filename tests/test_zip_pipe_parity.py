"""Every ZIP the tests have, read from a pipe and from a file: the same members after
the pass, the same data or failure for each, and the same files on disk.

The fixtures are the committed ``.zip`` files, the adversarial set
(``tests/create_adversarial.py``), and the corpus entries with encrypted members,
under the right password, no password, a wrong one, and a list. The corpus entries
without passwords are compared in ``test_zip_pipe.py`` and
``test_zip_pipe_extract.py``. Where the two reads may differ is in the native ZIP
reader's ``design.md`` (§"Failures found at the end of the pass"); ``_DIFFERS`` names
the fixtures that reach it.
"""

from __future__ import annotations

import contextlib
import io
import struct
import time
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

import archivey
from archivey.config import ArchiveyConfig, ListingLimits
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.zip_reader import ZipReader
from archivey.types import HashAlgorithm, OnError
from tests.create_adversarial import adversarial_archives
from tests.sample_archives import CORPUS, build_archive, skip_unless_runnable
from tests.streams_util import NonSeekableBytesIO
from tests.test_zip_pipe import _visible
from tests.test_zip_pipe_extract import _tree

_FIXTURES = Path(__file__).parent / "fixtures"

# Committed fixtures with encrypted members: the right password, and wrong ones that
# pass a member's check byte (tests/fixtures/zipcrypto/README.md).
_FIXTURE_PASSWORDS: dict[str, tuple[str, ...]] = {
    "zipcrypto/check_byte_collision.zip": ("secret", "wrong896", "wrong173"),
    "external/aes_ae1_pyzipper036.zip": ("secret",),
    "sevenzip/encrypted_link.zip": ("SECRET",),
}

_PasswordArg = str | list[str] | None

# Where the two reads may differ, by test id. ``"error"``: the same results but for
# the error type, the files on disk the same. A link the pass staged as a file keeps
# the error its data read gave (no password, ``EncryptionError``); from a file the
# link is refused for its missing target (``LinkTargetNotFoundError``).
_DIFFERS: dict[str, str] = {
    "sevenzip/encrypted_link.zip-no-password": "error",
    "sevenzip/encrypted_link.zip-wrong": "error",
}


def _password_cases(passwords: tuple[str, ...]) -> Iterator[tuple[str, _PasswordArg]]:
    """No password, each one alone, a wrong one, and all of them after a wrong one."""
    if not passwords:
        yield "", None
        return
    yield "no-password", None
    for password in passwords:
        yield f"password={password}", password
    yield "wrong", "not-the-password"
    yield "list", ["not-the-password", *passwords]


def _fixture_params() -> Iterator[pytest.ParameterSet]:
    for path in sorted(_FIXTURES.rglob("*.zip")):
        rel = path.relative_to(_FIXTURES).as_posix()
        for label, password in _password_cases(_FIXTURE_PASSWORDS.get(rel, ())):
            ident = f"{rel}-{label}" if label else rel
            yield pytest.param(
                path.read_bytes(), password, _DIFFERS.get(ident), id=ident
            )
    for entry, data in adversarial_archives():
        if entry.fmt == "zip":
            ident = f"adversarial-{entry.id}"
            yield pytest.param(data, None, _DIFFERS.get(ident), id=ident)


def _corpus_params() -> Iterator[pytest.ParameterSet]:
    for entry in CORPUS:
        if not entry.passwords:
            continue
        for key in ("zip", "zip-aes"):
            if key in entry.formats:
                for label, password in _password_cases(entry.passwords):
                    yield pytest.param(
                        entry, key, password, id=f"{entry.id}-{key}-{label}"
                    )


def _outcome(read: object) -> object:
    try:
        return read()  # type: ignore[operator]
    except ArchiveyError as exc:
        return type(exc)


def _from_file(data: bytes, password: _PasswordArg) -> object:
    try:
        with archivey.open_archive(io.BytesIO(data), password=password) as reader:
            members = reader.members()
            contents = {
                m._member_id: _outcome(lambda m=m: reader.read(m))  # type: ignore[misc]
                for m in members
                if m.is_file
            }
            return [_visible(m) for m in members], contents
    except ArchiveyError as exc:
        return type(exc)


def _from_pipe(data: bytes, password: _PasswordArg) -> object:
    try:
        with archivey.open_archive(
            NonSeekableBytesIO(data), streaming=True, password=password
        ) as reader:
            contents = {}
            for member, stream in reader.stream_members():
                if stream is not None:
                    contents[member._member_id] = _outcome(stream.read)  # type: ignore[misc]
            members = list(reader.members_report().members)
            # The pass reads every member as its local header says; one the
            # directory makes no file is not compared, as the file read reads none.
            contents = {
                m._member_id: contents.get(m._member_id)  # type: ignore[misc]
                for m in members
                if m.is_file
            }
            return [_visible(m) for m in members], contents
    except ArchiveyError as exc:
        return type(exc)


def _extracted(
    data: bytes, dest: Path, *, piped: bool, password: _PasswordArg
) -> object:
    source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
    try:
        with archivey.open_archive(
            source, streaming=piped, password=password
        ) as reader:
            report = reader.extract_all(dest, on_error=OnError.CONTINUE)
    except ArchiveyError as exc:
        return type(exc)
    return [
        (
            r.member.name,
            r.status,
            None if r.path is None else r.path.relative_to(dest).as_posix(),
            None if r.error is None else type(r.error),
        )
        for r in report.results
    ]


def _assert_same(
    data: bytes, password: _PasswordArg, tmp_path: Path, differs: str | None = None
) -> None:
    assert _from_pipe(data, password) == _from_file(data, password)
    started = time.time() - 1
    from_file = _extracted(data, tmp_path / "file", piped=False, password=password)
    from_pipe = _extracted(data, tmp_path / "pipe", piped=True, password=password)
    if differs == "error":
        assert isinstance(from_file, list) and isinstance(from_pipe, list)
        from_file = [result[:3] for result in from_file]
        from_pipe = [result[:3] for result in from_pipe]
    assert from_pipe == from_file
    for side in ("file", "pipe"):
        (tmp_path / side).mkdir(exist_ok=True)
    piped_tree = _tree(tmp_path / "pipe", since=started)
    tree = _tree(tmp_path / "file", since=started)
    assert piped_tree == tree


@pytest.mark.filterwarnings("ignore:Duplicate name")
@pytest.mark.parametrize(("data", "password", "differs"), list(_fixture_params()))
def test_a_fixture_reads_from_a_pipe_as_from_a_file(
    data: bytes, password: _PasswordArg, differs: str | None, tmp_path: Path
) -> None:
    _assert_same(data, password, tmp_path, differs)


@pytest.mark.parametrize(("entry", "key", "password"), list(_corpus_params()))
def test_an_encrypted_corpus_entry_reads_from_a_pipe_as_from_a_file(
    entry: object, key: str, password: _PasswordArg, tmp_path: Path
) -> None:
    skip_unless_runnable(entry, key)  # type: ignore[arg-type]
    path = tmp_path / "corpus.zip"
    build_archive(entry, key, path)  # type: ignore[arg-type]
    _assert_same(path.read_bytes(), password, tmp_path / "out")


def test_an_encrypted_directory_writes_nothing_either_way(tmp_path: Path) -> None:
    """PKWARE Strong Encryption over the directory masks the local headers too and
    encrypts every member's data with it: neither read gets a member out."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"data")
    raw = bytearray(buf.getvalue())
    flags = struct.unpack_from("<H", raw, 6)[0]
    struct.pack_into("<H", raw, 6, flags | 0x41)  # encrypted, Strong Encryption
    cd = raw.index(b"PK\x01\x02")
    body = raw.rindex(b"PK\x05\x06") - cd - 8
    raw[cd : cd + 8 + body] = b"PK\x06\x08" + struct.pack("<I", body) + b"\xa5" * body
    assert _from_file(bytes(raw), None) is UnsupportedFeatureError
    _assert_same(bytes(raw), None, tmp_path)
    assert not any((tmp_path / "pipe").iterdir())


# --- A ZIP with no end record ------------------------------------------------------


def _members_zip(*, pipe: bool) -> bytes:
    """Three deflated members, sized when written to a file, bit 3 when written to a
    sink that cannot seek."""
    out: io.BytesIO | NonSeekableSink = NonSeekableSink() if pipe else io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for n in range(3):
            zf.writestr(f"m{n}.txt", bytes(range(256)) * (n + 2))
    return bytes(out.getvalue())


class NonSeekableSink(io.RawIOBase):
    """Where stdlib ``zipfile`` writes bit-3 members: it cannot seek back."""

    def __init__(self) -> None:
        super().__init__()
        self._data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b: bytes | bytearray | memoryview) -> int:  # type: ignore[override]
        self._data += b
        return len(b)

    def getvalue(self) -> bytes:
        return bytes(self._data)


def _no_end_record_params() -> Iterator[pytest.ParameterSet]:
    """A ZIP cut at each kind of place before its end record, or with bytes that are
    no ZIP record where the directory or the end record should be.

    The second value says whether the two reads raise in the same words. A bit-3
    member followed by junk is the exception: the pass decodes it and looks for a
    descriptor with its CRC, while the file read, which decodes nothing, looks for
    one followed by a ZIP signature and reaches the end of the file; both fail it."""
    for kind, data in (
        ("sized", _members_zip(pipe=False)),
        ("bit3", _members_zip(pipe=True)),
    ):
        directory = data.index(b"PK\x01\x02")
        second = data.index(b"PK\x03\x04", 4)
        end = data.rindex(b"PK\x05\x06")
        shapes = {
            "before-the-directory": data[:directory],
            "inside-the-directory": data[: directory + 30],
            "before-the-end-record": data[:end],
            "inside-a-local-header": data[: second + 10],
            "inside-a-member": data[: second + 60],
            "junk-after-the-members": data[:directory] + b"junk" * 16,
            "junk-after-the-directory": data[:end] + b"junk" * 16,
            "junk-past-the-search-window": data[:directory] + b"\x01" * (1 << 20),
        }
        for shape, cut in shapes.items():
            alike = not (kind == "bit3" and shape.startswith("junk-after-the-members"))
            alike = alike and (kind, shape) != ("bit3", "junk-past-the-search-window")
            yield pytest.param(cut, alike, id=f"{kind}-{shape}")


def _report(data: bytes, *, piped: bool) -> object:
    source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
    try:
        with archivey.open_archive(source, streaming=piped) as reader:
            if piped:
                # The pass raises the walk's error; the report then holds it.
                with contextlib.suppress(ArchiveyError):
                    for _member, _stream in reader.stream_members():
                        pass
            report = reader.members_report()
    except ArchiveyError as exc:
        return type(exc), str(exc)
    error = report.error
    return (
        [_visible(m) for m in report.members],
        None if error is None else (type(error), str(error)),
    )


@pytest.mark.parametrize(("data", "alike"), list(_no_end_record_params()))
def test_a_zip_with_no_end_record_lists_from_a_file_as_from_a_pipe(
    data: bytes, alike: bool, tmp_path: Path
) -> None:
    """The members its local headers hold are listed, then the error the walk met is
    raised, in the same words; each member reads, and extracts, alike."""
    from_file = _report(data, piped=False)
    from_pipe = _report(data, piped=True)
    assert isinstance(from_file, tuple) and isinstance(from_file[0], list)
    assert from_file[0], "the members before the cut are listed"
    assert from_file[1] is not None
    if alike:
        assert from_file == from_pipe
    else:
        assert isinstance(from_pipe, tuple) and from_pipe[1] is not None
        assert from_file[0] == from_pipe[0]
        assert "member #2" in from_file[1][1] and "member #2" in from_pipe[1][1]
    if alike:
        _assert_same(data, None, tmp_path)
        return
    started = time.time() - 1
    for side in ("file", "pipe"):
        _extracted(data, tmp_path / side, piped=side == "pipe", password=None)
        (tmp_path / side).mkdir(exist_ok=True)
    tree = _tree(tmp_path / "file", since=started)
    assert tree and _tree(tmp_path / "pipe", since=started) == tree


def _lying_descriptor(field: str, value: int) -> bytes:
    """One bit-3 deflated member with 8-byte descriptor sizes, its descriptor's
    ``field`` (``"size"`` or ``"crc"``) set to ``value``, cut inside the directory."""
    out = NonSeekableSink()
    with (
        zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf,
        zf.open("a.txt", "w", force_zip64=True) as member,
    ):
        member.write(b"hello world")
    data = bytearray(out.getvalue())
    at = data.index(b"PK\x07\x08")
    if field == "size":
        struct.pack_into("<Q", data, at + 16, value)
    else:
        struct.pack_into("<L", data, at + 4, value)
    return bytes(data[: data.index(b"PK\x01\x02") + 30])


@pytest.mark.parametrize(
    ("field", "value"),
    [("size", 2**62), ("size", 2**64 - 1), ("crc", 0xDEADBEEF)],
)
def test_a_descriptor_a_file_read_cannot_check_is_listed_as_it_states(
    field: str, value: int, tmp_path: Path
) -> None:
    """The file read decodes nothing at open, so it lists a deflated bit-3 member's
    size and CRC32 as its descriptor states them, as it lists a directory's; the pipe
    read lists the size it measured, and the CRC32 only when its data matched it.
    Both refuse the data, raise the same cut, and write nothing."""
    data = _lying_descriptor(field, value)
    with archivey.open_archive(io.BytesIO(data)) as reader:
        report = reader.members_report()
        (member,) = report.members
        with pytest.raises(ArchiveyError):
            reader.read(member)
    with archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        with contextlib.suppress(ArchiveyError):
            for _member, stream in reader.stream_members():
                assert stream is not None
                with pytest.raises(ArchiveyError):
                    stream.read()
        piped = reader.members_report()
    (from_pipe,) = piped.members
    stated_crc = value if field == "crc" else zlib.crc32(b"hello world")
    assert (member.size, member.hashes) == (
        value if field == "size" else 11,
        {HashAlgorithm.CRC32: struct.pack(">I", stated_crc)},
    )
    # The pipe lists the CRC32 only where the data it decoded matched it.
    assert (from_pipe.size, from_pipe.hashes) == (
        11,
        {} if field == "crc" else member.hashes,
    )
    # Every other public field, and what each reports, is the same.
    file_view, pipe_view = _visible(member), _visible(from_pipe)
    for view in (file_view, pipe_view):
        del view["size"], view["hashes"]
    assert file_view == pipe_view
    assert type(piped.error) is type(report.error)
    assert str(piped.error) == str(report.error)
    started = time.time() - 1
    for side in ("file", "pipe"):
        extracted = _extracted(
            data, tmp_path / side, piped=side == "pipe", password=None
        )
        assert extracted is type(report.error)
        (tmp_path / side).mkdir(exist_ok=True)
        assert _tree(tmp_path / side, since=started) == {}


def _stream_past_the_limit(data: bytes, *, seekable: bool) -> object:
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=2))
    source = io.BytesIO(data) if seekable else NonSeekableBytesIO(data)
    yielded = []
    with archivey.open_archive(source, streaming=True, config=config) as reader:
        with pytest.raises(ResourceLimitError) as raised:
            for member, stream in reader.stream_members():
                assert stream is not None
                yielded.append((member.name, stream.read()))
        return yielded, str(raised.value), reader.members_report_if_available()


@pytest.mark.parametrize("pipe", [False, True], ids=["sized", "bit3"])
def test_a_zip_with_no_end_record_streams_to_the_limit_from_a_file_as_from_a_pipe(
    pipe: bool,
) -> None:
    """Streamed, a file read yields the members before ``max_members`` and then
    raises it, as a pipe read does; neither has a report it can give without a
    scan."""
    data = _members_zip(pipe=pipe)
    data = data[: data.index(b"PK\x01\x02")]
    from_file = _stream_past_the_limit(data, seekable=True)
    assert from_file == _stream_past_the_limit(data, seekable=False)
    yielded, _error, report = from_file
    assert [name for name, _ in yielded] == ["m0.txt", "m1.txt"]
    assert report is None


def test_a_whole_zip_streamed_past_its_directory_limit_has_no_report_to_peek() -> None:
    """The same rule one case over: a seekable ZIP whose directory crosses
    ``max_members`` yields the members before it, then raises, and the peek returns
    ``None`` as from a pipe. Its end record declares one entry, so the open does not
    refuse the count before the directory is walked."""
    data = bytearray(_members_zip(pipe=False))
    end = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, end + 8, 1, 1)
    data = bytes(data)
    for seekable in (True, False):
        yielded, _error, report = _stream_past_the_limit(data, seekable=seekable)
        assert [name for name, _ in yielded] == ["m0.txt", "m1.txt"]
        assert report is None


def _with_zip64_records(data: bytes, *, saturated: bool, damage: str) -> bytes:
    """``data`` with ZIP64 end records added before its classic one, damaged:
    ``"record"`` (no ZIP64 signature where the locator points), ``"locator"`` (the
    locator names an offset past itself), ``"into-members"`` (it names offset 5),
    ``"lone-locator"`` (no record, the locator naming offset 5, so the directory ends
    at the locator) or ``"no-directory"`` (``"record"`` with the classic record's
    directory size one byte longer than the directory, so no place it names starts at
    a central header and the classic record cannot stand in). ``saturated`` puts the
    ZIP64 sentinel in the count, size and offset fields of the classic record, so only
    the ZIP64 record holds them."""
    eocd = data.rindex(b"PK\x05\x06")
    _sig, _disk, _cd_disk, _here, entries, cd_size, cd_offset, _comment = struct.unpack(
        "<4s4H2LH", data[eocd : eocd + 22]
    )
    record = struct.pack(
        "<4sQ2H2L4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        entries,
        entries,
        cd_size,
        cd_offset,
    )
    record_at = {"locator": 1 << 40, "into-members": 5, "lone-locator": 5}.get(
        damage, eocd
    )
    if damage in ("record", "no-directory"):
        record = b"XXXX" + record[4:]
    if damage == "lone-locator":
        record = b""
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, record_at, 1)
    classic = bytearray(data[eocd:])
    if damage == "no-directory":
        struct.pack_into("<L", classic, 12, cd_size + 1)
    if saturated:
        struct.pack_into(
            "<4HLL", classic, 4, 0, 0, 0xFFFF, 0xFFFF, 2**32 - 1, 2**32 - 1
        )
    return data[:eocd] + record + locator + bytes(classic)


def _damaged_zip64_params() -> Iterator[pytest.ParameterSet]:
    for kind, pipe in (("sized", False), ("bit3", True)):
        for saturated in (False, True):
            for damage in (
                "record",
                "locator",
                "into-members",
                "lone-locator",
                "no-directory",
            ):
                if saturated and damage not in ("record", "locator"):
                    continue
                data = _with_zip64_records(
                    _members_zip(pipe=pipe), saturated=saturated, damage=damage
                )
                label = "saturated" if saturated else "classic"
                raised = "ZIP64" if saturated or damage == "no-directory" else None
                yield pytest.param(data, raised, id=f"{kind}-{label}-{damage}")
        # A directory that would start before the file: no ZIP64 records at all.
        data = bytearray(_members_zip(pipe=pipe))
        struct.pack_into("<I", data, data.rindex(b"PK\x05\x06") + 12, 0x7FFF_FFF0)
        yield pytest.param(
            bytes(data), "Bad offset for central directory", id=f"{kind}-bad-offset"
        )


def _diagnostic_codes(data: bytes, *, piped: bool) -> list[str]:
    source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
    with archivey.open_archive(source, streaming=piped) as reader:
        with contextlib.suppress(ArchiveyError):
            for _member, _stream in reader.stream_members():
                pass
        return [code.value for code in reader.members_report().diagnostics.counts]


@pytest.mark.parametrize(("data", "raised"), list(_damaged_zip64_params()))
def test_damaged_end_records_read_from_a_file_as_from_a_pipe(
    data: bytes, raised: str | None, tmp_path: Path
) -> None:
    """A classic end record that needs none of the ZIP64 fields stands in for them,
    reported; end records that cannot be used (a saturated classic record, no place
    that fits the directory's end, a directory before the file's start) list the
    members the local headers hold, then raise. Either way the two reads list, read and write alike."""
    from_file = _report(data, piped=False)
    assert from_file == _report(data, piped=True)
    assert isinstance(from_file, tuple)
    members, error = from_file
    assert isinstance(members, list) and len(members) == 3
    if raised is not None:
        assert error is not None and raised in error[1]
    else:
        assert error is None
        for piped in (False, True):
            assert "archive_eof_marker_missing" in _diagnostic_codes(data, piped=piped)
    _assert_same(data, None, tmp_path)


def _with_modes(*, pipe: bool) -> bytes:
    """Three members whose directory entries give mode 0o751, which their local
    headers cannot hold."""
    out: io.BytesIO | NonSeekableSink = NonSeekableSink() if pipe else io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for n in range(3):
            info = zipfile.ZipInfo(f"m{n}.txt", (2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o751 << 16
            info.create_system = 3
            zf.writestr(info, bytes(range(256)) * (n + 2))
    return bytes(out.getvalue())


def _damaged_directory_params() -> Iterator[pytest.ParameterSet]:
    for kind, pipe in (("sized", False), ("bit3", True)):
        data = bytearray(_with_modes(pipe=pipe))
        first = data.index(b"PK\x01\x02")
        second = data.index(b"PK\x01\x02", first + 4)
        data[second : second + 4] = b"XXXX"
        yield pytest.param(bytes(data), id=f"{kind}-second-entry")


@pytest.mark.parametrize("data", list(_damaged_directory_params()))
def test_a_damaged_directory_reads_from_a_file_as_from_a_pipe(
    data: bytes, tmp_path: Path
) -> None:
    """An unreadable directory entry: the entries before it list from the directory
    (its mode with them), the members after it from their local headers, then the
    damage is raised; both reads list, read and write alike."""
    from_file = _report(data, piped=False)
    assert from_file == _report(data, piped=True)
    assert isinstance(from_file, tuple)
    members, error = from_file
    assert isinstance(members, list)
    assert [m["name"] for m in members] == ["m0.txt", "m1.txt", "m2.txt"]
    assert [m["mode"] for m in members] == [0o751, None, None]
    assert error is not None and "Bad magic number for central directory" in error[1]
    started = time.time() - 1
    for side in ("file", "pipe"):
        _extracted(data, tmp_path / side, piped=side == "pipe", password=None)
    tree = _tree(tmp_path / "file", since=started)
    assert len(tree) == 3 and _tree(tmp_path / "pipe", since=started) == tree


def _length_overrun_params() -> Iterator[pytest.ParameterSet]:
    for kind, pipe in (("sized", False), ("bit3", True)):
        base = _with_modes(pipe=pipe)
        first = base.index(b"PK\x01\x02")
        second = base.index(b"PK\x01\x02", first + 4)
        for at, field in ((28, "name"), (30, "extra"), (32, "comment")):
            for grow, how in ((second - first, "swallows-next"), (0x8000, "past-end")):
                data = bytearray(base)
                old = struct.unpack_from("<H", data, first + at)[0]
                struct.pack_into("<H", data, first + at, old + grow)
                yield pytest.param(bytes(data), id=f"{kind}-{field}-{how}")
        data = bytearray(base)
        struct.pack_into("<H", data, first + 28, 4)  # "m0.txt" listed as "m0.t"
        yield pytest.param(bytes(data), id=f"{kind}-name-shortened")
        # The swallow leaves the count agreeing with the entries that remain.
        data = bytearray(base)
        struct.pack_into("<H", data, first + 28, 6 + second - first)
        eocd = data.rindex(b"PK\x05\x06")
        struct.pack_into("<HH", data, eocd + 8, 2, 2)
        yield pytest.param(bytes(data), id=f"{kind}-name-swallows-next-count-agrees")


@pytest.mark.parametrize("data", list(_length_overrun_params()))
def test_a_damaged_length_reads_from_a_file_as_from_a_pipe(
    data: bytes, tmp_path: Path
) -> None:
    """The first entry's name, extra or comment length grown past the next entry or
    past the directory's end, or its name length cut short. Cutting the field listed
    a member named ``m0.txtPK\\x01\\x02...`` (or ``m0.t``) and lost the entries
    it swallowed, with only a count warning. Both reads list every member under its
    local header's name, write the same files, then raise the damage."""
    from_file = _report(data, piped=False)
    assert from_file == _report(data, piped=True)
    assert isinstance(from_file, tuple)
    members, error = from_file
    assert isinstance(members, list)
    assert [m["name"] for m in members] == ["m0.txt", "m1.txt", "m2.txt"]
    assert error is not None and error[0] is CorruptionError
    started = time.time() - 1
    for side in ("file", "pipe"):
        _extracted(data, tmp_path / side, piped=side == "pipe", password=None)
    tree = _tree(tmp_path / "file", since=started)
    assert len(tree) == 3 and _tree(tmp_path / "pipe", since=started) == tree


@pytest.mark.parametrize("pipe", [False, True], ids=["sized", "bit3"])
def test_a_signature_in_a_name_with_a_wrong_count_reads_alike(pipe: bool) -> None:
    """A name holding ``PK\\x01\\x02`` in a directory whose end record declares one
    entry too many: nothing was swallowed, so both reads list both members with the
    directory's mode and report the count, as for any other wrong count."""
    out: io.BytesIO | NonSeekableSink = NonSeekableSink() if pipe else io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for name in ("a\x01PK\x01\x02.txt", "b.txt"):
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o640 << 16
            zf.writestr(info, b"data")
    data = bytearray(out.getvalue())
    eocd = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 8, 3, 3)
    from_file = _report(bytes(data), piped=False)
    assert from_file == _report(bytes(data), piped=True)
    assert isinstance(from_file, tuple) and isinstance(from_file[0], list)
    members, error = from_file
    assert error is None
    assert [m["name"] for m in members] == ["a\x01PK\x01\x02.txt", "b.txt"]
    assert [m["mode"] for m in members] == [0o640, 0o640]
    for piped in (False, True):
        source = NonSeekableBytesIO(bytes(data)) if piped else io.BytesIO(bytes(data))
        with archivey.open_archive(source, streaming=piped) as reader:
            for _ in reader.stream_members():
                pass
            assert list(reader.diagnostics.counts) == [
                DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING
            ]


@pytest.mark.parametrize("pipe", [False, True], ids=["sized", "bit3"])
def test_a_shortened_comment_is_not_listed_cut(pipe: bool) -> None:
    """Entry 0's comment length cut from 13 to 8: its name agrees with its local
    header, so it lists from the directory, but no central header follows it, so its
    lengths are wrong and its comment may be cut. Neither read lists ``hello-co``."""
    out: io.BytesIO | NonSeekableSink = NonSeekableSink() if pipe else io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for name in ("m0.txt", "m1.txt"):
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.comment = b"hello-comment"
            zf.writestr(info, b"data")
    data = bytearray(out.getvalue())
    first = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, first + 32, 8)
    for piped in (False, True):
        report = _report(bytes(data), piped=piped)
        assert isinstance(report, tuple) and isinstance(report[0], list)
        members, error = report
        assert [m["name"] for m in members] == ["m0.txt", "m1.txt"]
        assert [m["comment"] for m in members] == [None, None]
        assert error is not None and error[0] is CorruptionError


@pytest.mark.parametrize("pipe", [False, True], ids=["sized", "bit3"])
def test_many_signatures_in_names_and_comments_are_not_damage(pipe: bool) -> None:
    """An intact archive of 120 members, each with ``PK\\x01\\x02`` once in its
    name and twice in its comment. Each signature fails within a header, so following
    them never spends the walk's budget: every member lists with its mode and
    comment, with no error and no diagnostic, from a file and from a pipe."""
    out: io.BytesIO | NonSeekableSink = NonSeekableSink() if pipe else io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for i in range(120):
            info = zipfile.ZipInfo(f"m{i}PK\x01\x02.txt", (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o640 << 16
            info.comment = b"PK\x01\x02PK\x01\x02"
            zf.writestr(info, b"data")
    data = bytes(out.getvalue())
    for piped in (False, True):
        report = _report(data, piped=piped)
        assert isinstance(report, tuple) and isinstance(report[0], list)
        members, error = report
        assert error is None
        assert len(members) == 120
        assert {m["mode"] for m in members} == {0o640}
        assert {m["comment"] for m in members} == {"PK\x01\x02PK\x01\x02"}
        assert all(m["diagnostics"] == [] for m in members)
        source = NonSeekableBytesIO(data) if piped else io.BytesIO(data)
        with archivey.open_archive(source, streaming=piped) as reader:
            for _ in reader.stream_members():
                pass
            assert reader.diagnostics.total_count == 0


def _three_stored(names: tuple[str, ...]) -> bytearray:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o644 << 16
            zf.writestr(info, name.encode() * 3)
    return bytearray(buf.getvalue())


def _central_header(data: bytearray, nth: int) -> int:
    at = data.index(b"PK\x01\x02")
    for _ in range(nth):
        at = data.index(b"PK\x01\x02", at + 4)
    return at


@pytest.mark.filterwarnings("ignore:Duplicate name")
def test_a_name_on_both_sides_of_a_damaged_entry_is_current_alike() -> None:
    """The members kept from their local headers past the damage take part in which
    copy of a name is current, from a pipe as from a file."""
    data = _three_stored(("a.txt", "a.txt", "c.txt"))
    second = _central_header(data, 1)
    data[second : second + 4] = b"XXXX"
    from_file = _report(bytes(data), piped=False)
    assert from_file == _report(bytes(data), piped=True)
    assert isinstance(from_file, tuple) and isinstance(from_file[0], list)
    assert [m["is_current"] for m in from_file[0]] == [False, True, True]


def test_a_damaged_directory_is_the_error_over_an_entry_before_it_that_fails(
    tmp_path: Path,
) -> None:
    """An entry before the damage that points at no local header fails that member
    only; the listing's error is the damage, from a pipe as from a file. The file
    read also lists the local header that entry missed, so only the error and what
    is written are compared."""
    data = _three_stored(("a.txt", "b.txt", "c.txt"))
    struct.pack_into("<I", data, _central_header(data, 0) + 42, 0x1000)
    third = _central_header(data, 2)
    data[third : third + 4] = b"XXXX"
    reports = [_report(bytes(data), piped=piped) for piped in (False, True)]
    errors = [r[1] for r in reports if isinstance(r, tuple)]
    assert len(errors) == 2 and errors[0] == errors[1]
    assert errors[0] is not None and "Bad magic number" in errors[0][1]
    started = time.time() - 1
    for side in ("file", "pipe"):
        _extracted(bytes(data), tmp_path / side, piped=side == "pipe", password=None)
    tree = _tree(tmp_path / "file", since=started)
    assert len(tree) == 3 and _tree(tmp_path / "pipe", since=started) == tree


@pytest.mark.parametrize("cd_offset", [7, 0xFFFF_FFF0], ids=["by-7", "huge"])
def test_a_directory_offset_past_the_directory_writes_nothing_either_way(
    cd_offset: int, tmp_path: Path
) -> None:
    """A stored directory offset larger than where the directory is moves every
    member offset back by the difference, onto bytes that are no local header. That
    shift is what a stub sliced off the source gives (``start_offset``), so it is not
    refused: a file read lists the directory's entries and each read fails, the pass
    finds no local header for them and lists none. Neither writes anything, as
    Info-ZIP unzip and 7-Zip extract nothing."""
    data = bytearray(_members_zip(pipe=False))
    eocd = data.rindex(b"PK\x05\x06")
    (real,) = struct.unpack_from("<I", data, eocd + 16)
    struct.pack_into("<I", data, eocd + 16, min(real + cd_offset, 0xFFFF_FFF0))
    started = time.time() - 1
    results = [
        _extracted(bytes(data), tmp_path / side, piped=side == "pipe", password=None)
        for side in ("file", "pipe")
    ]
    assert results[0] == results[1]
    for side in ("file", "pipe"):
        (tmp_path / side).mkdir(exist_ok=True)
        assert _tree(tmp_path / side, since=started) == {}


def test_unusable_end_records_behind_trailing_bytes_walk_the_members_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Behind more trailing bytes than the search window, the tail search walks the
    local headers to find the end record; when that record cannot be used, the
    members listed are the ones that walk found, not a second walk's."""
    data = _with_zip64_records(
        _members_zip(pipe=False), saturated=True, damage="locator"
    ) + b"\x01" * (1 << 20)
    walks = []
    walk = ZipReader._walk_past_members

    def counted(self: ZipReader) -> int | None:
        walks.append(self)
        return walk(self)

    monkeypatch.setattr(ZipReader, "_walk_past_members", counted)
    from_file = _report(data, piped=False)
    assert len(walks) == 1
    assert isinstance(from_file, tuple) and isinstance(from_file[0], list)
    assert [m["name"] for m in from_file[0]] == ["m0.txt", "m1.txt", "m2.txt"]
    assert from_file[1] is not None and "ZIP64" in from_file[1][1]


def test_a_saturated_zip64_locator_naming_member_data_writes_the_same_files(
    tmp_path: Path,
) -> None:
    """A locator naming an offset among the members' data, with nothing in the
    classic record to stand in: a file read finds no ZIP64 record there that matches
    it; a pipe has passed those bytes and says so. Both list the members the local
    headers hold, raise, and write the same files."""
    data = _with_zip64_records(
        _members_zip(pipe=False), saturated=True, damage="into-members"
    )
    from_file = _report(data, piped=False)
    from_pipe = _report(data, piped=True)
    assert isinstance(from_file, tuple) and isinstance(from_pipe, tuple)
    assert from_file[0] == from_pipe[0] and len(from_file[0]) == 3
    assert from_file[1] is not None and from_pipe[1] is not None
    assert "Corrupt ZIP64 end of central directory record" in from_file[1][1]
    assert "inside the members' data" in from_pipe[1][1]
    started = time.time() - 1
    for side in ("file", "pipe"):
        _extracted(data, tmp_path / side, piped=side == "pipe", password=None)
        (tmp_path / side).mkdir(exist_ok=True)
    tree = _tree(tmp_path / "file", since=started)
    assert len(tree) == 3 and _tree(tmp_path / "pipe", since=started) == tree
