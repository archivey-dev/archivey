"""The verification contract, across formats (``verification-level-redesign`` task 5.1).

Design Decision 6 lists twelve rules. Each format's own tests check the cases that
are special to it; this module runs the rules that hold for every format over one
archive of each kind (ZIP, solid 7z, AES 7z, RAR, TAR, ``.tar.gz``, a single ``.xz``),
both random-access and streaming-only. Where a rule is about one format's checks, the
test that covers it lives with that format:

1. failures returned, not raised: ``test_verify_all.py`` (section 1) and here.
2. ``verified == verifiable`` after ``verify_all()``: here, and ``test_verify_all.py``.
3. a stream mirrors its member: here, and ``test_verify_all.py``.
4. ``stream.verify()`` on a proved member reads nothing: here, ``test_stream_verify.py``.
5. levels never fall, ``verified <= verifiable``: here, and ``test_verify_all.py``.
6. never over-report: ``test_verification_level.py``, ``test_codec_frame_checks.py``.
7. spanning checks raise the members they cover when they pass, not before:
   ``test_sevenzip_verification_levels.py``, ``test_tar_verification_levels.py``,
   ``test_sequential_verification_levels.py``, and the two-thread case here.
8. reading a level never reads: here.
9. ``stream.verify()`` leaves a seekable stream as it was: ``test_stream_verify.py``.
10. ``verify_all()`` leaves held streams alone; a second call re-reads only what is
    short: here, and ``test_verify_all.py``.
11. streaming ``members_report()`` after ``verify_all()`` reads nothing: here.
12. the "check everything" recipe: ``test_verify_all.py``
    (``test_a_missing_end_marker_is_a_diagnostic``) and here.
"""

from __future__ import annotations

import io
import lzma
import tarfile
import threading
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from archivey import Verification, open_archive
from archivey.types import ArchiveMember
from tests.conftest import requires, requires_binary
from tests.streams_util import CountingBytesIO
from tests.test_audit_sevenzip import _crc
from tests.test_sevenzip_verification_levels import _THREE, _copy_folder

CHECKSUM = Verification.CHECKSUM
LENGTH = Verification.LENGTH

_FILES = {
    "a.txt": b"alpha " * 3000,
    "b.bin": bytes(range(256)) * 300,
    "c.txt": b"gamma\n",
}
_RAR = Path(__file__).parent / "fixtures" / "rar"


def _zip() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _FILES.items():
            zf.writestr(name, data)
    return out.getvalue()


def _7z(password: str | None) -> bytes:
    import py7zr

    out = io.BytesIO()
    with py7zr.SevenZipFile(out, "w", password=password) as archive:
        for name, data in _FILES.items():
            archive.writestr(data, name)
    return out.getvalue()


def _tar(mode: str) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode=mode) as tar:
        for name, data in _FILES.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


# (build, the level every member can reach, the password, marks)
_Case = tuple[Callable[[], bytes], Verification, str | None]
_CASES: dict[str, _Case] = {
    "zip": (_zip, CHECKSUM, None),
    "7z-solid": (lambda: _7z(None), CHECKSUM, None),
    "7z-aes": (lambda: _7z("secret"), CHECKSUM, "secret"),
    "rar5-solid": (lambda: (_RAR / "basic_solid__.rar").read_bytes(), CHECKSUM, None),
    "tar": (lambda: _tar("w"), LENGTH, None),
    "tar.gz": (lambda: _tar("w:gz"), CHECKSUM, None),
    "xz": (lambda: lzma.compress(_FILES["a.txt"]), CHECKSUM, None),
}
_MARKS = {
    "7z-solid": [requires("py7zr")],
    "7z-aes": [requires("py7zr", "cryptography")],
    "rar5-solid": [requires_binary("unrar")],
}
_PARAMS = [pytest.param(name, marks=_MARKS.get(name, []), id=name) for name in _CASES]


def _open(name: str, *, streaming: bool, source: io.RawIOBase | None = None):
    build, _ceiling, password = _CASES[name]
    if source is None:
        source = CountingBytesIO(build())
    return open_archive(
        io.BufferedReader(source),
        streaming=streaming,
        password=password,
        concurrent_operations=not streaming,
    )


def _files(
    members: tuple[ArchiveMember, ...] | list[ArchiveMember],
) -> list[ArchiveMember]:
    return [member for member in members if member.is_file]


@pytest.fixture(params=[False, True], ids=["random-access", "streaming"])
def streaming(request: pytest.FixtureRequest) -> bool:
    return request.param


# --- 1, 2: verify_all() returns failures and leaves the rest at their ceiling ------


@pytest.mark.parametrize("name", _PARAMS)
def test_verify_all_brings_every_member_to_its_ceiling(
    name: str, streaming: bool
) -> None:
    ceiling = _CASES[name][1]
    with _open(name, streaming=streaming) as reader:
        assert reader.verify_all() == ()
        report = reader.members_report()
        assert report.error is None
        files = _files(report.members)
        assert files
        for member in files:
            assert (member.verified, member.verifiable) == (ceiling, ceiling), member


# --- 3, 5: a stream mirrors its member; levels only rise, under the ceiling -------


@pytest.mark.parametrize("name", _PARAMS)
def test_a_pass_mirrors_and_only_raises(name: str, streaming: bool) -> None:
    ceiling = _CASES[name][1]
    with _open(name, streaming=streaming) as reader:
        for member, stream in reader.stream_members():
            if stream is None:
                continue
            seen = [(stream.verified, stream.verifiable)]
            assert seen[0] == (member.verified, member.verifiable)
            while stream.read(4096):
                levels = (stream.verified, stream.verifiable)
                assert levels == (member.verified, member.verifiable)
                assert levels[0] <= levels[1]
                seen.append(levels)
            seen.append((stream.verified, stream.verifiable))
            assert seen == sorted(seen), seen
            # A spanning check (the .tar.gz trailer) may still be ahead.
            assert stream.verified >= LENGTH
            assert stream.verified <= ceiling


# --- 8: reading a level never reads ---------------------------------------------


@pytest.mark.parametrize("name", _PARAMS)
def test_reading_a_level_never_reads(name: str, streaming: bool) -> None:
    source = CountingBytesIO(_CASES[name][0]())
    with _open(name, streaming=streaming, source=source) as reader:
        for member, stream in reader.stream_members():
            before = (source.read_calls, source.tell())
            levels = [member.verified, member.verifiable]
            if stream is not None:
                # A lazy stream that has not opened its data answers from its member.
                levels += [stream.verified, stream.verifiable]
            assert (source.read_calls, source.tell()) == before, member.name
            assert levels


# --- 4, 10: after verify_all(), nothing proved is read again --------------------


@pytest.mark.parametrize("name", _PARAMS)
def test_a_proved_member_is_not_read_again(name: str) -> None:
    source = CountingBytesIO(_CASES[name][0]())
    with _open(name, streaming=False, source=source) as reader:
        files = _files(reader.members())
        first = max(files, key=lambda member: member.size or 0)
        held = reader.open(first)
        assert held.read(3) == _content(name, first)[:3]
        assert reader.verify_all() == ()
        before = source.bytes_read
        # 10: a second call has nothing left to prove.
        assert reader.verify_all() == ()
        # 4: nor has a stream of a proved member.
        for member in files:
            with reader.open(member) as stream:
                assert stream.verify() == stream.verifiable
        assert source.bytes_read == before
        # 10: the stream the caller held is where it was.
        assert held.tell() == 3
        assert held.read() == _content(name, first)[3:]
        held.close()


def _content(name: str, member: ArchiveMember) -> bytes:
    if name == "xz":
        return _FILES["a.txt"]
    if name == "rar5-solid":
        with _open(name, streaming=False) as reader:
            return reader.read(member.name)
    return _FILES[member.name]


# --- 11: a streaming reader's report after verify_all() reads nothing -----------


@pytest.mark.parametrize("name", _PARAMS)
def test_a_streaming_report_after_verify_all_reads_nothing(name: str) -> None:
    source = CountingBytesIO(_CASES[name][0]())
    with _open(name, streaming=True, source=source) as reader:
        assert reader.verify_all() == ()
        before = source.bytes_read
        report = reader.members_report()
        assert source.bytes_read == before
        assert report.error is None
        ceiling = _CASES[name][1]
        assert {m.verified for m in _files(report.members)} == {ceiling}


# --- 12: the "check everything" recipe -------------------------------------------


@pytest.mark.parametrize("name", _PARAMS)
def test_the_check_everything_recipe(name: str, streaming: bool) -> None:
    with _open(name, streaming=streaming) as reader:
        failures = reader.verify_all()
        report = reader.members_report()
        diagnostics = reader.diagnostics
    assert failures == ()
    assert report.error is None
    assert all(m.verified == m.verifiable for m in report.members)
    assert diagnostics.total_count == 0


# --- 7, 5: two threads raising one 7z folder's members ---------------------------


def test_two_threads_raising_one_folder_never_lower_a_level() -> None:
    # One stored folder with only a folder CRC: a read of "a" proves its length, a
    # read of "c" decodes the folder to its end and raises all three to CHECKSUM.
    data = _copy_folder(_THREE, folder_crc=_crc(b"".join(_THREE.values())))
    with open_archive(io.BytesIO(data), concurrent_operations=True) as reader:
        members = {m.name: m for m in reader.members()}
        stop = threading.Event()
        falls: list[str] = []

        def watch() -> Iterator[None]:
            last = {name: members[name].verified for name in members}
            while not stop.is_set():
                for name, member in members.items():
                    now = member.verified
                    if now < last[name] or now > member.verifiable:
                        falls.append(f"{name}: {last[name]!r} -> {now!r}")
                    last[name] = now
            yield

        watcher = threading.Thread(target=lambda: list(watch()))
        watcher.start()
        try:
            for _ in range(20):
                threads = [
                    threading.Thread(target=reader.read, args=(members[name],))
                    for name in ("a", "c", "b", "c")
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
        finally:
            stop.set()
            watcher.join()
    assert falls == []
    assert {(m.verified, m.verifiable) for m in members.values()} == {
        (CHECKSUM, CHECKSUM)
    }
