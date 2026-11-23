"""Passwords through the plugin API: ``NeedsPassword`` (``format-plugins``).

The test format, TOYX, is an indexed format whose members may be XORed with a key made
from the password. An archive is in one of two modes: ``checked`` stores a 4-byte check
of the password with each member (``CONFIRMED`` on a match), ``unchecked`` stores none,
so a password passes ``check`` ``INCONCLUSIVE`` and only the member's CRC-32
(``full_check``) settles it. A small sequential format, TOYW, yields its request from
its walk.
"""

from __future__ import annotations

import contextvars
import hashlib
import io
import struct
import threading
import time
import zlib
from collections.abc import Callable, Iterator
from contextlib import suppress
from pathlib import Path
from typing import Any, BinaryIO, ClassVar

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveMember,
    ArchiveyUsageError,
    CorruptionError,
    EncryptionError,
    HashAlgorithm,
    MemberType,
    PluginContainer,
    ResourceLimitError,
    StreamFormat,
    Verification,
    open_archive,
)
from archivey.config import ArchiveyConfig, DecoderLimits, PasswordRequest
from archivey.diagnostics import DiagnosticCode
from archivey.formats import (
    ForwardStream,
    IndexedFormatHandler,
    IndexedReader,
    Magic,
    MemberData,
    MemberDigest,
    MemberRecord,
    MemberSpan,
    NeedsPassword,
    PasswordConfirmVerdict,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
    SequentialFormatHandler,
    SequentialReader,
    register_format,
)
from archivey.internal.format_adapter import registration_scope
from archivey.internal.password import is_unverified_data_error

CONFIRMED = PasswordConfirmVerdict.CONFIRMED
INCONCLUSIVE = PasswordConfirmVerdict.INCONCLUSIVE
REJECTED = PasswordConfirmVerdict.REJECTED

_MAGIC = b"TOYXARC1"


class ToyContainer(PluginContainer):
    TOYX = "toyx"
    TOYW = "toyw"


TOYX = ArchiveFormat(ToyContainer.TOYX, StreamFormat.UNCOMPRESSED)
TOYW = ArchiveFormat(ToyContainer.TOYW, StreamFormat.UNCOMPRESSED)


def _key(password: bytes) -> bytes:
    return hashlib.sha256(b"key" + password).digest()


def _tag(password: bytes) -> bytes:
    return hashlib.sha256(b"check" + password).digest()[:4]


def _xor(data: bytes, key: bytes, start: int = 0) -> bytes:
    return bytes(b ^ key[(start + i) % len(key)] for i, b in enumerate(data))


def build_toyx(
    entries: list[tuple[str, bytes, bytes | None]], *, checked: bool = True
) -> bytes:
    """``entries`` are ``(name, data, password)``; ``None`` stores the data plain."""
    index = bytearray(_MAGIC + bytes([0 if checked else 1]))
    index += struct.pack("<I", len(entries))
    index_len = len(index) + sum(
        2 + len(n.encode()) + 1 + 4 + 4 + 4 + 8 for n, _, _ in entries
    )
    blobs = bytearray()
    for name, data, password in entries:
        raw = name.encode()
        stored = data if password is None else _xor(data, _key(password))
        tag = b"\0" * 4 if password is None or not checked else _tag(password)
        index += struct.pack("<H", len(raw)) + raw
        index += struct.pack(
            "<BII4sQ",
            password is not None,
            len(data),
            zlib.crc32(data),
            tag,
            index_len + len(blobs),
        )
        blobs += stored
    return bytes(index + blobs)


class _XorStream(io.RawIOBase):
    def __init__(self, inner: BinaryIO, key: bytes) -> None:
        self._inner = inner
        self._key = key
        self._pos = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        data = self._inner.read(len(buffer))
        out = _xor(data, self._key, self._pos)
        self._pos += len(out)
        buffer[: len(out)] = out
        return len(out)


class _Locator:
    def __init__(self, offset: int, size: int, crc: int, tag: bytes) -> None:
        self.offset = offset
        self.size = size
        self.crc = crc
        self.tag = tag


class Calls:
    """What the plugin's callbacks were asked, for the tests."""

    def __init__(self) -> None:
        self.check: list[bytes] = []
        self.full_check: list[bytes] = []


class ToyXReader(IndexedReader[_Locator]):
    use_full_check: ClassVar[bool] = True
    # Every password is rejected while this is set: a saved winner that no longer
    # unlocks the unit.
    reject_all: ClassVar[bool] = False
    rounds: ClassVar[int] = 0
    calls: ClassVar[Calls] = Calls()
    listing_unlocked: ClassVar[PasswordConfirmVerdict | None] = None
    archive_encrypted: ClassVar[bool] = False
    # What ``then`` says of the data's own checks (``MemberData.checked``).
    then_checked: ClassVar[bool] = False

    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._source = source
        self._context = context
        head = source.read_exact(0, 13)
        self._checked = head[8] == 0
        (self._count,) = struct.unpack_from("<I", head, 9)

    def iter_members(self) -> Iterator[MemberRecord[_Locator]]:
        pos = 13
        for _ in range(self._count):
            (name_len,) = struct.unpack("<H", self._source.read_exact(pos, 2))
            name = self._source.read_exact(pos + 2, name_len).decode()
            pos += 2 + name_len
            encrypted, size, crc, tag, offset = struct.unpack(
                "<BII4sQ", self._source.read_exact(pos, 21)
            )
            pos += 21
            member = ArchiveMember(
                type=MemberType.FILE,
                name=name,
                size=size,
                hashes={HashAlgorithm.CRC32: crc.to_bytes(4)},
                is_encrypted=bool(encrypted),
            )
            yield MemberRecord(
                member,
                _Locator(offset, size, crc, tag)
                if encrypted
                else _Locator(offset, size, crc, b""),
                unlocked=self.listing_unlocked if encrypted else None,
            )

    def _check(self, locator: _Locator) -> Callable[[bytes], Any]:
        def check(password: bytes) -> tuple[bytes | None, PasswordConfirmVerdict]:
            self.calls.check.append(password)
            if self.rounds:
                self._context.charge_key_derivation(self.rounds)
            if self.reject_all:
                return None, REJECTED
            if not self._checked:
                return _key(password), INCONCLUSIVE
            if _tag(password) != locator.tag:
                return None, REJECTED
            return _key(password), CONFIRMED

        return check

    def _full_check(self, locator: _Locator) -> Callable[[bytes], Any]:
        def full_check(password: bytes) -> tuple[bytes | None, PasswordConfirmVerdict]:
            self.calls.full_check.append(password)
            key = _key(password)
            data = _xor(self._source.read_exact(locator.offset, locator.size), key)
            if zlib.crc32(data) != locator.crc:
                return None, REJECTED
            return key, CONFIRMED if len(data) >= 4 else INCONCLUSIVE

        return full_check

    def open_member(
        self, member: ArchiveMember, locator: _Locator
    ) -> MemberData | NeedsPassword[bytes, MemberData]:
        view = self._source.view(locator.offset, locator.size)
        if not member.is_encrypted:
            return MemberData(view)

        def then(key: bytes, verdict: PasswordConfirmVerdict) -> MemberData:
            return MemberData(
                _XorStream(self._source.view(locator.offset, locator.size), key),
                unlocked=verdict,
                checked=self.then_checked,
            )

        view.close()
        return NeedsPassword(
            member.name,
            self._check(locator),
            full_check=self._full_check(locator) if self.use_full_check else None,
            member=member,
            then=then,
        )

    def archive_info(self) -> ReaderArchiveInfo:
        return ReaderArchiveInfo(is_encrypted=self.archive_encrypted)


class ToyXHandler(IndexedFormatHandler):
    format = TOYX
    extensions = (".toyx",)
    magic = (Magic(0, _MAGIC),)
    supports_password = True

    def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
        return ToyXReader(source, context)


@pytest.fixture
def toyx() -> Iterator[type[ToyXReader]]:
    with registration_scope():
        register_format(ToyXHandler)
        ToyXReader.calls = Calls()
        yield ToyXReader
    ToyXReader.use_full_check = True
    ToyXReader.reject_all = False
    ToyXReader.rounds = 0
    ToyXReader.listing_unlocked = None
    ToyXReader.archive_encrypted = False
    ToyXReader.then_checked = False


def _write(tmp_path: Path, data: bytes, name: str = "t.toyx") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


_SECRET = b"secret data, long enough to check"


def _one(tmp_path: Path, *, checked: bool = True, data: bytes = _SECRET) -> Path:
    return _write(tmp_path, build_toyx([("a.txt", data, b"right")], checked=checked))


# --- outcomes ---------------------------------------------------------------------


def test_right_password_reads_and_verifies(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    with open_archive(_one(tmp_path), password="right") as reader:
        member = reader.get("a.txt")
        assert member.is_encrypted
        assert member.verified is Verification.NONE
        with reader.open(member) as stream:
            assert stream.read() == _SECRET
        assert member.verified is Verification.CHECKSUM


def test_no_password_says_required(toyx: type[ToyXReader], tmp_path: Path) -> None:
    with (
        open_archive(_one(tmp_path)) as reader,
        pytest.raises(EncryptionError, match="a.txt is encrypted: pass password="),
    ):
        reader.read("a.txt")


def test_provider_none_first_says_required(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    with (
        open_archive(_one(tmp_path), password=lambda request: None) as reader,
        pytest.raises(EncryptionError, match="is encrypted: pass password="),
    ):
        reader.read("a.txt")


def test_every_password_rejected(toyx: type[ToyXReader], tmp_path: Path) -> None:
    with (
        open_archive(_one(tmp_path), password=["x", "y"]) as reader,
        pytest.raises(EncryptionError, match="Wrong password for a.txt"),
    ):
        reader.read("a.txt")
    assert toyx.calls.check == [b"x", b"y"]


def test_confirmed_wins_at_once_and_is_promoted(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    path = _write(
        tmp_path,
        build_toyx([("a.txt", _SECRET, b"right"), ("b.txt", b"more data", b"right")]),
    )
    with open_archive(path, password=["wrong", "right", "later"]) as reader:
        assert reader.read("a.txt") == _SECRET
        assert toyx.calls.check == [b"wrong", b"right"]
        toyx.calls.check.clear()
        assert reader.read("b.txt") == b"more data"
        # The password that worked is tried first for the next member.
        assert toyx.calls.check == [b"right"]


def test_several_inconclusive_settled_by_full_check(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    with (
        open_archive(_one(tmp_path, checked=False), password=["a", "right"]) as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.read() == _SECRET
    assert toyx.calls.check == [b"a", b"right"]
    assert toyx.calls.full_check == [b"a", b"right"]


def test_lone_inconclusive_wins_without_full_check(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    with open_archive(_one(tmp_path, checked=False), password="right") as reader:
        assert reader.read("a.txt") == _SECRET
    assert toyx.calls.full_check == []


def test_inconclusive_wrong_password_reads_as_password_or_damage(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    with (
        open_archive(_one(tmp_path, checked=False), password="wrong") as reader,
        pytest.raises(EncryptionError) as raised,
    ):
        reader.read("a.txt")
    assert is_unverified_data_error(raised.value)


def test_no_full_check_first_inconclusive_wins(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    toyx.use_full_check = False
    with open_archive(_one(tmp_path, checked=False), password=["right", "b"]) as reader:
        assert reader.read("a.txt") == _SECRET
    assert toyx.calls.check == [b"right", b"b"]


def test_inconclusive_stream_closed_early_reports(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    with open_archive(_one(tmp_path, checked=False), password="right") as reader:
        with reader.open("a.txt") as stream:
            stream.read(3)
        codes = [d.code for d in reader.diagnostics.retained]
    assert DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED in codes


def test_mixed_exhaustion_reports_password_or_damage(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    answers = iter([b"x", b"y", None])

    def provider(request: PasswordRequest) -> bytes | None:
        return next(answers)

    with (
        open_archive(_one(tmp_path, checked=False), password=provider) as reader,
        pytest.raises(EncryptionError) as raised,
    ):
        reader.read("a.txt")
    assert is_unverified_data_error(raised.value)
    assert toyx.calls.full_check == [b"x", b"y"]


# --- the provider -------------------------------------------------------------------


def test_provider_wrong_then_right(toyx: type[ToyXReader], tmp_path: Path) -> None:
    asked: list[PasswordRequest] = []
    answers = iter([b"wrong", b"right"])

    def provider(request: PasswordRequest) -> bytes | None:
        asked.append(request)
        return next(answers)

    with open_archive(_one(tmp_path), password=provider) as reader:
        assert reader.read("a.txt") == _SECRET
    assert [r.attempt for r in asked] == [1, 2]
    assert asked[0].member is not None
    assert asked[0].member.name == "a.txt"


def test_provider_reentry_raises(toyx: type[ToyXReader], tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        build_toyx([("a.txt", _SECRET, b"right"), ("b.txt", b"other", b"other")]),
    )
    box: list[Any] = []

    def provider(request: PasswordRequest) -> bytes | None:
        box[0].read("b.txt")
        return b"right"

    with open_archive(path, password=provider, concurrent_operations=True) as reader:
        box.append(reader)
        reader.members()
        with pytest.raises(ArchiveyUsageError, match="re-entered"):
            reader.read("a.txt")


def test_copied_context_close_from_provider_raises(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    outcome: list[BaseException | None] = []
    box: list[Any] = []

    def close_in_helper() -> None:
        try:
            box[0].close()
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - recorded for the test
            outcome.append(exc)

    def provider(request: PasswordRequest) -> bytes | None:
        context = contextvars.copy_context()
        helper = threading.Thread(target=context.run, args=(close_in_helper,))
        helper.start()
        helper.join(timeout=10)
        assert not helper.is_alive(), "close() waited on the provider"
        return b"right"

    with open_archive(
        _one(tmp_path), password=provider, concurrent_operations=True
    ) as reader:
        box.append(reader)
        reader.members()
        assert reader.read("a.txt") == _SECRET
    assert len(outcome) == 1
    assert isinstance(outcome[0], ArchiveyUsageError)


def test_copied_context_close_raises_while_another_close_drains(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    """An independent close() is already waiting for the worker whose provider is
    running: a close() from that provider's copied context must raise, not wait
    behind that closer, which waits for the provider."""
    outcome: list[BaseException | None] = []
    box: list[Any] = []
    closers: list[threading.Thread] = []

    def close_in_helper() -> None:
        try:
            box[0].close()
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - recorded for the test
            outcome.append(exc)

    def provider(request: PasswordRequest) -> bytes | None:
        # A fresh context: on a build whose threads inherit the starter's context
        # (free-threaded 3.14+), this thread would otherwise count as the
        # provider's copied context, and its close() would raise.
        closer = threading.Thread(
            target=contextvars.Context().run, args=(box[0].close,)
        )
        closers.append(closer)
        closer.start()
        state = box[0]._state
        deadline = time.monotonic() + 10
        while not state._closing and time.monotonic() < deadline:
            time.sleep(0.001)
        assert state._closing, "the independent close() never started draining"
        context = contextvars.copy_context()
        helper = threading.Thread(target=context.run, args=(close_in_helper,))
        helper.start()
        helper.join(timeout=10)
        assert not helper.is_alive(), "close() waited behind the draining closer"
        return b"right"

    with open_archive(
        _one(tmp_path), password=provider, concurrent_operations=True
    ) as reader:
        box.append(reader)
        reader.members()
        # Not read(): the independent closer closes the reader as soon as open()
        # returns, so the stream may already be closed when it comes back.
        reader.open("a.txt").close()
    for closer in closers:
        closer.join(timeout=10)
    assert len(outcome) == 1
    assert isinstance(outcome[0], ArchiveyUsageError)


@pytest.mark.parametrize("name", ["t.toyx", "t.toyw"])
def test_a_closed_reader_keeps_no_saved_winner(
    toyx: type[ToyXReader], toyw: None, tmp_path: Path, name: str
) -> None:
    if name == "t.toyx":
        path = _one(tmp_path)
        member = "a.txt"
    else:
        path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), name)
        member = "a"
    reader = open_archive(path, password=["no", "right", "pw"])
    with reader:
        reader.read(member)
        assert reader._saved_winners
    assert reader._saved_winners == {}
    # A sequential reader's walks keep none either.
    listing = getattr(reader, "_listing_walk", None)
    assert listing is None or listing.winners == {}


def test_two_threads_share_one_provider_turn(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    path = _write(
        tmp_path,
        build_toyx([("a.txt", _SECRET, b"right"), ("b.txt", b"other", b"right")]),
    )
    running = 0
    overlap = False
    lock = threading.Lock()

    def provider(request: PasswordRequest) -> bytes | None:
        nonlocal running, overlap
        with lock:
            running += 1
            overlap = overlap or running > 1
        time.sleep(0.05)
        with lock:
            running -= 1
        return b"right"

    results: dict[str, bytes] = {}
    with open_archive(path, password=provider, concurrent_operations=True) as reader:
        reader.members()
        threads = [
            threading.Thread(target=lambda n=n: results.__setitem__(n, reader.read(n)))
            for n in ("a.txt", "b.txt")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
    assert results == {"a.txt": _SECRET, "b.txt": b"other"}
    assert not overlap


def test_respawn_reuses_the_saved_winner(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    answers = iter([b"right"])

    def provider(request: PasswordRequest) -> bytes | None:
        return next(answers, None)

    with (
        open_archive(
            _one(tmp_path, checked=False),
            password=provider,
            seekable_members=True,
        ) as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.read() == _SECRET
        stream.seek(0)
        assert stream.read() == _SECRET


# --- the plugin's side ---------------------------------------------------------------


def test_check_exception_stops_resolution(tmp_path: Path) -> None:
    class Broken(ToyXReader):
        def _check(self, locator: _Locator) -> Callable[[bytes], Any]:
            def check(password: bytes) -> Any:
                raise CorruptionError("bad header")

            return check

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return Broken(source, context)

    with registration_scope():
        register_format(Handler)
        with (
            open_archive(_one(tmp_path), password=["a", "b"]) as reader,
            pytest.raises(CorruptionError, match="bad header"),
        ):
            reader.read("a.txt")


def test_bad_check_result_is_a_plugin_bug(tmp_path: Path) -> None:
    class Broken(ToyXReader):
        def _check(self, locator: _Locator) -> Callable[[bytes], Any]:
            return lambda password: b"not a tuple"

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return Broken(source, context)

    with registration_scope():
        register_format(Handler)
        with (
            open_archive(_one(tmp_path), password="right") as reader,
            pytest.raises(TypeError, match="not a \\(data, PasswordConfirmVerdict\\)"),
        ):
            reader.read("a.txt")


def test_a_handler_open_request_asks_the_provider_with_no_member(
    tmp_path: Path,
) -> None:
    """The first unlock of the archive itself, before any member exists, may ask the
    provider: the request has no member, and ``then`` builds the reader."""
    asked: list[PasswordRequest] = []

    class Handler(IndexedFormatHandler):
        format = TOYX
        extensions = (".toyx",)
        magic = (Magic(0, _MAGIC),)
        supports_password = True

        def open(
            self, source: ReaderSource, context: ReaderContext
        ) -> NeedsPassword[Any, IndexedReader[Any]]:
            def check(password: bytes) -> tuple[bytes | None, PasswordConfirmVerdict]:
                return (
                    (password, CONFIRMED) if password == b"right" else (None, REJECTED)
                )

            return NeedsPassword(
                "the TOYX archive",
                check,
                then=lambda key, verdict: ToyXReader(source, context),
            )

    def provider(request: PasswordRequest) -> bytes | None:
        asked.append(request)
        return b"right"

    with registration_scope():
        register_format(Handler)
        with open_archive(_one(tmp_path), password=provider) as reader:
            assert [m.name for m in reader.members()] == ["a.txt"]
    assert asked
    assert asked[0].member is None


def test_handler_without_supports_password(tmp_path: Path) -> None:
    class Handler(ToyXHandler):
        supports_password = False

    with registration_scope():
        register_format(Handler)
        with open_archive(_one(tmp_path), password="right") as reader:
            codes = [d.code for d in reader.diagnostics.retained]
            assert DiagnosticCode.PASSWORD_ARGUMENT_UNUSED in codes
            with pytest.raises(ArchiveyUsageError, match="supports_password is False"):
                reader.read("a.txt")


def test_provider_alone_is_not_reported_unused(tmp_path: Path) -> None:
    class Handler(ToyXHandler):
        supports_password = False

    called: list[PasswordRequest] = []
    with registration_scope():
        register_format(Handler)
        with open_archive(
            _write(tmp_path, build_toyx([("p.txt", b"plain", None)])),
            password=called.append,
        ) as reader:
            assert reader.read("p.txt") == b"plain"
            codes = [d.code for d in reader.diagnostics.retained]
    assert DiagnosticCode.PASSWORD_ARGUMENT_UNUSED not in codes
    assert called == []


def test_key_derivation_is_charged(toyx: type[ToyXReader], tmp_path: Path) -> None:
    toyx.rounds = 10_000
    config = ArchiveyConfig(
        decoder_limits=DecoderLimits(max_key_derivation_rounds=20_000)
    )
    with open_archive(
        _one(tmp_path), password=["a", "b", "right"], config=config
    ) as reader:
        with pytest.raises(ResourceLimitError):
            reader.read("a.txt")
        assert reader._resource_usage().key_derivation_rounds == 20_000
    # The third check is called, but its charge is refused before it derives a key.
    assert toyx.calls.check == [b"a", b"b", b"right"]


def test_key_derivation_rejects_a_bad_count(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    toyx.rounds = -1
    with (
        open_archive(_one(tmp_path), password="right") as reader,
        pytest.raises(ArchiveyUsageError, match="int of 0 or more"),
    ):
        reader.read("a.txt")


def test_archive_info_and_listing_verdict(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    toyx.archive_encrypted = True
    toyx.listing_unlocked = CONFIRMED
    with open_archive(_one(tmp_path), password="right") as reader:
        assert reader.info.is_encrypted
        assert reader.get("a.txt").verified is Verification.UNLOCKED


def test_plain_members_stay_unlocked(toyx: type[ToyXReader], tmp_path: Path) -> None:
    path = _write(tmp_path, build_toyx([("p.txt", b"plain", None)]))
    with open_archive(path) as reader:
        assert not reader.info.is_encrypted
        assert reader.get("p.txt").verified is Verification.UNLOCKED
        assert reader.read("p.txt") == b"plain"


def test_then_may_return_a_second_request(tmp_path: Path) -> None:
    class Chained(ToyXReader):
        def open_member(self, member: ArchiveMember, locator: _Locator) -> Any:
            inner = super().open_member(member, locator)
            assert isinstance(inner, NeedsPassword)
            return NeedsPassword(
                "the header",
                lambda password: (
                    (password, CONFIRMED) if password == b"header" else (None, REJECTED)
                ),
                then=lambda key, verdict: inner,
            )

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return Chained(source, context)

    with registration_scope():
        register_format(Handler)
        with open_archive(_one(tmp_path), password=["header", "right"]) as reader:
            assert reader.read("a.txt") == _SECRET


# --- a request yielded from a walk ------------------------------------------------------

_WMAGIC = b"TOYW\n"


def build_toyw(members: list[tuple[str, bytes]], password: bytes) -> bytes:
    """A magic, a password tag, then name/size/data for each member, XORed."""
    body = bytearray()
    for name, data in members:
        raw = name.encode()
        body += struct.pack("<H", len(raw)) + raw + struct.pack("<I", len(data)) + data
    body += struct.pack("<H", 0)
    return _WMAGIC + _tag(password) + _xor(bytes(body), _key(password))


class ToyWReader(SequentialReader):
    # Every password is rejected while this is set.
    reject_all: ClassVar[bool] = False
    # Charge metadata once the walk has its key: a step that needs the walk's state.
    charge_after_unlock: ClassVar[bool] = False
    # The verdict every walk after the first gives its spans, when set.
    rewalk_unlocked: ClassVar[PasswordConfirmVerdict | None] = None
    # A CRC-32 each span states for its data, when set.
    span_crc: ClassVar[bytes | None] = None
    # The verdict walk ``n`` (from 1) gives its spans, when set; wins over
    # ``rewalk_unlocked``.
    walk_unlocked: ClassVar[Callable[[int], PasswordConfirmVerdict | None] | None] = (
        None
    )
    # From this walk on (counted from 1), each member's first data byte is changed.
    corrupt_from_walk: ClassVar[int | None] = None
    walks: ClassVar[int] = 0

    def __init__(self, context: ReaderContext) -> None:
        self._context = context

    def walk(self, stream: ForwardStream) -> Iterator[Any]:
        if stream.read_exact(len(_WMAGIC)) != _WMAGIC:
            raise CorruptionError("not a TOYW archive")
        tag = stream.read_exact(4)

        def check(password: bytes) -> tuple[bytes | None, PasswordConfirmVerdict]:
            if self.reject_all or _tag(password) != tag:
                return None, REJECTED
            return _key(password), CONFIRMED

        key, verdict = yield NeedsPassword("the TOYW archive", check)
        ToyWReader.walks += 1
        if self.rewalk_unlocked is not None and ToyWReader.walks > 1:
            verdict = self.rewalk_unlocked
        # Read off the class: through ``self`` the function would be bound.
        pick = ToyWReader.walk_unlocked
        if pick is not None:
            verdict = pick(ToyWReader.walks)
        corrupt = (
            self.corrupt_from_walk is not None
            and ToyWReader.walks >= self.corrupt_from_walk
        )
        digests = (
            (MemberDigest("crc32", self.span_crc),) if self.span_crc is not None else ()
        )
        if self.charge_after_unlock:
            self._context.charge_metadata(10, what="header")
        pos = 0

        def read(n: int) -> bytes:
            nonlocal pos
            data = _xor(stream.read_exact(n), key, pos)
            pos += n
            return data

        while True:
            (name_len,) = struct.unpack("<H", read(2))
            if not name_len:
                return
            name = read(name_len).decode()
            (size,) = struct.unpack("<I", read(4))
            member = ArchiveMember(
                type=MemberType.FILE, name=name, size=size, is_encrypted=True
            )
            data = read(size)
            if corrupt and data:
                data = bytes([data[0] ^ 0xFF]) + data[1:]
            yield MemberSpan(
                member, data=io.BytesIO(data), unlocked=verdict, digests=digests
            )

    def archive_info(self) -> ReaderArchiveInfo:
        return ReaderArchiveInfo(is_encrypted=True)


class ToyWHandler(SequentialFormatHandler):
    format = TOYW
    extensions = (".toyw",)
    magic = (Magic(0, _WMAGIC),)
    supports_password = True

    def open_sequential(self, context: ReaderContext) -> ToyWReader:
        return ToyWReader(context)


@pytest.fixture
def toyw() -> Iterator[None]:
    with registration_scope():
        register_format(ToyWHandler)
        yield
    ToyWReader.reject_all = False
    ToyWReader.charge_after_unlock = False
    ToyWReader.rewalk_unlocked = None
    ToyWReader.span_crc = None
    ToyWReader.walk_unlocked = None
    ToyWReader.corrupt_from_walk = None
    ToyWReader.walks = 0


def test_walk_request_resolves(toyw: None, tmp_path: Path) -> None:
    path = _write(
        tmp_path, build_toyw([("a", b"alpha"), ("b", b"beta")], b"pw"), "t.toyw"
    )
    with open_archive(path, password=["no", "pw"]) as reader:
        assert [m.name for m in reader.members()] == ["a", "b"]
        assert reader.get("a").verified is Verification.UNLOCKED
        assert reader.read("b") == b"beta"
        assert reader.info.is_encrypted
    with open_archive(path, password=["no", "pw"], streaming=True) as reader:
        assert [
            (m.name, s.read() if s else None) for m, s in reader.stream_members()
        ] == [
            ("a", b"alpha"),
            ("b", b"beta"),
        ]


def test_walk_request_wrong_password(toyw: None, tmp_path: Path) -> None:
    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    with (
        pytest.raises(EncryptionError, match="Wrong password for the TOYW archive"),
        open_archive(path, password="no") as reader,
    ):
        reader.members()


def test_walk_rewalk_does_not_ask_again(toyw: None, tmp_path: Path) -> None:
    path = _write(
        tmp_path, build_toyw([("a", b"alpha"), ("b", b"beta")], b"pw"), "t.toyw"
    )
    asked: list[int] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asked.append(request.attempt)
        return b"pw" if len(asked) == 1 else None

    with open_archive(path, password=provider) as reader:
        reader.members()
        # Reading an earlier member out of order walks the archive again.
        assert reader.read("b") == b"beta"
        assert reader.read("a") == b"alpha"
    assert asked == [1]


def test_walk_generator_is_closed_on_failure(tmp_path: Path) -> None:
    closed: list[bool] = []

    class Watched(ToyWReader):
        def walk(self, stream: ForwardStream) -> Iterator[Any]:
            try:
                yield from super().walk(stream)
            finally:
                closed.append(True)

    class Handler(ToyWHandler):
        def open_sequential(self, context: ReaderContext) -> ToyWReader:
            return Watched(context)

    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    with registration_scope():
        register_format(Handler)
        with (
            pytest.raises(EncryptionError, match="Wrong password"),
            open_archive(path, password="no") as reader,
        ):
            reader.members()
    assert closed == [True]


def test_a_failing_walk_cleanup_keeps_the_password_error(tmp_path: Path) -> None:
    class Messy(ToyWReader):
        def walk(self, stream: ForwardStream) -> Iterator[Any]:
            try:
                yield from super().walk(stream)
            finally:
                raise RuntimeError("cleanup failed")

    class Handler(ToyWHandler):
        def open_sequential(self, context: ReaderContext) -> ToyWReader:
            return Messy(context)

    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    with registration_scope():
        register_format(Handler)
        with pytest.raises(EncryptionError, match="Wrong password"):
            open_archive(path, password="no")


def test_provider_reentry_during_a_paused_walk(tmp_path: Path) -> None:
    class Late(ToyWReader):
        """Lists a plain member before the walk's request, so the walk opens without
        asking and pauses on its request during the listing."""

        def walk(self, stream: ForwardStream) -> Iterator[Any]:
            plain = ArchiveMember(type=MemberType.FILE, name="p", size=1)
            yield MemberSpan(plain, data=io.BytesIO(b"p"))
            yield from super().walk(stream)

    class Handler(ToyWHandler):
        def open_sequential(self, context: ReaderContext) -> ToyWReader:
            return Late(context)

    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    box: list[Any] = []

    def provider(request: PasswordRequest) -> bytes | None:
        box[0].members()
        return b"pw"

    with registration_scope():
        register_format(Handler)
        with open_archive(path, password=provider) as reader:
            box.append(reader)
            with pytest.raises(ArchiveyUsageError, match="re-entered"):
                reader.members()


def test_another_thread_waits_for_the_answer_during_a_listing(tmp_path: Path) -> None:
    """The walk lock stays held while the provider runs: an independent thread's
    ``members()`` waits for the answer and the listing, and then sees every member."""

    class Late(ToyWReader):
        """Lists a plain member first, so the request comes during ``members()``."""

        def walk(self, stream: ForwardStream) -> Iterator[Any]:
            plain = ArchiveMember(type=MemberType.FILE, name="p", size=1)
            yield MemberSpan(plain, data=io.BytesIO(b"p"))
            yield from super().walk(stream)

    class Handler(ToyWHandler):
        def open_sequential(self, context: ReaderContext) -> ToyWReader:
            return Late(context)

    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    box: list[Any] = []
    seen: list[list[str]] = []
    other: list[threading.Thread] = []

    def list_members() -> None:
        seen.append([m.name for m in box[0].members()])

    def provider(request: PasswordRequest) -> bytes | None:
        # A fresh context, as in the copied-context close test: an inherited one
        # would make this thread the provider's.
        thread = threading.Thread(
            target=contextvars.Context().run, args=(list_members,)
        )
        other.append(thread)
        thread.start()
        thread.join(timeout=0.3)
        assert thread.is_alive(), "members() did not wait for the provider's answer"
        assert not seen
        return b"pw"

    with registration_scope():
        register_format(Handler)
        with open_archive(
            path, password=provider, concurrent_operations=True
        ) as reader:
            box.append(reader)
            assert [m.name for m in reader.members()] == ["p", "a"]
            other[0].join(timeout=10)
    assert seen == [["p", "a"]]


# --- how often the plugin is called ------------------------------------------------------


def test_open_member_and_then_run_once_per_request(tmp_path: Path) -> None:
    counts = {"open_member": 0, "then": 0}

    class Counted(ToyXReader):
        def open_member(self, member: ArchiveMember, locator: _Locator) -> Any:
            counts["open_member"] += 1
            request = super().open_member(member, locator)
            assert isinstance(request, NeedsPassword)
            then = request.then
            assert then is not None

            def counted_then(key: bytes, verdict: PasswordConfirmVerdict) -> Any:
                counts["then"] += 1
                return then(key, verdict)

            return NeedsPassword(
                request.what,
                request.check,
                full_check=request.full_check,
                member=request.member,
                then=counted_then,
            )

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return Counted(source, context)

    with registration_scope():
        register_format(Handler)
        with open_archive(_one(tmp_path), password=["a", "b", "right"]) as reader:
            assert reader.read("a.txt") == _SECRET
    assert counts == {"open_member": 1, "then": 1}


def test_skipped_members_never_ask_the_provider(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    path = _write(
        tmp_path,
        build_toyx(
            [
                ("p.txt", b"plain", None),
                ("a.txt", _SECRET, b"right"),
                ("b.txt", b"other data", b"right"),
            ]
        ),
    )
    asked: list[str] = []

    def provider(request: PasswordRequest) -> bytes | None:
        assert request.member is not None
        asked.append(request.member.name)
        return b"right"

    with open_archive(path, password=provider) as reader:
        read = {}
        for member, stream in reader.stream_members():
            if member.name != "a.txt" and stream is not None:
                read[member.name] = stream.read()
    assert read == {"p.txt": b"plain", "b.txt": b"other data"}
    assert asked == ["b.txt"]


def test_extract_all_with_a_provider(toyx: type[ToyXReader], tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        build_toyx([("a.txt", _SECRET, b"right"), ("b.txt", b"other", b"right")]),
    )
    asked: list[int] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asked.append(request.attempt)
        return b"right"

    dest = tmp_path / "out"
    with open_archive(path, password=provider) as reader:
        reader.extract_all(dest)
    assert (dest / "a.txt").read_bytes() == _SECRET
    assert (dest / "b.txt").read_bytes() == b"other"
    # The first answer is known-good, so the second member does not ask.
    assert asked == [1]


def test_chain_then_seek_to_zero_with_an_exhausted_provider(tmp_path: Path) -> None:
    class Chained(ToyXReader):
        def open_member(self, member: ArchiveMember, locator: _Locator) -> Any:
            inner = super().open_member(member, locator)
            assert isinstance(inner, NeedsPassword)
            return NeedsPassword(
                "the header",
                lambda password: (
                    (password, CONFIRMED) if password == b"header" else (None, REJECTED)
                ),
                then=lambda key, verdict: inner,
            )

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return Chained(source, context)

    answers = iter([b"header", b"right"])

    def provider(request: PasswordRequest) -> bytes | None:
        return next(answers, None)

    with registration_scope():
        register_format(Handler)
        # The inner request is checked: the header's winner, known-good by then, is
        # tried first and must be rejected, not survive alone as INCONCLUSIVE.
        with (
            open_archive(
                _one(tmp_path), password=provider, seekable_members=True
            ) as reader,
            reader.open("a.txt") as stream,
        ):
            assert stream.read() == _SECRET
            stream.seek(0)
            assert stream.read() == _SECRET
    assert next(answers, None) is None


def test_a_known_good_password_is_rechecked_when_a_provider_can_answer(
    tmp_path: Path,
) -> None:
    """The first request's winner is known-good, and survives the unchecked second
    request alone. With a provider set it goes through ``full_check``, which rejects
    it, and the provider is asked for the second request's password."""

    class Chained(ToyXReader):
        def open_member(self, member: ArchiveMember, locator: _Locator) -> Any:
            inner = super().open_member(member, locator)
            assert isinstance(inner, NeedsPassword)
            return NeedsPassword(
                "the header",
                lambda password: (
                    (password, CONFIRMED) if password == b"header" else (None, REJECTED)
                ),
                then=lambda key, verdict: inner,
            )

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return Chained(source, context)

    answers = iter([b"header", b"right"])

    def provider(request: PasswordRequest) -> bytes | None:
        return next(answers, None)

    with registration_scope():
        register_format(Handler)
        with open_archive(_one(tmp_path, checked=False), password=provider) as reader:
            assert reader.read("a.txt") == _SECRET
    assert next(answers, None) is None


# --- replacement opens never ask the provider ----------------------------------------------


def test_indexed_respawn_with_a_failing_saved_winner_does_not_ask(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    asked: list[int] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asked.append(request.attempt)
        return b"right"

    with (
        open_archive(
            _one(tmp_path), password=provider, seekable_members=True
        ) as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.read() == _SECRET
        toyx.reject_all = True
        with pytest.raises(EncryptionError, match="Wrong password"):
            stream.seek(0)
            stream.read()
    assert asked == [1]


def test_a_data_walk_uses_its_own_verdict(toyw: None, tmp_path: Path) -> None:
    """The listing walk confirmed the password and a later walk to the member did
    not: a checksum failure under that walk's data is the password-or-damage error,
    not plain damage."""
    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    ToyWReader.rewalk_unlocked = INCONCLUSIVE
    ToyWReader.span_crc = b"\0\0\0\0"
    with open_archive(path, password="pw") as reader:
        reader.members()
        with pytest.raises(EncryptionError) as raised:
            reader.read("a")
    assert is_unverified_data_error(raised.value)


def test_an_indexed_respawn_that_becomes_inconclusive_is_watched(
    toyx: type[ToyXReader], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first open states no verdict and the respawn after a backward seek says
    ``INCONCLUSIVE``: a checksum failure under the respawn's data is the
    password-or-damage error, not plain damage."""
    original = ToyXReader.open_member
    opens = 0

    def open_member(self: ToyXReader, member: ArchiveMember, locator: Any) -> Any:
        request = original(self, member, locator)
        assert isinstance(request, NeedsPassword)
        then = request.then
        assert then is not None

        def changed_then(key: bytes, verdict: PasswordConfirmVerdict) -> MemberData:
            nonlocal opens
            opens += 1
            data = then(key, verdict)
            if opens == 1:
                return data._replace(unlocked=None)
            data.stream.close()
            wrong = _XorStream(self._source.view(locator.offset, locator.size), b"x")
            return data._replace(stream=wrong, unlocked=INCONCLUSIVE)

        return request.__class__(
            request.what,
            request.check,
            full_check=request.full_check,
            member=request.member,
            then=changed_then,
        )

    monkeypatch.setattr(ToyXReader, "open_member", open_member)
    with (
        open_archive(_one(tmp_path), password="right", seekable_members=True) as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.read() == _SECRET
        stream.seek(0)
        with pytest.raises(EncryptionError) as raised:
            stream.read()
    assert is_unverified_data_error(raised.value)


def test_a_sequential_respawn_that_becomes_inconclusive_is_watched(
    toyw: None, tmp_path: Path
) -> None:
    """The listing walk and the first data walk state no verdict, and the walk a
    backward seek starts says ``INCONCLUSIVE``: its checksum failure is the
    password-or-damage error."""
    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    ToyWReader.span_crc = zlib.crc32(b"alpha").to_bytes(4)
    ToyWReader.walk_unlocked = lambda n: INCONCLUSIVE if n >= 3 else None
    ToyWReader.corrupt_from_walk = 3
    with open_archive(path, password="pw", seekable_members=True) as reader:
        reader.members()
        with reader.open("a") as stream:
            assert stream.read() == b"alpha"
            stream.seek(0)
            with pytest.raises(EncryptionError) as raised:
                stream.read()
    assert is_unverified_data_error(raised.value)


def test_a_respawn_keeps_its_own_winner_when_another_handle_saves_a_new_one(
    tmp_path: Path,
) -> None:
    """Handle A unlocks ``a.txt`` with a provider answer its check cannot reject.
    Another member confirms a different password, and handle B, a fresh open, takes
    it for ``a.txt``. A backward seek on A to a nonzero offset still reads with A's
    own password: the bytes it gave before come back, not B's."""

    class WeakA(ToyXReader):
        def open_member(self, member: ArchiveMember, locator: _Locator) -> Any:
            request = super().open_member(member, locator)
            if member.name != "a.txt" or not isinstance(request, NeedsPassword):
                return request

            def check(password: bytes) -> Any:
                _, verdict = request.check(password)
                return _key(password), INCONCLUSIVE if verdict is REJECTED else verdict

            return NeedsPassword(request.what, check, member=member, then=request.then)

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return WeakA(source, context)

    path = _write(
        tmp_path,
        build_toyx([("a.txt", _SECRET, b"right"), ("b.txt", b"other", b"right")]),
    )
    answers = iter([b"wrong", b"right"])

    def provider(request: PasswordRequest) -> bytes | None:
        return next(answers, None)

    with registration_scope():
        register_format(Handler)
        with open_archive(
            path, password=provider, seekable_members=True, concurrent_operations=True
        ) as reader:
            first = reader.open("a.txt")
            head = first.read(4)
            assert head != _SECRET[:4]
            assert reader.read("b.txt") == b"other"
            with reader.open("a.txt") as second:
                assert second.read(4) == _SECRET[:4]
            first.seek(1)
            assert first.read(3) == head[1:]
            with suppress(EncryptionError):
                first.close()


def test_a_rewalk_keeps_its_own_winner_when_another_handle_saves_a_new_one(
    tmp_path: Path,
) -> None:
    """The sequential form of the test above. Each member has a request whose check
    cannot reject a wrong password, and confirms the right one from the second walk
    on. Handle A unlocks ``a`` with the provider's wrong answer. A read of ``b``
    confirms the right password, and handle B, a fresh open of ``a``, takes it. A
    backward seek on A to a nonzero offset walks again with A's own password."""
    walks = 0

    def build(members: list[tuple[str, bytes]], password: bytes) -> bytes:
        body = bytearray(_WMAGIC)
        for name, data in members:
            raw = name.encode()
            body += struct.pack("<H", len(raw)) + raw + _tag(password)
            body += struct.pack("<I", len(data)) + _xor(data, _key(password))
        return bytes(body + struct.pack("<H", 0))

    class PerMember(ToyWReader):
        def walk(self, stream: ForwardStream) -> Iterator[Any]:
            nonlocal walks
            if stream.read_exact(len(_WMAGIC)) != _WMAGIC:
                raise CorruptionError("not a TOYW archive")
            walks += 1
            listing = walks == 1
            while True:
                (name_len,) = struct.unpack("<H", stream.read_exact(2))
                if not name_len:
                    return
                name = stream.read_exact(name_len).decode()
                tag = stream.read_exact(4)
                (size,) = struct.unpack("<I", stream.read_exact(4))

                def check(password: bytes, tag: bytes = tag) -> Any:
                    right = _tag(password) == tag and not listing
                    return _key(password), CONFIRMED if right else INCONCLUSIVE

                member = ArchiveMember(
                    type=MemberType.FILE, name=name, size=size, is_encrypted=True
                )
                key, verdict = yield NeedsPassword(name, check, member=member)
                data = _xor(stream.read_exact(size), key)
                yield MemberSpan(member, data=io.BytesIO(data), unlocked=verdict)

    class Handler(ToyWHandler):
        def open_sequential(self, context: ReaderContext) -> ToyWReader:
            return PerMember(context)

    path = _write(
        tmp_path,
        build([("a", b"alpha data"), ("b", b"beta data")], b"right"),
        "t.toyw",
    )

    def provider(request: PasswordRequest) -> bytes | None:
        # One answer for each member: ``a`` a wrong one, ``b`` the right one.
        assert request.member is not None
        if request.attempt > 1:
            return None
        return b"right" if request.member.name == "b" else b"wrong"

    with registration_scope():
        register_format(Handler)
        with open_archive(
            path, password=provider, seekable_members=True, concurrent_operations=True
        ) as reader:
            reader.members()
            first = reader.open("a")
            head = first.read(4)
            assert head != b"alph"
            assert reader.read("b") == b"beta data"
            with reader.open("a") as second:
                assert second.read(4) == b"alph"
            first.seek(1)
            assert first.read(3) == head[1:]
            with suppress(EncryptionError):
                first.close()


def test_a_rewalk_does_not_take_an_idle_walk_unlocked_another_way(
    tmp_path: Path,
) -> None:
    """One request unlocks every member's data. Handle A on ``b`` unlocked it with
    a wrong password the check could not reject. A fresh open of ``a``, while the
    check rejects that password, unlocks it with the right one and leaves its walk
    idle just past ``a``. A backward seek on A walks again from the start with A's
    own password, rather than going on with that idle walk."""
    strict = False

    def build(members: list[tuple[str, bytes]], password: bytes) -> bytes:
        body = bytearray(_WMAGIC + _tag(password))
        pos = 0
        for name, data in members:
            raw = name.encode()
            body += struct.pack("<H", len(raw)) + raw + struct.pack("<I", len(data))
            body += _xor(data, _key(password), pos)
            pos += len(data)
        return bytes(body + struct.pack("<H", 0))

    class OneKey(ToyWReader):
        def walk(self, stream: ForwardStream) -> Iterator[Any]:
            if stream.read_exact(len(_WMAGIC)) != _WMAGIC:
                raise CorruptionError("not a TOYW archive")
            tag = stream.read_exact(4)

            def check(password: bytes) -> Any:
                if _tag(password) == tag:
                    return _key(password), CONFIRMED
                return (None, REJECTED) if strict else (_key(password), INCONCLUSIVE)

            key, verdict = yield NeedsPassword("the archive", check)
            pos = 0
            while True:
                (name_len,) = struct.unpack("<H", stream.read_exact(2))
                if not name_len:
                    return
                name = stream.read_exact(name_len).decode()
                (size,) = struct.unpack("<I", stream.read_exact(4))
                data = _xor(stream.read_exact(size), key, pos)
                pos += size
                member = ArchiveMember(
                    type=MemberType.FILE, name=name, size=size, is_encrypted=True
                )
                yield MemberSpan(member, data=io.BytesIO(data), unlocked=verdict)

    class Handler(ToyWHandler):
        def open_sequential(self, context: ReaderContext) -> ToyWReader:
            return OneKey(context)

    path = _write(
        tmp_path,
        build([("a", b"alpha data"), ("b", b"beta data")], b"right"),
        "t.toyw",
    )
    answers = [b"wrong", b"right"]

    def provider(request: PasswordRequest) -> bytes | None:
        return answers[request.attempt - 1] if request.attempt <= 2 else None

    with registration_scope():
        register_format(Handler)
        with open_archive(
            path, password=provider, seekable_members=True, concurrent_operations=True
        ) as reader:
            reader.members()
            first = reader.open("b")
            head = first.read(4)
            assert head != b"beta"
            strict = True
            with reader.open("a") as second:
                assert second.read() == b"alpha data"
            strict = False
            first.seek(1)
            assert first.read(3) == head[1:]
            with suppress(EncryptionError):
                first.close()


def test_an_indexed_respawn_must_describe_its_checks_the_same(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    with (
        open_archive(_one(tmp_path), password="right", seekable_members=True) as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.read() == _SECRET
        toyx.then_checked = True
        with pytest.raises(ValueError, match="different checked when opened again"):
            stream.seek(0)
            stream.read()


@pytest.mark.parametrize("seek_back", [False, True])
def test_a_rewalk_must_state_the_same_digests(
    toyw: None, tmp_path: Path, seek_back: bool
) -> None:
    """A data walk, first or a backward seek's, whose span states other digests than
    the listing walk's is refused, not read against the listing's digests."""
    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    with open_archive(path, password="pw", seekable_members=seek_back) as reader:
        reader.members()
        with pytest.raises(ValueError, match="different digests when walked again"):
            if seek_back:
                with reader.open("a") as stream:
                    assert stream.read() == b"alpha"
                    ToyWReader.span_crc = b"\0\0\0\0"
                    stream.seek(0)
                    stream.read()
            else:
                ToyWReader.span_crc = b"\0\0\0\0"
                reader.read("a")


def test_a_rewalk_must_describe_its_checks_the_same(
    toyw: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    original = ToyWReader.walk

    def walk(self: ToyWReader, stream: ForwardStream) -> Iterator[Any]:
        first = ToyWReader.walks == 0
        gen = original(self, stream)
        sent = None
        while True:
            try:
                item = gen.send(sent)
            except StopIteration:
                return
            if isinstance(item, MemberSpan) and not first:
                item = item._replace(checked=True)
            sent = yield item

    monkeypatch.setattr(ToyWReader, "walk", walk)
    with open_archive(path, password="pw") as reader:
        reader.members()
        with pytest.raises(ValueError, match="checked=True when walked again"):
            reader.read("a")


def test_sequential_respawn_with_a_failing_saved_winner_does_not_ask(
    toyw: None, tmp_path: Path
) -> None:
    """A backward seek on data the walk decodes walks again, and that walk is a
    replacement open: its request gets the saved winner only."""
    path = _write(
        tmp_path, build_toyw([("a", b"alpha"), ("b", b"beta")], b"pw"), "t.toyw"
    )
    asked: list[int] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asked.append(request.attempt)
        return b"pw"

    with open_archive(path, password=provider, seekable_members=True) as reader:
        reader.members()
        with reader.open("b") as stream:
            assert stream.read() == b"beta"
            ToyWReader.reject_all = True
            with pytest.raises(EncryptionError, match="Wrong password"):
                stream.seek(0)
                stream.read()
    assert asked == [1]


def test_a_provider_call_puts_the_step_state_back(toyw: None, tmp_path: Path) -> None:
    """The handle lock is let go while the provider runs, so another thread's plugin
    step may set and clear the adapter's step fields meanwhile. They are this step's
    again after. (A listing in progress keeps other threads' opens waiting, and a
    data walk never asks the provider, so no public call interleaves today.)"""
    path = _write(tmp_path, build_toyw([("a", b"alpha")], b"pw"), "t.toyw")
    with open_archive(path, password="pw", concurrent_operations=True) as reader:
        lock = reader._handle_lock
        assert lock is not None
        with lock:
            reader._walk_step = "this step"
            reader._reopening = ("this", "step")
            with reader._unguarded():
                # Another thread's step, ending: its ``finally`` clears them.
                reader._walk_step = None
                reader._reopening = None
            assert reader._walk_step == "this step"
            assert reader._reopening == ("this", "step")
            reader._walk_step = None
            reader._reopening = None


# --- the rest of the spec rows -----------------------------------------------------------


class _LibraryError(Exception):
    """An exception from the plugin's own library, which it translates."""


def _translated_handler(reader_cls: type[ToyXReader]) -> type[ToyXHandler]:
    class Translating(reader_cls):  # type: ignore[valid-type,misc]
        def translate_exception(self, exc: Exception) -> Any:
            if isinstance(exc, _LibraryError):
                return CorruptionError(f"translated: {exc}")
            return None

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return Translating(source, context)

    return Handler


def test_a_check_error_goes_through_translate_exception(tmp_path: Path) -> None:
    class Broken(ToyXReader):
        def _check(self, locator: _Locator) -> Callable[[bytes], Any]:
            def check(password: bytes) -> Any:
                raise _LibraryError("bad key schedule")

            return check

    with registration_scope():
        register_format(_translated_handler(Broken))
        with (
            open_archive(_one(tmp_path), password=["a", "right"]) as reader,
            pytest.raises(CorruptionError, match="translated: bad key schedule"),
        ):
            reader.read("a.txt")


def test_a_then_error_goes_through_translate_exception(tmp_path: Path) -> None:
    class Broken(ToyXReader):
        def open_member(self, member: ArchiveMember, locator: _Locator) -> Any:
            request = super().open_member(member, locator)
            assert isinstance(request, NeedsPassword)

            def then(key: bytes, verdict: PasswordConfirmVerdict) -> Any:
                raise _LibraryError("cannot start the cipher")

            return NeedsPassword(request.what, request.check, then=then)

    with registration_scope():
        register_format(_translated_handler(Broken))
        with (
            open_archive(_one(tmp_path), password="right") as reader,
            pytest.raises(CorruptionError, match="translated: cannot start the cipher"),
        ):
            reader.read("a.txt")


def test_an_encryption_error_from_check_is_raised_as_it_is(tmp_path: Path) -> None:
    class Broken(ToyXReader):
        def _check(self, locator: _Locator) -> Callable[[bytes], Any]:
            def check(password: bytes) -> Any:
                raise EncryptionError("unsupported cipher suite")

            return check

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return Broken(source, context)

    with registration_scope():
        register_format(Handler)
        with (
            open_archive(_one(tmp_path), password=["a", "right"]) as reader,
            pytest.raises(EncryptionError, match="unsupported cipher suite"),
        ):
            reader.read("a.txt")


def test_full_check_inconclusive_for_both_takes_the_first(tmp_path: Path) -> None:
    calls: list[bytes] = []

    class Weak(ToyXReader):
        def _full_check(self, locator: _Locator) -> Callable[[bytes], Any]:
            def full_check(password: bytes) -> Any:
                calls.append(password)
                return _key(password), INCONCLUSIVE

            return full_check

    class Handler(ToyXHandler):
        def open(self, source: ReaderSource, context: ReaderContext) -> ToyXReader:
            return Weak(source, context)

    with registration_scope():
        register_format(Handler)
        with open_archive(
            _one(tmp_path, checked=False), password=["right", "b"]
        ) as reader:
            assert reader.read("a.txt") == _SECRET
            # Nothing confirmed it, and another password could still be the one.
            assert reader._passwords._known_good == []
    assert calls == [b"right", b"b"]


def test_no_full_check_first_inconclusive_is_not_promoted(
    toyx: type[ToyXReader], tmp_path: Path
) -> None:
    toyx.use_full_check = False
    with open_archive(_one(tmp_path, checked=False), password=["right", "b"]) as reader:
        assert reader.read("a.txt") == _SECRET
        assert reader._passwords._known_good == []


def test_two_requests_in_one_walk_keep_their_own_attempts(tmp_path: Path) -> None:
    """Each request has its own tried set and attempt count: the second request's
    provider call is its own attempt 1."""

    class TwoKeys(ToyWReader):
        def walk(self, stream: ForwardStream) -> Iterator[Any]:
            if stream.read_exact(len(_WMAGIC)) != _WMAGIC:
                raise CorruptionError("not a TOYW archive")
            for _ in range(2):
                tag = stream.read_exact(4)

                def check(
                    password: bytes, tag: bytes = tag
                ) -> tuple[bytes | None, PasswordConfirmVerdict]:
                    if _tag(password) != tag:
                        return None, REJECTED
                    return password, CONFIRMED

                yield NeedsPassword("a TOYW key", check)
            member = ArchiveMember(type=MemberType.FILE, name="a", size=1)
            yield MemberSpan(member, data=io.BytesIO(b"a"))

    class Handler(ToyWHandler):
        def open_sequential(self, context: ReaderContext) -> ToyWReader:
            return TwoKeys(context)

    path = _write(tmp_path, _WMAGIC + _tag(b"one") + _tag(b"two"), "t.toyw")
    answers = iter([b"one", b"two"])
    asked: list[int] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asked.append(request.attempt)
        return next(answers, None)

    with registration_scope():
        register_format(Handler)
        with open_archive(path, password=provider) as reader:
            assert reader.read("a") == b"a"
    # The second request tried the known-good "one" first, then asked.
    assert asked == [1, 1]
