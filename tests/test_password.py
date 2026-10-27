"""Tests for password candidates and provider (Phase 5 stage 2)."""

from __future__ import annotations

import ast
import re
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

import archivey
from archivey import PasswordRequest, open_archive
from archivey.exceptions import ArchiveyUsageError, EncryptionError
from archivey.internal.backends.sevenzip_reader import SevenZipReader
from archivey.internal.measurement import enable_measurement
from archivey.internal.password import _PasswordCandidates, wrong_password_error
from archivey.types import ArchiveMember, MemberType
from tests.conftest import requires, requires_binary


def _make_multi_password_zip(path: Path) -> None:
    (path.parent / "f1.txt").write_bytes(b"secret1\n")
    (path.parent / "f2.txt").write_bytes(b"secret2\n")
    subprocess.run(
        ["7z", "a", "-tzip", str(path), "f1.txt", "-psecret1", "-y"],
        cwd=path.parent,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["7z", "a", "-tzip", str(path), "f2.txt", "-psecret2", "-y"],
        cwd=path.parent,
        check=True,
        capture_output=True,
    )


def test_password_candidates_provider_header_request() -> None:
    seen: list[PasswordRequest] = []

    def provider(request: PasswordRequest) -> str | None:
        seen.append(request)
        return None

    candidates = _PasswordCandidates.from_input(provider)
    with pytest.raises(EncryptionError):
        candidates.attempt(
            None,
            lambda _pwd: (_ for _ in ()).throw(EncryptionError("wrong")),
        )
    assert len(seen) == 1
    assert seen[0].member is None
    assert seen[0].attempt == 1


def test_password_candidates_provider_attempt_increments() -> None:
    attempts: list[int] = []

    def provider(request: PasswordRequest) -> str | None:
        attempts.append(request.attempt)
        # Distinct guesses each time: a *repeated* guess is provably useless (decrypt is
        # deterministic in the password) and terminates the loop early — see
        # test_password_candidates_provider_repeat_terminates.
        if request.attempt < 3:
            return f"wrong{request.attempt}"
        return None

    candidates = _PasswordCandidates.from_input(provider)
    with pytest.raises(EncryptionError):
        candidates.attempt(
            None,
            lambda _pwd: (_ for _ in ()).throw(EncryptionError("bad")),
        )
    assert attempts == [1, 2, 3]


def test_password_candidates_provider_encryption_error_propagates_unchanged() -> None:
    provider_error = EncryptionError("password service unavailable")

    def provider(request: PasswordRequest) -> str | None:
        raise provider_error

    candidates = _PasswordCandidates.from_input(provider)
    with pytest.raises(EncryptionError) as caught:
        candidates.attempt(None, lambda _password: b"unused")

    assert caught.value is provider_error


def test_password_candidates_provider_reuses_known_good() -> None:
    calls = 0

    def provider(request: PasswordRequest) -> str | None:
        nonlocal calls
        calls += 1
        return "from-provider"

    candidates = _PasswordCandidates.from_input(provider)

    def decrypt(password: bytes) -> bytes:
        if password == b"from-provider":
            return b"ok"
        raise EncryptionError("bad")

    first = ArchiveMember(type=MemberType.FILE, name="first")
    second = ArchiveMember(type=MemberType.FILE, name="second")
    assert candidates.attempt(first, decrypt) == b"ok"
    assert candidates.attempt(second, decrypt) == b"ok"
    assert calls == 1


def test_password_candidates_provider_repeat_terminates() -> None:
    # A provider that keeps returning the same wrong password can make no progress;
    # attempt() must stop instead of re-running decrypt on it forever.
    calls = 0

    def provider(request: PasswordRequest) -> str | None:
        nonlocal calls
        calls += 1
        return "same-wrong"

    decrypt_calls = 0

    def decrypt(password: bytes) -> bytes:
        nonlocal decrypt_calls
        decrypt_calls += 1
        raise EncryptionError("bad")

    candidates = _PasswordCandidates.from_input(provider)
    with pytest.raises(EncryptionError):
        candidates.attempt(None, decrypt)
    # The password is tried once; three identical answers in a row end the loop.
    assert calls == 4
    assert decrypt_calls == 1


def test_password_candidates_provider_repeat_does_not_end_the_provider() -> None:
    # S25-K6: after unit 1 succeeds with pw_a, pw_a is known-good and tried first on
    # unit 2. A provider that leads with pw_a must still be asked again, with the next
    # attempt number, and its pw_b must open unit 2.
    answers = [b"pw_a", b"pw_b"]
    asks: list[int] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asks.append(request.attempt)
        return answers[request.attempt - 1] if request.attempt <= len(answers) else None

    def decrypt_for(right: bytes) -> Callable[[bytes], bytes]:
        def decrypt(password: bytes) -> bytes:
            if password != right:
                raise EncryptionError("Wrong password")
            return b"plaintext<" + password + b">"

        return decrypt

    candidates = _PasswordCandidates(provider=provider)
    assert candidates.attempt(None, decrypt_for(b"pw_a")) == b"plaintext<pw_a>"
    assert asks == [1]
    asks.clear()
    assert candidates.attempt(None, decrypt_for(b"pw_b")) == b"plaintext<pw_b>"
    assert asks == [1, 2]


def test_password_candidates_provider_keyring_longer_than_known_good() -> None:
    # Each opened unit adds one known-good password, which the next unit tries before
    # the provider and the provider then repeats. However many there are, a provider
    # walking its keyring by attempt must still reach the right one.
    keyring = [f"pw{i}".encode() for i in range(1, 41)]

    def provider(request: PasswordRequest) -> bytes | None:
        return keyring[request.attempt - 1] if request.attempt <= len(keyring) else None

    def decrypt_for(right: bytes) -> Callable[[bytes], bytes]:
        def decrypt(password: bytes) -> bytes:
            if password != right:
                raise EncryptionError("Wrong password")
            return password

        return decrypt

    candidates = _PasswordCandidates(provider=provider)
    for right in keyring:
        assert candidates.attempt(None, decrypt_for(right)) == right


def test_password_candidates_provider_repeating_its_own_answer_asks_again() -> None:
    # A person at a prompt may type a password again, thinking they mistyped it or
    # unsure whether they gave it. The repeat is not decrypted again, but it does not
    # end the asking: their next answer is still tried.
    script = [b"a", b"a", b"b", b"a", b"right"]
    asks: list[int] = []
    tried: list[bytes] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asks.append(request.attempt)
        return script[request.attempt - 1] if request.attempt <= len(script) else None

    def decrypt(password: bytes) -> bytes:
        tried.append(password)
        if password != b"right":
            raise EncryptionError("bad")
        return b"data"

    candidates = _PasswordCandidates(provider=provider)
    assert candidates.attempt(None, decrypt) == b"data"
    assert asks == [1, 2, 3, 4, 5]
    assert tried == [b"a", b"b", b"right"]


def test_password_candidates_provider_cycling_stops_after_three_repeats() -> None:
    # A provider cycling through answers it already gave stops after three in a row,
    # even when they are not the same answer: "right" is never asked for.
    script = [b"a", b"b", b"a", b"b", b"a", b"right"]
    asks: list[int] = []
    tried: list[bytes] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asks.append(request.attempt)
        return script[request.attempt - 1] if request.attempt <= len(script) else None

    def decrypt(password: bytes) -> bytes:
        tried.append(password)
        if password != b"right":
            raise EncryptionError("bad")
        return b"data"

    candidates = _PasswordCandidates(provider=provider)
    with pytest.raises(EncryptionError):
        candidates.attempt(None, decrypt)
    assert asks == [1, 2, 3, 4, 5]
    assert tried == [b"a", b"b"]


def test_password_candidates_provider_new_answer_resets_the_repeat_count() -> None:
    # Only repeats in a row count: a person who re-types each password once is never
    # cut off, however many passwords they go through.
    script = [b"a", b"a", b"b", b"b", b"c", b"c", b"right"]
    asks: list[int] = []
    tried: list[bytes] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asks.append(request.attempt)
        return script[request.attempt - 1] if request.attempt <= len(script) else None

    def decrypt(password: bytes) -> bytes:
        tried.append(password)
        if password != b"right":
            raise EncryptionError("bad")
        return b"data"

    candidates = _PasswordCandidates(provider=provider)
    assert candidates.attempt(None, decrypt) == b"data"
    assert asks == [1, 2, 3, 4, 5, 6, 7]
    assert tried == [b"a", b"b", b"c", b"right"]


def test_password_candidates_provider_wrong_repeated_then_right() -> None:
    # The password-matrix row: a wrong answer, the same again, then the right one.
    script = [b"a", b"a", b"right"]
    asks: list[int] = []
    tried: list[bytes] = []

    def provider(request: PasswordRequest) -> bytes | None:
        asks.append(request.attempt)
        return script[request.attempt - 1] if request.attempt <= len(script) else None

    def decrypt(password: bytes) -> bytes:
        tried.append(password)
        if password != b"right":
            raise EncryptionError("bad")
        return b"data"

    candidates = _PasswordCandidates(provider=provider)
    assert candidates.attempt(None, decrypt) == b"data"
    assert asks == [1, 2, 3]
    assert tried == [b"a", b"right"]


def test_password_candidates_provider_repeat_of_candidate_terminates() -> None:
    # A provider echoing a static candidate that already failed also makes no progress.
    decrypt_calls: list[bytes] = []

    def decrypt(password: bytes) -> bytes:
        decrypt_calls.append(password)
        raise EncryptionError("bad")

    def provider(request: PasswordRequest) -> str | None:
        return "cand"

    candidates = _PasswordCandidates(candidates=[b"cand"], provider=provider)
    with pytest.raises(EncryptionError):
        candidates.attempt(None, decrypt)
    # "cand" is tried once as a static candidate; the provider echo doesn't re-run it.
    assert decrypt_calls == [b"cand"]


def test_password_candidates_sequence_order() -> None:
    tried: list[bytes] = []

    def decrypt(password: bytes) -> bytes:
        tried.append(password)
        if password == b"second":
            return b"data"
        raise EncryptionError("bad")

    candidates = _PasswordCandidates.from_input([b"first", b"second"])
    assert candidates.attempt(None, decrypt) == b"data"
    assert tried == [b"first", b"second"]


def test_password_candidates_str_with_lone_surrogates() -> None:
    """A ``sys.argv``/``fsdecode`` escape gives back its byte; any other is refused."""
    candidates = _PasswordCandidates.from_input(["caf\udce9", b"x"])
    assert list(candidates.iter_candidates()) == [b"caf\xe9", b"x"]
    with pytest.raises(ArchiveyUsageError):
        _PasswordCandidates.from_input("\ud800")


@requires_binary("7z")
def test_multi_password_zip_streaming_pass(tmp_path: Path) -> None:
    archive = tmp_path / "mpw.zip"
    _make_multi_password_zip(archive)

    with open_archive(archive, password=[b"secret1", b"secret2"], streaming=True) as ar:
        contents = {
            member.name: stream.read() if stream is not None else None
            for member, stream in ar.stream_members()
            if member.type is MemberType.FILE
        }
    assert contents == {"f1.txt": b"secret1\n", "f2.txt": b"secret2\n"}


def _make_encrypted_7z(path: Path, *, solid: bool, password: str = "correctpw") -> None:
    """A 3-member 7z with an unencrypted header and encrypted folder(s).

    ``solid=True`` puts all three in one folder; ``solid=False`` gives each its own,
    which is what makes per-folder laziness observable.
    """
    for i in range(3):
        (path.parent / f"f{i}.txt").write_bytes(f"member {i} ".encode() * 20000)
    subprocess.run(
        [
            "7z",
            "a",
            f"-p{password}",
            "-mhe=off",
            "-ms=on" if solid else "-ms=off",
            str(path),
            "f0.txt",
            "f1.txt",
            "f2.txt",
            "-y",
        ],
        cwd=path.parent,
        check=True,
        capture_output=True,
    )


@requires_binary("7z")
@pytest.mark.parametrize("solid", [True, False], ids=["solid", "nonsolid"])
def test_7z_iterating_without_reading_never_asks_for_a_password(
    tmp_path: Path, solid: bool
) -> None:
    """A folder nobody reads is never decoded, so a wrong password goes unnoticed.

    The corollary matters more than the mechanism: iterating a ``stream_members``
    pass without error is *not* evidence that the password is right.
    """
    archive = tmp_path / "enc.7z"
    _make_encrypted_7z(archive, solid=solid)

    with open_archive(archive, password="wrongpassword") as ar:
        names = [member.name for member, _ in ar.stream_members()]
    assert names == ["f0.txt", "f1.txt", "f2.txt"]


@requires("cryptography")
@requires_binary("7z")
@pytest.mark.parametrize("solid", [True, False], ids=["solid", "nonsolid"])
def test_7z_wrong_password_raises_on_the_read_not_the_yield(
    tmp_path: Path, solid: bool
) -> None:
    archive = tmp_path / "enc.7z"
    _make_encrypted_7z(archive, solid=solid)

    yielded: list[str] = []
    with (
        open_archive(archive, password="wrongpassword") as ar,
        pytest.raises(EncryptionError),
    ):
        for member, stream in ar.stream_members():
            yielded.append(member.name)
            if member.name == "f2.txt":
                assert stream is not None
                stream.read()

    # The whole pass got through before the failure: the error came from the read,
    # not from reaching the member.
    assert yielded == ["f0.txt", "f1.txt", "f2.txt"]


@requires("cryptography")
@requires_binary("7z")
def test_7z_reading_one_member_opens_only_its_own_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-folder laziness: the two folders nobody reads are never opened."""
    archive = tmp_path / "enc.7z"
    _make_encrypted_7z(archive, solid=False)
    member_size = len("member 0 ") * 20000

    opened: list[int] = []
    original = SevenZipReader._open_folder_stream

    def spy(self: SevenZipReader, folder_index: int, *args: object, **kwargs: object):
        opened.append(folder_index)
        return original(self, folder_index, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(SevenZipReader, "_open_folder_stream", spy)

    with enable_measurement(), open_archive(archive, password="correctpw") as ar:
        for member, stream in ar.stream_members():
            if member.name == "f1.txt":
                assert stream is not None
                assert len(stream.read()) == member_size
        stats = ar.io_stats()

    assert len(opened) == 1, f"expected one folder open, got {opened}"
    assert stats is not None
    assert stats.bytes_decompressed == member_size


@requires_binary("7z")
def test_zip_provider_receives_member(tmp_path: Path) -> None:
    archive = tmp_path / "one.zip"
    (tmp_path / "only.txt").write_bytes(b"hello\n")
    subprocess.run(
        ["7z", "a", "-tzip", str(archive), "only.txt", "-phunter2", "-y"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    seen: list[PasswordRequest] = []

    def provider(request: PasswordRequest) -> str | None:
        seen.append(request)
        return "hunter2"

    with open_archive(archive, password=provider) as ar:
        assert ar.read("only.txt") == b"hello\n"
    assert len(seen) == 1
    assert seen[0].member is not None
    assert seen[0].member.name == "only.txt"
    assert seen[0].attempt == 1


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        # The marker keeps the backend's message, whatever its wording.
        (
            wrong_password_error("Incorrect key for this member"),
            "Incorrect key for this member",
        ),
        # Unmarked text that happens to say "wrong password" does not.
        (
            EncryptionError("Wrong password, or so it seems"),
            "Password(s) rejected for this encrypted member",
        ),
    ],
)
def test_exhaustion_message_follows_the_marker_not_the_wording(
    raised: EncryptionError, expected: str
) -> None:
    def decrypt(_password: bytes) -> bytes:
        raise raised

    candidates = _PasswordCandidates.from_input("guess")
    with pytest.raises(EncryptionError) as caught:
        candidates.attempt(None, decrypt)
    assert caught.value.message == expected


@requires_binary("7z")
def test_a_wrong_zip_password_raises_a_plain_encryption_error(tmp_path: Path) -> None:
    """The mark rides on the exception; the type a caller sees stays public."""
    archive = tmp_path / "secret.zip"
    # ZipCrypto checks a password against one byte of a random header, so about one
    # archive in 256 accepts "wrongpw" and the read fails its CRC instead. Build until
    # the stdlib rejects it up front, which is the case this test is about.
    for _ in range(20):
        archive.unlink(missing_ok=True)
        _make_multi_password_zip(archive)
        try:
            zipfile.ZipFile(archive).open("f1.txt", pwd=b"wrongpw").close()
        except RuntimeError:
            break
    else:  # pragma: no cover - (1/256) ** 20
        pytest.fail("every archive built accepted the wrong password's check byte")
    with open_archive(archive, password="wrongpw") as reader:
        member = next(m for m in reader.members() if m.name == "f1.txt")
        with pytest.raises(EncryptionError) as caught:
            reader.open(member).read()
    assert type(caught.value) is EncryptionError
    assert caught.value.message == "Wrong password for this ZIP member"


# Wrong-password wording a raise site may use without the mark: the two unrar
# exit-code sites, which never feed ``_PasswordCandidates.attempt``.
_UNMARKED_WRONG_PASSWORD_MESSAGES = {
    ("internal/backends/rar_reader.py", "Incorrect RAR password or encrypted member"),
}


def _message_text(node: ast.expr) -> str:
    """The literal text of a message argument, with ``{…}`` for interpolated parts."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
            else "{…}"
            for part in node.values
        )
    return ""


def test_every_wrong_password_message_carries_the_mark() -> None:
    """Every ``EncryptionError(...)`` whose message says the password is wrong uses the mark.

    Walks the AST, so a message split over several literals (what the formatter does
    to a long one) is joined before matching, and f-string text counts too. A message
    built entirely from an expression (``raw_message_of(exc)``) has no text to match
    and is not checked.
    """
    src = Path(archivey.__file__).parent
    wording = re.compile(r"wrong password|incorrect .*password", re.IGNORECASE)
    unmarked: set[tuple[str, str]] = set()
    for path in src.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "EncryptionError"
                and node.args
            ):
                message = _message_text(node.args[0])
                if wording.search(message):
                    unmarked.add((path.relative_to(src).as_posix(), message))
    assert unmarked == _UNMARKED_WRONG_PASSWORD_MESSAGES


def _verdict_decrypt(
    verdicts: dict[bytes, str], tried: list[bytes]
) -> Callable[[bytes], tuple[bytes, str]]:
    """A probe that answers each password from ``verdicts`` (missing means rejected)."""

    def decrypt(password: bytes) -> tuple[bytes, str]:
        tried.append(password)
        if password not in verdicts:
            raise wrong_password_error("Wrong password for this test unit")
        return password, verdicts[password]

    return decrypt


def _is_confirmed(result: tuple[bytes, str]) -> bool:
    return result[1] == "confirmed"


def test_a_settled_candidate_stops_the_loop() -> None:
    """A confirmed candidate wins at once: an expensive probe runs for none after it."""
    tried: list[bytes] = []
    candidates = _PasswordCandidates.from_input([b"a", b"b", b"c"])
    result = candidates.attempt(
        None,
        _verdict_decrypt({b"b": "confirmed", b"c": "confirmed"}, tried),
        settled=_is_confirmed,
        settle=lambda _password, _result: pytest.fail("no survivor to settle"),
    )
    assert result == (b"b", "confirmed")
    assert tried == [b"a", b"b"]


def test_an_unsettled_survivor_does_not_win_outright() -> None:
    """The rest of the list is probed; a lone survivor then wins with no full check."""
    tried: list[bytes] = []
    candidates = _PasswordCandidates.from_input([b"a", b"b", b"c"])
    result = candidates.attempt(
        None,
        _verdict_decrypt({b"a": "inconclusive"}, tried),
        promote=_is_confirmed,
        settled=_is_confirmed,
        settle=lambda _password, _result: pytest.fail("one survivor needs no check"),
    )
    assert result == (b"a", "inconclusive")
    assert tried == [b"a", b"b", b"c"]
    # Kept out of known-good: another candidate could still be right for later units.
    assert list(candidates.iter_candidates()) == [b"a", b"b", b"c"]


def test_several_survivors_are_settled_in_order() -> None:
    """The full check runs on each survivor until one settles; that one is promoted."""
    tried: list[bytes] = []
    settled_calls: list[bytes] = []

    def settle(password: bytes, _result: tuple[bytes, str]) -> tuple[bytes, str]:
        settled_calls.append(password)
        if password == b"c":
            return password, "confirmed"
        raise wrong_password_error("Wrong password for this test unit")

    candidates = _PasswordCandidates.from_input([b"a", b"b", b"c"])
    result = candidates.attempt(
        None,
        _verdict_decrypt({b"a": "inconclusive", b"c": "inconclusive"}, tried),
        promote=_is_confirmed,
        settled=_is_confirmed,
        settle=settle,
    )
    assert result == (b"c", "confirmed")
    assert settled_calls == [b"a", b"c"]
    assert next(candidates.iter_candidates()) == b"c"


def test_survivors_the_full_check_cannot_settle_fall_back_to_the_first() -> None:
    """A unit with nothing to walk to keeps the first survivor, as before."""
    candidates = _PasswordCandidates.from_input([b"a", b"b"])
    result = candidates.attempt(
        None,
        _verdict_decrypt({b"a": "inconclusive", b"b": "inconclusive"}, []),
        settled=_is_confirmed,
        settle=lambda password, result: result,
    )
    assert result == (b"a", "inconclusive")


def test_survivors_the_full_check_all_rejects_exhaust_the_list() -> None:
    def settle(_password: bytes, _result: tuple[bytes, str]) -> tuple[bytes, str]:
        raise wrong_password_error("Wrong password for this test unit")

    candidates = _PasswordCandidates.from_input([b"a", b"b"])
    with pytest.raises(EncryptionError, match="Wrong password for this test unit"):
        candidates.attempt(
            None,
            _verdict_decrypt({b"a": "inconclusive", b"b": "inconclusive"}, []),
            settled=_is_confirmed,
            settle=settle,
        )


def test_provider_answers_are_not_gathered() -> None:
    """The provider is lazy: its first answer that survives the probe wins."""
    asked: list[int] = []

    def provider(request: PasswordRequest) -> str | None:
        asked.append(request.attempt)
        return ["a", "b"][request.attempt - 1] if request.attempt <= 2 else None

    candidates = _PasswordCandidates.from_input(provider)
    result = candidates.attempt(
        None,
        _verdict_decrypt({b"a": "inconclusive", b"b": "confirmed"}, []),
        settled=_is_confirmed,
        settle=lambda _password, _result: pytest.fail("provider answers not settled"),
    )
    assert result == (b"a", "inconclusive")
    assert asked == [1]
