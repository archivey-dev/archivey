"""Run ``unar`` (The Unarchiver's XADMaster command-line tool) for member bytes on stdout.

Format-agnostic. The caller names the archive by path and the entries by ``unar``'s own
entry indexes, in the order ``lsar`` lists them. This module does not decide which
archives ``unar`` reads correctly; a backend refuses those before it calls here
(see :mod:`archivey.internal.backends.rar_unar` for RAR).

The argv is fixed except for the archive path and the optional index list:

``unar -o - -q -nr -k skip [-p <password>] [-i] -- <absolute archive path> [index …]``

- ``-o -`` writes every selected entry to stdout, concatenated in archive order with no
  framing, and creates no file.
- ``-nr`` stops ``unar`` from opening an archive found inside the archive and emitting
  *its* contents instead (a ``.tar.gz`` member would otherwise come out as tar members).
- ``-k skip`` drops Mac OS resource forks, which would otherwise reach stdout as extra
  bytes after the data fork.
- ``-i`` makes every trailing argument an entry index; without it, every entry is
  selected. Indexes are decimal numbers built
  here, so a hostile entry name never reaches the argv; there is no include mask to
  match siblings, and no glob to backtrack on.
- ``--`` ends option parsing and the archive path is absolute, so a path that starts
  with ``-`` cannot read as an option.

A password goes on the command line as ``-p <password>``, the only way ``unar``
accepts one. **Other local users can read it** from the process list (``ps``,
``/proc/<pid>/cmdline``) while ``unar`` runs; the public docs say so. ``unar`` answers a
wrong password with exit 0 and no output, so :class:`UnarOutputStream` can map an empty
pipe to ``EncryptionError`` when the caller says the entry is encrypted. Measured on
1.10.1: a password that is not ASCII does not decrypt (RAR5), whatever the locale, so
:func:`unar_password_supported` rejects one before ``unar`` runs.

A ``unar`` that identifies itself is also checked once for what it does: it must decode
an 85-byte RAR5 archive (:data:`_RAR5_PROBE_ARCHIVE`) whose one member the Debian and
Ubuntu ``unar`` packages that carry ``CSInputBuffer-bit-string-reading.patch`` write
as nothing, with exit 0. Those builds lose about one compressed RAR5 member in 25, and
no version string tells them apart from a good build, so one that fails the check is
not used (:func:`unar_rar5_probe_failure`). ``dev-docs/known-issues.md`` has the
measurements.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import IO, BinaryIO

from archivey.exceptions import CorruptionError, EncryptionError
from archivey.internal.external import cli
from archivey.internal.external.cli import (
    Banner,
    CliToolFinder,
    ProcessOutputStream,
    signal_exit_error,
    spawn_for_stdout,
)
from archivey.internal.streams.child_process import describe_exit, is_system_kill

# Inclusive floor. Measured: Debian/Ubuntu ``unar`` 1.10.1 and MacPaw XADMaster v1.10.8
# built from source (banner v1.10.7). Homebrew's formula builds the same v1.10.8.
UNAR_VERSION_FLOOR: tuple[int, int] = (1, 10)

# ``unar -h`` opens with ``unar v1.10.1, a tool for extracting the contents of archive
# files.`` (Debian). Homebrew's build adds its build date: ``unar v1.10.7 (Oct 10
# 2023), a tool for extracting …``. The digit runs are bounded so ``int()`` cannot hit
# CPython's digit limit, and ``[0-9]``, not ``\d``, which matches Unicode digits too
# (``tests/test_src_regex_ascii.py`` holds the rule).
_UNAR_BANNER_RE = re.compile(
    r"^unar v([0-9]{1,4})\.([0-9]{1,4})(?:\.([0-9]{1,4}))?(?: \([^)\n]{0,64}\))?, "
    r"a tool for extracting",
    re.MULTILINE,
)

UNAR_INSTALL_HINT = (
    "Install unar 1.10 or later (Homebrew: brew install unar; Debian and Ubuntu: "
    "apt install unar, though packages before 1.10.8+ds1-10 fail archivey's RAR5 "
    "check and are not used)."
)


def parse_unar_banner(text: str) -> Banner:
    """Classify the output of ``unar -h``."""
    match = _UNAR_BANNER_RE.search(text)
    if match is None:
        return Banner(identified=False, version=None)
    parts = tuple(int(group) for group in match.groups() if group is not None)
    return Banner(identified=True, version=parts)


# ``tests/fixtures/rar/unar_drop__.rar`` (``scripts/gen_rar_fixtures.py``
# ``_build_unar_drop``): RAR 7.00 ``-m3``, one 14-byte member ``f.txt`` whose last
# Huffman lookup peeks past the end of its packed data. A ``unar`` build with Debian's
# bit-reader patch writes nothing for it and exits 0; upstream 1.10.1, 1.10.7, 1.10.8
# and master write it exactly. ``scripts/find_unar_probe_member.py`` found the member
# and explains the condition.
_RAR5_PROBE_ARCHIVE = bytes.fromhex(
    "526172211a0701003392b5e50a010506000501018080004ef6e8102302030b8e"
    "00048e00a4830245296e7180030105662e7478740a0313e8ecbf6a629e630fc7"
    "960b022fe156f7f1087be6e96c1d77565103050400"
)
_RAR5_PROBE_MEMBER = b"aaaaabababbabb"

# Reserved for the signature measured on the patched builds: exit 0 and less than the
# member. Any other failure says what happened instead.
_DROPS_MEMBERS = (
    "drops some compressed RAR5 members: it wrote {size} bytes, not {want}, for a test "
    "archive, and exited 0. Debian and Ubuntu unar packages before 1.10.8+ds1-10 "
    "(Ubuntu 22.04 to 26.04 among them) carry a patch, "
    "CSInputBuffer-bit-string-reading.patch, that does this, so archivey does not use "
    "this unar. Install RARLAB unrar, or a unar built without that patch (1.10.8 from "
    "Homebrew or from source)."
)


def unar_rar5_probe_failure(unar: str) -> str | None:
    """Run ``unar`` once on the embedded RAR5 test archive: ``None`` when it decodes it.

    Otherwise, why this ``unar`` is not used, as text that follows its path. A run that
    cannot start, runs out of time (``PROBE_TIMEOUT_SECONDS``), exits non-zero or
    writes the wrong bytes is a failure. ``OSError`` comes from the two file-system
    steps before the run, creating the private directory and writing the archive into
    it; a program that cannot start is a failure, not an ``OSError``.

    The archive is written as ``archive.rar`` in a directory of its own, because
    ``unar`` picks a volume set by file name (``RarReader._unar_archive_path``).
    """
    temp_dir = Path(tempfile.mkdtemp(prefix="archivey-unar-probe-"))
    try:
        archive = temp_dir / "archive.rar"
        archive.write_bytes(_RAR5_PROBE_ARCHIVE)
        return _run_rar5_probe(unar, archive)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _run_rar5_probe(unar: str, archive: Path) -> str | None:
    """Decode ``archive`` with ``unar`` and judge the result. See the caller."""
    want = len(_RAR5_PROBE_MEMBER)
    timeout = cli.PROBE_TIMEOUT_SECONDS
    try:
        proc = subprocess.Popen(
            unar_argv(unar, archive, None),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        return f"could not be run on a test archive ({exc}). {UNAR_INSTALL_HINT}"
    if proc.stdout is None:  # stdout=PIPE was asked for; satisfies the type checkers
        cli.terminate_process(proc)
        return f"gave no output pipe for a test archive. {UNAR_INSTALL_HINT}"
    # The timer kills a program that runs too long, which ends the read below with end
    # of file. ``killed`` tells that kill apart from one that came from outside.
    killed = threading.Event()

    def _kill() -> None:
        killed.set()
        try:
            proc.kill()
        except OSError:
            pass

    timer = threading.Timer(timeout, _kill)
    timer.daemon = True
    timer.start()
    try:
        # One byte past the member is enough to fail it; nothing more is held.
        out = _read_at_most(proc.stdout, want + 1)
        if len(out) <= want:
            # End of file: the program closed its output and is exiting. The timer
            # still bounds the wait.
            proc.wait()
    finally:
        timer.cancel()
        # Stops a program still writing past the member, and reaps it.
        cli.terminate_process(proc)
        proc.stdout.close()
    returncode = proc.returncode
    if out == _RAR5_PROBE_MEMBER and returncode == 0:
        return None
    if len(out) > want:
        return (
            f"wrote more than {want} bytes for a test archive whose one member is "
            f"{want} bytes, so archivey does not use this unar. {UNAR_INSTALL_HINT}"
        )
    if killed.is_set():
        return (
            f"did not decode an 85-byte test archive within {timeout:g} seconds. "
            "archivey does not try an unchanged binary again in this process. "
            f"{UNAR_INSTALL_HINT}"
        )
    if returncode == 0:
        if len(out) < want:
            return _DROPS_MEMBERS.format(size=len(out), want=want)
        return (
            f"wrote {want} bytes for a test archive's {want}-byte member, but not the "
            f"member's bytes, so archivey does not use this unar. {UNAR_INSTALL_HINT}"
        )
    how = describe_exit(returncode)
    if is_system_kill(returncode):
        return (
            f"was killed ({how}) while decoding a test archive. SIGKILL comes from "
            "outside the program, most often the system's out-of-memory killer; "
            "archivey does not try an unchanged binary again in this process. "
            f"{UNAR_INSTALL_HINT}"
        )
    if returncode < 0:
        return (
            f"stopped on a signal ({how}) while decoding a test archive, after "
            f"writing {len(out)} of its {want} bytes, so archivey does not use this "
            f"unar. {UNAR_INSTALL_HINT}"
        )
    return (
        f"failed on a test archive ({how}) after writing {len(out)} of its {want} "
        f"bytes, so archivey does not use this unar. {UNAR_INSTALL_HINT}"
    )


def _read_at_most(stream: IO[bytes], limit: int) -> bytes:
    """Read until ``limit`` bytes or end of file, whichever comes first."""
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


_finder = CliToolFinder(
    display_name="unar",
    names=("unar",),
    probe_args=("-h",),
    parse_banner=parse_unar_banner,
    version_floor=UNAR_VERSION_FLOOR,
    install_hint=UNAR_INSTALL_HINT,
    # Looked up at call time, so a test can replace the module function.
    verify=lambda path: unar_rar5_probe_failure(path),
)


def find_unar(*, purpose: str) -> str:
    """Absolute path of a usable ``unar`` 1.10+ on ``PATH``, or ``PackageNotInstalledError``.

    Usable: it identifies itself, and it decodes the RAR5 test archive
    (:func:`unar_rar5_probe_failure`). Each binary pays for both once per process.
    """
    return _finder.find(purpose=purpose)


def clear_unar_cache() -> None:
    """Forget the identification answers. For tests that swap ``unar`` on ``PATH``."""
    _finder.clear_cache()


def unar_password_supported(password: str) -> bool:
    """Whether ``unar`` 1.10 can use ``password``: ASCII only, and no NUL for argv."""
    return password.isascii() and "\x00" not in password


def unar_argv(
    unar: str,
    archive_path: str | Path,
    indexes: Sequence[int] | None,
    *,
    password: str | None = None,
) -> list[str]:
    """The complete argv for one ``unar`` stdout run. See the module docstring.

    ``indexes=None`` selects every entry. An empty sequence is refused: ``unar -i`` with
    no index also selects every entry, which is never what an empty selection means.
    ``password`` is passed as the value of ``-p``, a separate argument, so one that
    starts with ``-`` is still read as the value.
    """
    cmd = [unar, "-o", "-", "-q", "-nr", "-k", "skip"]
    if password is not None:
        if not unar_password_supported(password):
            raise ValueError("unar cannot use a password with non-ASCII or NUL")
        cmd += ["-p", password]
    selected: list[str] = []
    if indexes is not None:
        if not indexes:
            raise ValueError(
                "unar_argv needs at least one entry index, or None for all"
            )
        if any(index < 0 for index in indexes):
            raise ValueError("unar entry indexes are non-negative")
        cmd.append("-i")
        selected = [str(index) for index in indexes]
    return [*cmd, "--", str(Path(archive_path).absolute()), *selected]


def open_unar_stdout(
    archive_path: str | Path,
    indexes: Sequence[int] | None,
    *,
    purpose: str,
    password: str | None = None,
) -> tuple[subprocess.Popen[bytes], BinaryIO]:
    """Spawn ``unar`` for the given entries (``None``: all) and return ``(proc, stdout)``.

    The caller owns the process: wrap ``stdout`` in :class:`UnarOutputStream` at once,
    or call :func:`~archivey.internal.external.cli.terminate_process` on failure.

    Reading ``stdout`` has no time bound, for the reason ``open_unrar_p`` gives: a solid
    archive legitimately produces no bytes while earlier entries decode.
    """
    unar = find_unar(purpose=purpose)
    # ``unar`` asks for a missing password on a terminal. With stdin on DEVNULL (the
    # default) it reports the missing password and exits non-zero instead.
    return spawn_for_stdout(
        unar_argv(unar, archive_path, indexes, password=password),
        name="unar",
        not_started=f"unar could not be started {purpose}. {UNAR_INSTALL_HINT}",
    )


class UnarOutputStream(ProcessOutputStream):
    """``unar`` stdout that owns the process: close stops and reaps it.

    The exit status is checked once the pipe reaches end of file: on that read, or on
    close if the child exited after that read. A child still running at close is
    stopped and its status not checked. ``unar`` exits 0 on success and 1 or 2
    on a failure it noticed (bad data, missing password). A negative status is a
    signal: a crash, which ``unar`` 1.10.1 does on some archives, or a kill from
    outside. Neither is a verdict on the data (:func:`signal_exit_error`), and both
    are reported even when the caller verifies digests, whose short read would
    otherwise say the archive is truncated. A close before end of file checks
    nothing: archivey closed the pipe on a child that was still writing, so whatever
    status follows is archivey's doing.

    ``unar`` also returns exit 0 with missing or short output on some archives, so exit
    status is not the integrity check. The caller verifies the declared size and any
    stored digest of every entry it reads; that is what catches short or wrong bytes.
    ``has_verifiable_digest`` says the caller does that for every byte of this pipe, and
    then a failure status is not reported: the digest check has already decided.

    ``empty_means_wrong_password`` says the pipe carries encrypted data that is not
    empty. ``unar`` answers a wrong password with exit 0 and nothing on stdout, so end
    of file before any byte then raises ``EncryptionError`` rather than the short read
    the caller's size check would report.
    """

    def __init__(
        self,
        stdout: BinaryIO,
        proc: subprocess.Popen[bytes],
        *,
        has_verifiable_digest: bool,
        empty_means_wrong_password: bool = False,
    ) -> None:
        self._has_verifiable_digest = has_verifiable_digest
        self._empty_means_wrong_password = empty_means_wrong_password
        self._saw_eof = False
        super().__init__(stdout, proc)

    def _at_eof(self) -> None:
        self._saw_eof = True
        if self._empty_means_wrong_password and self._bytes_read == 0:
            # This is the verdict; the exit status that follows (2 when no password was
            # given, 0 for a wrong one) must not replace it.
            self._exit_checked = True
            raise EncryptionError(
                "unar produced no data for encrypted content: the password is "
                "missing or wrong"
            )
        super()._at_eof()

    def _raise_for_returncode(self, rc: int) -> None:
        # A status before end of file is archivey's doing: it closed the pipe on a
        # program that was still writing.
        if rc == 0 or not self._saw_eof:
            return
        if rc < 0:
            # Checked before the digest: a program ended by a signal leaves the
            # caller's size check a short read to report, which would name a
            # truncated archive for what happened to the process.
            raise signal_exit_error("unar", rc)
        if self._has_verifiable_digest:
            return
        raise CorruptionError(f"unar reported a failure (exit {rc}) reading data")
