"""Native 7z reader fixture coverage."""

from __future__ import annotations

import io
import lzma
import os
import random
import shutil
import struct
import subprocess
import sys
import types
import zlib
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey import ExtractionStatus, open_archive
from archivey.config import (
    AcceleratorMode,
    ArchiveyConfig,
    PasswordInput,
    PasswordRequest,
)
from archivey.diagnostics import ARCHIVE_INTEGRITY_CODES, DiagnosticCode
from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    EncryptionError,
    PackageNotInstalledError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import sevenzip_aes
from archivey.internal.backends.sevenzip_parser import (
    SevenZipCoder,
    SevenZipFileRecord,
    SevenZipFolder,
)
from archivey.internal.backends.sevenzip_pipeline import open_folder_pipeline
from archivey.internal.backends.sevenzip_reader import (
    SevenZipReader,
    load_sevenzip_archive,
)
from archivey.internal.config import DEFAULT_STREAM_CONFIG
from archivey.internal.password_confirm import PASSWORD_CONFIRM_CHUNK_BYTES
from archivey.internal.streams import codecs, crypto
from archivey.types import CompressionAlgorithm, CreateSystem, HashAlgorithm, MemberType
from tests.conftest import (
    ReadSizeSpy,
    requires,
    requires_binary,
    requires_zstd,
    run_7z,
)
from tests.corruption_util import raises_corruption_not_truncation

_FILES = {
    "alpha.txt": b"alpha\n" * 100,
    "nested/beta.bin": bytes(range(64)) * 16,
}

# Repo root for subprocess PYTHONPATH (mirrors pyproject pythonpath = src, tests, .).
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _py7zr():
    return pytest.importorskip("py7zr")


def _filters(*names: str) -> list[dict[str, int]]:
    py7zr = _py7zr()
    return [{"id": getattr(py7zr, f"FILTER_{name}")} for name in names]


def _write_py7zr_archive(
    path: Path,
    files: dict[str, bytes],
    *,
    filters: list[dict[str, int]] | None = None,
    password: str | None = None,
    header_encryption: bool = False,
) -> None:
    py7zr = _py7zr()
    source = path.parent / f"{path.stem}-src"
    for name, data in files.items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    with py7zr.SevenZipFile(
        path,
        "w",
        filters=filters,
        password=password,
        header_encryption=header_encryption,
    ) as archive:
        for name in sorted(files):
            archive.write(source / name, arcname=name)


def _assert_roundtrip(
    path: Path, files: dict[str, bytes], *, password: PasswordInput = None
) -> None:
    with open_archive(path, password=password) as archive:
        members = {
            member.name: member for member in archive.members() if member.is_file
        }
        assert set(members) == set(files)
        for name, expected in files.items():
            assert archive.read(members[name]) == expected


def _codec_roundtrip_body(
    workdir: Path, label: str, filter_names: tuple[str, ...]
) -> None:
    """Build a py7zr fixture and read it back through the native reader."""
    archive = workdir / f"{label}.7z"
    _write_py7zr_archive(archive, _FILES, filters=_filters(*filter_names))
    _assert_roundtrip(archive, _FILES)


# NTSTATUS values Windows has surfaced (or may surface) for native aborts in this suite.
_WINDOWS_NTSTATUS: dict[int, str] = {
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",  # rapidgzip shutdown canary on win32
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0x80000003: "STATUS_BREAKPOINT",
}


def _format_windows_rc(returncode: int) -> str:
    """Human-readable subprocess return code, including known NTSTATUS names."""
    unsigned = returncode & 0xFFFFFFFF
    if returncode < 0 or returncode > 255:
        name = _WINDOWS_NTSTATUS.get(unsigned)
        if name is not None:
            return f"0x{unsigned:08X} ({name}); signed={returncode}"
        # Small negatives are usually POSIX signal exits (-N == signal N), not NTSTATUS.
        if -64 < returncode < 0:
            return f"{returncode} (likely signal {-returncode})"
        return f"0x{unsigned:08X} (unknown); signed={returncode}"
    return str(returncode)


_NATIVE_PROBE_MODULES: tuple[str, ...] = (
    "py7zr",
    "bcj",
    "pyppmd",
    "brotli",
    "inflate64",
    "rapidgzip",
    "Cryptodome",
    "cryptography",
    # Stdlib codecs the native 7z reader also uses:
    "lzma",
    "_lzma",
    "bz2",
    "_bz2",
    "zlib",
)


def _native_extension_probe() -> str:
    """Versions + file paths of native libs the codec matrix may load."""
    lines: list[str] = []
    for mod_name in _NATIVE_PROBE_MODULES:
        try:
            mod = __import__(mod_name)
        except ImportError as exc:
            lines.append(f"  {mod_name}: NOT IMPORTABLE ({exc})")
            continue
        ver = getattr(mod, "__version__", getattr(mod, "version", "?"))
        path = getattr(mod, "__file__", "?")
        lines.append(f"  {mod_name}: version={ver!s} path={path}")
    return "\n".join(lines)


def _windows_isolated_codec_roundtrip(
    tmp_path: Path, label: str, filter_names: tuple[str, ...]
) -> None:
    """Run one codec roundtrip in a fresh process.

    Windows CI has shown intermittent ``STATUS_HEAP_CORRUPTION`` (``0xc0000374``) mid
    ``test_py7zr_codec_fixtures_roundtrip``, aborting the entire pytest process. Isolating
    each codec contains the blast radius and surfaces which label crashed (non-zero rc /
    NTSTATUS) instead of a suite-wide fatal exception with an ambiguous stack.

    Isolation pinned the flake to the ``ppmd`` label (valid solid PPMd / ``pyppmd``).
    With PPMd decodes now bounded by folder ``unpack_size``, that param runs on
    ``win32`` again through this harness like the other codec labels; the non-blocking
    ``PPMd native stress`` workflow / ``scripts/ppmd_native_stress.py`` keep watching
    for regressions — see ``dev-docs/known-issues.md``.

    The child writes flushed phase breadcrumbs to ``phase.txt`` so a hard abort still
    leaves a last-known step for the parent to report.
    """
    import platform

    work = tmp_path / f"win-iso-{label}"
    work.mkdir()
    phase_path = work / "phase.txt"
    archive_path = work / f"{label}.7z"
    diag_path = work / "diag.txt"
    probe_mods = ", ".join(repr(m) for m in _NATIVE_PROBE_MODULES)

    # Driver: faulthandler + phase breadcrumbs + native-lib probe. Keep it self-contained
    # so a hard abort still leaves phase.txt / diag.txt for the parent to print.
    driver = work / "_driver.py"
    driver.write_text(
        "\n".join(
            [
                "from __future__ import annotations",
                "import faulthandler",
                "import os",
                "import platform",
                "import sys",
                "import traceback",
                "from pathlib import Path",
                "",
                "faulthandler.enable(all_threads=True, file=sys.stderr)",
                "",
                f"label = {label!r}",
                f"filter_names = {filter_names!r}",
                f"workdir = Path({str(work)!r})",
                f"phase_path = Path({str(phase_path)!r})",
                f"diag_path = Path({str(diag_path)!r})",
                f"archive_path = Path({str(archive_path)!r})",
                f"probe_mods = ({probe_mods},)",
                "",
                "def _phase(msg: str) -> None:",
                "    # Flushed line so a hard abort still leaves the last known step.",
                "    line = msg + '\\n'",
                "    with phase_path.open('a', encoding='utf-8') as fh:",
                "        fh.write(line)",
                "        fh.flush()",
                "        os.fsync(fh.fileno())",
                "    print(f'[phase] {msg}', flush=True)",
                "",
                "def _probe() -> str:",
                "    lines = [",
                "        f'python={sys.version!r}',",
                "        f'executable={sys.executable!r}',",
                "        f'platform={platform.platform()!r}',",
                "        f'machine={platform.machine()!r}',",
                "        f'label={label!r}',",
                "        f'filter_names={filter_names!r}',",
                '        f\'PYTHONPATH={os.environ.get("PYTHONPATH", "")!r}\',',
                "    ]",
                "    for mod_name in probe_mods:",
                "        try:",
                "            mod = __import__(mod_name)",
                "        except ImportError as exc:",
                "            lines.append(f'{mod_name}: NOT IMPORTABLE ({exc})')",
                "            continue",
                "        ver = getattr(mod, '__version__', getattr(mod, 'version', '?'))",
                "        path = getattr(mod, '__file__', '?')",
                "        lines.append(f'{mod_name}: version={ver!s} path={path}')",
                "    return '\\n'.join(lines)",
                "",
                "try:",
                "    _phase('start')",
                "    diag_path.write_text(_probe() + '\\n', encoding='utf-8')",
                "    _phase('diag-written')",
                "    from archivey import open_archive",
                "    from tests.test_sevenzip_reader import (",
                "        _FILES,",
                "        _filters,",
                "        _write_py7zr_archive,",
                "    )",
                "    _phase('imports-ok')",
                "    _phase(f'building-archive filters={filter_names!r}')",
                "    _write_py7zr_archive(archive_path, _FILES, filters=_filters(*filter_names))",
                "    size = archive_path.stat().st_size if archive_path.exists() else -1",
                "    head = archive_path.read_bytes()[:32].hex() if archive_path.exists() else ''",
                "    _phase(f'archive-built path={archive_path} size={size} head32={head}')",
                "    _phase('open_archive')",
                "    with open_archive(archive_path) as archive:",
                "        _phase('list_members')",
                "        members = {",
                "            member.name: member",
                "            for member in archive.members()",
                "            if member.is_file",
                "        }",
                "        _phase(f'listed count={len(members)} names={sorted(members)!r}')",
                "        assert set(members) == set(_FILES)",
                "        for name in sorted(_FILES):",
                "            _phase(f'read_member:{name}:start')",
                "            data = archive.read(members[name])",
                "            _phase(f'read_member:{name}:done len={len(data)}')",
                "            assert data == _FILES[name]",
                "    _phase('roundtrip-ok')",
                "except BaseException:",
                "    _phase('exception')",
                "    traceback.print_exc()",
                "    raise",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(_REPO_ROOT / "src"),
            str(_REPO_ROOT / "tests"),
            str(_REPO_ROOT),
            env.get("PYTHONPATH", ""),
        ]
    )
    # Prefer a full faulthandler dump on fatal native errors when the CRT cooperates.
    env.setdefault("PYTHONFAULTHANDLER", "1")

    proc = subprocess.run(
        [sys.executable, "-u", str(driver)],  # -u: unbuffered so phase prints survive
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    if proc.returncode == 0:
        return

    phase_text = (
        phase_path.read_text(encoding="utf-8") if phase_path.exists() else "<missing>"
    )
    diag_text = (
        diag_path.read_text(encoding="utf-8") if diag_path.exists() else "<missing>"
    )
    archive_info = "<not created>"
    if archive_path.exists():
        head = archive_path.read_bytes()[:32].hex()
        archive_info = (
            f"path={archive_path} size={archive_path.stat().st_size} "
            f"head32={head} "
            f"(preserved under tmp_path for CI artifact upload if configured)"
        )

    parent_probe = _native_extension_probe()
    pytest.fail(
        "Windows-isolated codec roundtrip FAILED — details for the next investigation:\n"
        f"  label={label!r}\n"
        f"  filter_names={filter_names!r}\n"
        f"  returncode={_format_windows_rc(proc.returncode)}\n"
        f"  parent python={sys.version!r}\n"
        f"  parent executable={sys.executable!r}\n"
        f"  parent platform={platform.platform()!r}\n"
        f"  child archive: {archive_info}\n"
        f"--- child phase breadcrumbs (last line = last step before abort) ---\n"
        f"{phase_text}"
        f"--- child diag (native libs / versions as seen in the child) ---\n"
        f"{diag_text}"
        f"--- parent native-lib probe ---\n"
        f"{parent_probe}\n"
        f"--- child stdout ---\n{proc.stdout}\n"
        f"--- child stderr (faulthandler dumps land here) ---\n{proc.stderr}\n"
    )


@pytest.mark.parametrize(
    ("label", "filter_names"),
    [
        pytest.param("stored", ("COPY",), id="stored"),
        pytest.param("lzma2", ("LZMA2",), id="lzma2"),
        pytest.param("lzma2-bcj", ("X86", "LZMA2"), id="lzma2-bcj"),
        pytest.param("lzma2-delta", ("DELTA", "LZMA2"), id="lzma2-delta"),
        pytest.param("deflate", ("DEFLATE",), id="deflate"),
        pytest.param("bzip2", ("BZIP2",), id="bzip2"),
        pytest.param("zstd", ("ZSTD",), marks=requires_zstd(), id="zstd"),
        pytest.param("brotli", ("BROTLI",), marks=requires("brotli"), id="brotli"),
        # PPMd: previously skipped on win32 due to intermittent pyppmd STATUS_HEAP_CORRUPTION
        # on unbounded decode(..., -1). archivey now always passes folder unpack_size as
        # max_length and never does unbounded after-eof decode; see known-issues.md.
        # Still covered by the non-blocking PPMd native stress workflow.
        pytest.param("ppmd", ("PPMD",), marks=requires("pyppmd"), id="ppmd"),
    ],
)
def test_py7zr_codec_fixtures_roundtrip(
    tmp_path: Path, label: str, filter_names: tuple[str, ...]
) -> None:
    if sys.platform == "win32":
        _windows_isolated_codec_roundtrip(tmp_path, label, filter_names)
        return
    _codec_roundtrip_body(tmp_path, label, filter_names)


def test_solid_archive_stream_and_random_access(tmp_path: Path) -> None:
    archive = tmp_path / "solid.7z"
    _write_py7zr_archive(archive, _FILES, filters=_filters("LZMA2"))

    with open_archive(archive) as reader:
        assert reader.info.is_solid is True
        streamed = {
            member.name: stream.read()
            for member, stream in reader.stream_members()
            if member.is_file and stream is not None
        }
        assert streamed == _FILES
        assert reader.read("nested/beta.bin") == _FILES["nested/beta.bin"]


def test_aes_encrypted_archive_roundtrip(tmp_path: Path) -> None:
    archive = tmp_path / "aes.7z"
    _write_py7zr_archive(archive, _FILES, password="secret")

    _assert_roundtrip(archive, _FILES, password="secret")
    with open_archive(archive) as reader:
        encrypted = next(member for member in reader.members() if member.is_file)
        with pytest.raises(EncryptionError):
            reader.read(encrypted)


@requires("cryptography")
def test_aes_encrypted_member_seeks_when_requested(tmp_path: Path) -> None:
    """Encrypted 7z members used to lose seek because AesDecryptStream had none."""
    archive = tmp_path / "aes-seek.7z"
    _write_py7zr_archive(archive, _FILES, password="secret")
    payload = _FILES["alpha.txt"]
    with open_archive(archive, password="secret", seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.name == "alpha.txt")
        with reader.open(member) as stream:
            assert stream.seekable() is True
            head = stream.read(5)
            assert head == payload[:5]
            stream.seek(0)
            assert stream.read() == payload
            stream.seek(10)
            assert stream.read() == payload[10:]


class _DecoderTruncatedStream:
    """Coder-stage stand-in: AES has already decrypted; this is the decoder.

    PPMd reports wrong-key garbage as ``TruncatedError("File is truncated")``
    (~0.5–0.8 % of wrong passwords). Confirm must remap that to
    ``EncryptionError`` so ``PasswordManager.attempt`` can try the next
    candidate. A hand-constructed AES-message ``TruncatedError`` from a
    fake pipeline (the old test) cannot tell the two origins apart.
    """

    def __init__(self, inner: object) -> None:
        self._inner = inner

    def read(self, _n: int = -1) -> bytes:
        raise TruncatedError("File is truncated")

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if close is not None:
            close()


def _patch_codec_raises_truncated(
    monkeypatch: pytest.MonkeyPatch, *, first_n: int | None = None
) -> dict[str, int]:
    """Raise decoder ``TruncatedError`` from the codec sitting on AES.

    ``first_n=None`` wraps every AES-backed codec; ``first_n=1`` wraps only
    the first (wrong-password confirm) so later candidates and the member
    open see the real decoder. Header LZMA (no AES) is left alone — a
    blanket ``open_codec_stream`` wrap fires during encoded-header decode
    and never reaches confirm. Patch ``_execute_stage``: that is the
    coder-stage open, and production never routes through a reader method.
    """
    import archivey.internal.backends.sevenzip_pipeline as pipeline_mod
    from archivey.internal.streams.crypto import AesDecryptStream

    original = pipeline_mod._execute_stage
    state = {"calls": 0, "wrapped": 0}

    def wrapping(stream: object, stage: object, **kwargs: object) -> object:
        out = original(stream, stage, **kwargs)
        if not isinstance(stream, AesDecryptStream):
            return out
        if not isinstance(
            stage, (pipeline_mod._CodecStage, pipeline_mod._LzmaChainStage)
        ):
            return out
        state["calls"] += 1
        if first_n is None or state["calls"] <= first_n:
            state["wrapped"] += 1
            return _DecoderTruncatedStream(out)
        return out

    monkeypatch.setattr(pipeline_mod, "_execute_stage", wrapping)
    return state


@requires("cryptography")
def test_decoder_truncated_error_during_confirm_is_wrong_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A decoder ``TruncatedError`` under a wrong password is still a bad key.

    AES+LZMA2 (py7zr default). The codec stage raises the same
    ``TruncatedError("File is truncated")`` PPMd emits on garbage. Confirm
    used to re-raise every ``TruncatedError``, which aborted password
    iteration. Origin-tagging means only the AES-CBC subclass passes
    through; this one remaps.

    Raise from the codec ``read()``, not from ``open_folder_pipeline``
    construction: confirm calls the pipeline *before* its ``try``.
    """
    archive = tmp_path / "aes-lzma2.7z"
    _write_py7zr_archive(archive, {"a.txt": b"hello" * 200}, password="secret")
    state = _patch_codec_raises_truncated(monkeypatch)

    with (
        pytest.raises(EncryptionError, match="Wrong password or corrupt 7z folder"),
        open_archive(archive, password="wrong") as reader,
    ):
        member = next(m for m in reader.members() if m.is_file)
        # Mutation D: catch base TruncatedError in the confirm
        # passthrough — this leaks TruncatedError and never remaps.
        reader.read(member)

    assert state["wrapped"] >= 1, "codec stage was never opened"


@requires("cryptography")
def test_decoder_truncated_error_does_not_abort_password_iteration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``PasswordManager.attempt`` advances only on ``EncryptionError``.

    First candidate: decoder ``TruncatedError`` (wrong key). That must
    remap so the second candidate is tried. AES+LZMA2 so the codec stage
    actually runs (Copy+AES never calls ``open_codec_stream``).
    """
    archive = tmp_path / "aes-lzma2.7z"
    payload = {"a.txt": b"hello" * 200}
    _write_py7zr_archive(archive, payload, password="secret")
    state = _patch_codec_raises_truncated(monkeypatch, first_n=1)

    # Mutation D: catch base TruncatedError in the confirm passthrough —
    # attempt aborts on the first candidate and never reaches "secret".
    with open_archive(archive, password=["wrong", "secret"]) as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert reader.read(member) == payload["a.txt"]

    assert state["wrapped"] == 1, (
        "decoder TruncatedError was not injected on the first candidate"
    )
    assert state["calls"] >= 2, "correct password never reached a real codec stage"


@requires_binary("7z")
@requires("cryptography")
def test_truncated_encrypted_folder_is_not_wrong_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Store+AES, correct password, pack view short of a last CBC block.

    Confirm used to drain the short block as garbage and, if that raised at
    all, remap it to ``EncryptionError``. Finalize now raises
    ``TruncatedError``; the confirm ladder must let that through.
    """
    payload = tmp_path / "blob.bin"
    payload.write_bytes(bytes(range(256)) * 8)
    archive = tmp_path / "store-aes-trunc.7z"
    result = run_7z(
        ["a", "-t7z", "-psecret", "-mhe=off", "-mx0", str(archive), payload.name, "-y"],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot build store+AES fixture: {result.stderr}")

    original = SevenZipReader._folder_pack_views

    def short_view(self: SevenZipReader, folder_index: int) -> list[BinaryIO]:
        (view,) = original(self, folder_index)
        data = view.read()
        assert len(data) >= 16
        return [io.BytesIO(data[:-5])]

    monkeypatch.setattr(SevenZipReader, "_folder_pack_views", short_view)

    with open_archive(archive, password="secret") as reader:
        member = next(m for m in reader.members() if m.is_file)
        # Mutation A: restore zero-pad drain — CRC mismatch, EncryptionError.
        # Mutation C: drop _AesCbcTruncatedError from the confirm passthrough —
        # same EncryptionError wrapping.
        with pytest.raises(TruncatedError, match="mid-block"):
            reader.read(member)


@requires("cryptography")
def test_truncated_aes_lzma2_folder_is_not_wrong_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AES+LZMA2 (py7zr default), correct password, pack view short of a last CBC block.

    AES ``finalize`` wins the race against the decompressor: a mid-block
    leftover is ``_AesCbcTruncatedError`` before LZMA2 sees a short stream.
    Confirm must let that subclass through. The store+AES case above is
    Copy; this is the compressed composition F1 lives in.
    """
    archive = tmp_path / "aes-lzma2-trunc.7z"
    _write_py7zr_archive(
        archive, {"blob.bin": bytes(range(256)) * 8}, password="secret"
    )

    original = SevenZipReader._folder_pack_views

    def short_view(self: SevenZipReader, folder_index: int) -> list[BinaryIO]:
        (view,) = original(self, folder_index)
        data = view.read()
        assert len(data) >= 16
        return [io.BytesIO(data[:-5])]

    monkeypatch.setattr(SevenZipReader, "_folder_pack_views", short_view)

    with open_archive(archive, password="secret") as reader:
        member = next(m for m in reader.members() if m.is_file)
        # Mutation A: restore zero-pad drain — LZMA2 rejects garbage,
        # EncryptionError.
        # Mutation C: drop _AesCbcTruncatedError from the confirm passthrough —
        # EncryptionError wrapping.
        with pytest.raises(TruncatedError, match="mid-block"):
            reader.read(member)


@requires_binary("7z")
@requires("cryptography")
def test_stored_encrypted_member_seeks_past_first_block(tmp_path: Path) -> None:
    """The py7zr LZMA2 fixtures only ever restart at block 0 because the
    decompressor rewinds to origin; a stored member seeks the AES stream
    directly, so an offset past block 0 exercises the CBC restart.

    7-Zip gives every COPY member its own folder regardless of ``-ms``, so
    this is not a prefix-over-AES case — that shape is not constructible
    with the CLI.
    """
    payloads = {
        "a.bin": bytes(range(256)) * 8,  # 2 KiB
        "b.bin": bytes(range(256))[::-1] * 8,
    }
    for name, data in payloads.items():
        (tmp_path / name).write_bytes(data)
    archive = tmp_path / "store-aes.7z"
    result = run_7z(
        ["a", "-t7z", "-psecret", "-mhe=off", "-mx0", str(archive), *payloads, "-y"],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot build store+AES fixture: {result.stderr}")

    offsets = (0, 7, 1000, 1023, 2047)
    with open_archive(archive, password="secret", seekable_members=True) as reader:
        members = {m.name: m for m in reader.members() if m.is_file}
        assert set(members) == set(payloads)
        for name, expected in payloads.items():
            chain = members[name].compression
            assert chain and all(c.algo is CompressionAlgorithm.STORED for c in chain)
            with reader.open(members[name]) as stream:
                assert stream.seekable() is True
                for off in offsets:
                    assert stream.seek(off) == off
                    assert stream.read() == expected[off:]


def _encrypted_codec_archive(tmp_path: Path, *, method: str, payload: bytes) -> Path:
    (tmp_path / "blob.bin").write_bytes(payload)
    archive = tmp_path / f"enc-{method.lower()}.7z"
    result = run_7z(
        [
            "a",
            "-t7z",
            f"-m0={method}",
            "-psecret",
            "-mhe=off",
            str(archive),
            "blob.bin",
            "-y",
        ],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot build encrypted {method} fixture: {result.stderr}")
    return archive


@requires_binary("7z")
@requires("cryptography")
@requires("rapidgzip")
@pytest.mark.parametrize(
    ("method", "config_field", "algo"),
    [
        ("Deflate", "use_rapidgzip", CompressionAlgorithm.DEFLATE),
        ("BZip2", "use_indexed_bzip2", CompressionAlgorithm.BZIP2),
    ],
)
def test_encrypted_deflate_family_seeks_with_accelerator(
    tmp_path: Path,
    method: str,
    config_field: str,
    algo: CompressionAlgorithm,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Encrypted Deflate/BZip2 with seekable_members=True, AUTO and ON.

    Deflate AUTO is blocked by the truncation-verifiability gate
    (``expected_decompressed_size is None`` on a 7z coder stage), so that
    leg pins the stdlib path over an AES source. Deflate ON pins the
    accelerator — the wrong-password lie. BZip2 AUTO and ON both
    engage rapidgzip's bundled indexed bzip2 (no verifiability gate).
    ``capfd`` catches the C-level ``Trailing garbage after EOF ignored!``
    that an unbounded AES pad used to print on the bzip2 accelerator.
    Seed 1 is load-bearing: AES unpack_size is not a multiple of 16, so
    the pad exists and the warning is observable (urandom is often aligned).
    """
    payload = random.Random(1).randbytes(1_600_000)
    archive = _encrypted_codec_archive(tmp_path, method=method, payload=payload)
    for mode in (AcceleratorMode.AUTO, AcceleratorMode.ON):
        config = ArchiveyConfig(**{config_field: mode})
        with open_archive(
            archive,
            password="secret",
            seekable_members=True,
            config=config,
        ) as reader:
            aes_unpack = reader._archive.folders[0].unpack_sizes[0]
            assert aes_unpack % 16, (
                "fixture AES unpack_size must include pad so trailing "
                "garbage is observable"
            )
            member = next(m for m in reader.members() if m.is_file)
            assert any(c.algo is algo for c in member.compression)
            with reader.open(member) as stream:
                assert stream.seekable() is True
                assert stream.read(16) == payload[:16]
                stream.seek(0)
                assert stream.read() == payload
                stream.seek(1000)
                assert stream.read() == payload[1000:]
        captured = capfd.readouterr()
        assert "Trailing garbage" not in captured.err


@requires("pyppmd")
@requires("cryptography")
def test_encrypted_ppmd_chunked_reads_roundtrip(tmp_path: Path) -> None:
    """Encrypted PPMd folder: PPMd's compressed input is the AES decrypt stream, which
    has no knowable length, so ``pack_size`` must be plumbed from the folder header
    (the AES coder's output size). Highly compressible members read in small chunks hit
    a premature native ``eof``; without the plumbed ``pack_size`` the decoder would
    truncate them (or refuse to construct). Read via ``open(...).read(64)`` — ``read()``
    alone passes a large ``max_length`` and would hide the regression.
    """
    if sys.platform == "win32":
        # Valid decodes are bounded/safe, but win32 PPMd runs are isolated in the
        # non-required stress workflow; keep required CI off the native-abort surface.
        pytest.skip("win32 PPMd runs are covered by the isolated stress workflow")
    files = {
        "big.txt": b"alpha\n" * 4000,  # compressible -> tiny pack -> premature eof
        "nested/z.bin": b"\x00" * 20000,
    }
    archive = tmp_path / "enc-ppmd.7z"
    # The crypto filter must be present for py7zr to actually AES-encrypt the content
    # (a bare password without it is a no-op). AES wraps PPMd, so PPMd's compressed
    # input is the unsized decrypt stream — the case the pipeline plumbing exists for.
    _write_py7zr_archive(
        archive,
        files,
        filters=_filters("PPMD", "CRYPTO_AES256_SHA256"),
        password="secret",
    )
    # Guard the fixture: a non-encrypted archive would make this test vacuous.
    with pytest.raises(EncryptionError), open_archive(archive) as unauth:
        unauth.read(next(m for m in unauth.members() if m.is_file))
    with open_archive(archive, password="secret") as reader:
        members = {m.name: m for m in reader.members() if m.is_file}
        assert set(members) == set(files)
        for name, expected in files.items():
            with reader.open(members[name]) as stream:
                chunks: list[bytes] = []
                while True:
                    piece = stream.read(64)
                    if not piece:
                        break
                    chunks.append(piece)
                assert b"".join(chunks) == expected, name


def test_header_encrypted_archive_requires_password(tmp_path: Path) -> None:
    archive = tmp_path / "header-encrypted.7z"
    _write_py7zr_archive(archive, _FILES, password="secret", header_encryption=True)

    with pytest.raises(EncryptionError, match="header"):
        open_archive(archive).close()
    _assert_roundtrip(archive, _FILES, password="secret")


def test_header_encrypted_wrong_password_mentions_header(tmp_path: Path) -> None:
    archive = tmp_path / "header-encrypted-wrong.7z"
    _write_py7zr_archive(archive, _FILES, password="secret", header_encryption=True)

    with pytest.raises(EncryptionError, match="(?i)header") as caught:
        open_archive(archive, password="wrong").close()
    assert "rejected" in caught.value.message.lower()
    assert "Password required" not in caught.value.message


def test_header_encrypted_password_list_order_does_not_matter(tmp_path: Path) -> None:
    """A wrong key's garbage header used to end the attempt at the first candidate."""
    archive = tmp_path / "header-encrypted-list.7z"
    _write_py7zr_archive(archive, _FILES, password="secret", header_encryption=True)
    _assert_roundtrip(archive, _FILES, password=["wrong", "secret"])


@requires("cryptography")
@requires_binary("7z")
def test_header_encrypted_cli_archive_password_list_order_does_not_matter(
    tmp_path: Path,
) -> None:
    """Same, on 7-Zip's own output, which (unlike py7zr) CRCs the encoded header."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.txt").write_bytes(b"hello")
    archive = tmp_path / "cli-header-encrypted.7z"
    run_7z(
        ["a", "-psecret", "-mhe=on", str(archive), str(source / "a.txt")], check=True
    )
    with open_archive(archive, password=["wrong", "secret"]) as reader:
        assert reader.read("a.txt") == b"hello"


def test_header_encrypted_provider_asked_again_after_a_wrong_answer(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "header-encrypted-provider.7z"
    _write_py7zr_archive(archive, _FILES, password="secret", header_encryption=True)
    asked: list[tuple[object, int]] = []

    def provider(request: PasswordRequest) -> str:
        asked.append((request.member, request.attempt))
        return "wrong" if request.attempt == 1 else "secret"

    _assert_roundtrip(archive, _FILES, password=provider)
    assert asked == [(None, 1), (None, 2)]


@requires("cryptography")
def test_header_encrypted_empty_decoded_header_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O8: EncodedHeader that decrypts to a file-less plain header is a rejected password.

    7zAES has no check value; py7zr omits the encoded-header folder CRC, so wrong-key
    garbage occasionally LZMA-decodes into a zero-member header (~0.3% of salts). Force
    that slip-through mode and require EncryptionError instead of a silent empty listing.
    """
    archive = tmp_path / "header-encrypted-o8.7z"
    _write_py7zr_archive(archive, _FILES, password="secret", header_encryption=True)

    # HEADER + END → PlainHeader with zero file records (legitimate empty archives use
    # nextHeaderSize == 0 instead, never an encrypted empty header).
    monkeypatch.setattr(
        "archivey.internal.backends.sevenzip_reader.decode_encoded_header",
        lambda *args, **kwargs: b"\x01\x00",
    )

    with pytest.raises(EncryptionError, match="(?i)rejected.*header") as caught:
        open_archive(archive, password="secret").close()
    assert "Password required" not in caught.value.message


@requires("cryptography")
def test_fuzz_header_target_reaches_the_encrypted_header_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Atheris 7z header target passes the corpus password.

    Without one, an AES-coded encoded header stops at "Password required" and the
    fuzzer never reaches the folder pipeline or the O8 check behind it.
    """
    pytest.importorskip("py7zr")
    from archivey.internal.backends import sevenzip_pipeline
    from tests.atheris_fuzz.targets import sevenzip_header_one
    from tests.sample_archives import CORPUS, corpus_archive_path

    entry = next(e for e in CORPUS if e.id == "encrypted-header")
    data = corpus_archive_path(entry, "7z", tmp_path).read_bytes()

    planned: list[object] = []
    original = sevenzip_pipeline.plan_folder

    def counting(folder: object) -> object:
        planned.append(folder)
        return original(folder)  # type: ignore[arg-type]

    monkeypatch.setattr(sevenzip_pipeline, "plan_folder", counting)
    sevenzip_header_one(data)
    assert planned


def test_lzma1_bcj_fixture_roundtrip(tmp_path: Path) -> None:
    """py7zr LZMA1+BCJ archives decode via a staged BCJ filter (not combined liblzma)."""
    archive = tmp_path / "lzma1-bcj.7z"
    _write_py7zr_archive(archive, _FILES, filters=_filters("X86", "LZMA"))
    _assert_roundtrip(archive, _FILES)


@requires_binary("7z")
def test_7z_cli_lzma1_bcj_avoids_liblzma_truncation(tmp_path: Path) -> None:
    """7-Zip CLI LZMA1+BCJ can silently truncate under combined liblzma filters.

    A ~12800-byte payload with 0xE8 call patterns reproduces the look-ahead flush
    failure (output 12796 instead of 12800). The staged BCJ filter must return
    full bytes.
    """
    payload = bytearray(os.urandom(12800))
    for offset in range(0, 12800 - 5, 40):
        payload[offset] = 0xE8
    payload_bytes = bytes(payload)
    src = tmp_path / "payload.bin"
    src.write_bytes(payload_bytes)
    archive = tmp_path / "lzma1-bcj-cli.7z"
    result = run_7z(
        ["a", "-t7z", "-m0=BCJ", "-m1=LZMA", str(archive), src.name, "-y"],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot write LZMA1+BCJ fixtures: {result.stderr}")

    _assert_roundtrip(archive, {src.name: payload_bytes})


@requires_binary("7z")
@pytest.mark.parametrize(
    ("switches", "expected"),
    [
        pytest.param(
            ("-m0=BCJ", "-m1=LZMA2"),
            (CompressionAlgorithm.BCJ, CompressionAlgorithm.LZMA2),
            id="bcj-lzma2",
        ),
        pytest.param(
            ("-m0=Delta:2", "-m1=BCJ", "-m2=LZMA2"),
            (
                CompressionAlgorithm.DELTA,
                CompressionAlgorithm.BCJ,
                CompressionAlgorithm.LZMA2,
            ),
            id="delta-bcj-lzma2",
        ),
        pytest.param(
            ("-m0=BCJ", "-m1=LZMA2", "-psecret"),
            (CompressionAlgorithm.BCJ, CompressionAlgorithm.LZMA2),
            id="bcj-lzma2-aes",
        ),
    ],
)
def test_member_compression_is_in_compress_order(
    tmp_path: Path,
    switches: tuple[str, ...],
    expected: tuple[CompressionAlgorithm, ...],
) -> None:
    """``member.compression`` runs filters first, packing codec last, as 7-Zip lists it.

    A folder stores its coders in decode order; a BCJ member used to read
    ``(LZMA2, BCJ)``. The ``-mN`` switches name the chain in compress order too.
    """
    src = tmp_path / "payload.bin"
    src.write_bytes(bytes(range(256)) * 64)
    archive = tmp_path / "chain.7z"
    result = run_7z(
        ["a", "-t7z", *switches, str(archive), src.name, "-y"],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot write {switches}: {result.stderr}")

    with open_archive(archive) as reader:
        (member,) = reader.members()
        assert tuple(m.algo for m in member.compression) == expected


@requires_binary("7z")
def test_bcj2_member_compression_starts_with_bcj2(tmp_path: Path) -> None:
    """BCJ2 is the last coder applied on decode, so it leads the compress-order tuple.

    The whole tuple, and why the side-branch coders are not in it, is pinned in
    tests/test_sevenzip_bcj2.py.
    """
    src = tmp_path / "payload.bin"
    src.write_bytes(bytes(range(256)) * 64)
    archive = tmp_path / "bcj2.7z"
    result = run_7z(
        [
            "a",
            "-t7z",
            "-m0=BCJ2",
            "-m1=LZMA",
            "-m2=LZMA",
            "-m3=LZMA",
            str(archive),
            src.name,
            "-y",
        ],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot write a BCJ2 fixture: {result.stderr}")

    with open_archive(archive) as reader:
        (member,) = reader.members()
        assert member.compression[0].algo is CompressionAlgorithm.BCJ2


def test_py7zr_member_compression_is_in_compress_order(tmp_path: Path) -> None:
    """py7zr's ``filters`` list is compress order; the member reads it back unchanged."""
    archive = tmp_path / "delta-bcj-lzma2.7z"
    _write_py7zr_archive(
        archive, {"x.bin": b"x" * 4096}, filters=_filters("DELTA", "X86", "LZMA2")
    )
    with open_archive(archive) as reader:
        (member,) = reader.members()
        assert tuple(m.algo for m in member.compression) == (
            CompressionAlgorithm.DELTA,
            CompressionAlgorithm.BCJ,
            CompressionAlgorithm.LZMA2,
        )


def test_unregistered_coder_is_listed_as_unknown_not_dropped() -> None:
    """A coder the registry does not know stays in the chain as ``UNKNOWN``.

    ``0x0f`` is a method id no 7-Zip registers. Dropping such a coder listed the member
    as plain LZMA, and the read then refused a codec the listing never showed. AES is
    encryption and stays out of the chain.
    """

    def coder(method: bytes) -> SevenZipCoder:
        return SevenZipCoder(
            method=method, num_in_streams=1, num_out_streams=1, properties=None
        )

    folder = SevenZipFolder(
        # Decode order: AES, then LZMA, then the unknown coder.
        coders=[coder(b"\x06\xf1\x07\x01"), coder(b"\x03\x01\x01"), coder(b"\x0f")],
        bind_pairs=[(1, 0), (2, 1)],
        packed_indices=[0],
        unpack_sizes=[16, 16, 16],
        crc=None,
        digest_defined=False,
    )
    (chain,) = SevenZipReader._build_folder_compression(
        types.SimpleNamespace(folders=[folder])
    )
    assert tuple(m.algo for m in chain) == (
        CompressionAlgorithm.UNKNOWN,
        CompressionAlgorithm.LZMA,
    )


def test_listing_walk_stops_at_a_coder_with_no_input() -> None:
    """A coder with no in-stream ends the first-input walk; it does not borrow one.

    The parser accepts such a coder (only decoding refuses it). Its in-stream offset is
    the next coder's first in-stream, here the Delta coder's, which the PPMd coder
    feeds: reading that offset as the LZMA coder's input listed PPMd in the chain.
    """

    def coder(method: bytes, num_in: int = 1) -> SevenZipCoder:
        return SevenZipCoder(
            method=method, num_in_streams=num_in, num_out_streams=1, properties=None
        )

    folder = SevenZipFolder(
        # In-streams: Delta 0, LZMA2 1 and 2, PPMd 3. LZMA2 (the output) reads the
        # LZMA coder first and the Delta coder second; PPMd feeds Delta.
        coders=[
            coder(b"\x03\x01\x01", num_in=0),
            coder(b"\x03"),
            coder(b"\x21", num_in=2),
            coder(b"\x03\x04\x01"),
        ],
        bind_pairs=[(1, 0), (2, 1), (0, 3)],
        packed_indices=[3],
        unpack_sizes=[16, 16, 16, 16],
        crc=None,
        digest_defined=False,
    )
    (chain,) = SevenZipReader._build_folder_compression(
        types.SimpleNamespace(folders=[folder])
    )
    assert tuple(m.algo for m in chain) == (
        CompressionAlgorithm.LZMA2,
        CompressionAlgorithm.LZMA,
    )


@requires_binary("7z")
@requires("inflate64")
def test_7z_cli_deflate64_fixture_roundtrip(tmp_path: Path) -> None:
    payload = tmp_path / "payload.bin"
    payload.write_bytes(bytes(range(251)) * 200)
    archive = tmp_path / "deflate64.7z"
    result = run_7z(
        ["a", "-t7z", "-m0=Deflate64", str(archive), payload.name, "-y"],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot write Deflate64 7z fixtures: {result.stderr}")

    _assert_roundtrip(archive, {payload.name: payload.read_bytes()})


@requires_binary("7z")
@requires("cryptography")
def test_7z_cli_multi_password_archive_roundtrip(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"first secret")
    second.write_bytes(b"second secret")
    archive = tmp_path / "multi-password.7z"
    commands = (
        ["a", "-t7z", str(archive), first.name, "-pfirst", "-y"],
        ["a", "-t7z", str(archive), second.name, "-psecond", "-y"],
    )
    for command in commands:
        result = run_7z(command, cwd=tmp_path, check=False, text=True)
        if result.returncode != 0:
            pytest.skip(
                f"7z CLI cannot build multi-password 7z fixture: {result.stderr}"
            )

    _assert_roundtrip(
        archive,
        {first.name: first.read_bytes(), second.name: second.read_bytes()},
        password=["first", "second"],
    )


@requires_binary("7z")
@requires("cryptography")
def test_7z_multi_password_rejects_wrong_candidate_via_crc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wrong keys that decompress to the right length must still lose on CRC."""
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"first secret")
    second.write_bytes(b"second secret")
    archive = tmp_path / "multi-password-crc.7z"
    for command in (
        ["a", "-t7z", str(archive), first.name, "-pfirst", "-y"],
        ["a", "-t7z", str(archive), second.name, "-psecond", "-y"],
    ):
        result = run_7z(command, cwd=tmp_path, check=False, text=True)
        if result.returncode != 0:
            pytest.skip(
                f"7z CLI cannot build multi-password 7z fixture: {result.stderr}"
            )

    import archivey.internal.backends.sevenzip_reader as sevenzip_reader_mod

    # Patch the module-level function the reader actually calls. Patching a method on
    # SevenZipReader looks equivalent and is not: production has never routed through
    # one, so the fake below would never run and this test would pass vacuously.
    original_pipeline = sevenzip_reader_mod.open_folder_pipeline
    first_kdf = "first".encode("utf-16le")
    garbage = b"\x05\x7f\xc6\x01\xebI\x03j\x88\x93\x8e\xe5\xb5"

    garbage_served: list[bool] = []

    def pipeline_with_wrong_first(source, folder, *, password, **kwargs):
        # After the first folder unlocks, known-good "first" is tried on the second
        # folder. Simulate a decompressor that yields plausible garbage of the
        # expected length instead of raising, so only the CRC confirm rejects it.
        if password == first_kdf and folder.unpack_sizes[-1] == len(garbage):
            garbage_served.append(True)
            return io.BytesIO(garbage)
        return original_pipeline(source, folder, password=password, **kwargs)

    monkeypatch.setattr(
        sevenzip_reader_mod, "open_folder_pipeline", pipeline_with_wrong_first
    )

    with open_archive(archive, password=["first", "second"]) as reader:
        members = {member.name: member for member in reader.members() if member.is_file}
        assert reader.read(members["first.txt"]) == b"first secret"
        assert reader.read(members["second.txt"]) == b"second secret"

    # Without this the patch could run and still never take the CRC-only path,
    # and the test would pass via codec rejection of the wrong key.
    assert garbage_served, "the CRC-only garbage path was never taken"


@requires_binary("7z")
def test_7z_cli_multi_volume_archive_roundtrip(tmp_path: Path) -> None:
    payload = tmp_path / "large.bin"
    payload.write_bytes(bytes(range(256)) * 1200)
    result = run_7z(
        ["a", "-t7z", "-v100k", str(tmp_path / "vol.7z"), payload.name, "-y"],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot build multi-volume 7z fixture: {result.stderr}")
    first_volume = tmp_path / "vol.7z.001"
    if not first_volume.exists() or not (tmp_path / "vol.7z.002").exists():
        pytest.skip("7z CLI did not split the fixture into multiple volumes")

    _assert_roundtrip(first_volume, {payload.name: payload.read_bytes()})


@requires("cryptography")
@requires_binary("7z")
def test_password_confirm_does_not_request_the_whole_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Encrypted 7z confirm used to ``read_exact`` the whole folder into RAM.

    7z AES has no verifier, so a candidate is checked by decoding and CRCing. That
    decode must not materialise the folder: a single ``read(n)`` with ``n`` equal
    to the unpack size is the previous gather. Store+AES so a wrong-key path
    cannot fail fast inside LZMA and hide the request size.
    """
    import archivey.internal.backends.sevenzip_reader as sevenzip_reader_mod

    folder_size = 2 * 1024 * 1024
    payload = tmp_path / "payload.bin"
    payload.write_bytes(bytes(range(256)) * (folder_size // 256))
    archive = tmp_path / "store-aes.7z"
    result = run_7z(
        [
            "a",
            "-t7z",
            "-psecret",
            "-mhe=off",
            "-m0=Copy",
            "-ms=off",
            str(archive),
            payload.name,
            "-y",
        ],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot build store+AES fixture: {result.stderr}")

    spies: list[ReadSizeSpy] = []
    original = sevenzip_reader_mod.open_folder_pipeline

    def wrapping(*args: object, **kwargs: object) -> ReadSizeSpy:
        stream = original(*args, **kwargs)
        spy = ReadSizeSpy(stream)
        spies.append(spy)
        return spy

    monkeypatch.setattr(sevenzip_reader_mod, "open_folder_pipeline", wrapping)

    with open_archive(archive, password="secret") as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert member.size == folder_size
        with reader.open(member) as stream:
            assert stream.read(1) == payload.read_bytes()[:1]

    # One pipeline for the confirm decode, one for the member read. Pinned rather
    # than left to the comment below, so a change in call count fails here instead of
    # silently making `spies[0]` the wrong stream.
    assert len(spies) == 2, f"expected confirm + member pipelines, got {len(spies)}"
    # `max_requested` is a proxy for peak memory, not a measurement of it: a rewrite
    # that looped 64 KiB reads into one bytearray would still pass. It pins the
    # specific regression this PR fixes — a single read sized to the whole folder.
    assert spies[0].max_requested <= PASSWORD_CONFIRM_CHUNK_BYTES, (
        f"confirm requested {spies[0].max_requested} bytes in one read "
        f"(chunk is {PASSWORD_CONFIRM_CHUNK_BYTES}, folder is {folder_size})"
    )

    # The same fixture with a wrong password is the only end-to-end exercise of the
    # rewritten CRC branch: store+AES has no decompressor to reject a wrong key, so
    # the confirm CRC is the sole rejector. Without this the branch is covered only
    # by BytesIO unit tests.
    with (
        pytest.raises(EncryptionError, match="Wrong password or corrupt 7z folder"),
        open_archive(archive, password="wrong") as reader,
    ):
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            stream.read(1)


def _reader_for_unit_tests() -> SevenZipReader:
    reader = object.__new__(SevenZipReader)
    reader._stream_config = DEFAULT_STREAM_CONFIG
    reader._diagnostics_collector = None
    reader._key_cache = sevenzip_aes.SevenZipKeyCache()
    return reader


def _open_pipeline(
    reader: SevenZipReader,
    source: io.BytesIO,
    folder: SevenZipFolder,
    *,
    password: bytes | None = None,
) -> object:
    """Open a folder pipeline with a unit-test reader's own wiring.

    Replaces the `_open_folder_pipeline` shim that used to live on the reader purely
    so tests could reach it. Production never routed through that method, which is
    what made a monkeypatch of it silently inert.
    """
    return open_folder_pipeline(
        [source],
        folder,
        password=password,
        key_cache=reader._key_cache,
        stream_config=reader._stream_config,
        collector=reader._diagnostics_collector,
    )


def _folder(method: bytes, properties: bytes | None = None) -> SevenZipFolder:
    return SevenZipFolder(
        coders=[
            SevenZipCoder(
                method=method,
                num_in_streams=1,
                num_out_streams=1,
                properties=properties,
            )
        ],
        bind_pairs=[],
        packed_indices=[0],
        unpack_sizes=[0],
        crc=None,
        digest_defined=False,
    )


def test_first_stage_bcj_does_not_close_pack_source() -> None:
    """A first-stage BCJ stage borrows the pack view (Copy+BCJ / BCJ-alone).

    Later BCJ stages wrap a private previous output and pass ``owns_inner=True``.
    Hardcoding True on every ``_FilterStage`` closed a raw ``BytesIO`` here;
    production pack views are ``SharedView``, so the over-close was absorbed.
    """

    class _Tracked(io.BytesIO):
        def __init__(self, initial: bytes) -> None:
            super().__init__(initial)
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            super().close()

    reader = _reader_for_unit_tests()
    source = _Tracked(b"\x00" * 16)
    stream = _open_pipeline(reader, source, _folder(b"\x03\x03\x01\x03"), password=None)
    assert isinstance(stream, io.IOBase)
    stream.close()
    assert source.close_calls == 0
    assert not source.closed


def test_multi_input_coder_other_than_bcj2_is_rejected() -> None:
    """BCJ2 is the only multi-input coder the planner runs (tests/test_sevenzip_bcj2.py)."""
    reader = _reader_for_unit_tests()
    folder = _folder(b"\x03\x01\x01")
    folder.coders[0].num_in_streams = 2
    folder.packed_indices = [0, 1]

    with pytest.raises(UnsupportedFeatureError, match="0x030101 with 2 inputs"):
        _open_pipeline(reader, io.BytesIO(b""), folder, password=None)


def test_unknown_folder_method_is_rejected() -> None:
    reader = _reader_for_unit_tests()

    with pytest.raises(UnsupportedFeatureError, match="0x99"):
        _open_pipeline(reader, io.BytesIO(b""), _folder(b"\x99"), password=None)


def test_ppmd_without_pyppmd_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader_for_unit_tests()
    monkeypatch.setattr(
        codecs.deps, "pyppmd", codecs.deps.LazyOptional("pyppmd", present=False)
    )
    properties = struct.pack("<BL", 6, 1 << 20)

    with pytest.raises(PackageNotInstalledError, match="pyppmd"):
        _open_pipeline(
            reader, io.BytesIO(b""), _folder(b"\x03\x04\x01", properties), password=None
        )


def test_aes_without_crypto_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader_for_unit_tests()
    monkeypatch.setattr(crypto, "_crypto_available", lambda: False)
    properties = b"\xc0\x00\x00\x00"  # one-byte salt, one-byte IV, both zero

    with pytest.raises(PackageNotInstalledError, match="cryptography"):
        _open_pipeline(
            reader,
            io.BytesIO(b""),
            _folder(b"\x06\xf1\x07\x01", properties),
            password=b"pw",
        )


@pytest.mark.parametrize(
    "properties",
    [
        pytest.param(b"\x00\x00", id="no-salt-or-iv-flags"),
        pytest.param(b"\xc0", id="one-byte"),
        pytest.param(b"\xc0\x00\x00", id="short-by-one"),
        pytest.param(b"\xc0\x00\x00\x00\x00", id="long-by-one"),
    ],
)
def test_malformed_aes_properties_raise_corruption_error(properties: bytes) -> None:
    """``parse_sevenzip_aes_properties`` raises a bare ``ValueError``; the one caller
    in the pipeline must turn it into an archivey error, cause kept.

    The properties are parsed before any ``cryptography`` import, so this also runs
    on the core-only leg.
    """
    reader = _reader_for_unit_tests()
    with raises_corruption_not_truncation(match="Malformed 7z AES properties") as info:
        _open_pipeline(
            reader,
            io.BytesIO(bytes(64)),
            _folder(b"\x06\xf1\x07\x01", properties),
            password=b"pw",
        )
    assert isinstance(info.value.__cause__, ValueError)


@requires("cryptography")
def test_truncated_aes_pack_raises_truncated_error() -> None:
    """AES-only folder: a short last ciphertext block is TruncatedError, not garbage."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    password = b"pw"
    properties = b"\xc0\x00\x00\x00"
    cache = sevenzip_aes.SevenZipKeyCache()
    params = cache.aes_params_from_properties(password, properties)
    plaintext = bytes(range(64))
    encryptor = Cipher(algorithms.AES(params.key), modes.CBC(params.iv)).encryptor()
    cipher = encryptor.update(plaintext) + encryptor.finalize()
    reader = _reader_for_unit_tests()
    stream = _open_pipeline(
        reader,
        io.BytesIO(cipher[:53]),
        _folder(b"\x06\xf1\x07\x01", properties),
        password=password,
    )
    try:
        # Mutation A: restore zero-pad drain in finalize — 64 garbage-tailed
        # bytes, no raise.
        with pytest.raises(TruncatedError, match="mid-block"):
            stream.read()
    finally:
        stream.close()


def _u64(value: int) -> bytes:
    assert 0 <= value < 0x80
    return bytes([value])


def _bools(values: list[bool]) -> bytes:
    out = bytearray()
    current = 0
    mask = 0x80
    for value in values:
        if value:
            current |= mask
        mask >>= 1
        if mask == 0:
            out.append(current)
            current = 0
            mask = 0x80
    if mask != 0x80:
        out.append(current)
    return bytes(out)


def _property(prop: int, payload: bytes) -> bytes:
    return bytes([prop]) + _sevenzip_uint64(len(payload)) + payload


def _names_payload(names: list[str]) -> bytes:
    encoded = bytearray(b"\x00")
    for name in names:
        encoded.extend(name.encode("utf-16le"))
        encoded.extend(b"\x00\x00")
    return bytes(encoded)


def _anti_item_archive(payload: bytes = b"obsolete") -> bytes:
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    pack_info = b"\x06" + _u64(0) + _u64(1) + b"\x09" + _u64(len(payload)) + b"\x00"
    folder = _u64(1) + b"\x00"  # one COPY coder
    unpack_info = (
        b"\x07\x0b"
        + _u64(1)
        + b"\x00"
        + folder
        + b"\x0c"
        + _u64(len(payload))
        + b"\x0a"
        + b"\x01"
        + crc.to_bytes(4, "little")
        + b"\x00"
    )
    streams_info = b"\x04" + pack_info + unpack_info + b"\x00"
    files_info = (
        b"\x05"
        + _u64(2)
        + _property(0x0E, _bools([False, True]))
        + _property(0x10, _bools([True]))
        + _property(0x11, _names_payload(["gone.txt", "gone.txt"]))
        + b"\x00"
    )
    header = b"\x01" + streams_info + files_info + b"\x00"
    start_header = (
        len(payload).to_bytes(8, "little")
        + len(header).to_bytes(8, "little")
        + (zlib.crc32(header) & 0xFFFFFFFF).to_bytes(4, "little")
    )
    signature = (
        b"7z\xbc\xaf'\x1c\x00\x04"
        + (zlib.crc32(start_header) & 0xFFFFFFFF).to_bytes(4, "little")
        + start_header
    )
    return signature + payload + header


def test_synthetic_anti_item_lists_and_extracts_safely(tmp_path: Path) -> None:
    archive = tmp_path / "anti.7z"
    archive.write_bytes(_anti_item_archive())

    with open_archive(archive) as reader:
        content, anti = reader.members()
        assert content.name == "gone.txt"
        assert content.type is MemberType.FILE
        assert content.is_anti is False
        assert content.is_current is False
        assert anti.name == "gone.txt"
        assert anti.type is MemberType.ANTI
        assert anti.is_anti is True
        assert anti.is_file is False
        assert anti.is_current is True
        assert reader.read(content) == b"obsolete"
        with pytest.raises(ArchiveyUsageError, match="anti"):
            reader.read(anti)
        for member, stream in reader.stream_members():
            if member.is_anti:
                assert stream is None
            elif member.is_file:
                assert stream is not None
                stream.read()
                stream.close()

    fresh = tmp_path / "fresh"
    with open_archive(archive) as reader:
        results = reader.extract_all(fresh).results
    assert [result.status for result in results] == [
        ExtractionStatus.SUPERSEDED,
        ExtractionStatus.EXTRACTED,
    ]
    assert not (fresh / "gone.txt").exists()

    existing = tmp_path / "existing"
    existing.mkdir()
    preexisting = existing / "gone.txt"
    preexisting.write_bytes(b"keep me")
    with open_archive(archive) as reader:
        reader.extract_all(existing)
    assert preexisting.read_bytes() == b"keep me"


@requires_binary("7z")
def test_anti_item_fresh_extract_matches_7z_cli(tmp_path: Path) -> None:
    """Build a real anti-item archive with the 7z CLI and compare fresh-dest trees.

    Recipe: archive keep.txt + gone.txt, delete gone.txt on disk, then ``7z u`` with
    anti-item update options into a new archive. Fresh ``7z x`` and archivey extract
    must both leave keep.txt and omit gone.txt.
    """
    work = tmp_path / "work"
    work.mkdir()
    (work / "keep.txt").write_text("keep\n", encoding="utf-8")
    (work / "gone.txt").write_text("gone\n", encoding="utf-8")
    base = tmp_path / "base.7z"
    archive = tmp_path / "with_anti.7z"
    create = run_7z(
        ["a", "-t7z", str(base), "keep.txt", "gone.txt", "-y"],
        cwd=work,
        check=False,
        text=True,
    )
    if create.returncode != 0:
        pytest.skip(f"7z CLI cannot build base archive: {create.stderr}")
    (work / "gone.txt").unlink()
    update = run_7z(
        [
            "u",
            str(base),
            "-u-",
            f"-up0q3x2y2z1!{archive}",
            "keep.txt",
            "gone.txt",
            "-y",
        ],
        cwd=work,
        check=False,
        text=True,
    )
    if update.returncode != 0 or not archive.is_file():
        pytest.skip(f"7z CLI cannot build anti-item update archive: {update.stderr}")

    with open_archive(archive) as reader:
        members = reader.members()
        by_name = {m.name: m for m in members}
        assert by_name["gone.txt"].type is MemberType.ANTI
        assert by_name["gone.txt"].is_anti is True
        assert by_name["gone.txt"].is_current is True
        assert by_name["keep.txt"].is_anti is False
        assert by_name["keep.txt"].is_current is True
        with pytest.raises(ArchiveyUsageError):
            reader.read(by_name["gone.txt"])

    archivey_dest = tmp_path / "archivey"
    cli_dest = tmp_path / "cli"
    cli_dest.mkdir()
    with open_archive(archive) as reader:
        reader.extract_all(archivey_dest)
    run_7z(["x", str(archive), f"-o{cli_dest}", "-y"], check=True)

    assert sorted(
        p.relative_to(archivey_dest) for p in archivey_dest.rglob("*") if p.is_file()
    ) == sorted(p.relative_to(cli_dest) for p in cli_dest.rglob("*") if p.is_file())
    assert (archivey_dest / "keep.txt").read_bytes() == (
        cli_dest / "keep.txt"
    ).read_bytes()
    assert not (archivey_dest / "gone.txt").exists()
    assert not (cli_dest / "gone.txt").exists()


def _sevenzip_uint64(value: int) -> bytes:
    """Encode ``value`` as a 7z UINT64. Small values stay one byte; large ones use 0xFF+u64."""
    if value < 0x80:
        return bytes([value])
    return b"\xff" + value.to_bytes(8, "little")


def _num_unpack_stream_header(
    count: int,
    *,
    crc_all_defined: bool = False,
    header_pad: int = 0,
    with_sizes: bool = False,
) -> bytes:
    """HEADER + one COPY folder + ``kNumUnPackStream = count``, no SIZE (S2-F1).

    A count that survives the bounds is refused without ``kSize`` (S2-F3), so the
    cases that must parse set ``with_sizes``: ``count - 1`` zero sizes, the last
    substream taking the folder's 10 bytes.

    When ``crc_all_defined`` is set, a ``kCRC`` / all-defined flag follows the count so
    the ``_load_boolean(..., check_all=True)`` ``[True] * count`` path is the one that
    would allocate. Remaining bytes after the flag are irrelevant: the count must be
    rejected before that allocation.

    ``header_pad`` inserts a FILES_INFO DUMMY payload so a legitimate-scale count
    can sit in a header large enough to pass the O1-style buffer bound.
    """
    body = bytearray(bytes.fromhex("0104070b010001000c0a00080d"))
    body += _sevenzip_uint64(count)
    if with_sizes:
        body += b"\x09" + b"\x00" * (count - 1)
    if crc_all_defined:
        body += bytes.fromhex("0a01")
    else:
        body += b"\x00"
    body += b"\x00\x05\x00"  # END streams, FILES_INFO, num_files=0
    if header_pad:
        body += bytes([0x19]) + _sevenzip_uint64(header_pad) + (b"\x00" * header_pad)
    body += b"\x00\x00"  # END files, END header
    return bytes(body)


def test_files_info_count_is_bounded_against_header_size() -> None:
    # A crafted 7z header can declare an absurd file count in a few bytes; the parser must
    # reject it against the header size instead of pre-allocating one object per claimed
    # file and OOM-ing the process (threat-model O1 / review L1). Encode num_files = 2**40
    # in the 7z uint64 form (0xFF marker + 8 LE bytes) and feed it straight to the reader.
    from archivey.internal.backends.sevenzip_parser import _Cursor, _read_files_info

    huge = (1 << 40).to_bytes(8, "little")
    cur = _Cursor(b"\xff" + huge)  # a 9-byte "header" claiming 2**40 files
    with raises_corruption_not_truncation(match="exceeds the .* header"):
        _read_files_info(cur, max_members=None)


# The parser's old per-folder coder-graph cap. It once also bounded unpack streams,
# pack streams and folders, which rejected legitimate archives with more members
# (review F1/F2). The tests below keep it as the member count those regressions need.
_MAX_NUM_STREAMS = 65536


def test_num_unpack_streams_count_is_bounded() -> None:
    """``kNumUnPackStream`` is not bounded by remaining header bytes (S2-F1 / O13)."""
    from archivey.internal.backends.sevenzip_parser import (
        PlainHeader,
        parse_header_block,
    )

    ok = parse_header_block(_num_unpack_stream_header(2, with_sizes=True))
    assert isinstance(ok, PlainHeader)
    assert ok.streams.num_unpackstreams_folders == [2]
    assert ok.streams.digests == [None, None]

    # Above the structural pack/folder cap, but inside a header large enough
    # for the count — the bound that used to reject this is the F1 regression.
    above_stream_cap = _MAX_NUM_STREAMS + 1
    at_scale = parse_header_block(
        _num_unpack_stream_header(
            above_stream_cap, header_pad=above_stream_cap, with_sizes=True
        )
    )
    assert isinstance(at_scale, PlainHeader)
    assert at_scale.streams.num_unpackstreams_folders == [above_stream_cap]
    assert len(at_scale.streams.digests) == above_stream_cap

    for count in (above_stream_cap, 1 << 20, 1 << 40):
        with raises_corruption_not_truncation(match="unpack stream count .* header"):
            parse_header_block(_num_unpack_stream_header(count))
        with raises_corruption_not_truncation(match="unpack stream count .* header"):
            parse_header_block(_num_unpack_stream_header(count, crc_all_defined=True))


def test_num_unpack_streams_sum_across_folders_is_bounded() -> None:
    """Per-folder counts under the header-size cap can still sum past it."""
    from archivey.internal.backends.sevenzip_parser import parse_header_block

    # Two COPY folders, counts that each fit in this ~24-byte header (20 < 24)
    # but sum past it (40 > 24).
    header = (
        bytes.fromhex("0104070b0200010001000c0a0a00080d")
        + _sevenzip_uint64(20)
        + _sevenzip_uint64(20)
        + bytes.fromhex("000005000000")
    )
    assert 20 < len(header) < 40
    with raises_corruption_not_truncation(match="unpack stream count .* header"):
        parse_header_block(header)


def test_member_scaled_counts_respect_max_members() -> None:
    """Honest counts over ``listing_limits.max_members`` are ResourceLimitError, not corrupt."""
    from archivey.exceptions import ResourceLimitError
    from archivey.internal.backends.sevenzip_parser import parse_header_block

    header = _num_unpack_stream_header(200, header_pad=200, with_sizes=True)
    parse_header_block(header)
    parse_header_block(header, max_members=None)
    with pytest.raises(ResourceLimitError, match="max_members"):
        parse_header_block(header, max_members=100)

    # An unknown archive property pads the header ahead of the count, so the count
    # passes the header-size bound and nothing follows the final END.
    pad = b"\x02\x30" + _sevenzip_uint64(200) + (b"\x00" * 200) + b"\x00"
    pack = b"\x01" + pad + bytes.fromhex("040600") + _sevenzip_uint64(200)
    pack += bytes.fromhex("000000")  # END pack info, END streams, END header
    # Pack streams are a coder-graph quantity (BCJ2 has four per folder), not a
    # member count — header-size bound only.
    parse_header_block(pack, max_members=100)

    folders = b"\x01" + pad + bytes.fromhex("04070b") + _sevenzip_uint64(200)
    with pytest.raises(ResourceLimitError, match="max_members"):
        parse_header_block(folders, max_members=100)


def test_cursor_truncated_property_payload_raises() -> None:
    """A property size larger than remaining header bytes must raise CorruptionError."""
    from archivey.internal.backends.sevenzip_parser import _Cursor, _read_files_info

    # FILES_INFO: num_files=1, then NAME property (0x11) claiming 100-byte payload
    # with only a few bytes left → truncated at slice().
    cur = _Cursor(bytes([1, 0x11, 100]))
    with pytest.raises(CorruptionError, match="Truncated"):
        _read_files_info(cur, max_members=None)


def test_cursor_fixed_width_field_at_eof_raises() -> None:
    from archivey.internal.backends.sevenzip_parser import _Cursor

    cur = _Cursor(b"\x01\x02")  # only 2 bytes; uint32 needs 4
    with pytest.raises(CorruptionError, match="Truncated 7z UINT32"):
        cur.uint32()


def test_cursor_parse_matches_open_archive_fixture(tmp_path: Path) -> None:
    """Representative fixture: names, sizes, times, attrs, CRCs survive the cursor port."""
    path = tmp_path / "cursor-roundtrip.7z"
    files = {
        "readme.txt": b"hello cursor\n",
        "dir/data.bin": bytes(range(32)),
    }
    _write_py7zr_archive(path, files, filters=_filters("COPY"))

    with open_archive(path) as archive:
        members = {m.name: m for m in archive.members() if m.is_file}
        assert set(members) == set(files)
        for name, data in files.items():
            m = members[name]
            assert m.size == len(data)
            assert HashAlgorithm.CRC32 in m.hashes
            assert m.modified is not None
            assert archive.read(m) == data
        # Archive-level comment is optional; presence must not break listing.
        _ = archive.info.comment


def test_next_header_offset_overflow_is_typed_corruption() -> None:
    """Huge nextHeaderOffset must not raise OverflowError on seek (Atheris finding)."""
    import struct
    import zlib

    from archivey.internal.backends.sevenzip_parser import MAGIC_7Z

    # Valid signature CRC over a start_header that claims an absurd next-header offset.
    next_offset = (1 << 64) - 1
    next_size = 16
    next_crc = 0
    start_header = struct.pack("<QQI", next_offset, next_size, next_crc)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    blob = MAGIC_7Z + bytes([0, 4]) + struct.pack("<I", start_crc) + start_header

    with raises_corruption_not_truncation(match="next-header offset"):
        load_sevenzip_archive(io.BytesIO(blob))


def test_next_header_size_cap_is_typed_corruption() -> None:
    import struct
    import zlib

    from archivey.internal.backends.sevenzip_parser import (
        MAGIC_7Z,
        MAX_NEXT_HEADER_SIZE,
    )

    next_offset = 0
    next_size = MAX_NEXT_HEADER_SIZE + 1
    next_crc = 0
    start_header = struct.pack("<QQI", next_offset, next_size, next_crc)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    blob = MAGIC_7Z + bytes([0, 4]) + struct.pack("<I", start_crc) + start_header

    with raises_corruption_not_truncation(match="next-header size"):
        load_sevenzip_archive(io.BytesIO(blob))


def test_archive_property_payload_size_is_bounded() -> None:
    """Hostile ARCHIVE_PROPERTIES size must not raise OverflowError (Atheris finding)."""
    import struct
    import zlib

    from archivey.internal.backends.sevenzip_parser import MAGIC_7Z

    # Minimal next-header: HEADER + ARCHIVE_PROPERTIES + prop_id + 0xFF-encoded u64 size.
    # Mirrors the CI crash input shape (payload claim >> remaining header bytes).
    huge = b"\xff" + b"\xff" * 8
    header_body = (
        b"\x01\x02\x17" + huge + b"\x00"
    )  # HEADER, ARCHIVE_PROPERTIES, prop, size, END
    next_crc = zlib.crc32(header_body) & 0xFFFFFFFF
    start_header = struct.pack("<QQI", 0, len(header_body), next_crc)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    blob = (
        MAGIC_7Z
        + bytes([0, 4])
        + struct.pack("<I", start_crc)
        + start_header
        + header_body
    )

    with pytest.raises(CorruptionError, match="(length|Truncated|parser limit)"):
        load_sevenzip_archive(io.BytesIO(blob))


def test_encoded_header_huge_unpack_size_is_typed_corruption() -> None:
    """Hostile encoded-header unpack size must not raise MemoryError (Atheris finding)."""

    # CI crash input (sevenzip_header, 2026-07-15): ENCODED_HEADER claims ~7.26e17
    # uncompressed bytes; previously blew up in lzma/read_exact as MemoryError. The
    # original input had one byte after the encoded header's final kEnd; it is trimmed
    # here (next-header size and both CRCs recomputed) so the unpack-size guard, not
    # the trailing-bytes check, is what fires.
    blob = bytes.fromhex(
        "377abcaf271c00048fac0b60e30000000000000023000000000000000531888e"
        "e0002800255d00241949986f16028ce8e65bb147c6e8785df977f152c4a859c0"
        "a9300dd98729229ab2993c9f00e0016d00ae5d0000813307ae0fd0d36d7c9f39"
        "109c6cea561a8ee1ce421bf7dd8a7d61fa2b2e795eb720494abfaa6e563e7783"
        "6034574bfe117d9bf2e6acdd947c4c39e3007228af9cc251620efa22eded9bf5"
        "a5d5098d4562a390f7a8707038e8a889585b98fe0a641968b481d04b24eb5853"
        "1946a77f37cd1773040ccbc8b9053fefb060f8b4b0b770e4be72e602741c8904"
        "1b2c1343fbf55ece457ecb05f85ff07810e4d6b1959f3d4a90a6a92f3d532e00"
        "00000017062d010980b600070b010001212101180cffffffffffffff110a0a0a"
        "0a010000000002830a0a0a0a0a0a0a0a0a0a0a0a816e0000"
    )
    with raises_corruption_not_truncation(match="unpack size|parser limit"):
        load_sevenzip_archive(io.BytesIO(blob))


def _sevenzip_blob(*, packed: bytes, next_header: bytes) -> bytes:
    from archivey.internal.backends.sevenzip_parser import MAGIC_7Z

    next_crc = zlib.crc32(next_header) & 0xFFFFFFFF
    start_header = struct.pack("<QQI", len(packed), len(next_header), next_crc)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    return (
        MAGIC_7Z
        + bytes([0, 4])
        + struct.pack("<I", start_crc)
        + start_header
        + packed
        + next_header
    )


@pytest.mark.timeout(5)
def test_encoded_header_self_copy_is_typed_corruption() -> None:
    """COPY encoded header whose packed bytes are itself must not hang (S2-F2 / O14)."""

    # 66-byte archive from the S2-F2 trigger: signature + 17-byte COPY payload that
    # *is* the next-header (kEncodedHeader, one COPY folder, unpack=17).
    next_header = bytes.fromhex("17060001091100070b010001000c110000")
    blob = _sevenzip_blob(packed=next_header, next_header=next_header)
    assert len(blob) == 66
    with (
        raises_corruption_not_truncation(match="decoded to another encoded header"),
        open_archive(io.BytesIO(blob)),
    ):
        pass


_NOT_ONE_FOLDER = "must have exactly one"
_NOT_A_HEADER = "did not decode to a 7z HEADER"
_TRAILING = "bytes after its END"
_NESTED = "decoded to another encoded header"
# kEncodedHeader with one COPY folder of unpack size 2: the folder decodes to the two
# packed bytes.
_ENCODED_COPY_OF_2 = bytes.fromhex("17060001090200070b010001000c020000")


@pytest.mark.parametrize(
    ("packed", "next_header", "match"),
    [
        # kEncodedHeader with a PackInfo of zero streams and no folders.
        pytest.param(
            b"", bytes.fromhex("170600000000"), _NOT_ONE_FOLDER, id="zero-folders"
        ),
        # One COPY folder with unpack size 0: decodes to b"".
        pytest.param(
            b"",
            bytes.fromhex("17060001090000070b010001000c000000"),
            _NOT_A_HEADER,
            id="decodes-to-nothing",
        ),
        # One COPY folder that decodes to a bare kEnd.
        pytest.param(
            b"\x00",
            bytes.fromhex("17060001090100070b010001000c010000"),
            _NOT_A_HEADER,
            id="decodes-to-bare-end",
        ),
        # A valid plain header (kHeader, kEnd) split across two COPY folders.
        pytest.param(
            b"\x01\x00",
            bytes.fromhex("1706000209010100070b0200010001000c01010000"),
            _NOT_ONE_FOLDER,
            id="two-folders",
        ),
        # One COPY folder that decodes to kHeader kEnd plus two more bytes.
        pytest.param(
            bytes.fromhex("0100ffee"),
            bytes.fromhex("17060001090400070b01000101000c040000"),
            _TRAILING,
            id="decodes-to-header-with-trailing-bytes",
        ),
        # The same header stored plain: 7-Zip reports a headers error for it too.
        pytest.param(
            b"",
            bytes.fromhex("0100ffee"),
            _TRAILING,
            id="plain-header-with-trailing-bytes",
        ),
        # An encoded header with two bytes after its final kEnd. Its folder decodes to
        # kHeader kEnd; the control is test_encoded_header_to_empty_header_opens.
        pytest.param(
            b"\x01\x00",
            _ENCODED_COPY_OF_2 + b"\xff\xee",
            _TRAILING,
            id="encoded-header-with-trailing-bytes",
        ),
        # A folder that decodes to kEncodedHeader with a malformed body (0x1a is not a
        # streams-info ID): the verdict is the nesting, not the body's parse error.
        pytest.param(
            b"\x17\x1a",
            _ENCODED_COPY_OF_2,
            _NESTED,
            id="decodes-to-malformed-encoded-header",
        ),
    ],
)
def test_header_that_is_not_one_plain_header_is_corruption(
    packed: bytes, next_header: bytes, match: str
) -> None:
    """7-Zip refuses each of these; none may open as an archive (DR-1)."""
    blob = _sevenzip_blob(packed=packed, next_header=next_header)
    with raises_corruption_not_truncation(match=match), open_archive(io.BytesIO(blob)):
        pass


def test_encoded_header_to_empty_header_opens() -> None:
    """Control for encoded-header-with-trailing-bytes: without the two bytes, 7-Zip
    lists this archive cleanly, and so does archivey."""
    blob = _sevenzip_blob(packed=b"\x01\x00", next_header=_ENCODED_COPY_OF_2)
    with open_archive(io.BytesIO(blob)) as archive:
        assert archive.members() == []


@pytest.mark.parametrize(
    "decoded",
    [
        pytest.param(b"\x17\x1a", id="unknown-streams-info-id"),
        # Claims 200 folders: parsing the body would hit the listing limit first.
        pytest.param(
            bytes.fromhex("17060001090100070b") + b"\x80\xc8" + b"\x00" * 300,
            id="folder-count-over-listing-limit",
        ),
    ],
)
def test_decoded_encoded_header_is_refused_before_its_body(decoded: bytes) -> None:
    """The nesting verdict comes before the body parse, so it is always CorruptionError."""
    from archivey.internal.backends.sevenzip_parser import parse_decoded_header

    with raises_corruption_not_truncation(match=_NESTED):
        parse_decoded_header(decoded, max_members=100)


@pytest.mark.parametrize(
    "prop_id",
    [pytest.param(b"\x30", id="one-byte"), pytest.param(b"\x80\x90", id="two-byte")],
)
def test_unknown_archive_property_is_skipped(prop_id: bytes) -> None:
    """7-Zip skips an archive property it does not know by its size, as for FILES_INFO."""
    # kHeader, kArchiveProperties {id, size 2, payload}, kEnd, then a FILES_INFO with
    # one empty file "a": a skip of the wrong length lands inside the FILES_INFO.
    name = b"\x00" + "a".encode("utf-16le") + b"\x00\x00"
    files_info = (
        b"\x05\x01"  # FILES_INFO, one file
        b"\x0e\x01\x80"  # EMPTY_STREAM: file 0 has no stream
        b"\x0f\x01\x80"  # EMPTY_FILE: file 0 is an empty file
        b"\x11" + bytes([len(name)]) + name + b"\x00"
    )
    next_header = (
        b"\x01\x02" + prop_id + b"\x02\xff\xff" + b"\x00" + files_info + b"\x00"
    )
    blob = _sevenzip_blob(packed=b"", next_header=next_header)
    with open_archive(io.BytesIO(blob)) as archive:
        assert [(m.name, m.type) for m in archive.members()] == [("a", MemberType.FILE)]


def test_encoded_header_unpack_size_is_capped() -> None:
    """A COPY folder claiming more than the next-header cap is refused before decoding."""
    from archivey.internal.backends.sevenzip_parser import MAX_NEXT_HEADER_SIZE

    next_header = (
        bytes.fromhex("17060001090100070b010001000c")
        + _sevenzip_uint64(MAX_NEXT_HEADER_SIZE + 1)
        + bytes.fromhex("0000")
    )
    blob = _sevenzip_blob(packed=b"\x00", next_header=next_header)
    with raises_corruption_not_truncation(match="parser limit"):
        load_sevenzip_archive(io.BytesIO(blob))


def _lzma2_dict_prop(dict_size: int) -> int:
    """The one-byte LZMA2 coder property for ``dict_size``, a power of two of 4 KiB or more."""
    assert dict_size >= 4096 and dict_size & (dict_size - 1) == 0
    return 2 * (dict_size.bit_length() - 1 - 12)


# ``many/`` plus one ``dNNN/`` per 1000 files of the archives below.
_ABOVE_CAP_DIRS = 1 + -(-(_MAX_NUM_STREAMS + 1) // 1000)


def _above_stream_cap_archive(*, solid: bool) -> bytes:
    """A 7z of ``_MAX_NUM_STREAMS + 1`` one-byte files, written in Python.

    The layout is the one 7-Zip 23.01 writes for a tree of that many files under
    ``many/dNNN/`` -- ``7z a`` for the solid shape, ``7z a -ms=off -mx=0`` for the
    non-solid one -- read off that writer's output with the header left plain
    (``-mhc=off``):

    * solid: one LZMA2 folder holding every file, so one pack stream and
      ``kNumUnPackStream`` of 65 537 with 65 536 ``kSize`` entries (F1);
    * non-solid: one Copy folder and one pack stream per file, 65 537 of each,
      and no ``kNumUnPackStream`` because every folder holds one stream (F2);
    * both: the ``_ABOVE_CAP_DIRS`` (67) directories as leading empty-stream entries, a CRC for every
      file stream, names and Windows attributes, and the whole header
      LZMA-encoded behind a ``kEncodedHeader``, as 7-Zip's default does.

    The fields 7-Zip writes that no limit reads are left out: modification times
    and the ``kDummy`` it pads names to alignment with.

    Built here rather than by ``7z a``: that needs the 65 537 files on disk, and
    writing them took 17 s of setup on Linux and timed out a Windows runner.
    ``test_above_stream_cap_archives_pass_7z_test`` has real 7-Zip test both
    archives. That catches a wrong structure (counts, sizes, empty-stream bits) or
    CRC, but not every coder property: a too-small LZMA2 dictionary still passes,
    because this content never reaches back that far.
    """
    n = _MAX_NUM_STREAMS + 1
    u64 = _sevenzip_uint64
    dirs = ["many", *(f"many/d{k:03d}" for k in range(_ABOVE_CAP_DIRS - 1))]
    names = dirs + [f"many/d{i // 1000:03d}/f{i:05d}.txt" for i in range(n)]
    content = b"x" * n
    crcs = (zlib.crc32(b"x") & 0xFFFFFFFF).to_bytes(4, "little") * n

    if solid:
        dict_size = 1 << 16
        packed = lzma.compress(
            content,
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}],
        )
        coder = b"\x21\x21\x01" + bytes([_lzma2_dict_prop(dict_size)])
        pack_info = b"\x06\x00\x01\x09" + u64(len(packed)) + b"\x00"
        unpack_info = b"\x07\x0b\x01\x00\x01" + coder + b"\x0c" + u64(n) + b"\x00"
        sub_streams = (
            b"\x08\x0d" + u64(n) + b"\x09" + u64(1) * (n - 1) + b"\x0a\x01" + crcs
        ) + b"\x00"
    else:
        packed = content
        pack_info = b"\x06\x00" + u64(n) + b"\x09" + u64(1) * n + b"\x00"
        unpack_info = (
            b"\x07\x0b" + u64(n) + b"\x00" + b"\x01\x01\x00" * n + b"\x0c" + u64(1) * n
        ) + b"\x00"
        sub_streams = b"\x08\x0a\x01" + crcs + b"\x00"

    dir_attributes = (0x41ED8010).to_bytes(4, "little")  # 0o40755, directory
    file_attributes = (0x81A48020).to_bytes(4, "little")  # 0o100644, archive
    files_info = (
        b"\x05"
        + u64(len(names))
        + _property(0x0E, _bools([True] * len(dirs) + [False] * n))
        + _property(0x11, _names_payload(names))
        + _property(
            0x15,
            b"\x01\x00" + dir_attributes * len(dirs) + file_attributes * n,
        )
        + b"\x00"
    )
    header = (
        b"\x01\x04" + pack_info + unpack_info + sub_streams + b"\x00" + files_info
    ) + b"\x00"

    # LZMA (``03 01 01``) with lc=3, lp=0, pb=2: the coder 7-Zip encodes headers with.
    header_dict = 1 << 20
    encoded = lzma.compress(
        header,
        format=lzma.FORMAT_RAW,
        filters=[
            {"id": lzma.FILTER_LZMA1, "dict_size": header_dict, "lc": 3, "lp": 0},
        ],
    )
    lzma_coder = b"\x23\x03\x01\x01\x05\x5d" + header_dict.to_bytes(4, "little")
    next_header = (
        b"\x17"
        + (b"\x06" + u64(len(packed)) + b"\x01\x09" + u64(len(encoded)) + b"\x00")
        + (b"\x07\x0b\x01\x00\x01" + lzma_coder + b"\x0c" + u64(len(header)))
        + (b"\x0a\x01" + (zlib.crc32(header) & 0xFFFFFFFF).to_bytes(4, "little"))
        + b"\x00\x00"
    )
    return _sevenzip_blob(packed=packed + encoded, next_header=next_header)


@pytest.fixture(scope="module")
def above_stream_cap_archives(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Path]:
    """Both archives of :func:`_above_stream_cap_archive`, written once per module.

    Building one is about a second, so the module scope only saves repeating it for
    the 7-Zip check below; the tests' 120 s budget covers it either way.
    """
    root = tmp_path_factory.mktemp("above-stream-cap")
    built = {}
    for shape, solid in (("solid", True), ("nonsolid", False)):
        built[shape] = root / f"{shape}.7z"
        built[shape].write_bytes(_above_stream_cap_archive(solid=solid))
    return built


@pytest.mark.timeout(120)
@pytest.mark.parametrize(
    ("shape", "single_folder"),
    [
        pytest.param("solid", True, id="solid"),
        pytest.param("nonsolid", False, id="nonsolid"),
    ],
)
def test_archives_above_stream_cap_still_open(
    above_stream_cap_archives: dict[str, Path],
    shape: str,
    single_folder: bool,
) -> None:
    """A 7z above ``_MAX_NUM_STREAMS`` must still open, solid or not.

    That cap was structural (per-folder coders). Applying it to unpack streams
    rejected ordinary solid 7-Zip output (review F1); applying it to pack
    streams / folders rejected non-solid output (review F2). ``max_members``
    is the liftable budget and fires at parse, not after allocating the table.

    The two shapes are separate tests because they shared one 120 s budget and
    together came close enough to it to time out on the slower CI runners. The
    worst item measured on Linux, with coverage on, took 26-35 s, nearly all of
    it the reader opening the non-solid archive's 65 537 folders three times; the
    mark stays at 120 s because the margin is for the spread, not for the mean.

    The non-solid archive uses the Copy coder, as ``7z a -ms=off -mx=0`` does,
    where 7-Zip's default would write LZMA2. The caps do not depend on the coder:
    ``_require_header_count`` and ``_require_member_scaled_count`` compare a count
    read from the header against the header size and against the configured
    ``max_members``, and both run at header-parse time, before any coder is
    instantiated. The header is LZMA-encoded in both shapes, so the
    ``kEncodedHeader`` path runs at this size too.
    """
    from archivey.config import ListingLimits
    from archivey.exceptions import ResourceLimitError

    n = _MAX_NUM_STREAMS + 1
    archive = above_stream_cap_archives[shape]
    with archive.open("rb") as raw:
        parsed = load_sevenzip_archive(raw)
    assert sum(parsed.num_unpackstreams_folders) == n
    assert len(parsed.folders) == (1 if single_folder else n)

    with open_archive(archive) as reader:
        files = [m for m in reader.members() if m.is_file]
        assert len(files) == n
        assert reader.read(files[-1]) == b"x"

    tight = ArchiveyConfig(listing_limits=ListingLimits(max_members=100))
    with pytest.raises(ResourceLimitError, match="max_members"):
        open_archive(archive, config=tight)

    unlimited = ArchiveyConfig(listing_limits=ListingLimits.UNLIMITED)
    with open_archive(archive, config=unlimited) as reader:
        assert sum(1 for m in reader.members() if m.is_file) == n


@pytest.mark.timeout(120)
@requires_binary("7z")
@pytest.mark.parametrize("shape", ["solid", "nonsolid"])
def test_above_stream_cap_archives_pass_7z_test(
    above_stream_cap_archives: dict[str, Path], shape: str
) -> None:
    """Real 7-Zip reads the archives built above as the tree they stand for.

    ``7z t`` decodes the header, every folder and every CRC, so a field the builder
    encodes wrongly fails here rather than leaving the open test above checking an
    archive no 7-Zip would write. The counts are those of the source tree, 65 537
    files in 67 directories, and the blocks are the folders each shape is named for.
    """
    result = run_7z(["t", str(above_stream_cap_archives[shape])], text=True)
    banner = next((line for line in result.stdout.splitlines() if line.strip()), "")
    assert result.returncode == 0, (banner, result.stdout[-2000:], result.stderr)
    assert "Everything is Ok" in result.stdout, banner
    assert f"Files: {_MAX_NUM_STREAMS + 1}" in result.stdout, banner
    assert f"Folders: {_ABOVE_CAP_DIRS}" in result.stdout, banner
    blocks = 1 if shape == "solid" else _MAX_NUM_STREAMS + 1
    assert f"Blocks = {blocks}" in result.stdout, banner


@pytest.mark.timeout(30)
@requires_binary("7z")
def test_bcj2_nonsolid_pack_streams_are_not_member_scaled(tmp_path: Path) -> None:
    """Non-solid BCJ2 has four pack streams per folder; max_members must not use that count."""

    from archivey.config import ListingLimits
    from archivey.exceptions import ResourceLimitError

    src = tmp_path / "exes"
    src.mkdir()
    sevenz = shutil.which("7z")
    assert sevenz is not None
    n_files = 5
    for i in range(n_files):
        shutil.copy(sevenz, src / f"prog{i}.exe")
    archive = tmp_path / "bcj2.7z"
    result = run_7z(
        [
            "a",
            "-t7z",
            "-ms=off",
            "-m0=BCJ2",
            "-m1=LZMA",
            "-m2=LZMA",
            "-m3=LZMA",
            str(archive),
            ".",
        ],
        cwd=src,
        check=False,
    )
    if result.returncode != 0 or not archive.is_file():
        pytest.skip(f"7z cannot build BCJ2 fixture: {result.stderr!r}")

    with open(archive, "rb") as fh:
        parsed = load_sevenzip_archive(fh)
    with open_archive(archive) as reader:
        n_members = len(reader.members())
    assert n_members >= n_files
    if len(parsed.pack_sizes) <= n_members + 1:
        pytest.skip("7z did not produce a multi-stream BCJ2 folder")
    # Pack streams ≈ 4 × files. A budget between member count and pack-stream
    # count must still open (review F6).
    mid = ArchiveyConfig(listing_limits=ListingLimits(max_members=n_members + 1))
    with open_archive(archive, config=mid) as reader:
        assert len(reader.members()) == n_members
    tight = ArchiveyConfig(listing_limits=ListingLimits(max_members=2))
    with pytest.raises(ResourceLimitError, match="max_members"):
        open_archive(archive, config=tight)


# py7zr's empty.7z: signature + start_header with nextHeaderSize == 0.
_EMPTY_7Z = bytes.fromhex(
    "377abcaf271c00038d9bd50f0000000000000000000000000000000000000000"
)


def test_empty_archive_opens_with_zero_members() -> None:
    with open_archive(io.BytesIO(_EMPTY_7Z)) as archive:
        assert list(archive.members()) == []
        assert archive.info.member_count == 0


def test_infer_nameless_member_name_matrix() -> None:
    from archivey.internal.backends.sevenzip_reader import _infer_nameless_member_name

    assert _infer_nameless_member_name(None) == "data"
    assert _infer_nameless_member_name("/tmp/github_14.7z") == "github_14"
    assert _infer_nameless_member_name("GitHub_14.7Z") == "GitHub_14"
    assert _infer_nameless_member_name("archive.7z.001") == "archive"
    assert _infer_nameless_member_name("archive.7z.002") == "archive"
    assert _infer_nameless_member_name("foo.bin") == "foo.bin.uncompressed"
    assert _infer_nameless_member_name("noext") == "noext.uncompressed"
    assert _infer_nameless_member_name("") == "data"


@requires_binary("7z")
def test_nameless_7z_members_use_archive_stem(tmp_path: Path) -> None:
    """7z ``-si`` archives omit NAME; list with the archive stem (no ``_1`` suffixes)."""
    single = tmp_path / "github_14.7z"
    result = run_7z(
        ["a", "-si", "-t7z", str(single)], input=b"hello nameless\n", check=False
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot write nameless fixture: {result.stderr!r}")

    with open_archive(single) as archive:
        members = list(archive.members())
        assert len(members) == 1
        assert members[0].name == "github_14"
        assert members[0].raw_name == b""
        assert archive.read(members[0]) == b"hello nameless\n"

    multi = tmp_path / "github_14_multi.7z"
    for payload in (b"one\n", b"two\n"):
        result = run_7z(["a", "-si", "-t7z", str(multi)], input=payload, check=False)
        if result.returncode != 0:
            pytest.skip(f"7z CLI cannot append nameless member: {result.stderr!r}")

    with open_archive(multi) as archive:
        members = list(archive.members())
        assert [m.name for m in members] == ["github_14_multi", "github_14_multi"]
        assert all(m.raw_name == b"" for m in members)
        assert [archive.read(m) for m in members] == [b"one\n", b"two\n"]


@requires("py7zr")
def test_copy_bcj_folder_roundtrip(tmp_path: Path) -> None:
    """Standalone BCJ (no LZMA) must be staged on its own, not folded into a chain."""
    payload = bytes(range(256)) * 40
    archive = tmp_path / "copy_bcj.7z"
    _write_py7zr_archive(
        archive,
        {"x.bin": payload},
        filters=_filters("X86", "COPY"),
    )
    _assert_roundtrip(archive, {"x.bin": payload})


# x86-like machine code: dense enough in branch opcodes that every architecture's
# filter rewrites something, so these round-trips exercise the filter rather than a
# pass-through.
_BCJ_CODE_PATTERN = bytes(
    [0x8B, 0x45, 0xF8, 0xE8, 0x10, 0x20, 0x00, 0x00]
    + [0x89, 0x45, 0xFC, 0xE9, 0x00, 0x01, 0x00, 0x00]
)


@pytest.mark.parametrize("method", ["IA64", "ARM", "ARMT", "PPC", "SPARC", "BCJ"])
@requires_binary("7z")
def test_bcj_member_whose_length_is_not_a_whole_number_of_blocks(
    tmp_path: Path, method: str
) -> None:
    """Every branch filter must return the trailing partial block.

    IA64 is the one that was broken: pybcj's decoder dropped the final incomplete
    16-byte block, so a 2911-byte member came back as 2896 bytes and archivey
    raised ``TruncatedError`` on an archive 7-Zip writes and reads back fine
    (dev-docs/investigations/pybcj-upstream-report.md). 2911 is not a multiple of any filter's block size,
    so the same payload covers the other five through the liblzma path.
    """
    payload = (_BCJ_CODE_PATTERN * 200)[:2911]
    src = tmp_path / "payload.bin"
    src.write_bytes(payload)
    archive = tmp_path / f"{method.lower()}.7z"
    run_7z(
        ["a", "-t7z", f"-m0={method}", "-m1=LZMA", str(archive), src.name, "-y"],
        cwd=tmp_path,
        check=True,
    )
    _assert_roundtrip(archive, {"payload.bin": payload})


def test_bcj_decoder_accepts_an_unpack_size_above_two_gib() -> None:
    """A BCJ member of 2 GiB or more must be decodable.

    pybcj takes the stream size as a C signed ``int``, so ``BCJDecoder(2**31)``
    raised a bare ``OverflowError`` — not even an ``ArchiveyError`` — before any byte
    was read, on archives 7-Zip writes with ``-m0=BCJ -m1=LZMA`` and reads back fine
    (dev-docs/investigations/pybcj-upstream-report.md). The declared size no longer reaches the filter at
    all, so the same bytes decode the same way whatever it says; this pins that
    without building a 2 GiB fixture.
    """
    import lzma

    from archivey.internal.streams.codecs.lzma_filter_decoder import FilterDecoder

    payload = bytes(range(256)) * 8
    small = FilterDecoder(lzma_filter={"id": lzma.FILTER_X86}, unpack_size=len(payload))
    huge = FilterDecoder(lzma_filter={"id": lzma.FILTER_X86}, unpack_size=2**31)
    assert huge.feed(payload).data == small.feed(payload).data
    # The declared size still decides whether the stream finished, so the 2 GiB
    # decoder arms the truncation error that the correctly-sized one does not.
    assert small.flush().data == huge.flush().data
    assert small.finished and small.pending_error is None
    assert not huge.finished and isinstance(huge.pending_error, TruncatedError)


_LZ4_7Z_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sevenzip" / "lz4.7z"


@requires("lz4")
def test_lz4_7z_fixture_reads_members() -> None:
    """7z method 0x04f71104 decodes via shared Codec.LZ4 (py7zr/7z CLI cannot extract)."""
    assert _LZ4_7Z_FIXTURE.is_file(), f"missing fixture {_LZ4_7Z_FIXTURE}"
    with open_archive(_LZ4_7Z_FIXTURE) as archive:
        files = {m.name: m for m in archive.members() if m.is_file}
        assert set(files) == {"scripts/py7zr", "setup.cfg", "setup.py"}
        assert files["setup.cfg"].size == 58
        assert files["setup.py"].size == 559
        assert files["scripts/py7zr"].size == 111
        for member in files.values():
            assert CompressionAlgorithm.LZ4 in {
                method.algo for method in member.compression
            }
            data = archive.read(member)
            assert len(data) == member.size
            # Header CRC (when present) is checked by VerifyingStream on read.


def test_decode_utf16_names_bulk() -> None:
    from archivey.internal.backends.sevenzip_parser import _decode_utf16_names

    blob = _names_payload(["a.txt", "dir/b"])
    # _names_payload includes the external flag byte; strip it for the decoder.
    assert blob[0] == 0
    names = _decode_utf16_names(blob[1:], expected_count=2)
    assert names == ["a.txt", "dir/b"]
    # Zero files: empty blob is the legitimate encoding (old loop was a no-op).
    assert _decode_utf16_names(b"", expected_count=0) == []
    with raises_corruption_not_truncation(match="non-empty for zero files"):
        _decode_utf16_names(b"\x00\x00", expected_count=0)
    with raises_corruption_not_truncation(match="odd byte length"):
        _decode_utf16_names(b"abc", expected_count=1)
    with raises_corruption_not_truncation(match="not null-terminated"):
        _decode_utf16_names(b"a\x00", expected_count=1)
    with raises_corruption_not_truncation(match="name count"):
        _decode_utf16_names(blob[1:], expected_count=3)


def test_is_aes_matches_primary_id_and_aliases() -> None:
    from archivey.internal.backends.sevenzip_methods import METHOD_AES, is_aes

    assert is_aes(METHOD_AES.method_id)
    assert not is_aes(b"\x00")
    # AES has no aliases today; the helper still checks ``aliases`` so a future
    # short/long id pair (as BCJ already uses) cannot silently break encryption
    # detection that switched off ``lookup()``.
    assert METHOD_AES.aliases == ()


def test_map_files_to_folders_solid_and_nonsolid() -> None:
    """Per-folder cache must assign indices correctly for both folder shapes."""
    from archivey.internal.backends.sevenzip_parser import (
        SevenZipCoder,
        SevenZipFileRecord,
        SevenZipFolder,
        _map_files_to_folders,
    )

    def _record() -> SevenZipFileRecord:
        return SevenZipFileRecord(
            filename="x",
            emptystream=False,
            is_anti=False,
            is_directory=False,
            attributes=None,
            creation_time=None,
            last_access_time=None,
            last_write_time=None,
            folder_index=None,
            file_in_folder=None,
            uncompressed_size=0,
            crc32=None,
            compressed_size=None,
            is_encrypted=False,
        )

    def _folder() -> SevenZipFolder:
        return SevenZipFolder(
            coders=[
                SevenZipCoder(
                    method=b"\x00",
                    num_in_streams=1,
                    num_out_streams=1,
                    properties=None,
                )
            ],
            bind_pairs=[],
            packed_indices=[0],
            unpack_sizes=[1],
            crc=None,
            digest_defined=False,
        )

    n = 8
    # Solid: one folder, n substreams.
    solid_files = [_record() for _ in range(n)]
    solid = _map_files_to_folders(
        solid_files,
        folders=[_folder()],
        pack_sizes=[n],
        num_unpackstreams_folders=[n],
        unpack_sizes=[1] * n,
        digests=[None] * n,
    )
    assert [f.folder_index for f in solid] == [0] * n
    assert [f.file_in_folder for f in solid] == list(range(n))
    assert all(f.compressed_size == n for f in solid)

    # Non-solid: n folders, one substream each (cache miss every member).
    nonsolid_files = [_record() for _ in range(n)]
    nonsolid = _map_files_to_folders(
        nonsolid_files,
        folders=[_folder() for _ in range(n)],
        pack_sizes=[1] * n,
        num_unpackstreams_folders=[1] * n,
        unpack_sizes=[1] * n,
        digests=[None] * n,
    )
    assert [f.folder_index for f in nonsolid] == list(range(n))
    assert [f.file_in_folder for f in nonsolid] == [0] * n
    assert all(f.compressed_size == 1 for f in nonsolid)


def test_lz4_without_lz4_package_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader_for_unit_tests()
    monkeypatch.setattr(codecs.deps, "lz4_frame", None)

    with pytest.raises(PackageNotInstalledError, match="lz4"):
        _open_pipeline(
            reader, io.BytesIO(b""), _folder(b"\x04\xf7\x11\x04"), password=None
        )


@requires_binary("7z")
def test_lzma1_bcj_decodes_without_pybcj_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BCJ decoding must not import ``bcj``: liblzma carries the branch filters now.

    ``sys.modules[name] = None`` makes any ``import bcj`` raise ImportError, so this
    runs in every dependency leg including the one where pybcj is present.
    """
    import sys

    payload = bytes(range(256)) * 50
    src = tmp_path / "payload.bin"
    src.write_bytes(payload)
    archive = tmp_path / "lzma1-bcj-no-pybcj.7z"
    run_7z(
        ["a", "-t7z", "-m0=BCJ", "-m1=LZMA", str(archive), src.name, "-y"],
        cwd=tmp_path,
        check=True,
    )

    monkeypatch.setitem(sys.modules, "bcj", None)
    _assert_roundtrip(archive, {"payload.bin": payload})


def test_external_comment_is_refused_like_every_other_external_property() -> None:
    """``kComment``'s leading byte is the same "external" flag ``kName`` carries.

    A comment stored in additional streams was decoded as UTF-16LE text — the flag and
    the stream reference presented as an archive comment — while every sibling property
    refuses the same byte.
    """
    from archivey.exceptions import UnsupportedFeatureError
    from archivey.internal.backends.sevenzip_parser import _Cursor, _read_comment

    # external == 0: the payload after it is the comment.
    assert _read_comment(_Cursor(b"\x00" + "hi".encode("utf-16le"))) == "hi"

    with pytest.raises(UnsupportedFeatureError, match="External 7z comment"):
        _read_comment(_Cursor(b"\x01" + (7).to_bytes(8, "little")))


def test_comment_terminator_is_trimmed_a_code_unit_at_a_time() -> None:
    """A byte-wise rstrip ate the high byte of a trailing ASCII character.

    "hi" is ``68 00 69 00``; stripping trailing zero *bytes* leaves ``68 00 69``, an
    odd-length payload that raised ``CorruptionError`` for a well-formed comment.
    """
    from archivey.internal.backends.sevenzip_parser import _Cursor, _read_comment

    assert _read_comment(_Cursor(b"\x00" + "hi\x00".encode("utf-16le"))) == "hi"
    assert _read_comment(_Cursor(b"\x00" + "hi\x00\x00".encode("utf-16le"))) == "hi"
    assert _read_comment(_Cursor(b"\x00")) is None
    assert _read_comment(_Cursor(b"\x00" + "\x00".encode("utf-16le"))) is None
    with raises_corruption_not_truncation(match="odd byte length"):
        _read_comment(_Cursor(b"\x00abc"))


def _encode_7z_number(value: int) -> bytes:
    """7z ``NUMBER``: leading 1-bits of the first byte count the extra LE bytes."""
    for extra in range(8):
        if value < 1 << (8 * extra + 7 - extra):
            first = (0xFF << (8 - extra)) & 0xFF | (value >> (8 * extra))
            return bytes([first]) + (value & ((1 << 8 * extra) - 1)).to_bytes(
                extra, "little"
            )
    return b"\xff" + value.to_bytes(8, "little")


def _overstate_ppmd_unpack_size(path: Path, unpack_size: int) -> int:
    """Rewrite a one-folder PPMd 7z's ``kCodersUnpackSize``, repairing both CRCs.

    Returns the size the writer declared. The CRC repair is what makes this test
    reach the decoder at all: without it the parser refuses the header for
    corruption first.
    """
    data = bytearray(path.read_bytes())
    next_offset, next_size = struct.unpack("<QQ", bytes(data[12:28]))
    start = 32 + next_offset
    header = bytes(data[start : start + next_size])
    coder = header.find(b"\x23\x03\x04\x01")  # PPMd method id, 7z var.H
    assert coder > 0, "no plaintext PPMd coder record in the 7z header"
    field = header.index(b"\x0c", coder)  # kCodersUnpackSize
    declared = header[field + 1]
    assert declared < 0x80, "fixture member must be under 128 bytes"
    header = header[: field + 1] + _encode_7z_number(unpack_size) + header[field + 2 :]
    data[start:] = header
    data[12:28] = struct.pack("<QQ", next_offset, len(header))
    data[28:32] = struct.pack("<L", zlib.crc32(header))
    data[8:12] = struct.pack("<L", zlib.crc32(bytes(data[12:32])))
    path.write_bytes(bytes(data))
    return declared


@requires_binary("7z")
@requires("pyppmd")
@pytest.mark.parametrize("unpack_size", [56, 1 << 40], ids=["plus-1", "1TiB"])
def test_ppmd_folder_overstating_unpack_size_is_truncated(
    tmp_path: Path, unpack_size: int
) -> None:
    """A PPMd folder declaring more output than its pack holds is a truncated member.

    #315 thread K6: the read used to end in a bare ``MemoryError`` from pyppmd, which
    reads as the host running out of memory. The decode runs in a child process
    like the other truncated-PPMd cases in ``test_ppmd_raw_streams``.
    """
    from tests.test_ppmd_raw_streams import _K6_PAYLOAD, _run_ppmd_child

    member = tmp_path / "small.txt"
    member.write_bytes(_K6_PAYLOAD)
    archive = tmp_path / "overstated.7z"
    run_7z(["a", "-mhc=off", "-m0=PPMd", str(archive), str(member)], check=True)
    assert _overstate_ppmd_unpack_size(archive, unpack_size) == len(_K6_PAYLOAD)

    _run_ppmd_child(
        f"""\
from archivey import open_archive
from archivey.exceptions import TruncatedError
from archivey.types import CompressionAlgorithm

with open_archive({str(archive)!r}) as reader:
    (entry,) = reader.members()
    # 7-Zip stores what it cannot compress; a stored member never reaches PPMd.
    assert [m.algo for m in entry.compression] == [CompressionAlgorithm.PPMD]
    assert entry.size == {unpack_size}
    for read_size in (-1, 64, 3_000_000_000):
        with reader.open(entry) as stream:
            try:
                while stream.read(read_size):
                    pass
            except TruncatedError:
                continue
            raise SystemExit(f"read({{read_size}}) ended without TruncatedError")
print("ok")
"""
    )


# 194-byte 7z: PPMd + 7zAES, headers in the clear, one member of 51200 ``a`` bytes,
# password "secret". Measured with 7-Zip 23.01; its salt and IV make "wrong856" decrypt
# to a PPMd pack that ends short of the declared size, the same shape as the
# overstated folder above. A rebuild gets a different salt, so the bytes are pinned.
_AES_PPMD_WRONG_KEY_7Z = (
    "N3q8ryccAARi2VNcIAAAAAAAAACCAAAAAAAAAIuCqMonpMt3igbDY+G+w+v4QIi/"
    "UMHCwxS/uDM9NxKUj6xH9QEEBgABCSAABwsBAAIkBvEHARJTDyPgfVpOxFoWzpLc"
    "0dKtViYjAwQBBQYAABAAAQAMGcAAyAAICgGfWJo8AAAFARkJAAAAAAAAAAAAERkA"
    "cABhAHkAbABvAGEAZAAuAGIAaQBuAAAAGQIAABQKAQD1wcosnEbdARUGAQAggKSB"
    "AAA="
)


@requires("pyppmd")
@requires("cryptography")
def test_aes_ppmd_wrong_key_moves_on_to_the_next_password(tmp_path: Path) -> None:
    """A wrong key whose garbage stops PPMd short is a wrong key, not a crash.

    ``wrong856`` used to end password iteration with pyppmd's ``MemoryError`` before
    ``secret`` was tried (``dev-docs/investigations/ppmd-native-investigation-results.md``
    §K.4). Run in a child process like
    the other PPMd garbage decodes.
    """
    import base64
    import hashlib

    from tests.test_ppmd_raw_streams import _run_ppmd_child

    raw = base64.b64decode(_AES_PPMD_WRONG_KEY_7Z)
    assert hashlib.sha256(raw).hexdigest() == (
        "35dbb0c965d7030d5d27986d165483f9db1d923f347fb23a92acdb02d80b8dbb"
    )
    archive = tmp_path / "aes-ppmd.7z"
    archive.write_bytes(raw)

    _run_ppmd_child(
        f"""\
from archivey import open_archive

with open_archive({str(archive)!r}, password=["wrong856", "secret"]) as reader:
    member = next(m for m in reader.members() if m.is_file)
    assert reader.read(member) == b"a" * 51200
print("ok")
"""
    )


def _created_slot_record(attributes: int | None) -> SevenZipFileRecord:
    return SevenZipFileRecord(
        filename="a.txt",
        emptystream=True,
        is_anti=False,
        is_directory=False,
        attributes=attributes,
        creation_time=_to_filetime_ticks(1_600_000_200),
        last_access_time=None,
        last_write_time=None,
        folder_index=None,
        file_in_folder=None,
        uncompressed_size=0,
        crc32=None,
        compressed_size=None,
        is_encrypted=False,
    )


def _unix_directory_record_with_reparse_bit() -> SevenZipFileRecord:
    return SevenZipFileRecord(
        filename="tree",
        emptystream=True,
        is_anti=False,
        is_directory=True,
        attributes=0x8000 | 0x400 | (0o040755 << 16),
        creation_time=None,
        last_access_time=None,
        last_write_time=None,
        folder_index=None,
        file_in_folder=None,
        uncompressed_size=0,
        crc32=None,
        compressed_size=None,
        is_encrypted=False,
    )


def test_a_unix_directory_with_the_reparse_bit_is_a_plain_directory() -> None:
    """The high word's S_IFDIR types the entry, so the low word's 0x400 makes no link.

    The member stays flagged as a reparse point, since the bit is in the header, but
    with nothing typed as a link there is no link target to report missing.
    """
    with open_archive(io.BytesIO(_EMPTY_7Z)) as reader:
        assert isinstance(reader, SevenZipReader)
        member = reader._to_member(_unix_directory_record_with_reparse_bit(), 0)
        codes = [d.code for d in reader.diagnostics.retained]
    assert member.type is MemberType.DIRECTORY
    assert member.is_reparse_point
    assert DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE not in codes


@pytest.mark.parametrize(
    ("attributes", "expected"),
    [
        (0x8000 | 0x20 | (0o020644 << 16), MemberType.OTHER),  # char device
        (0x8000 | 0x20 | (0o060660 << 16), MemberType.OTHER),  # block device
        (0x8000 | 0x20 | (0o010644 << 16), MemberType.OTHER),  # FIFO
        (0x8000 | 0x20 | (0o140755 << 16), MemberType.OTHER),  # socket
        (0x8000 | 0x20 | (0o100644 << 16), MemberType.FILE),
        # No 0x8000: a Windows attribute word with stray bits above 0xFFFF
        # (0x20000000 is STRICTLY_SEQUENTIAL), not a Unix mode.
        (0x20000020, MemberType.FILE),
        (0o020644 << 16, MemberType.FILE),
    ],
)
def test_unix_special_file_is_other(attributes: int, expected: MemberType) -> None:
    """p7zip stores a FIFO or device with its Unix mode and no data. It is OTHER, as
    in TAR and ISO, so extraction refuses it rather than writing an empty file."""
    with open_archive(io.BytesIO(_EMPTY_7Z)) as reader:
        assert isinstance(reader, SevenZipReader)
        member = reader._to_member(_created_slot_record(attributes), 0)
    assert member.type is expected


_UNIX = CreateSystem.UNIX
_NTFS = CreateSystem.WINDOWS_NTFS


@pytest.mark.parametrize(
    ("attributes", "mode", "expected", "create_system", "special"),
    [
        # 7-Zip on Linux
        (0x8000 | 0x20 | (0o100644 << 16), 0o644, MemberType.FILE, _UNIX, None),
        (0x8000 | 0x20 | (0o120777 << 16), 0o777, MemberType.SYMLINK, _UNIX, None),
        (0x8000 | (0o040755 << 16), 0o755, MemberType.DIRECTORY, _UNIX, None),
        (0x8000 | (0o010644 << 16), 0o644, MemberType.OTHER, _UNIX, "fifo"),
        # Windows words whose high half is not a Unix mode: no mode, and no type from it.
        (0x80020, None, MemberType.FILE, _NTFS, None),  # ARCHIVE | PINNED (OneDrive)
        (0x20000020, None, MemberType.FILE, _NTFS, None),  # | STRICTLY_SEQUENTIAL
        (0x8000 | 0x80020, None, MemberType.FILE, _NTFS, None),  # | INTEGRITY_STREAM
        # A Unix file type without the bit is a mode, as 7-Zip 23.01 lists it, except a
        # special type, which STRICTLY_SEQUENTIAL fakes.
        (0o120777 << 16, 0o777, MemberType.SYMLINK, _UNIX, None),
        (0o040755 << 16, 0o755, MemberType.DIRECTORY, _UNIX, None),
        (0o010644 << 16, None, MemberType.FILE, _NTFS, None),
        # The bit with permission bits only: no file type, so no mode (7-Zip agrees).
        (0x8000 | (0o644 << 16), None, MemberType.FILE, _NTFS, None),
        # Known limit: INTEGRITY_STREAM | STRICTLY_SEQUENTIAL | ARCHIVE (ReFS) is a
        # bit-set Unix char device with no permission bits, and 7-Zip reads it so too.
        (0x20008020, 0, MemberType.OTHER, _UNIX, "char_device"),
    ],
)
def test_one_unix_mode_test_decides_mode_and_type(
    attributes: int,
    mode: int | None,
    expected: MemberType,
    create_system: CreateSystem,
    special: str | None,
) -> None:
    """Every field read from the attribute word's high half reads it by one test.

    Before, ``mode`` took any non-zero high word (ARCHIVE | PINNED gave ``0o10`` and
    ``create_system`` UNIX) while the special-file test needed the ``0x8000`` bit, so
    one record could have a Unix mode for one field and none for another.
    """
    with open_archive(io.BytesIO(_EMPTY_7Z)) as reader:
        assert isinstance(reader, SevenZipReader)
        member = reader._to_member(_created_slot_record(attributes), 0)
    assert member.mode == mode
    assert member.type is expected
    assert member.create_system is create_system
    assert member.extra.get("special_file_type") == special


def _special_file_with_data_record(attributes: int) -> SevenZipFileRecord:
    from dataclasses import replace

    return replace(
        _created_slot_record(attributes),
        emptystream=False,
        folder_index=0,
        file_in_folder=0,
        uncompressed_size=5,
        crc32=0,
        compressed_size=5,
    )


@pytest.mark.parametrize(
    ("attributes", "special"),
    [
        (0x8000 | 0x20 | (0o020644 << 16), "char_device"),
        (0x8000 | 0x20 | (0o060660 << 16), "block_device"),
        (0x8000 | 0x20 | (0o010644 << 16), "fifo"),
        (0x8000 | 0x20 | (0o140755 << 16), "socket"),
    ],
)
def test_unix_special_file_records_name_their_type(
    attributes: int, special: str
) -> None:
    """Stream-less special entries stay OTHER and say which kind of special file
    the archive described, so a caller can tell a FIFO from a device."""
    with open_archive(io.BytesIO(_EMPTY_7Z)) as reader:
        assert isinstance(reader, SevenZipReader)
        member = reader._to_member(_created_slot_record(attributes), 0)
        codes = [d.code for d in reader.diagnostics.retained]
    assert member.type is MemberType.OTHER
    assert member.extra["special_file_type"] == special
    assert DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA not in codes


@pytest.mark.parametrize(
    ("attributes", "special"),
    [
        (0x8000 | 0x20 | (0o020644 << 16), "char_device"),
        (0x8000 | 0x20 | (0o010644 << 16), "fifo"),
    ],
)
def test_unix_special_file_with_a_stream_is_a_file(
    attributes: int, special: str
) -> None:
    """A special mode on an entry that owns a data stream does not hide the data: the
    stream is the structure, so the member is a FILE that keeps the mode in ``extra``
    and reports the mismatch (advisory, so strict still reads it)."""
    py7zr = pytest.importorskip("py7zr")
    archive = io.BytesIO()
    with py7zr.SevenZipFile(archive, "w") as z:
        z.writestr(b"hello", "a.txt")
    archive.seek(0)
    with open_archive(archive) as reader:
        assert isinstance(reader, SevenZipReader)
        member = reader._to_member(_special_file_with_data_record(attributes), 0)
        diags = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
        ]
    assert member.type is MemberType.FILE
    assert member.size == 5
    assert member.extra["special_file_type"] == special
    assert len(diags) == 1
    assert diags[0].context is not None
    assert diags[0].context.to_dict()["special_file_type"] == special
    assert diags[0].context.to_dict()["size"] == 5
    assert DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA not in ARCHIVE_INTEGRITY_CODES


def test_special_mode_reparse_point_with_content_reports_its_data() -> None:
    """A reparse-point bit with a FIFO mode in the high word types the entry a SYMLINK
    provisionally; when its data turns out not to be a link buffer it is re-typed a
    FILE at resolution, and the special-file advisory is reported from that site, since
    the backend's own emit (gated on FILE while the member is typed) did not run."""
    py7zr = pytest.importorskip("py7zr")
    archive = io.BytesIO()
    with py7zr.SevenZipFile(archive, "w") as z:
        z.writestr(b"hello", "a.txt")
    archive.seek(0)
    with open_archive(archive) as reader:
        assert isinstance(reader, SevenZipReader)
        record = _special_file_with_data_record(0x8000 | 0x400 | (0o010644 << 16))
        member = reader._to_member(record, 0)
        assert member.type is MemberType.SYMLINK
        assert member.extra["special_file_type"] == "fifo"
        assert not [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
        ]
        reader._apply_reparse_data(
            member, b"hello", fallback_type=MemberType.FILE, member_id=0
        )
        diags = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
        ]
    assert member.type is MemberType.FILE
    assert len(diags) == 1
    assert diags[0].context is not None
    assert diags[0].context.to_dict()["special_file_type"] == "fifo"
    assert diags[0].context.to_dict()["size"] == 5
    assert [d.code for d in member.diagnostics].count(
        DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
    ) == 1


@requires_binary("7z")
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_real_7z_cli_fifo_is_other_and_not_extracted(tmp_path: Path) -> None:
    """7-Zip and p7zip store a FIFO with its Unix mode and no data."""
    src = tmp_path / "src"
    src.mkdir()
    os.mkfifo(src / "fifo")
    (src / "reg.txt").write_bytes(b"hi")
    archive = tmp_path / "fifo.7z"
    run_7z(["a", str(archive), "fifo", "reg.txt"], cwd=src, check=True)
    with open_archive(archive) as reader:
        types = {m.name: m.type for m in reader.members()}
        assert types == {"fifo": MemberType.OTHER, "reg.txt": MemberType.FILE}
        reader.extract_all(tmp_path / "out")
    assert not (tmp_path / "out" / "fifo").exists()
    assert (tmp_path / "out" / "reg.txt").read_bytes() == b"hi"


def _to_filetime_ticks(unix_seconds: int) -> int:
    return (unix_seconds + 11_644_473_600) * 10_000_000


@pytest.mark.parametrize(
    ("slot", "field", "attributes"),
    [
        ("last_write_time", "modified", None),
        ("last_access_time", "accessed", None),
        ("creation_time", "created", None),
        ("creation_time", "created", 0x20),  # 7-Zip on Windows
        # 7-Zip on Linux, p7zip: the slot would have filled ``ctime``.
        ("creation_time", "ctime", 0x8000 | 0x20 | (0o100644 << 16)),
    ],
)
def test_an_out_of_range_filetime_is_none_and_reported(
    slot: str, field: str, attributes: int | None
) -> None:
    """Each of the three 7z time slots reports a value past datetime's range, naming
    the member field it would have filled."""
    from dataclasses import replace

    from archivey.diagnostics import MemberTimestampContext

    record = replace(_created_slot_record(attributes), creation_time=None)
    record = replace(record, **{slot: 2**64 - 1})
    with open_archive(io.BytesIO(_EMPTY_7Z)) as reader:
        assert isinstance(reader, SevenZipReader)
        member = reader._to_member(record, 0)
        (diagnostic,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
        ]
    assert getattr(member, field) is None
    context = diagnostic.context
    assert isinstance(context, MemberTimestampContext)
    assert (context.field, context.source) == (field, "ntfs")
    assert context.value_repr == str(2**64 - 1)
    assert diagnostic.message == f"Invalid NTFS timestamp for 'a.txt': {2**64 - 1}"


@pytest.mark.parametrize(
    ("attributes", "unix_written"),
    [
        (0x8000 | 0x20 | (0o100644 << 16), True),  # 7-Zip on Linux, p7zip
        (0x8000 | (0o040755 << 16), True),  # a directory from the same writers
        (0o100644 << 16, True),  # Unix mode, bit clear (nonstandard; 7-Zip reads it)
        # ARCHIVE | STRICTLY_SEQUENTIAL: the high word 0x2000 reads as S_IFCHR, a
        # special type, which counts only with the bit.
        (0x20000020, False),
        (0x20, False),  # FILE_ATTRIBUTE_ARCHIVE: 7-Zip on Windows
        (0x8000 | 0x20, False),  # 0x8000 alone: also INTEGRITY_STREAM (ReFS)
        (0x80020, False),  # ARCHIVE | PINNED (OneDrive): high word, no file type
        (0x400020, False),  # ARCHIVE | RECALL_ON_DATA_ACCESS
        (None, False),  # no attribute word
    ],
)
def test_created_slot_follows_the_writer(
    attributes: int | None, unix_written: bool
) -> None:
    """A Unix writer's "Created" is st_ctime: ``ctime``, not ``created``."""
    from datetime import UTC, datetime

    with open_archive(io.BytesIO(_EMPTY_7Z)) as reader:
        assert isinstance(reader, SevenZipReader)
        member = reader._to_member(_created_slot_record(attributes), 0)
    expected = datetime.fromtimestamp(1_600_000_200, tz=UTC)
    if unix_written:
        assert member.created is None
        assert member.ctime == expected
    else:
        assert member.created == expected
        assert member.ctime is None


@requires_binary("7z")
def test_real_7z_cli_created_slot_matches_its_host(tmp_path: Path) -> None:
    """The real writer behind the rule, on whichever host runs the suite."""
    (tmp_path / "a.txt").write_bytes(b"hi")
    archive = tmp_path / "ctime.7z"
    result = run_7z(
        ["a", "-t7z", "-mtc=on", str(archive), "a.txt", "-y"],
        cwd=tmp_path,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"7z CLI cannot build a -mtc=on fixture: {result.stderr}")
    with open_archive(archive) as reader:
        member = reader.get("a.txt")
        record = member._raw.record
        if record.creation_time is None:
            pytest.skip("this 7z CLI stored no creation time")
        assert record.attributes is not None
        if record.attributes & 0x8000:
            assert member.created is None
            assert member.ctime.tzinfo is not None
        else:
            assert member.ctime is None
            assert member.created is not None
