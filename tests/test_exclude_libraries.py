"""``FormatPolicy(exclude_libraries=)``: optional packages that read as not installed.

An excluded package behaves as a missing one for the calls made with that config, and
only for them: the refusal names the policy instead of an install command, and another
call in the process, on any thread, sees the package as it is.
"""

from __future__ import annotations

import ast
import dataclasses
import gzip
import io
import subprocess
import sys
import textwrap
import threading
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyUsageError,
    ContainerFormat,
    FormatDetectionError,
    FormatPolicy,
    FormatSupport,
    OptionalLibrary,
    PackageNotInstalledError,
    detect_format,
    format_availability,
    list_supported_formats,
    open_archive,
    open_stream,
)
from archivey.config import AcceleratorMode, RarDecompressor
from archivey.internal.excluded_libraries import EXCLUDED_REASON
from archivey.internal.plugin_adapter import registration_scope
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.brotli_codec import BrotliCodec
from archivey.plugins import PluginContext, PluginSource
from archivey.types import OptionalLibraryStr
from tests.conftest import requires, requires_binary, requires_zstd, run_7z
from tests.test_format_policy import StdlibZipPlugin
from tests.test_plugins import _ENTRIES, _MAGIC, _plugin_with, build_toya

C = ContainerFormat
L = OptionalLibrary

_SRC = Path(__file__).resolve().parents[1] / "src" / "archivey"
_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


def _excluding(
    *libraries: OptionalLibrary | OptionalLibraryStr, **config: Any
) -> ArchiveyConfig:
    """A config whose policy excludes ``libraries``, with ``config``'s other fields."""
    return dataclasses.replace(
        ArchiveyConfig(formats=FormatPolicy(exclude_libraries=libraries)), **config
    )


def _assert_refused_by_policy(
    exc: PackageNotInstalledError, library: OptionalLibrary
) -> None:
    (component,) = exc.missing
    assert component.name == library
    assert component.reason == EXCLUDED_REASON
    assert "exclude_libraries" in str(exc)
    assert "pip install" not in str(exc)


@pytest.fixture
def clean_registry() -> Iterator[None]:
    with registration_scope():
        yield


# --- the setting ------------------------------------------------------------------------


def test_names_and_values_are_accepted_and_stored_as_members() -> None:
    policy = FormatPolicy(exclude_libraries={L.PYPPMD, "inflate64", "BROTLI"})  # type: ignore[arg-type]
    assert policy.exclude_libraries == frozenset({L.PYPPMD, L.INFLATE64, L.BROTLI})
    assert FormatPolicy().exclude_libraries == frozenset()


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ({"pyppm"}, "Accepted: 'pyppmd'"),
        ({"unrar"}, "not a valid OptionalLibrary"),
        ({"zlib"}, "standard library codecs cannot be turned off"),
        ({"lzma", "bz2"}, "'bz2', 'lzma'"),
        ("pyppmd", "bare string"),
        (L.PYPPMD, "single member"),
        ({3}, "OptionalLibrary"),
    ],
)
def test_anything_but_an_optional_library_is_refused(value: object, match: str) -> None:
    with pytest.raises(ArchiveyUsageError, match=match):
        FormatPolicy(exclude_libraries=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["use_rapidgzip", "use_indexed_bzip2"])
def test_an_accelerator_set_on_conflicts_with_excluding_it(field: str) -> None:
    with pytest.raises(ArchiveyUsageError, match=f"{field}=ON"):
        _excluding(L.RAPIDGZIP, **{field: AcceleratorMode.ON})
    _excluding(L.RAPIDGZIP, **{field: AcceleratorMode.AUTO})


class _NeedsCrypto(StdlibZipPlugin):
    requires = ("cryptography",)


def test_a_named_replacement_that_needs_an_excluded_package_is_refused() -> None:
    with pytest.raises(ArchiveyUsageError, match="_NeedsCrypto, which requires"):
        FormatPolicy(replace={C.ZIP: _NeedsCrypto}, exclude_libraries={L.CRYPTOGRAPHY})
    FormatPolicy(replace={C.ZIP: _NeedsCrypto}, exclude_libraries={L.PYPPMD})


def test_a_plugin_listed_in_only_that_needs_an_excluded_package_is_refused(
    clean_registry: None,
) -> None:
    plugin = _plugin_with("needy", requires=("cryptography",))
    with pytest.raises(ArchiveyUsageError, match="only= lists"):
        FormatPolicy(only={plugin.format.container}, exclude_libraries={L.CRYPTOGRAPHY})


@requires("cryptography")
def test_an_unnamed_plugin_that_needs_an_excluded_package_reads_as_none(
    clean_registry: None, tmp_path: Path
) -> None:
    plugin = _plugin_with("needy", requires=("cryptography",))
    config = _excluding(L.CRYPTOGRAPHY)
    assert format_availability(plugin.format).support is FormatSupport.FULL
    availability = format_availability(plugin.format, config=config)
    assert availability.support is FormatSupport.NONE
    (component,) = availability.missing
    assert (component.name, component.reason) == ("cryptography", EXCLUDED_REASON)
    path = tmp_path / "a.needy"
    path.write_bytes(build_toya(_ENTRIES))
    with pytest.raises(PackageNotInstalledError) as exc_info:
        open_archive(path, config=config)
    assert exc_info.value.missing == availability.missing


@requires("cryptography")
def test_a_plugin_requiring_a_submodule_of_an_excluded_package_reads_as_none(
    clean_registry: None,
) -> None:
    # ``requires`` names modules, so a submodule of an excluded package is off too.
    plugin = _plugin_with("subneedy", requires=("cryptography.hazmat",))
    assert format_availability(plugin.format).support is FormatSupport.FULL
    availability = format_availability(plugin.format, config=_excluding(L.CRYPTOGRAPHY))
    assert availability.support is FormatSupport.NONE
    (component,) = availability.missing
    assert component.reason == EXCLUDED_REASON
    with pytest.raises(ArchiveyUsageError, match="which requires"):
        FormatPolicy(only={plugin.format.container}, exclude_libraries={L.CRYPTOGRAPHY})


def test_a_plugin_probe_does_not_run_when_its_package_is_excluded(
    clean_registry: None,
) -> None:
    # A probe is handed no policy, so archivey leaves it out rather than let it import
    # an excluded package on untrusted bytes.
    calls: list[bytes] = []

    def probe(prefix: bytes) -> bool:
        calls.append(prefix)
        return prefix.startswith(_MAGIC)

    plugin = _plugin_with("probedneedy", probe=probe, requires=("cryptography",))
    data = build_toya(_ENTRIES)
    config = _excluding(L.CRYPTOGRAPHY, always_probe_content=True)
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data), config=config)
    assert calls == []
    other = _excluding(L.PYPPMD, always_probe_content=True)
    assert detect_format(io.BytesIO(data), config=other).format == plugin.format
    assert calls


# --- codecs -----------------------------------------------------------------------------


def _ppmd_and_lzma2_7z(tmp_path: Path) -> Path:
    """A 7z with one PPMd member and one LZMA2 member, each in its own folder."""
    (tmp_path / "ppmd.txt").write_bytes(b"ppmd member\n" * 100)
    (tmp_path / "lzma2.txt").write_bytes(b"lzma2 member\n" * 100)
    path = tmp_path / "mixed.7z"
    for name, method in (("ppmd.txt", "PPMd"), ("lzma2.txt", "LZMA2")):
        run_7z(["a", f"-m0={method}", str(path), name], cwd=tmp_path, check=True)
    return path


@requires("pyppmd")
@requires_binary("7z")
def test_an_excluded_pyppmd_refuses_only_the_ppmd_member(tmp_path: Path) -> None:
    path = _ppmd_and_lzma2_7z(tmp_path)
    config = _excluding("pyppmd")
    with open_archive(path, config=config) as reader:
        assert sorted(m.name for m in reader.members()) == ["lzma2.txt", "ppmd.txt"]
        with reader.open("lzma2.txt") as stream:
            assert stream.read() == b"lzma2 member\n" * 100
        with (
            pytest.raises(PackageNotInstalledError) as exc_info,
            reader.open("ppmd.txt") as stream,
        ):
            stream.read()
    _assert_refused_by_policy(exc_info.value, L.PYPPMD)
    availability = format_availability(ArchiveFormat.SEVEN_Z, config=config)
    assert availability.support is FormatSupport.PARTIAL
    assert [(m.name, m.reason) for m in availability.missing] == [
        ("pyppmd", EXCLUDED_REASON)
    ]
    # The same archive without the setting reads in full.
    with open_archive(path) as reader, reader.open("ppmd.txt") as stream:
        assert stream.read() == b"ppmd member\n" * 100


@requires("pyppmd")
@requires_binary("7z")
def test_threads_with_and_without_the_exclusion_get_their_own_answer(
    tmp_path: Path,
) -> None:
    path = _ppmd_and_lzma2_7z(tmp_path)
    barrier = threading.Barrier(2)
    results: dict[str, object] = {}

    def read(label: str, config: ArchiveyConfig | None) -> None:
        with open_archive(path, config=config) as reader:
            barrier.wait()
            for _ in range(20):
                try:
                    with reader.open("ppmd.txt") as stream:
                        results[label] = stream.read()
                except PackageNotInstalledError as exc:
                    results[label] = exc

    threads = [
        threading.Thread(target=read, args=("excluded", _excluding(L.PYPPMD))),
        threading.Thread(target=read, args=("plain", None)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert isinstance(results["excluded"], PackageNotInstalledError)
    assert results["plain"] == b"ppmd member\n" * 100


@requires_zstd()
def test_excluding_the_zstd_module_in_use_turns_zstd_off(tmp_path: Path) -> None:
    in_use = deps.zstd_library
    assert in_use is not None and deps.zstd is not None
    other = L.BACKPORTS_ZSTD if in_use is L.COMPRESSION_ZSTD else L.COMPRESSION_ZSTD
    path = tmp_path / "a.zst"
    path.write_bytes(deps.zstd.compress(b"zstd data"))
    with open_stream(path, config=_excluding(other)) as stream:
        assert stream.read() == b"zstd data"
    with pytest.raises(PackageNotInstalledError) as exc_info:
        open_stream(path, config=_excluding(in_use)).read()
    _assert_refused_by_policy(exc_info.value, in_use)
    availability = format_availability(ArchiveFormat.ZST, config=_excluding(in_use))
    assert availability.support is FormatSupport.NONE
    assert [m.name for m in availability.missing] == [in_use]


@requires("rapidgzip")
def test_an_excluded_rapidgzip_under_auto_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey.internal.streams.codecs import deflate_family_codec

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("rapidgzip ran although the policy excludes it")

    monkeypatch.setattr(deflate_family_codec, "_open_rapidgzip", refuse)
    path = tmp_path / "a.gz"
    payload = bytes(range(256)) * 40_000
    path.write_bytes(gzip.compress(payload))
    config = _excluding(L.RAPIDGZIP, use_rapidgzip=AcceleratorMode.AUTO)
    with open_stream(path, seekable=True, config=config) as stream:
        stream.seek(len(payload) - 10)
        assert stream.read() == payload[-10:]


_NEVER_IMPORTED = textwrap.dedent(
    """
    import io, sys
    import brotli
    data = brotli.compress(b"brotli data")
    del sys.modules["brotli"]
    from archivey import ArchiveyConfig, FormatPolicy, PackageNotInstalledError
    from archivey import open_stream
    config = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={{"brotli"}}))
    try:
        open_stream(io.BytesIO(data), format="br", config=config).read()
    except PackageNotInstalledError as exc:
        print("refused", exc.missing[0].reason == {reason!r})
    print("imported", "brotli" in sys.modules)
    """
)


@requires("brotli")
def test_an_excluded_lazy_package_is_never_imported() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-W",
            "ignore",
            "-c",
            _NEVER_IMPORTED.format(reason=EXCLUDED_REASON),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    assert proc.stdout.split("\n")[:2] == ["refused True", "imported False"]


@requires("brotli")
def test_detection_does_not_probe_with_an_excluded_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import brotli

    data = brotli.compress(b"brotli data " * 50)
    probing = ArchiveyConfig(always_probe_content=True)
    assert (
        detect_format(io.BytesIO(data), config=probing).format == ArchiveFormat.BROTLI
    )

    def refuse(*args: object, **kwargs: object) -> bool:
        raise AssertionError("the Brotli probe ran although the policy excludes it")

    monkeypatch.setattr(BrotliCodec, "content_probe", refuse)
    with pytest.raises(FormatDetectionError):
        detect_format(
            io.BytesIO(data), config=_excluding(L.BROTLI, always_probe_content=True)
        )


# --- whole formats ----------------------------------------------------------------------


@requires("pycdlib")
def test_an_excluded_pycdlib_refuses_iso(tmp_path: Path) -> None:
    from tests.test_audit2_iso_dir_detect import _iso_image

    path = tmp_path / "a.iso"
    path.write_bytes(_iso_image())
    config = _excluding(L.PYCDLIB)
    with pytest.raises(PackageNotInstalledError) as exc_info:
        open_archive(path, config=config)
    assert [m.name for m in exc_info.value.missing] == ["pycdlib"]
    assert exc_info.value.missing[0].reason == EXCLUDED_REASON
    availability = format_availability(ArchiveFormat.ISO, config=config)
    assert availability.support is FormatSupport.NONE
    assert ArchiveFormat.ISO not in list_supported_formats(config=config)
    assert ArchiveFormat.ISO in list_supported_formats()


def test_supported_formats_do_not_filter_by_allows() -> None:
    config = ArchiveyConfig(formats=FormatPolicy(only={C.ZIP}))
    assert set(list_supported_formats(config=config)) == set(list_supported_formats())


class _NeedsAbsentModule(StdlibZipPlugin):
    requires = ("archivey_no_such_module",)

    def open(self, source: PluginSource, context: PluginContext) -> object:  # type: ignore[override]
        raise AssertionError("the plugin opened although its module is missing")


def test_availability_answers_for_the_replacement(tmp_path: Path) -> None:
    config = ArchiveyConfig(formats=FormatPolicy(replace={C.ZIP: _NeedsAbsentModule}))
    availability = format_availability(ArchiveFormat.ZIP, config=config)
    assert availability.support is FormatSupport.NONE
    assert [m.name for m in availability.missing] == ["archivey_no_such_module"]
    assert format_availability(ArchiveFormat.ZIP).support is not FormatSupport.NONE
    assert ArchiveFormat.ZIP not in list_supported_formats(config=config)
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"alpha")
    with pytest.raises(PackageNotInstalledError) as exc_info:
        open_archive(path, config=config)
    assert exc_info.value.missing == availability.missing


# --- cryptography -----------------------------------------------------------------------


def _encrypted(tmp_path: Path, kind: str) -> Path:
    (tmp_path / "secret.txt").write_bytes(b"secret\n" * 10)
    path = tmp_path / f"a.{kind}"
    flags = ["-tzip", "-mem=AES256"] if kind == "zip" else []
    run_7z(["a", *flags, "-ppw", str(path), "secret.txt"], cwd=tmp_path, check=True)
    return path


@requires("cryptography")
@requires_binary("7z")
@pytest.mark.parametrize("kind", ["zip", "7z"])
@pytest.mark.parametrize("streaming", [False, True])
def test_an_excluded_cryptography_refuses_aes_members(
    tmp_path: Path, kind: str, streaming: bool
) -> None:
    path = _encrypted(tmp_path, kind)
    config = _excluding(L.CRYPTOGRAPHY)
    with (
        pytest.raises(PackageNotInstalledError) as exc_info,
        open_archive(path, password="pw", config=config, streaming=streaming) as reader,
    ):
        for member, stream in reader.stream_members():
            assert member.name == "secret.txt"
            assert stream is not None
            stream.read()
    _assert_refused_by_policy(exc_info.value, L.CRYPTOGRAPHY)
    with open_archive(path, password="pw") as reader:
        assert reader.read("secret.txt") == b"secret\n" * 10


@requires("cryptography")
def test_an_excluded_cryptography_refuses_a_stored_rar_member() -> None:
    config = _excluding(L.CRYPTOGRAPHY, rar_decompressor=RarDecompressor.NONE)
    path = _RAR_FIXTURES / "encryption_stored__.rar"
    with open_archive(path, password="password", config=config) as reader:
        member = reader.members()[0]
        with pytest.raises(PackageNotInstalledError) as exc_info:
            reader.read(member)
    _assert_refused_by_policy(exc_info.value, L.CRYPTOGRAPHY)


@requires("cryptography")
def test_an_excluded_cryptography_refuses_rar_header_decryption() -> None:
    path = _RAR_FIXTURES / "encrypted_header__.rar"
    with (
        pytest.raises(PackageNotInstalledError) as exc_info,
        open_archive(
            path, password="header_password", config=_excluding(L.CRYPTOGRAPHY)
        ) as reader,
    ):
        reader.members()
    _assert_refused_by_policy(exc_info.value, L.CRYPTOGRAPHY)
    with open_archive(path, password="header_password") as reader:
        assert reader.members()


# The entry points into AES. Each takes the call's excluded set; a call that left it
# out would decrypt with cryptography although the policy turns it off.
# Each call that carries the policy to a cipher, with the keyword that carries it. Their
# defaults mean "no exclusions" for the test callers, so a production call that leaves
# the keyword out would decrypt under a policy that turns ``cryptography`` off.
_CRYPTO_ENTRIES = {
    **dict.fromkeys(
        (
            "get_crypto_backend",
            "open_aes_decrypt_stage",
            "open_aes_ctr_stage",
            "open_aes_decrypt_stream",
            "AesDecryptStream",
            "open_winzip_aes_member",
            "open_winzip_aes_forward",
            "WinZipAesDecryptStream",
            "WinZipAesForwardStream",
            "_HeaderDecryptStream",
            # RAR header decryption reaches the cipher through the parser.
            "parse_rar_archive",
            "parse_rar_volumes",
            "_parse_rar_volume",
            "_parse_rar3",
            "_parse_rar5",
        ),
        "excluded",
    ),
    # A 7z folder's AES stage takes the policy from its ``StreamConfig``.
    **dict.fromkeys(
        ("open_folder_pipeline", "decode_folder_to_bytes", "decode_encoded_header"),
        "stream_config",
    ),
}


def test_every_crypto_entry_call_passes_the_excluded_set() -> None:
    offenders = []
    sites = 0
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name not in _CRYPTO_ENTRIES:
                continue
            sites += 1
            # ``get_crypto_backend(excluded)`` takes it positionally.
            if node.args and name == "get_crypto_backend":
                continue
            if not any(k.arg == _CRYPTO_ENTRIES[name] for k in node.keywords):
                rel = path.relative_to(_SRC).as_posix()
                offenders.append(f"{rel}:{node.lineno} {name}")
    assert sites > 10, "the scan found almost no call sites, so it guards nothing"
    assert not offenders, "crypto entry without the policy: " + ", ".join(offenders)
