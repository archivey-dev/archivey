"""Backend-registry tests — Stage 1 scope.

Covers always-register-via-sentinel, tri-state FULL/PARTIAL/NONE availability,
``list_supported_formats()`` vs ``list_known_formats()``, install-hint selection errors,
and two simultaneous readers. The NONE-end-to-end ISO-without-pycdlib path is exercised in
Stage 4 with the real ISO backend.
"""

from __future__ import annotations

import importlib
import importlib.util
import io
import operator
import sys
import types
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    FormatSupport,
    StreamCapability,
    StreamNotSeekableError,
    format_availability,
    list_known_formats,
    list_supported_formats,
    open_archive,
)
from archivey.exceptions import PackageNotInstalledError, UnsupportedFeatureError
from archivey.internal.base_reader import ReadBackend
from archivey.internal.registry import BackendRegistry, get_registry
from archivey.internal.streams import codecs as codecs_module
from archivey.types import ContainerFormat, MagicSignature, MissingComponent
from tests.sample_archives import (
    CORPUS,
    FORMAT_KEYS,
    corpus_archive_path,
    skip_unless_runnable,
)

# ---------------------------------------------------------------------------
# Synthetic backends, registered into a *fresh* registry (no global pollution)
# ---------------------------------------------------------------------------


class _CoreBackend(ReadBackend):
    FORMATS = (ArchiveFormat.TAR,)
    EXTENSIONS: Mapping[str, ArchiveFormat] = {".tar": ArchiveFormat.TAR}
    MAGIC = (MagicSignature(257, b"ustar", ArchiveFormat.TAR),)

    def open_read(
        self, source, streaming, password, encoding, archive_name
    ):  # pragma: no cover
        raise NotImplementedError


class _OptionalPresentBackend(ReadBackend):
    FORMATS = (ArchiveFormat.RAR,)
    OPTIONAL_DEPENDENCY = "io"  # a module that always imports
    INSTALL_HINT = "pip install archivey[present]"

    def open_read(
        self, source, streaming, password, encoding, archive_name
    ):  # pragma: no cover
        raise NotImplementedError


class _OptionalMissingBackend(ReadBackend):
    FORMATS = (ArchiveFormat.ISO,)
    OPTIONAL_DEPENDENCY = "a_package_that_does_not_exist_xyz"
    INSTALL_HINT = "pip install archivey[recommended]"

    def open_read(
        self, source, streaming, password, encoding, archive_name
    ):  # pragma: no cover
        raise NotImplementedError


class _RecognisedOnlyBackend(ReadBackend):
    FORMATS = (ArchiveFormat.ZIP,)
    READ_IMPLEMENTED = False  # and no UNSUPPORTED_MESSAGE: the fallback text applies

    def open_read(
        self, source, streaming, password, encoding, archive_name
    ):  # pragma: no cover
        raise NotImplementedError


@pytest.fixture
def registry() -> BackendRegistry:
    reg = BackendRegistry()
    reg.register_reader(_CoreBackend)
    reg.register_reader(_OptionalPresentBackend)
    reg.register_reader(_OptionalMissingBackend)
    return reg


# ---------------------------------------------------------------------------
# Always-register; availability derived from the module-or-None sentinel
# ---------------------------------------------------------------------------


def test_optional_missing_backend_is_known_but_unavailable(
    registry: BackendRegistry,
) -> None:
    # Registered regardless of its dependency: present in "known", absent from "supported".
    assert ArchiveFormat.ISO in registry.list_known_formats()
    assert ArchiveFormat.ISO not in registry.list_supported_formats()

    avail = registry.format_availability(ArchiveFormat.ISO)
    assert avail.support is FormatSupport.NONE
    assert len(avail.missing) == 1
    assert avail.missing[0].name == "a_package_that_does_not_exist_xyz"
    assert "archivey[recommended]" in avail.missing[0].install_hint


def test_optional_present_backend_is_full(registry: BackendRegistry) -> None:
    avail = registry.format_availability(ArchiveFormat.RAR)
    assert avail.support is FormatSupport.FULL
    assert avail.missing == ()
    assert ArchiveFormat.RAR in registry.list_supported_formats()


def test_core_backend_is_full(registry: BackendRegistry) -> None:
    avail = registry.format_availability(ArchiveFormat.TAR)
    assert avail.support is FormatSupport.FULL


def test_unknown_format_is_none(registry: BackendRegistry) -> None:
    avail = registry.format_availability(ArchiveFormat.SEVEN_Z)
    assert avail.support is FormatSupport.NONE
    assert avail.missing == ()


def test_reader_for_missing_dependency_raises_with_hint(
    registry: BackendRegistry,
) -> None:
    with pytest.raises(PackageNotInstalledError) as excinfo:
        registry.reader_for_format(ArchiveFormat.ISO)
    msg = str(excinfo.value)
    assert "a_package_that_does_not_exist_xyz" in msg
    assert "archivey[recommended]" in msg


def test_reader_for_unknown_format_raises(registry: BackendRegistry) -> None:
    with pytest.raises(UnsupportedFeatureError):
        registry.reader_for_format(ArchiveFormat.SEVEN_Z)


def test_recognised_only_backend_is_refused_with_its_message(
    registry: BackendRegistry,
) -> None:
    # Any READ_IMPLEMENTED-false backend, not only DMG. Without UNSUPPORTED_MESSAGE
    # the refusal still has text.
    registry.register_reader(_RecognisedOnlyBackend)
    expected = f"Reading {ArchiveFormat.ZIP.display_name} is not supported."
    assert registry.unread_format_message(ArchiveFormat.ZIP) == expected
    with pytest.raises(UnsupportedFeatureError) as excinfo:
        registry.reader_for_format(ArchiveFormat.ZIP)
    assert expected in str(excinfo.value)
    # A readable format and an unregistered one have no refusal text.
    assert registry.unread_format_message(ArchiveFormat.TAR) is None
    assert registry.unread_format_message(ArchiveFormat.SEVEN_Z) is None


# ---------------------------------------------------------------------------
# Detection tables aggregate backend data
# ---------------------------------------------------------------------------


def test_magic_and_extension_tables_aggregate(registry: BackendRegistry) -> None:
    assert MagicSignature(257, b"ustar", ArchiveFormat.TAR) in registry.magic_entries()
    assert registry.extension_map()[".tar"] == ArchiveFormat.TAR


# ---------------------------------------------------------------------------
# Tri-state PARTIAL: a multi-codec container missing an optional member codec
# ---------------------------------------------------------------------------


def test_zip_partial_when_optional_codecs_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ZIP can store deflate64 (inflate64) and zstd, both in [recommended]; with those absent it
    # still opens and lists common (stored/deflate) members -> PARTIAL.
    monkeypatch.setattr(
        codecs_module.deps,
        "inflate64",
        codecs_module.deps.LazyOptional("inflate64", present=False),
    )
    monkeypatch.setattr(codecs_module.deps, "zstd", None)

    avail = format_availability(ArchiveFormat.ZIP)
    assert avail.support is FormatSupport.PARTIAL
    missing_names = {m.name for m in avail.missing}
    assert {"inflate64", "backports.zstd"} <= missing_names
    # PARTIAL formats are still "supported" (readable for their common members).
    assert ArchiveFormat.ZIP in list_supported_formats()


def test_zip_full_when_optional_codecs_present(monkeypatch: pytest.MonkeyPatch) -> None:
    # With the codec layer wired into ZIP member reads, ZIP reports FULL when every
    # optional member codec backend is installed (deflate64 / zstd / ppmd).
    monkeypatch.setattr(codecs_module.deps, "zstd", object())
    for name in ("inflate64", "pyppmd"):
        monkeypatch.setattr(
            codecs_module.deps,
            name,
            codecs_module.deps.LazyOptional(name, present=True),
        )
    avail = format_availability(ArchiveFormat.ZIP)
    assert avail.support is FormatSupport.FULL
    assert avail.missing == ()
    assert ArchiveFormat.ZIP in list_supported_formats()


def test_single_codec_format_none_when_codec_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A bare single-file compressor whose sole codec backend is missing is NONE (not
    # PARTIAL): there is nothing to fall back to. ZST's codec is backports.zstd / stdlib zstd.
    monkeypatch.setattr(codecs_module.deps, "zstd", None)
    avail = format_availability(ArchiveFormat.ZST)
    assert avail.support is FormatSupport.NONE
    assert avail.missing[0].name == "backports.zstd"
    assert ArchiveFormat.ZST in list_known_formats()
    assert ArchiveFormat.ZST not in list_supported_formats()


def test_single_codec_format_full_when_codec_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(codecs_module.deps, "zstd", object())
    assert format_availability(ArchiveFormat.ZST).support is FormatSupport.FULL


# ---------------------------------------------------------------------------
# Global registry: known includes everything; supported excludes NONE
# ---------------------------------------------------------------------------


def test_global_known_and_supported() -> None:
    known = list_known_formats()
    supported = list_supported_formats()
    assert ArchiveFormat.ZIP in known
    assert ArchiveFormat.DIRECTORY in known
    assert ArchiveFormat.ZIP in supported
    # Supported is always a subset of known.
    assert set(supported) <= set(known)


def test_directory_is_full() -> None:
    assert format_availability(ArchiveFormat.DIRECTORY).support is FormatSupport.FULL


# ---------------------------------------------------------------------------
# Two simultaneous readers
# ---------------------------------------------------------------------------


def _make_zip(path: Path, content: bytes) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("data.txt", content)


def test_two_simultaneous_readers(tmp_path: Path) -> None:
    a = tmp_path / "a.zip"
    b = tmp_path / "b.zip"
    _make_zip(a, b"alpha")
    _make_zip(b, b"beta")

    with open_archive(a) as ra, open_archive(b) as rb:
        # Independent readers: interleaved reads do not interfere.
        assert ra.read("data.txt") == b"alpha"
        assert rb.read("data.txt") == b"beta"
        assert ra.read("data.txt") == b"alpha"


def test_partial_container_does_not_lower_for_unrelated_format(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Removing a ZIP-relevant codec must not affect a codec-less format like DIRECTORY.
    monkeypatch.setattr(codecs_module.deps, "zstd", None)
    assert format_availability(ArchiveFormat.DIRECTORY).support is FormatSupport.FULL
    assert ContainerFormat.DIRECTORY == ArchiveFormat.DIRECTORY.container


# ---------------------------------------------------------------------------
# Stage 4: NONE end-to-end — the real ISO backend without pycdlib degrades
# gracefully (simulated absence, so this runs in the core-only leg too).
# ---------------------------------------------------------------------------


def test_iso_none_without_pycdlib(monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    import archivey.internal.backends  # noqa: F401 - ensures the ISO backend is registered
    from archivey.internal import registry as registry_module

    real_optional = registry_module._optional
    monkeypatch.setattr(
        registry_module,
        "_optional",
        lambda name: None if name == "pycdlib" else real_optional(name),
    )

    avail = format_availability(ArchiveFormat.ISO)
    assert avail.support is FormatSupport.NONE
    assert any(m.name == "pycdlib" for m in avail.missing)
    assert any("archivey[recommended]" in m.install_hint for m in avail.missing)

    # NONE is excluded from the supported list but still known.
    assert ArchiveFormat.ISO not in list_supported_formats()
    assert ArchiveFormat.ISO in list_known_formats()

    # Selecting it raises an install-hint error rather than crashing.
    with pytest.raises(PackageNotInstalledError) as excinfo:
        open_archive(io.BytesIO(b"not an iso"), format=ArchiveFormat.ISO)
    assert "pycdlib" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Compressed tar: the outer stream codec is a single-codec gate (NONE, not PARTIAL)
# ---------------------------------------------------------------------------


def test_compressed_tar_none_when_stream_codec_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io

    # A compressed tar cannot even be listed without its outer codec, so per the
    # single-codec rule tar.zst is NONE with the codec's install hint — not FULL.
    monkeypatch.setattr(codecs_module.deps, "zstd", None)
    avail = format_availability(ArchiveFormat.TAR_ZST)
    assert avail.support is FormatSupport.NONE
    assert avail.missing[0].name == "backports.zstd"
    assert ArchiveFormat.TAR_ZST in list_known_formats()
    assert ArchiveFormat.TAR_ZST not in list_supported_formats()

    # Selecting it raises an install-hint error rather than failing later at decode time.
    with pytest.raises(PackageNotInstalledError) as excinfo:
        open_archive(io.BytesIO(b"not a tar.zst"), format=ArchiveFormat.TAR_ZST)
    assert "backports.zstd" in str(excinfo.value)


def test_compressed_tar_full_when_stream_codec_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(codecs_module.deps, "zstd", object())
    assert format_availability(ArchiveFormat.TAR_ZST).support is FormatSupport.FULL


@pytest.mark.skipif(
    importlib.util.find_spec("pycdlib") is None,
    reason=(
        "with pycdlib genuinely absent the registry gate rejects ISO before dispatch "
        "reaches the backend (that path is test_iso_none_without_pycdlib); this test "
        "needs the gate to pass so the reader's own raise runs"
    ),
)
def test_iso_reader_missing_pycdlib_hint_matches_availability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reader's own raise must advise the same extra the registry reports.

    Patching only ``iso_reader.pycdlib`` (not the registry's ``_optional``) lets dispatch
    reach the backend, which is the path that used to name a deleted ``[iso]`` extra while
    ``format_availability`` already said ``[recommended]``.
    """
    import io

    from archivey.exceptions import PackageNotInstalledError
    from archivey.internal.backends import iso_reader

    monkeypatch.setattr(iso_reader, "pycdlib", None)
    with pytest.raises(PackageNotInstalledError) as excinfo:
        open_archive(io.BytesIO(b"not an iso"), format=ArchiveFormat.ISO)
    message = str(excinfo.value)
    assert "pycdlib" in message
    assert "archivey[recommended]" in message
    assert iso_reader.IsoReadBackend.INSTALL_HINT in message


# ---------------------------------------------------------------------------
# required_source — the pipe/seek split, as data
# ---------------------------------------------------------------------------


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


# The documented table, written out rather than derived, so a backend that flips
# SUPPORTS_STREAMING_NON_SEEKABLE has to change this list too instead of silently
# agreeing with itself.
# TAR, ar, CPIO, ZIP and the raw codecs read from a pipe. DMG reports the same shape so the
# spool recipe does not copy a file that open refuses from either shape.
_FORWARD_ONLY_CONTAINERS = {
    ContainerFormat.TAR,
    ContainerFormat.AR,
    ContainerFormat.CPIO,
    ContainerFormat.ZIP,
    ContainerFormat.RAW_STREAM,
    ContainerFormat.DMG,
}


@pytest.mark.parametrize("fmt", list_known_formats(), ids=lambda f: f.display_name)
def test_required_source_is_declared_for_every_known_format(fmt: ArchiveFormat) -> None:
    """Every known format answers "can I read this from a pipe?" without being tried."""
    expected = (
        StreamCapability.FORWARD_ONLY
        if fmt.container in _FORWARD_ONLY_CONTAINERS
        else StreamCapability.SEEKABLE
    )
    assert format_availability(fmt).required_source is expected


@pytest.mark.parametrize("key", ["tar", "tar.gz", "gz", "zip", "iso", "7z"])
def test_required_source_predicts_whether_a_pipe_works(
    key: str, tmp_path: Path
) -> None:
    """The field is only worth having if it agrees with what actually happens.

    Opening from a non-seekable source succeeds exactly when the format's
    ``required_source`` is satisfied by ``FORWARD_ONLY`` — which is what makes the
    comparison against ``reader.cost.stream_capability`` a usable substitute for
    catching ``StreamNotSeekableError``.
    """
    entry = next(
        e for e in CORPUS if e.id == ("single-file" if key == "gz" else "basic")
    )
    skip_unless_runnable(entry, key)
    data = corpus_archive_path(entry, key, tmp_path).read_bytes()

    required = format_availability(FORMAT_KEYS[key]).required_source
    pipe_is_enough = required <= StreamCapability.FORWARD_ONLY

    if pipe_is_enough:
        with open_archive(_NonSeekable(data), streaming=True) as reader:
            assert reader.cost.stream_capability is StreamCapability.FORWARD_ONLY
    else:
        with pytest.raises(StreamNotSeekableError):
            open_archive(_NonSeekable(data), streaming=True)


def test_required_source_survives_a_missing_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whether ISO needs to seek does not depend on whether ``pycdlib`` is installed."""
    monkeypatch.setattr(
        "archivey.internal.registry._optional", lambda name: None, raising=True
    )
    availability = format_availability(ArchiveFormat.ISO)
    assert availability.support is FormatSupport.NONE
    assert availability.required_source is StreamCapability.SEEKABLE


# Formats whose backend needs seek in either access mode, read from the classes rather
# than listed, so a format that gains such a backend (or an optional package) is covered.
_SEEK_ONLY_FORMATS = [
    fmt
    for fmt in list_known_formats()
    if get_registry().needs_seekable_source(fmt)
    and fmt.container is not ContainerFormat.DIRECTORY
]


@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_a_piped_iso_without_pycdlib_is_refused_as_a_pipe(
    streaming: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pipe cannot be read even with ``pycdlib``, so the pipe is what gets named.

    Asking for ``pycdlib`` first sends the caller to install a package and only then
    tells them the source could never have worked.
    """
    monkeypatch.setattr(
        "archivey.internal.registry._optional", lambda name: None, raising=True
    )
    # Just enough of an ISO 9660 image for detection: the primary volume descriptor's
    # "CD001" at sector 16.
    image = bytes(0x8001) + b"CD001" + bytes(0x1000)
    with pytest.raises(StreamNotSeekableError, match="either access mode") as ei:
        open_archive(_NonSeekable(image), streaming=streaming)
    assert ei.value.source_format == ArchiveFormat.ISO


@pytest.mark.parametrize("fmt", _SEEK_ONLY_FORMATS, ids=lambda f: f.display_name)
def test_the_read_once_refusal_does_not_depend_on_optional_packages(
    fmt: ArchiveFormat, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every seek-only format refuses a pipe the same way with no optional package."""
    monkeypatch.setattr(
        "archivey.internal.registry._optional", lambda name: None, raising=True
    )
    with pytest.raises(StreamNotSeekableError, match="either access mode"):
        open_archive(_NonSeekable(bytes(64)), format=fmt, streaming=True)


@pytest.mark.parametrize(
    ("fmt", "reason"),
    [
        # RAR headers sit at the front; the header walk's seeks and unrar needing a
        # file are what stop a pipe.
        (ArchiveFormat.RAR, "the header walk seeks past each member's data"),
        (ArchiveFormat.SEVEN_Z, "its index is at the end of the file"),
        (ArchiveFormat.ISO, "at absolute offsets in the image"),
    ],
    ids=["RAR", "7z", "ISO"],
)
def test_the_read_once_refusal_names_the_format_s_own_reason(
    fmt: ArchiveFormat, reason: str
) -> None:
    """The refusal says why this format needs seek, not one reason for all of them."""
    with pytest.raises(StreamNotSeekableError) as ei:
        open_archive(_NonSeekable(bytes(64)), format=fmt, streaming=True)
    assert reason in str(ei.value)
    assert ei.value.source_format == fmt


def test_a_backend_sets_its_own_reason_exactly_when_it_refuses_pipes() -> None:
    """Every seek-only backend says why; no pipe-capable backend carries dead text.

    Fails if any one of the three ``NON_SEEKABLE_REASON`` lines is deleted, or if a
    backend that streams from a pipe sets one nobody reads.
    """
    assert _SEEK_ONLY_FORMATS, "the registry should still have seek-only formats"
    registry = get_registry()
    for fmt in list_known_formats():
        backend_cls = registry.registered_reader(fmt)
        if backend_cls is None or fmt.container is ContainerFormat.DIRECTORY:
            continue
        overrides = any(
            "NON_SEEKABLE_REASON" in vars(klass)
            for klass in backend_cls.__mro__
            if klass is not ReadBackend
        )
        assert overrides is (fmt in _SEEK_ONLY_FORMATS), fmt


def test_the_streaming_hint_still_follows_the_install_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A format that reads from a pipe needs its package first; the mode comes after.

    Only the capability refusal moved ahead of the availability check. For ``.tar.lz4``
    without ``lz4`` the pipe is not the obstacle, so the install hint is the answer.
    """
    monkeypatch.setattr(
        "archivey.internal.registry._optional", lambda name: None, raising=True
    )
    monkeypatch.setattr(
        "archivey.internal.registry.is_codec_available",
        lambda codec, excluded=frozenset(): False,
    )
    with pytest.raises(PackageNotInstalledError):
        open_archive(
            _NonSeekable(bytes(64)), format=ArchiveFormat.TAR_LZ4, streaming=False
        )


def test_needs_seekable_source_is_false_without_a_backend() -> None:
    """With no backend there is nothing to refuse with; ``reader_for_format`` says so."""
    assert BackendRegistry().needs_seekable_source(ArchiveFormat.ZIP) is False


def test_unregistered_format_defaults_to_the_conservative_answer() -> None:
    """A format nothing can read has no honest source shape; SEEKABLE sends you to buffer."""
    availability = BackendRegistry().format_availability(ArchiveFormat.ZIP)
    assert availability.support is FormatSupport.NONE
    assert availability.required_source is StreamCapability.SEEKABLE


def test_stream_capability_is_ordered_weakest_first() -> None:
    """``required_source`` reads as a minimum only because the enum is ordered."""
    assert StreamCapability.FORWARD_ONLY < StreamCapability.SEEKABLE
    assert StreamCapability.SEEKABLE >= StreamCapability.FORWARD_ONLY
    assert StreamCapability.FORWARD_ONLY <= StreamCapability.FORWARD_ONLY
    assert not (StreamCapability.SEEKABLE < StreamCapability.FORWARD_ONLY)
    assert sorted(StreamCapability) == [
        StreamCapability.FORWARD_ONLY,
        StreamCapability.SEEKABLE,
    ]


def test_stream_capability_does_not_compare_against_foreign_types() -> None:
    with pytest.raises(TypeError):
        operator.lt(StreamCapability.SEEKABLE, "seekable")


# ---------------------------------------------------------------------------
# Optional-dependency lookups are memoized
# ---------------------------------------------------------------------------


def test_missing_optional_dependency_is_looked_up_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed import is not repeated: Python has no negative import cache.

    The present-module case is a cheap ``sys.modules`` hit either way; the missing one
    re-walks every ``sys.path`` entry, and it lands on the ``open_archive`` path through
    ``reader_for_format``. Asserting the call count rather than a timing is what keeps
    this from silently regressing when someone inlines the lookup.
    """
    from archivey.internal import registry as registry_module

    calls: list[str] = []
    real_import = importlib.import_module

    def counting_import(name: str, *args: object, **kwargs: object) -> object:
        calls.append(name)
        return real_import(name, *args, **kwargs)  # pyrefly: ignore[bad-argument-type]

    registry_module._optional.cache_clear()
    monkeypatch.setattr(registry_module.importlib, "import_module", counting_import)
    try:
        missing = "a_package_that_does_not_exist_xyz"
        assert registry_module._optional(missing) is None
        assert registry_module._optional(missing) is None
        assert registry_module._optional(missing) is None
        assert calls.count(missing) == 1

        present = registry_module._optional("io")
        assert present is not None
        assert registry_module._optional("io") is present
        assert calls.count("io") == 1
    finally:
        registry_module._optional.cache_clear()


def test_availability_of_a_missing_extra_does_not_reimport_per_call(
    registry: BackendRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``list_supported_formats()`` over N formats must not pay N failed imports."""
    from archivey.internal import registry as registry_module

    calls: list[str] = []
    real_import = importlib.import_module

    def counting_import(name: str, *args: object, **kwargs: object) -> object:
        calls.append(name)
        return real_import(name, *args, **kwargs)  # pyrefly: ignore[bad-argument-type]

    registry_module._optional.cache_clear()
    monkeypatch.setattr(registry_module.importlib, "import_module", counting_import)
    try:
        for _ in range(5):
            registry.list_supported_formats()
            registry.format_availability(ArchiveFormat.ISO)
        assert calls.count("a_package_that_does_not_exist_xyz") == 1
    finally:
        registry_module._optional.cache_clear()


def test_cache_clear_picks_up_a_dependency_installed_later(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The documented escape hatch for the one thing memoizing gives up."""
    from archivey.internal import registry as registry_module

    name = "a_package_that_does_not_exist_xyz"
    installed = types.ModuleType(name)
    visible = False

    def fake_import(module_name: str, *args: object, **kwargs: object) -> object:
        if module_name == name:
            if not visible:
                raise ImportError(name)
            return installed
        return importlib.import_module(module_name, *args, **kwargs)  # pyrefly: ignore[bad-argument-type]

    registry_module._optional.cache_clear()
    monkeypatch.setattr(registry_module.importlib, "import_module", fake_import)
    try:
        assert registry_module._optional(name) is None
        visible = True
        assert registry_module._optional(name) is None  # still the memoized answer
        registry_module._optional.cache_clear()
        assert registry_module._optional(name) is installed
    finally:
        registry_module._optional.cache_clear()


# ---------------------------------------------------------------------------
# The optional codec lists match the method tables; RAR counts unrar
# ---------------------------------------------------------------------------


def test_container_optional_codecs_match_method_tables() -> None:
    # The registry keeps its own list of each container's optional member codecs. It
    # once left LZ4 out of 7z, so 7z reported FULL without ``lz4``. Every codec a
    # method table uses that needs a package must be on the list, and nothing else.
    from archivey.internal.backends.sevenzip_methods import _METHODS
    from archivey.internal.backends.zip_reader import _ZIP_METHOD_CODECS
    from archivey.internal.registry import _CONTAINER_OPTIONAL_CODECS
    from archivey.internal.streams.codecs.registry import codec_requirement

    used = {
        ContainerFormat.SEVEN_Z: {m.codec for m in _METHODS if m.codec is not None},
        ContainerFormat.ZIP: set(_ZIP_METHOD_CODECS.values()),
    }
    for container, codecs in used.items():
        optional = {c for c in codecs if codec_requirement(c) is not None}
        assert set(_CONTAINER_OPTIONAL_CODECS[container]) == optional, container


def test_7z_partial_without_lz4(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codecs_module.deps, "lz4_frame", None)
    avail = format_availability(ArchiveFormat.SEVEN_Z)
    assert avail.support is FormatSupport.PARTIAL
    assert "lz4" in {m.name for m in avail.missing}


def _hide_rarlab_unrar(monkeypatch: pytest.MonkeyPatch) -> None:
    from archivey.internal.backends import rar_unrar

    def _missing() -> str:
        # As the real finder raises: the refusal text and the component it names.
        component = MissingComponent("unrar", "no unrar here")
        raise PackageNotInstalledError("no unrar here", missing=(component,))

    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", _missing)


def test_rar_partial_without_unrar(monkeypatch: pytest.MonkeyPatch) -> None:
    _hide_rarlab_unrar(monkeypatch)
    avail = format_availability(ArchiveFormat.RAR)
    assert avail.support is FormatSupport.PARTIAL
    assert [m.name for m in avail.missing] == ["unrar"]
    # The hint is the finder's own refusal, the text a member read raises.
    assert avail.missing[0].install_hint == "no unrar here"
    # PARTIAL still opens and lists, so RAR stays supported.
    assert ArchiveFormat.RAR in list_supported_formats()


def test_rar_partial_with_empty_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The real finder, not a stub: with nothing on PATH there is no unrar or rar.
    monkeypatch.setenv("PATH", str(tmp_path))
    avail = format_availability(ArchiveFormat.RAR)
    assert avail.support is FormatSupport.PARTIAL
    assert [m.name for m in avail.missing] == ["unrar"]


def test_rar_hint_names_a_too_old_unrar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A RARLAB unrar under the 6.0 floor is installed but refused: the hint names it
    # and its version, as the read refusal does, instead of advising an install.
    if sys.platform == "win32":
        pytest.skip("a shell-script stand-in for unrar needs a POSIX shell")
    fake = tmp_path / "unrar"
    fake.write_text(
        "#!/bin/sh\necho 'UNRAR 5.91 freeware      Copyright (c) 1993-2020 "
        "Alexander Roshal'\n"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    avail = format_availability(ArchiveFormat.RAR)
    assert avail.support is FormatSupport.PARTIAL
    (component,) = avail.missing
    assert component.name == "unrar"
    assert "5.91" in component.install_hint
    assert str(fake) in component.install_hint


def test_check_programs_false_runs_no_program(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.backends import rar_unrar

    def _fail() -> str:
        raise AssertionError("probed for unrar")

    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", _fail)
    avail = format_availability(ArchiveFormat.RAR, check_programs=False)
    assert avail.support is FormatSupport.FULL
    assert avail.missing == ()


def test_rar_full_with_unrar(monkeypatch: pytest.MonkeyPatch) -> None:
    from archivey.internal.backends import rar_unrar

    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", lambda: "/usr/bin/unrar")
    avail = format_availability(ArchiveFormat.RAR)
    assert avail.support is FormatSupport.FULL
    assert avail.missing == ()


def test_open_path_does_not_probe_for_unrar(monkeypatch: pytest.MonkeyPatch) -> None:
    # The probe runs a binary, so only the public query pays for it. The open path
    # (reader_for_format) and list_supported_formats get the same answer without it.
    from archivey.internal.backends import rar_unrar

    def _fail() -> str:
        raise AssertionError("probed for unrar")

    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", _fail)
    registry = get_registry()
    support = registry.format_availability(ArchiveFormat.RAR).support
    assert support is not FormatSupport.NONE
    registry.reader_for_format(ArchiveFormat.RAR)
    assert ArchiveFormat.RAR in list_supported_formats()
