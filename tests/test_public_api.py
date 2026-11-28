"""Guards on the public ``archivey`` namespace.

``archivey.__all__`` is curated by hand (not generated) so it lists only the public
API and not re-imported helpers like ``version``/``PackageNotFoundError``. This test
is the safety net that keeps the hand-maintained list from drifting.
"""

from __future__ import annotations

import inspect
import json
import shutil
import subprocess
import sys
import tomllib
import typing
from pathlib import Path
from types import FunctionType

import pytest

import archivey
from tests.public_names import public_objects, public_spellings


def test_archive_reader_is_an_abstract_public_interface() -> None:
    """The public ``ArchiveReader`` is an abstract interface, not the internal helper."""
    with pytest.raises(TypeError):
        archivey.ArchiveReader()  # type: ignore[abstract]  # abstract: cannot instantiate


def test_open_archive_returns_an_archive_reader(tmp_path) -> None:
    (tmp_path / "f.txt").write_bytes(b"x")
    with archivey.open_archive(tmp_path) as ar:
        assert isinstance(ar, archivey.ArchiveReader)


# The four methods a streaming reader refuses at run time, which the narrower
# ``ForwardArchiveReader`` type leaves out so a type checker refuses them too.
_RANDOM_ACCESS_METHODS = {"members", "get", "open", "read"}


def test_forward_reader_type_leaves_out_exactly_the_random_access_methods() -> None:
    assert issubclass(archivey.ArchiveReader, archivey.ForwardArchiveReader)
    streaming_api = {
        name
        for name in dir(archivey.ForwardArchiveReader)
        if not name.startswith("_") or name in ("__iter__", "__contains__")
    }
    full_api = {
        name
        for name in dir(archivey.ArchiveReader)
        if not name.startswith("_") or name in ("__iter__", "__contains__")
    }
    assert full_api - streaming_api == _RANDOM_ACCESS_METHODS


def test_a_streaming_reader_is_still_an_archive_reader_at_run_time(tmp_path) -> None:
    """The narrowing is static only: one runtime class serves both access modes."""
    (tmp_path / "f.txt").write_bytes(b"x")
    with archivey.open_archive(tmp_path, streaming=True) as ar:
        assert isinstance(ar, archivey.ArchiveReader)
        with pytest.raises(archivey.ArchiveyUsageError):
            ar.members()  # type: ignore[attr-defined]  # the call this type refuses


_OPEN_ARCHIVE_TYPING_SAMPLE = """\
from typing import assert_type

import archivey
from archivey import ArchiveReader, ForwardArchiveReader
from archivey.reader import MemberPass


def check(flag: bool) -> None:
    assert_type(archivey.open_archive("a.zip"), ArchiveReader)
    assert_type(archivey.open_archive("a.zip", streaming=False), ArchiveReader)
    assert_type(archivey.open_archive("a.zip", streaming=True), ForwardArchiveReader)
    assert_type(archivey.open_archive("a.zip", streaming=flag), ForwardArchiveReader)
    assert_type(archivey.open_archive("a.zip", pipe=False), ArchiveReader)
    assert_type(
        archivey.open_archive("a.zip", streaming=False, pipe=False), ArchiveReader
    )
    assert_type(archivey.open_archive("a.zip", pipe=True), ForwardArchiveReader)
    assert_type(archivey.open_archive("a.zip", pipe=flag), ForwardArchiveReader)
    assert_type(
        archivey.open_archive("a.zip", streaming=False, pipe=True),
        ForwardArchiveReader,
    )
    assert_type(
        archivey.open_archive("a.zip", salvage=True), ArchiveReader
    )
    assert_type(
        archivey.open_archive("a.zip", streaming=True, salvage=False),
        ForwardArchiveReader,
    )
    assert_type(
        archivey.open_archive("a.zip", pipe=True, salvage=False),
        ForwardArchiveReader,
    )
    with archivey.open_archive("a.zip") as full:
        assert_type(full, ArchiveReader)
        full.members()
        with full.stream_members() as members:
            assert_type(
                members,
                MemberPass[tuple[archivey.ArchiveMember, archivey.ArchiveStream | None]],
            )
            for member, stream in members:
                assert_type(member, archivey.ArchiveMember)
                assert_type(stream, archivey.ArchiveStream | None)
        with iter(full) as each:
            assert_type(each, MemberPass[archivey.ArchiveMember])
    with archivey.open_archive("a.zip", streaming=True) as forward:
        assert_type(forward, ForwardArchiveReader)
        forward.members()
"""


_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _checker_command(
    checker: str, exe: str, src: Path, python_version: str
) -> list[str]:
    """The command line that runs ``checker`` on ``sample.py`` in the working directory.

    Pyrefly reads its search path and Python version from a ``pyrefly.toml`` beside
    the sample, which the test writes; ty takes both as arguments.
    """
    if checker == "ty":
        return [
            exe,
            "check",
            "--python",
            sys.executable,
            "--python-version",
            python_version,
            "--extra-search-path",
            str(src),
            "--output-format",
            "concise",
            "sample.py",
        ]
    return [exe, "check", "--output-format", "min-text", "sample.py"]


def _checker_diagnostics(checker: str, sample: str, tmp_path: Path) -> list[str]:
    """Run ``checker`` on ``sample`` as a caller's module, and return its diagnostics.

    Each diagnostic is one line, ``sample.py:L:C...``. Skips when the checker is not
    installed (it is a dev dependency).
    """
    exe = shutil.which(checker)
    if exe is None:
        pytest.skip(f"{checker} is not installed (it is a dev dependency)")
    # The same Python version CI checks ``src/`` at, so the two cannot drift apart.
    python_version = tomllib.loads(_PYPROJECT.read_text())["tool"]["pyrefly"][
        "python_version"
    ]
    src = Path(archivey.__file__).resolve().parent.parent
    (tmp_path / "sample.py").write_text(sample)
    # Without a config file Pyrefly falls back to a preset that reports nothing here.
    (tmp_path / "pyrefly.toml").write_text(
        f"search-path = [{json.dumps(src.as_posix())}]\n"
        f"python_version = {json.dumps(python_version)}\n"
    )
    result = subprocess.run(
        _checker_command(checker, exe, src, python_version),
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    output = result.stdout + result.stderr
    # ty prints ``sample.py:L:C: ...``; Pyrefly prints ``ERROR sample.py:L:C-C: ...``.
    diagnostics = [
        line.removeprefix("ERROR ")
        for line in output.splitlines()
        if line.startswith(("sample.py:", "ERROR sample.py:"))
    ]
    # Neither checker may have failed without a diagnostic to show for it.
    assert diagnostics or result.returncode == 0, output
    return diagnostics


def _line_of(sample: str, text: str) -> int:
    """The 1-based line of ``sample`` that is exactly ``text``."""
    return sample.splitlines().index(text) + 1


@pytest.mark.parametrize("checker", ["ty", "pyrefly"])
def test_type_checker_refuses_random_access_on_a_streaming_reader(
    checker: str, tmp_path: Path
) -> None:
    """``open_archive``'s overloads, as seen by each checker CI runs.

    CI type-checks ``src/`` only, so the overloads' effect on a caller is checked here:
    every ``assert_type`` holds and the one diagnostic is ``forward.members()``. Both
    checkers, because the library is kept clean on both so that one's blind spot
    cannot hide what the other would catch.
    """
    diagnostics = _checker_diagnostics(checker, _OPEN_ARCHIVE_TYPING_SAMPLE, tmp_path)
    refused_line = _line_of(_OPEN_ARCHIVE_TYPING_SAMPLE, "        forward.members()")
    assert len(diagnostics) == 1, diagnostics
    assert diagnostics[0].startswith(f"sample.py:{refused_line}:"), diagnostics
    assert "`members`" in diagnostics[0], diagnostics


_STRING_SPELLING_TYPING_SAMPLE = """\
from typing import assert_type

from archivey import ArchiveFormat, ArchiveyConfig, ContainerFormat, StreamFormat
from archivey.config import AcceleratorMode, ProcessIsolation, RarDecompressor
from archivey.types import PluginContainer, PluginStream
from archivey.detection_cost import DetectionBudget


def check() -> None:
    config = ArchiveyConfig(
        use_rapidgzip="off",
        use_indexed_bzip2="auto",
        process_isolation="none",
        rar_decompressor="unrar",
        detection_budget="fast",
    )
    ArchiveyConfig(process_isolation="native-decoders")
    ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON)
    assert_type(config.use_rapidgzip, AcceleratorMode)
    assert_type(config.process_isolation, ProcessIsolation)
    assert_type(config.rar_decompressor, RarDecompressor)
    assert_type(config.detection_budget, DetectionBudget)
    fmt = ArchiveFormat("raw_stream", "gz")
    ArchiveFormat("tar", "Z")
    assert_type(fmt.container, ContainerFormat | PluginContainer)
    assert_type(fmt.stream, StreamFormat | PluginStream)
    ArchiveyConfig(process_isolation="nonee")
    ArchiveFormat("raw_stream", "gzz")
    ArchiveyConfig(rar_decompressor="UNAR")
"""


@pytest.mark.parametrize("checker", ["ty", "pyrefly"])
def test_type_checker_takes_the_documented_string_spellings(
    checker: str, tmp_path: Path
) -> None:
    """``ArchiveyConfig`` and ``ArchiveFormat`` take a string spelling, typed.

    The docs set these fields by their strings (``process_isolation="none"``,
    ``ArchiveFormat("raw_stream", "gz")``), so a typed caller copying the docs must get
    no diagnostic, while the attribute still reads as the enum alone. The input types are
    ``Literal`` lists, not ``str``, so the only diagnostics are the three calls at the
    end: two misspellings, and the member name ``"UNAR"``, which the runtime accepts but
    no ``Literal`` lists.
    """
    sample = _STRING_SPELLING_TYPING_SAMPLE
    diagnostics = _checker_diagnostics(checker, sample, tmp_path)
    refused = [
        _line_of(sample, '    ArchiveyConfig(process_isolation="nonee")'),
        _line_of(sample, '    ArchiveFormat("raw_stream", "gzz")'),
        # Valid at runtime (a member name), but no Literal lists it: the spec says it
        # still gets a diagnostic.
        _line_of(sample, '    ArchiveyConfig(rar_decompressor="UNAR")'),
    ]
    assert [int(d.split(":")[1]) for d in diagnostics] == refused, diagnostics


def test_member_streams_is_demoted_from_the_surface(tmp_path) -> None:
    """The flag type behind ``seekable_members`` / ``concurrent_operations`` stays internal.

    Pins the archive-reading spec: not re-exported, not in ``__all__``, still importable
    from ``archivey.types``, and no reader attribute exposes the declared flags.
    """
    from archivey.types import MemberStreams

    assert MemberStreams is not None
    assert "MemberStreams" not in archivey.__all__
    assert not hasattr(archivey, "MemberStreams")
    (tmp_path / "f.txt").write_bytes(b"x")
    with archivey.open_archive(tmp_path, seekable_members=True) as ar:
        assert not hasattr(ar, "member_streams")


def test_crc32_digest_is_internal() -> None:
    """The CRC encoder for ``member.hashes`` left the public surface before 0.2.0.

    Callers only read ``hashes``; comparing their own CRC is
    ``zlib.crc32(data).to_bytes(4, "big")``. 0.2.0rc1 exported it from the root and
    ``archivey.types``; neither may again.
    """
    from archivey.internal.hashing import crc32_digest

    assert crc32_digest(0x1234) == b"\x00\x00\x12\x34"
    assert "crc32_digest" not in archivey.__all__
    assert not hasattr(archivey, "crc32_digest")
    assert not hasattr(archivey.types, "crc32_digest")


def test_io_measurement_is_not_public() -> None:
    """IO counters serve the benchmark harness and the CLI's ``--track-io`` only.

    Not in ``__all__``, not on the package, not on the ``ArchiveReader`` ABC, and no
    public ``archivey.measurement`` module. The internal reader still answers.
    """
    import importlib.util

    from archivey.internal.base_reader import BaseArchiveReader

    for name in ("IoStats", "enable_measurement"):
        assert name not in archivey.__all__
        assert not hasattr(archivey, name)
    assert importlib.util.find_spec("archivey.measurement") is None
    assert "io_stats" not in vars(archivey.ArchiveReader)
    assert "io_stats" not in vars(archivey.ForwardArchiveReader)
    assert "io_stats" in vars(BaseArchiveReader)


def test_public_interface_hides_internal_hooks() -> None:
    """The public ``ArchiveReader`` surface must not expose backend-internal hooks.

    The concrete machinery (``_open_member`` etc.) lives on the internal
    ``BaseArchiveReader`` helper; the public interface declares only the public contract.
    """
    from archivey.internal.base_reader import BaseArchiveReader

    assert issubclass(BaseArchiveReader, archivey.ArchiveReader)
    internal_hooks = {
        "_iter_members",
        "_open_member",
        "_get_archive_info",
        "_close_archive",
    }
    public_names = set(vars(archivey.ArchiveReader)) | set(
        vars(archivey.ForwardArchiveReader)
    )
    leaked = internal_hooks & public_names
    assert not leaked, f"internal hooks leaked onto the public ArchiveReader: {leaked}"
    # They DO live on the internal helper.
    assert internal_hooks <= set(dir(BaseArchiveReader))


def test_all_entries_are_exported() -> None:
    """Every name in __all__ must actually be an attribute of the package."""
    missing = [name for name in archivey.__all__ if not hasattr(archivey, name)]
    assert not missing, f"__all__ lists names that are not exported: {missing}"


def test_all_has_no_duplicates() -> None:
    assert len(archivey.__all__) == len(set(archivey.__all__))


def test_root_exposes_nothing_public_outside_all() -> None:
    """Every public name on the package root is in ``__all__`` or is a submodule.

    DR-13: a niche name lives in its public submodule and is not imported at the root
    as well, so the root offers one import path per name. A module attribute must be
    a real submodule of ``archivey``, not some other module an import left behind.
    """
    import inspect

    stray = sorted(
        name
        for name, obj in vars(archivey).items()
        if not name.startswith("_")
        and name not in archivey.__all__
        and not (inspect.ismodule(obj) and obj.__name__ == f"archivey.{name}")
    )
    assert not stray, f"public names on archivey outside __all__: {stray}"


def test_niche_names_live_only_in_their_submodule() -> None:
    """The diagnostic context payloads and the accelerator size gates are not root names.

    They were importable from ``archivey`` before 0.2.0; they now come only from
    ``archivey.diagnostics`` and ``archivey.config``.
    """
    import archivey.config
    import archivey.diagnostics

    def is_payload(name: str) -> bool:
        return (
            name.endswith("Context")
            and name != "DiagnosticContext"
            and not name.startswith("_")
        )

    # The submodule is the only public path to a payload, so its __all__ must list
    # every one the module defines.
    unlisted = sorted(
        name
        for name in vars(archivey.diagnostics)
        if is_payload(name) and name not in archivey.diagnostics.__all__
    )
    assert unlisted == []
    contexts = [name for name in archivey.diagnostics.__all__ if is_payload(name)]
    # The 39 payload classes the module defines; update the count when one is added
    # or removed, so the loop below cannot pass on a shrunken list.
    assert len(contexts) == 39, contexts
    gates = [
        "INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE",
        "RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE",
    ]
    for name in [*contexts, *gates]:
        assert not hasattr(archivey, name), name
    assert archivey.config.RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE > 0


def test_no_public_name_reports_an_internal_module() -> None:
    """Every public class and function, at the root or in a public submodule's
    ``__all__``, reports a public module, not ``internal``.

    ``pickle`` stores ``__module__``, so a name reporting ``archivey.internal.…`` would
    freeze that path into data callers persist. ``__init__`` pins it for every function
    defined under ``internal``, including ones added later. It pins no class, so a
    public class must be defined in a public module.
    """
    leaked = {
        name: obj.__module__
        for name, obj in public_objects().items()
        if isinstance(obj, (type, FunctionType))
        if obj.__module__.startswith("archivey.internal")
    }
    assert leaked == {}


@pytest.mark.parametrize(
    ("function", "module"),
    [
        (archivey.core.list_known_formats, "archivey.core"),
        (archivey.core.list_supported_formats, "archivey.core"),
        (archivey.paths.sanitize_names, "archivey.paths"),
        (archivey.formats.collision_key, "archivey.formats"),
        (archivey.formats.str_retained_bytes, "archivey.formats"),
        (archivey.detect_format, "archivey"),
    ],
    ids=lambda v: getattr(v, "__name__", v),
)
def test_a_function_defined_under_internal_reports_the_module_that_exports_it(
    function: FunctionType, module: str
) -> None:
    assert function.__module__ == module


@pytest.mark.parametrize(
    "cls",
    [c for c in public_objects().values() if isinstance(c, type)],
    ids=lambda c: f"{c.__module__}.{c.__qualname__}",
)
def test_public_class_type_hints_resolve(cls: type) -> None:
    """``get_type_hints`` works on every public class."""
    typing.get_type_hints(cls)


@pytest.mark.parametrize(
    "value",
    [
        archivey.types.OverwritePolicy.SKIP,
        archivey.detection.DetectionConfidence.CERTAIN,
        archivey.types.FormatSupport.FULL,
    ],
    ids=lambda v: type(v).__name__,
)
def test_pickles_name_the_public_module(value: object) -> None:
    import pickle

    data = pickle.dumps(value)
    assert b"archivey.internal" not in data
    assert pickle.loads(data) is value


def test_pinning_leaves_the_internal_objects_shared() -> None:
    from archivey.internal import detection

    assert detection.detect_format is archivey.detect_format
    assert archivey.detect_format.__module__ == "archivey"


@pytest.mark.parametrize(
    "cls",
    [
        archivey.types.OverwritePolicy,
        archivey.types.ExtractionResult,
        archivey.detection.FormatInfo,
    ],
    ids=lambda c: c.__name__,
)
def test_moved_classes_keep_their_source(cls: type) -> None:
    assert inspect.getsource(cls).lstrip().startswith(("class ", "@dataclass"))


def test_version_is_computed_on_first_access() -> None:
    code = (
        "import archivey\n"
        "assert '__version__' not in vars(archivey)\n"
        "v = archivey.__version__\n"
        "assert isinstance(v, str) and v, v\n"
        "assert vars(archivey)['__version__'] == v\n"
        "assert not hasattr(archivey, 'PackageNotFoundError')\n"
        "assert not hasattr(archivey, 'version')\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
    assert "__version__" in archivey.__all__


# Public names with no entry on the API page, each for a stated reason.
_NOT_ON_API_PAGE = {
    # The package version string: nothing to document beyond its name.
    "archivey.__version__",
    # Thresholds of the AUTO accelerator rule, documented in the prose of
    # ``use_rapidgzip`` rather than as blocks of their own.
    "archivey.config.INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE",
    "archivey.config.RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE",
    # Helpers a format reader or a diagnostic consumer calls, documented in
    # docs/adding-a-format.md and on ``DiagnosticContext``.
    "archivey.diagnostics.DiagnosticCodeStr",
    "archivey.diagnostics.format_path_name",
    "archivey.diagnostics.raw_name_to_base64",
    "archivey.diagnostics.validate_code_context",
}
# Whole groups with no blocks of their own: the typed diagnostic contexts, which the
# ``DiagnosticContext`` block and the diagnostics table describe, and the plugin API of
# ``archivey.formats`` and ``archivey.speedups``, which docs/adding-a-format.md
# describes.
_NOT_ON_API_PAGE_GROUPS = ("archivey.formats.", "archivey.speedups.")


def _off_the_page_by_group(spelling: str) -> bool:
    if spelling.startswith(_NOT_ON_API_PAGE_GROUPS):
        return True
    return spelling.startswith("archivey.diagnostics.") and spelling.endswith("Context")


def test_every_public_name_is_on_the_api_page() -> None:
    """The API page carries a ``::: <module>.<Name>`` block for each public name.

    A name is public at the root or in a public submodule's ``__all__``; a block under
    any of its spellings counts. Nothing in a docs build notices a name that was
    exported and never documented, and 29 had drifted off the page before this test.
    """
    api_page = Path(__file__).resolve().parent.parent / "docs" / "api.md"
    documented = {
        line.removeprefix(":::").strip()
        for line in api_page.read_text(encoding="utf-8").splitlines()
        if line.startswith("::: archivey.")
    }
    missing = sorted(
        spellings[0]
        for spellings in public_spellings()
        if not documented.intersection(spellings)
        and not _NOT_ON_API_PAGE.intersection(spellings)
        and not any(_off_the_page_by_group(s) for s in spellings)
    )
    assert not missing, f"public names with no ::: block in docs/api.md: {missing}"
    stale = sorted(_NOT_ON_API_PAGE & documented)
    assert not stale, f"_NOT_ON_API_PAGE entries now documented, remove them: {stale}"
