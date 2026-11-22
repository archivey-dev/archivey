"""``archivey --version -v``: the format report and its install hints."""

from __future__ import annotations

import sys
from importlib import metadata
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    FormatAvailability,
    FormatSupport,
    MissingComponent,
    OptionalLibrary,
    format_availability,
    list_known_formats,
)
from archivey.cli import version_report
from archivey.cli.exit_codes import EXIT_OK
from archivey.cli.main import main
from archivey.cli.version_report import (
    Install,
    cli_package_hint,
    detect_installer,
    install_command,
    unimportable_packages,
)


@pytest.fixture(autouse=True)
def _no_broken_packages(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the report off the host's packages: the import probe imports every one
    found, and a broken one would make it ask the faked ``format_availability`` again
    with ``config=``. A test that wants a broken package replaces this stub."""
    monkeypatch.setattr(version_report, "unimportable_packages", lambda skip=(): {})


def _report(capsys: pytest.CaptureFixture[str]) -> str:
    assert main(["--version", "-v"]) == EXIT_OK
    return capsys.readouterr().out


def _level_row(out: str, section: str, level: str) -> list[str]:
    """The labels on one support-level row of a report section, continuation lines
    included."""
    lines = out.split(f"\n{section}\n")[1].split("\n\n")[0].splitlines()
    prefix = f"  {level + ':':<10}"
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            text = line[len(prefix) :]
            for more in lines[i + 1 :]:
                if not more.startswith(" " * 12):
                    break
                text += " " + more.strip()
            return [label.strip() for label in text.split(",")]
    return []


def test_version_alone_is_one_line(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == EXIT_OK
    assert capsys.readouterr().out.count("\n") == 1


def test_report_splits_archives_from_compression(
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = _report(capsys)
    assert out.startswith("archivey ")
    archives, compression = out.split("\narchive formats\n")[1].split(
        "\ncompression and encodings\n"
    )
    assert "zip" in archives and "tar" in archives
    # DMG is read now: listed among the formats read in full, with no note.
    assert "dmg" in archives
    assert "recognised, not readable" not in archives
    assert "gz" in compression and "xz" in compression
    assert (
        "tar also open inside any of these that can be read, such as tar.gz."
        in out.replace("\n  ", " ")
    )
    # No container x stream pair is listed on its own.
    assert "tar.gz" not in archives
    assert "tar.zst" not in out
    assert main(["-v", "--version"]) == EXIT_OK
    assert "archive formats" in capsys.readouterr().out


def test_each_piece_of_advice_is_printed_once(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Vacuous on a full install (nothing is missing); real on the core-only legs and
    under PyPy, where a package archivey does not use prints its reason instead."""
    out = _report(capsys)
    flat = " ".join(out.split())
    installer = detect_installer()
    advice = {
        component.advice
        for fmt in list_known_formats()
        for availability in (format_availability(fmt),)
        for component in (*availability.missing, *availability.faster_with)
    }
    for text in advice:
        command = " ".join(install_command(text, installer).split())
        assert flat.count(command) == 1, command


def test_missing_and_slower_are_grouped_by_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    hint = "pip install archivey[recommended]"
    real = version_report.format_availability

    def fake(fmt: ArchiveFormat) -> FormatAvailability:
        if fmt == ArchiveFormat.ISO:
            return FormatAvailability(
                fmt, FormatSupport.NONE, (MissingComponent("pycdlib", hint),)
            )
        if fmt == ArchiveFormat.SEVEN_Z:
            return FormatAvailability(
                fmt, FormatSupport.PARTIAL, (MissingComponent("pyppmd", hint),)
            )
        if fmt == ArchiveFormat.LZOP:
            return FormatAvailability(
                fmt,
                FormatSupport.FULL,
                faster_with=(MissingComponent("compress_utils", hint),),
            )
        return FormatAvailability(fmt, real(fmt).support)

    monkeypatch.setattr(version_report, "format_availability", fake)
    monkeypatch.setattr(version_report, "detect_installer", lambda: Install("pip"))
    out = _report(capsys)
    printed = 'pip install "archivey[recommended]"'
    assert out.count(printed) == 1
    section = out.split("to read more, or faster\n")[1]
    # The packages are named as pip installs them, not by their import names.
    assert section.splitlines()[:5] == [
        f"  {printed}",
        "    adds iso",
        "    completes 7z",
        "    faster for lzo",
        "    packages: pyppmd, pycdlib, compress-utils",
    ]
    assert "slower without optional packages: lzo" in out


def test_slower_line_leaves_out_packages_with_a_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A package the policy turns off, or archivey does not use here, is explained in
    the grouped section; the summary line names only what installing would fix."""
    real = version_report.format_availability
    reason = "archivey does not use rapidgzip under PyPy"

    def fake(fmt: ArchiveFormat) -> FormatAvailability:
        if fmt == ArchiveFormat.GZ:
            return FormatAvailability(
                fmt,
                FormatSupport.FULL,
                faster_with=(MissingComponent("rapidgzip", "x", reason=reason),),
            )
        return FormatAvailability(fmt, real(fmt).support)

    monkeypatch.setattr(version_report, "format_availability", fake)
    out = _report(capsys)
    assert "slower without optional packages" not in out
    assert f"  {reason}\n    faster for gz\n" in out


def test_pair_sentence_limits_itself_to_readable_compressions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real = version_report.format_availability

    def fake(fmt: ArchiveFormat) -> FormatAvailability:
        if fmt.stream.value == "zst":
            return FormatAvailability(fmt, FormatSupport.NONE)
        return FormatAvailability(fmt, real(fmt).support)

    monkeypatch.setattr(version_report, "format_availability", fake)
    flat = " ".join(_report(capsys).split())
    # Other compressions may sit on the same line on a core-only install.
    none_line = flat.split("compression and encodings")[1].split("none:")[1]
    assert "zst" in none_line.split(" also open inside")[0]
    assert "also open inside any of these that can be read, such as tar.gz." in flat
    assert "combinations that differ" not in flat


def test_a_pair_that_differs_from_its_parts_is_printed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real = version_report.format_availability

    def fake(fmt: ArchiveFormat) -> FormatAvailability:
        if fmt == ArchiveFormat.TAR_XZ:
            return FormatAvailability(fmt, FormatSupport.NONE)
        return FormatAvailability(fmt, real(fmt).support)

    monkeypatch.setattr(version_report, "format_availability", fake)
    out = _report(capsys)
    assert "combinations that differ from their parts\n" in out
    assert "  tar.xz: none (recognised, not readable)\n" in out


@pytest.mark.parametrize(
    ("installer", "expected"),
    [
        ("pip", 'pip install "archivey[bzip3]"'),
        ("uvx", 'uvx --with "archivey[bzip3]" archivey-cli'),
        ("uv-tool", 'uv tool install --with "archivey[bzip3]" archivey-cli'),
        ("pipx", 'pipx inject archivey-cli "archivey[bzip3]"'),
    ],
)
def test_install_command_fits_the_installer(installer: str, expected: str) -> None:
    install = Install(installer)  # type: ignore[arg-type]
    assert install_command("pip install archivey[bzip3]", install) == expected


def test_install_command_targets_the_library_tool() -> None:
    install = Install("uvx", "archivey")
    assert install_command("pip install archivey[bzip3]", install) == (
        'uvx --with "archivey[bzip3]" archivey'
    )


def test_install_command_keeps_other_advice() -> None:
    assert install_command("pip install compress-utils", Install("uvx")) == (
        "uvx --with compress-utils archivey-cli"
    )
    assert install_command("pip install compress-utils", Install("pip")) == (
        "pip install compress-utils"
    )
    reason = "archivey does not use lz4 under PyPy"
    assert install_command(reason, Install("uvx")) == reason
    assert install_command("Install RARLAB unrar", Install("pipx")) == (
        "Install RARLAB unrar"
    )


class _Dist:
    def __init__(self, installer: str) -> None:
        self._installer = installer

    def read_text(self, name: str) -> str:
        assert name == "INSTALLER"
        return f"{self._installer}\n"


@pytest.mark.parametrize(
    ("installer", "prefix", "expected"),
    [
        ("uv", "/home/u/.cache/uv/archive-v0/l3A6DnngECMlzMwB", "uvx"),
        ("uv", "/home/u/.local/share/uv/tools/archivey-cli", "uv-tool"),
        # Windows: %APPDATA%\\uv\\data\\tools, as a POSIX path of the same shape.
        ("uv", "/c/Users/u/AppData/Roaming/uv/data/tools/archivey-cli", "uv-tool"),
        ("pip", "/home/u/.local/share/pipx/venvs/archivey-cli", "pipx"),
        ("uv", "/home/u/project/.venv", "pip"),
        ("pip", "/usr", "pip"),
    ],
)
def test_detect_installer(
    monkeypatch: pytest.MonkeyPatch, installer: str, prefix: str, expected: str
) -> None:
    monkeypatch.delenv("UV_TOOL_DIR", raising=False)
    monkeypatch.setattr(metadata, "distribution", lambda name: _Dist(installer))
    monkeypatch.setattr(sys, "prefix", str(Path(prefix)))
    assert detect_installer().installer == expected


def test_detect_installer_honours_uv_tool_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("UV_TOOL_DIR", str(tmp_path))
    monkeypatch.setattr(metadata, "distribution", lambda name: _Dist("uv"))
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "archivey-cli"))
    assert detect_installer() == Install("uv-tool", "archivey-cli")


def test_detect_installer_without_the_cli_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(name: str) -> None:
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(metadata, "distribution", missing)
    assert detect_installer() == Install("pip")


def _library_only(name: str) -> _Dist:
    if name == "archivey-cli":
        raise metadata.PackageNotFoundError(name)
    return _Dist("uv")


@pytest.mark.parametrize(
    ("prefix", "installer", "command"),
    [
        ("/home/u/.cache/uv/archive-v0/l3A6DnngECMlzMwB", "uvx", "uvx archivey-cli"),
        (
            "/home/u/.local/share/uv/tools/archivey",
            "uv-tool",
            "uv tool install archivey-cli",
        ),
    ],
)
def test_library_tool_points_at_the_cli_package(
    monkeypatch: pytest.MonkeyPatch, prefix: str, installer: str, command: str
) -> None:
    """``uvx archivey`` runs the same command without the recommended packages."""
    monkeypatch.delenv("UV_TOOL_DIR", raising=False)
    monkeypatch.setattr(metadata, "distribution", _library_only)
    monkeypatch.setattr(sys, "prefix", str(Path(prefix)))
    install = detect_installer()
    assert install == Install(installer, "archivey")  # type: ignore[arg-type]
    hint = cli_package_hint(install)
    assert hint is not None and command in hint
    assert cli_package_hint(Install(installer)) is None  # type: ignore[arg-type]
    assert cli_package_hint(Install("pip", "archivey")) is None


def test_report_prints_the_cli_package_hint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real = version_report.format_availability

    def fake(fmt: ArchiveFormat) -> FormatAvailability:
        if fmt == ArchiveFormat.LZOP:
            return FormatAvailability(
                fmt,
                FormatSupport.FULL,
                faster_with=(MissingComponent("compress_utils", "pip install x"),),
            )
        return FormatAvailability(fmt, real(fmt).support)

    monkeypatch.setattr(version_report, "format_availability", fake)
    monkeypatch.setattr(
        version_report, "detect_installer", lambda: Install("uvx", "archivey")
    )
    flat = " ".join(_report(capsys).split())
    assert "uvx archivey-cli installs the same command" in flat
    assert "uvx --with x archivey" in flat


def test_packages_line_uses_pypi_names(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real = version_report.format_availability
    hint = "pip install archivey[bzip3]"

    def fake(fmt: ArchiveFormat) -> FormatAvailability:
        if fmt == ArchiveFormat.BZIP3:
            missing = (MissingComponent(OptionalLibrary.BZIP3, hint),)
            return FormatAvailability(fmt, FormatSupport.NONE, missing)
        if fmt == ArchiveFormat.SNAPPY:
            faster = (MissingComponent(OptionalLibrary.GOOGLE_CRC32C, "pip install x"),)
            return FormatAvailability(fmt, FormatSupport.FULL, faster_with=faster)
        return FormatAvailability(fmt, real(fmt).support)

    monkeypatch.setattr(version_report, "format_availability", fake)
    monkeypatch.setattr(version_report, "detect_installer", lambda: Install("pip"))
    out = _report(capsys)
    assert '  pip install "archivey[bzip3]"\n    adds bz3\n    packages: bzip3\n' in out
    assert "    packages: google-crc32c\n" in out


def test_a_package_that_fails_to_import_is_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "brotli").mkdir()
    (tmp_path / "brotli" / "__init__.py").write_text(
        'raise ImportError("simulated broken wheel")\n'
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "brotli", raising=False)
    broken = unimportable_packages()
    assert broken[OptionalLibrary.BROTLI] == "ImportError: simulated broken wheel"
    assert "brotli" not in sys.modules
    # A package to skip is not imported.
    assert OptionalLibrary.BROTLI not in unimportable_packages({"brotli"})


def test_report_counts_a_package_that_fails_to_import_as_absent(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``format_availability`` only looks a package up, so it counts a broken one as
    present; a read treats it as absent, and so does the report."""
    monkeypatch.setattr(
        version_report,
        "unimportable_packages",
        lambda skip: {OptionalLibrary.BROTLI: "ImportError: simulated broken wheel"},
    )
    monkeypatch.setattr(version_report, "detect_installer", lambda: Install("pip"))
    out = _report(capsys)
    assert "br" in _level_row(out, "compression and encodings", "none")
    flat = " ".join(out.split())
    assert (
        "brotli is installed but fails to import (ImportError: simulated broken "
        "wheel); reinstalling it may fix this adds br"
    ) in flat
    assert "ArchiveyConfig.formats turns it off" not in flat


def test_a_combination_row_names_packages_as_pip_does() -> None:
    hint = "pip install archivey[bzip3]"
    availability = FormatAvailability(
        ArchiveFormat.BZIP3,
        FormatSupport.NONE,
        (MissingComponent(OptionalLibrary.BZIP3, hint),),
    )
    line = version_report._format_line(ArchiveFormat.BZIP3, availability)
    assert line == ["  bz3: none (missing bzip3)"]
