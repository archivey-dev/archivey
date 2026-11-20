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
    format_availability,
    list_known_formats,
)
from archivey.cli import version_report
from archivey.cli.exit_codes import EXIT_OK
from archivey.cli.main import main
from archivey.cli.version_report import detect_installer, install_command


def _report(capsys: pytest.CaptureFixture[str]) -> str:
    assert main(["--version", "-v"]) == EXIT_OK
    return capsys.readouterr().out


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
    assert "dmg (recognised, not readable)" in archives
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
    monkeypatch.setattr(version_report, "detect_installer", lambda: "pip")
    out = _report(capsys)
    assert out.count(hint) == 1
    section = out.split("to read more, or faster\n")[1]
    assert section.splitlines()[:5] == [
        f"  {hint}",
        "    adds iso",
        "    completes 7z",
        "    faster for lzo",
        "    packages: pyppmd, pycdlib, compress_utils",
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
    assert "none: zst" in flat
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
        ("pip", "pip install archivey[bzip3]"),
        ("uvx", 'uvx --with "archivey[bzip3]" archivey-cli'),
        ("uv-tool", 'uv tool install --with "archivey[bzip3]" archivey-cli'),
        ("pipx", 'pipx inject archivey-cli "archivey[bzip3]"'),
    ],
)
def test_install_command_fits_the_installer(installer: str, expected: str) -> None:
    assert install_command("pip install archivey[bzip3]", installer) == expected  # type: ignore[arg-type]


def test_install_command_keeps_other_advice() -> None:
    assert install_command("pip install compress-utils", "uvx") == (
        "uvx --with compress-utils archivey-cli"
    )
    reason = "archivey does not use lz4 under PyPy"
    assert install_command(reason, "uvx") == reason
    assert install_command("Install RARLAB unrar", "pipx") == "Install RARLAB unrar"


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
    assert detect_installer() == expected


def test_detect_installer_honours_uv_tool_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("UV_TOOL_DIR", str(tmp_path))
    monkeypatch.setattr(metadata, "distribution", lambda name: _Dist("uv"))
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "archivey-cli"))
    assert detect_installer() == "uv-tool"


def test_detect_installer_without_the_cli_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(name: str) -> None:
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(metadata, "distribution", missing)
    assert detect_installer() == "pip"
