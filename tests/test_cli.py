"""CLI behavior-matrix tests (argv → exit / stdout / stderr)."""

from __future__ import annotations

import errno
import io
import os
import stat
import sys
import tarfile
import time
import zipfile
from collections.abc import Callable, Generator
from pathlib import Path

import pytest

from archivey import (
    ExtractionReport,
    ExtractionResult,
    ExtractionStatus,
    MemberPass,
    MissingComponent,
    OverwritePolicy,
    format_availability,
    list_known_formats,
    open_archive,
)
from archivey.cli import test_cmd
from archivey.cli.exit_codes import (
    EXIT_BROKEN_PIPE,
    EXIT_FAIL,
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_USAGE,
)
from archivey.cli.extract_cmd import _report_extraction
from archivey.cli.format import format_format_label
from archivey.cli.info_cmd import _can_reread
from archivey.cli.main import _inject_default_list, _parse_cli_args, build_parser, main
from archivey.diagnostics import DiagnosticSummary
from archivey.exceptions import ArchiveyError, TruncatedError
from archivey.types import ArchiveMember, MemberType
from tests.conftest import case_sensitive, requires_binary


def _as_pass(
    fake: Callable[..., Generator[tuple[ArchiveMember, object], None, None]],
) -> Callable[..., MemberPass]:
    """A generator standing in for ``stream_members()``, returned the way it returns."""
    return lambda self, members=None: MemberPass._new(fake(self, members))  # type: ignore[arg-type]


def _zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


@pytest.fixture
def sample_zip(tmp_path: Path) -> Path:
    return _zip(
        tmp_path / "sample.zip",
        {
            "a.txt": b"hello",
            "b/c.py": b"print(1)\n",
            "b/d_test.py": b"x",
        },
    )


def test_inject_default_list() -> None:
    assert _inject_default_list(["a.zip"]) == ["list", "a.zip"]
    assert _inject_default_list(["--track-io", "a.zip"]) == [
        "--track-io",
        "list",
        "a.zip",
    ]
    assert _inject_default_list(["x", "a.zip"]) == ["x", "a.zip"]
    assert _inject_default_list(["create", "a.zip"]) == ["create", "a.zip"]
    # Bare "-" is a positional (reserved stdin), not an option.
    assert _inject_default_list(["-"]) == ["list", "-"]


def test_global_flags_before_verb(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Shared-parents argparse pitfall: pre-verb globals must survive subparser defaults.
    assert main(["--track-io", str(sample_zip)]) == EXIT_OK
    err = capsys.readouterr().err
    assert "track-io:" in err

    assert main(["-v", "test", str(sample_zip)]) == EXIT_OK
    err = capsys.readouterr().err
    assert "OK   a.txt" in err or "a.txt" in err
    assert "OK," in err or "failed" in err


def test_password_before_verb_reaches_dispatch(
    sample_zip: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey.cli import main as main_mod

    seen: dict[str, object] = {}

    def _capture_test(**kwargs: object) -> int:
        seen.update(kwargs)
        return EXIT_OK

    monkeypatch.setattr(main_mod, "run_test", _capture_test)
    assert main(["--password", "secret", "test", str(sample_zip)]) == EXIT_OK
    assert seen.get("password") == "secret"


def test_abbrev_password_rejected(sample_zip: Path) -> None:
    # allow_abbrev=False: --pass must not become --password with a mangled value.
    assert main(["--pass", "secret", str(sample_zip)]) == EXIT_USAGE


def test_abbrev_overwrite_rejected_post_verb(sample_zip: Path, tmp_path: Path) -> None:
    # Subparsers also need allow_abbrev=False (R2) — --over must not become --overwrite.
    dest = tmp_path / "out"
    assert (
        main(["x", str(sample_zip), "-d", str(dest), "--over", "error"]) == EXIT_USAGE
    )


def test_bare_invocation_is_usage() -> None:
    assert main([]) == EXIT_USAGE


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == EXIT_OK
    assert capsys.readouterr().out.strip().startswith("archivey ")


def test_version_verbose_lists_formats(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version", "-v"]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("archivey ")
    assert "formats:" in out
    assert "zip:" in out
    assert "dmg: none — recognised, not readable" in out
    assert main(["-v", "--version"]) == EXIT_OK
    assert "formats:" in capsys.readouterr().out


def test_version_verbose_names_each_install_hint_once() -> None:
    """Missing packages that one command installs share one hint, in first-seen order."""
    hint = "pip install archivey[recommended]"
    missing = [
        MissingComponent("pyppmd", hint, ("ppmd",)),
        MissingComponent("unrar", "install RARLAB unrar", ("rar",)),
        MissingComponent("brotli", hint, ("brotli",)),
        MissingComponent("lz4", hint, ("lz4",), reason="archivey does not use lz4"),
    ]
    from archivey.cli import main as main_mod

    assert main_mod._format_missing_components(missing) == (
        f"pyppmd, brotli ({hint}); unrar (install RARLAB unrar); "
        "lz4 (archivey does not use lz4)"
    )


def test_version_verbose_never_repeats_an_install_hint(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each format's printed line names each of its components' advice exactly once.

    Vacuous on a full install (nothing is missing); real on the core-only legs, where
    the recommended-extra packages must share one hint, and under PyPy, where a package
    archivey does not use prints its reason instead (``MissingComponent.advice``).
    Advice is free text (unrar's is a whole refusal with ``;`` and parentheses), so
    count it, don't parse it.
    """
    assert main(["--version", "-v"]) == EXIT_OK
    lines = capsys.readouterr().out.splitlines()
    for fmt in list_known_formats():
        hints = {m.advice for m in format_availability(fmt).missing}
        if not hints:
            continue
        prefix = f"  {format_format_label(fmt)}: "
        line = next(ln for ln in lines if ln.startswith(prefix))
        for hint in hints:
            assert line.count(hint) == 1, line


def test_default_list_dispatch(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(sample_zip)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "a.txt" in out
    assert "b/c.py" in out


def test_list_alias(sample_zip: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["l", str(sample_zip)]) == EXIT_OK
    assert "a.txt" in capsys.readouterr().out


def test_list_digests_names_the_algorithm_by_value(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--digests`` prints ``crc32=<hex>``, not the enum's repr-like ``str()``."""
    with zipfile.ZipFile(sample_zip) as zf:
        crc = zf.getinfo("a.txt").CRC
    assert main(["list", "--digests", str(sample_zip)]) == EXIT_OK
    line = next(ln for ln in capsys.readouterr().out.splitlines() if ln.endswith("]"))
    assert "a.txt" in line
    assert line.endswith(f"[crc32={crc:08x}]")


def test_list_long_adds_packed_size_method_and_crc(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--long`` prints a header, then each member's packed size, space saved, method
    and CRC."""
    path = tmp_path / "long.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("big.txt", b"a" * 1000, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("raw.bin", b"xyz", compress_type=zipfile.ZIP_STORED)
    with zipfile.ZipFile(path) as zf:
        big = zf.getinfo("big.txt")
    assert main(["list", "--long", str(path)]) == EXIT_OK
    header, big_line, raw_line = capsys.readouterr().out.splitlines()
    assert header.split() == [
        "ts",
        "mode",
        "size",
        "packed",
        "saved",
        "method",
        "crc32",
        "modified",
        "name",
    ]
    saved = round(100 * (1000 - big.compress_size) / 1000)
    assert big_line.split()[2:7] == [
        "1000",
        str(big.compress_size),
        f"{saved}%",
        "deflate",
        f"{big.CRC:08x}",
    ]
    assert raw_line.split()[2:6] == ["3", "3", "0%", "stored"]
    # The name column lines up under its header.
    assert big_line.index("big.txt") == header.index("name")


def test_list_details_prints_one_block_per_member(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--details`` prints ``key: value`` blocks, leaving out fields not recorded."""
    path = tmp_path / "details.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("a.txt", date_time=(2020, 1, 2, 3, 4, 6))
        info.external_attr = 0o100640 << 16
        info.create_system = 3
        info.comment = b"a\x1bnote"
        zf.writestr(info, b"hello", compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("b.txt", b"x")
    assert main(["list", "--details", str(path)]) == EXIT_OK
    first, second = capsys.readouterr().out.split("\n\n")
    fields = dict(line.split(":", 1) for line in first.splitlines())
    fields = {k: v.strip() for k, v in fields.items()}
    assert fields["name"] == "a.txt"
    assert fields["type"] == "file"
    assert fields["size"] == "5"
    assert fields["method"] == "deflate"
    assert fields["mode"] == "0640 (rw-r-----)"
    assert fields["host_os"] == "unix"
    assert fields["modified"].startswith("2020-01-02 03:04:06")
    assert fields["comment"] == "a\\x1bnote"  # escaped, not a raw ESC
    assert "uid" not in fields  # ZIP without a Unix extra field records no owner
    assert second.startswith("name:")
    assert "b.txt" in second


def test_list_long_and_details_on_tar_show_what_tar_does_not_record(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """TAR stores no packed size or digest, and a directory no method: ``-`` cells in
    ``--long``; ``--details`` leaves those keys out and prints bytes extras as hex."""
    src = tmp_path / "src"
    (src / "d").mkdir(parents=True)
    (src / "d" / "f.txt").write_bytes(b"hello")
    path = tmp_path / "t.tar"
    with tarfile.open(path, "w") as tf:
        tf.add(src / "d", arcname="d")
    assert main(["list", "--long", str(path)]) == EXIT_OK
    header, dir_line, file_line = capsys.readouterr().out.splitlines()
    assert dir_line.split()[2:7] == ["-", "-", "-", "-", "-"]
    assert file_line.split()[2:7] == ["5", "-", "-", "stored", "-"]
    assert file_line.index("d/f.txt") == header.index("name")

    assert main(["list", "--details", str(path)]) == EXIT_OK
    dir_block, file_block = capsys.readouterr().out.split("\n\n")
    fields = {
        k: v.strip() for k, v in (ln.split(":", 1) for ln in file_block.splitlines())
    }
    assert "packed_size" not in fields
    assert "crc32" not in fields
    assert fields["extra.tar.type"] == "hex:30"  # the typeflag b"0", not "30"
    assert "method:" not in dir_block


def test_long_listing_sizes_columns_to_their_widest_cell() -> None:
    """A long method chain or a negative saving widens its column for every row."""
    from archivey.cli.format import format_long_listing
    from archivey.types import CompressionAlgorithm, CompressionMethod

    chain = tuple(
        CompressionMethod(a)
        for a in (
            CompressionAlgorithm.DELTA,
            CompressionAlgorithm.BCJ,
            CompressionAlgorithm.LZMA2,
        )
    )
    members = [
        ArchiveMember(
            type=MemberType.FILE,
            name="one",
            size=1,
            compressed_size=13,
            compression=chain,
        ),
        ArchiveMember(type=MemberType.FILE, name="two", size=10, compressed_size=5),
    ]
    header, one, two = format_long_listing(members, digests=False, verbose=False)
    assert "delta+bcj+lzma2" in one
    assert "-1200%" in one
    assert one.index("one") == two.index("two") == header.index("name")
    assert format_long_listing([], digests=False, verbose=False) == []


def test_long_listing_keeps_the_digests_and_verbose_suffixes() -> None:
    """``--digests`` and ``-v`` add to a ``--long`` line what they add to the default one."""
    from types import SimpleNamespace

    from archivey.cli.format import format_long_listing
    from archivey.diagnostics import DiagnosticCode
    from archivey.types import HashAlgorithm

    member = ArchiveMember(
        type=MemberType.FILE,
        name="a",
        size=1,
        hashes={HashAlgorithm.BLAKE2SP: b"\xab\xcd"},
        _diagnostics=(
            SimpleNamespace(
                code=DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED, message="skipped"
            ),
        ),
    )
    _, plain = format_long_listing([member], digests=False, verbose=False)
    _, both = format_long_listing([member], digests=True, verbose=True)
    assert both == f"{plain}  [blake2sp=abcd]  (skipped)"


def test_member_details_raw_name_and_diagnostics() -> None:
    """``raw_name`` shows when it is not ``name`` in UTF-8, as hex; a diagnostic's
    message, stored escaped, is not escaped a second time."""
    from types import SimpleNamespace

    from archivey.cli.format import format_member_details
    from archivey.diagnostics import DiagnosticCode

    def fields(member: ArchiveMember) -> dict[str, str]:
        return {
            k: v.strip()
            for k, v in (ln.split(":", 1) for ln in format_member_details(member))
        }

    iso = ArchiveMember(type=MemberType.FILE, name="a.txt", raw_name=b"A.TXT;1")
    assert fields(iso)["raw_name"] == "hex:" + b"A.TXT;1".hex()
    same = ArchiveMember(type=MemberType.FILE, name="a.txt", raw_name=b"a.txt")
    assert "raw_name" not in fields(same)

    code = DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
    damaged = ArchiveMember(
        type=MemberType.FILE,
        name="a",
        _diagnostics=(SimpleNamespace(code=code, message="name a\\x01b"),),
    )
    assert fields(damaged)["diagnostic"] == f"{code.value}: name a\\x01b"


def test_list_long_and_details_are_exclusive(sample_zip: Path) -> None:
    assert main(["list", "--long", "--details", str(sample_zip)]) == EXIT_USAGE


def test_list_incomplete_members_report_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI list prints recovered members then exits 1 when members_report.error is set."""
    from contextlib import contextmanager

    from archivey.cli import list_cmd
    from archivey.diagnostics import DiagnosticSummary, MemberListReport
    from archivey.exceptions import TruncatedError
    from archivey.types import ArchiveMember, MemberType

    member = ArchiveMember(type=MemberType.FILE, name="recovered.txt", size=4)
    report = MemberListReport(
        members=(member,),
        error=TruncatedError("truncated for test"),
        diagnostics=DiagnosticSummary.empty(),
    )

    class _FakeReader:
        def members_report(self) -> MemberListReport:
            return report

    @contextmanager
    def fake_open(*_args: object, **_kwargs: object):
        yield _FakeReader()

    monkeypatch.setattr(list_cmd, "open_for_cli", fake_open)
    archive = tmp_path / "dummy.tar"
    archive.write_bytes(b"x")
    assert (
        list_cmd.run_list(
            archive=str(archive),
            patterns=[],
            exclude=[],
            digests=False,
            long=False,
            details=False,
            verbose=False,
            password=None,
            track_io=False,
        )
        == EXIT_FAIL
    )
    captured = capsys.readouterr()
    assert "recovered.txt" in captured.out
    assert "truncated for test" in captured.err


def test_verb_named_file_known_verb_wins(tmp_path: Path) -> None:
    # A file named "x" collides with the extract alias; a bare verb word is a verb, so
    # this dispatches extract. Escape hatches: `archivey list x`, or a path-qualified
    # token such as `archivey ./x` (next test).
    named = tmp_path / "x"
    _zip(named, {"f.txt": b"data"})
    # extract into dest — should not fall through to list
    dest = tmp_path / "out"
    code = main(["x", str(named), "-d", str(dest)])
    assert code == EXIT_OK
    assert (dest / "f.txt").read_bytes() == b"data"
    # escape hatch lists the verb-named archive
    code = main(["list", str(named)])
    assert code == EXIT_OK


@pytest.mark.parametrize("shape", ["./x", "sub/x", "absolute"])
def test_path_qualified_verb_word_is_listed_not_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    shape: str,
) -> None:
    """A path-qualified token whose basename is a verb word is a path, never a verb.

    A regression here would run ``extract`` and write into the working directory.
    """
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "sub" / "x" if shape == "sub/x" else tmp_path / "x"
    target.parent.mkdir(exist_ok=True)
    _zip(target, {"f.txt": b"data"})
    token = str(target) if shape == "absolute" else shape
    before = sorted(p.name for p in tmp_path.iterdir())
    assert main([token]) == EXIT_OK
    assert "f.txt" in capsys.readouterr().out
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_dash_prefixed_verb_rejected(sample_zip: Path) -> None:
    assert main(["-x", str(sample_zip)]) == EXIT_USAGE


def test_stdin_token_reserved(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list", "-"]) == EXIT_USAGE
    assert main(["-"]) == EXIT_USAGE
    err = capsys.readouterr().err
    if sys.platform == "win32":
        # Windows has no /dev/stdin, so the message names the action that works there.
        assert "/dev/stdin" not in err
        assert "copy the archive to a regular file" in err
    else:
        # The token is reserved, but a piped archive is readable through /dev/stdin.
        assert "/dev/stdin" in err


@pytest.mark.parametrize("verb", ["list", "test", "info", "extract"])
def test_empty_archive_argument_is_a_usage_error(
    verb: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``archivey <verb> ""`` (an unset ``$ARCHIVE``) does not read the cwd.

    ``Path("")`` is ``Path(".")``, so the empty string used to open the working
    directory as a directory archive. It is a usage error, reported as a message.
    """
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "precious.txt").write_text("keep")
    monkeypatch.chdir(cwd)

    assert main([verb, ""]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "empty" in err
    assert "Traceback" not in err
    assert sorted(p.name for p in cwd.iterdir()) == ["precious.txt"]


def test_extract_empty_dest_is_a_usage_error(
    sample_zip: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``-d ""`` (an unset ``$OUT``) does not extract into the cwd; ``-d .`` does."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "precious.txt").write_text("keep")
    monkeypatch.chdir(cwd)

    assert main(["x", str(sample_zip), "-d", ""]) == EXIT_USAGE
    assert "--dest" in capsys.readouterr().err
    assert sorted(p.name for p in cwd.iterdir()) == ["precious.txt"]


def test_reserved_verbs(sample_zip: Path) -> None:
    assert main(["create", str(sample_zip)]) == EXIT_USAGE
    assert main(["hash", str(sample_zip)]) == EXIT_USAGE
    assert main(["convert", str(sample_zip)]) == EXIT_USAGE


def test_salvage_reserved(sample_zip: Path) -> None:
    assert main(["list", str(sample_zip), "--salvage"]) == EXIT_USAGE
    assert main(["--salvage", "list", str(sample_zip)]) == EXIT_USAGE
    assert (
        main(
            [
                "extract",
                str(sample_zip),
                "--salvage",
                "-d",
                str(sample_zip.parent / "o"),
            ]
        )
        == EXIT_USAGE
    )


def test_top_level_errors_share_one_prefix(
    sample_zip: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A CliError, an ArchiveyError and an OSError that end the run print alike."""
    not_an_archive = tmp_path / "plain.bin"
    not_an_archive.write_bytes(b"not an archive at all\n" * 8)
    runs = {
        "CliError": ["list", str(sample_zip), "--salvage"],
        "ArchiveyError": ["list", str(not_an_archive)],
        "OSError": ["list", str(tmp_path / "missing.zip")],
    }
    for kind, argv in runs.items():
        assert main(argv) != EXIT_OK, kind
        err = capsys.readouterr().err
        assert err.startswith("archivey: "), (kind, err)


def test_include_flag_rejected(sample_zip: Path) -> None:
    assert main(["list", str(sample_zip), "--include", "x"]) == EXIT_USAGE


def test_exclude_filter(sample_zip: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(["list", str(sample_zip), "**/*.py", "--exclude", "**/*_test.py"])
        == EXIT_OK
    )
    out = capsys.readouterr().out
    assert "b/c.py" in out
    assert "d_test.py" not in out
    assert "a.txt" not in out


def test_test_quiet_summary(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["test", str(sample_zip)]) == EXIT_OK
    captured = capsys.readouterr()
    assert "OK," in captured.err
    assert "failed" in captured.err
    # Quiet: no per-member OK lines on stderr by default
    assert "OK   a.txt" not in captured.err


def test_test_verbose_per_member(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["test", "-v", str(sample_zip)]) == EXIT_OK
    err = capsys.readouterr().err
    assert "OK   a.txt" in err or "OK   " in err


def test_extract_policy_and_dest(sample_zip: Path, tmp_path: Path) -> None:
    dest = tmp_path / "out"
    assert (
        main(
            [
                "extract",
                str(sample_zip),
                "-d",
                str(dest),
                "--policy",
                "strict",
                "--overwrite",
                "rename",
            ]
        )
        == EXIT_OK
    )
    assert (dest / "a.txt").read_bytes() == b"hello"


def test_extract_strict_blocks_device_name_and_continues(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Windows-reserved device names are rejected under STRICT; default CONTINUE
    # still extracts the remaining members (Q1). Trailing-dot names are stripped,
    # not rejected — see #123.
    from archivey.cli.exit_codes import EXIT_POLICY

    bad = _zip(tmp_path / "bad.zip", {"NUL": b"x", "ok.txt": b"y"})
    dest = tmp_path / "out"
    code = main(["extract", str(bad), "-d", str(dest), "--policy", "strict"])
    assert code == EXIT_POLICY
    err = capsys.readouterr().err
    assert "NUL" in err
    assert "blocked:" in err
    assert "extraction stopped" not in err.lower()
    assert (dest / "ok.txt").read_bytes() == b"y"


def test_extract_strict_stop_on_error_continues_on_device_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # --stop-on-error = library STOP = failures only; policy blocks continue.
    from archivey.cli.exit_codes import EXIT_POLICY

    bad = _zip(tmp_path / "bad.zip", {"NUL": b"x", "ok.txt": b"y"})
    dest = tmp_path / "out"
    code = main(
        [
            "extract",
            str(bad),
            "-d",
            str(dest),
            "--policy",
            "strict",
            "--stop-on-error",
        ]
    )
    assert code == EXIT_POLICY
    err = capsys.readouterr().err
    assert "NUL" in err
    assert "blocked:" in err
    assert "extraction stopped" not in err.lower()
    assert (dest / "ok.txt").read_bytes() == b"y"


def test_extract_zip_root_slash_under_default_strict(tmp_path: Path) -> None:
    # ZIP root entry "/" normalizes to "."; STRICT must not abort on that spelling.
    archive = tmp_path / "rooted.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(zipfile.ZipInfo("/"), b"")
        zf.writestr("a.txt", b"hello")
    dest = tmp_path / "out"
    assert main(["extract", str(archive), "-d", str(dest)]) == EXIT_OK
    assert (dest / "a.txt").read_bytes() == b"hello"


def test_extract_smart_dest_multi_toplevel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    z = _zip(tmp_path / "multi.zip", {"a.txt": b"a", "b.txt": b"b"})
    assert main(["extract", str(z)]) == EXIT_OK
    assert (tmp_path / "multi" / "a.txt").exists()
    assert not (tmp_path / "a.txt").exists()


def test_extract_smart_dest_single_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    z = _zip(tmp_path / "one.zip", {"root/a.txt": b"a", "root/b.txt": b"b"})
    assert main(["extract", str(z)]) == EXIT_OK
    assert (tmp_path / "root" / "a.txt").exists()
    assert not (tmp_path / "one").exists()


def test_extract_dest_dot_splatter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    z = _zip(tmp_path / "splat.zip", {"a.txt": b"a", "b.txt": b"b"})
    assert main(["extract", str(z), "-d", "."]) == EXIT_OK
    assert (tmp_path / "a.txt").exists()
    assert (tmp_path / "b.txt").exists()


def test_info_and_detect(sample_zip: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", str(sample_zip)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "format:      zip" in out or "format:" in out and "zip" in out
    assert "ArchiveFormat.ZIP" not in out
    assert "SEVEN_Z" not in out
    assert "access:      random (indexed)" in out
    assert main(["detect", str(sample_zip)]) == EXIT_OK


def test_info_detects_once(
    sample_zip: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``info`` prints the detection the open ran instead of detecting again."""
    from typing import Any

    from archivey import FormatInfo
    from archivey.internal import detection

    calls = 0
    real = detection._detect_format_body

    def counting(*args: Any, **kwargs: Any) -> FormatInfo:
        nonlocal calls
        calls += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(detection, "_detect_format_body", counting)
    assert main(["info", str(sample_zip)]) == EXIT_OK
    assert calls == 1
    out = capsys.readouterr().out
    assert "confidence:  certain" in out
    assert "detected_by: magic" in out


def test_info_prints_identity_once_when_the_open_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A recognised format that fails to open still gets its identity lines, once."""
    bad = tmp_path / "bad.zip"
    # Cut inside the first local header: no member to list.
    bad.write_bytes(b"PK\x03\x04" + b"\x00" * 20)
    assert main(["info", str(bad)]) != EXIT_OK
    captured = capsys.readouterr()
    assert captured.out.count("path:") == 1
    assert "format:" in captured.out
    assert "open:" in captured.err


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tf.addfile(member, io.BytesIO(data))
    return buf.getvalue()


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _main_on_fifo(fifo: Path, argv: list[str]) -> int:
    """Run ``main(argv)`` in a thread and fail the test if it blocks on ``fifo``.

    A second open of a FIFO blocks every time, not now and then, so the window only
    has to outlast a slow runner: 10 s was missed once on macOS under ``-n auto``
    (a test that passed on the same commit in another run). 40 s plus the 5 s
    unblock stays under the suite's 60 s ``--timeout``, so a real block still fails
    here with its message.
    """
    import threading

    result: list[int] = []
    worker = threading.Thread(target=lambda: result.append(main(argv)), daemon=True)
    worker.start()
    worker.join(40)
    if worker.is_alive():
        # Unblock a stuck second open so the thread can finish, then fail.
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        worker.join(5)
        pytest.fail(f"archivey {argv[0]} blocked on a FIFO")
    return result[0]


_FIFO_TAR = {"a.txt": b"hello", "b/c.txt": b"see"}
# The formats the CLI reads from a pipe in one forward pass.
_FIFO_BUILDERS = {"tar": _tar_bytes, "zip": _zip_bytes}


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is Unix-only")
def test_info_on_a_fifo_reports_the_open_error_without_reopening(
    tmp_path: Path,
    named_fifo_with_writer: Callable[[Path, bytes], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failed open on a FIFO must not run ``detect_format`` on the path again.

    A pipe is read once, so a second open waits for a writer that never comes.
    ``info`` must print the open error and return. A 7z cannot be read in one
    forward pass, so its open fails even in the streaming mode the CLI picks.
    """
    fifo = tmp_path / "pipe.7z"
    named_fifo_with_writer(fifo, _SEEK_ONLY_PAYLOADS["7z"])
    assert _main_on_fifo(fifo, ["info", str(fifo)]) == EXIT_FAIL
    captured = capsys.readouterr()
    assert "open:" in captured.err
    assert "Copy the archive to a regular file first" in captured.err
    # The user cannot pass streaming=True, so the message must not suggest it.
    assert "streaming=True" not in captured.err
    # The detected format is named plainly, not as an enum repr.
    assert "ArchiveFormat." not in captured.err


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is Unix-only")
@pytest.mark.parametrize("fmt", sorted(_FIFO_BUILDERS))
def test_info_on_a_tar_or_zip_fifo_opens_in_streaming_mode(
    tmp_path: Path,
    named_fifo_with_writer: Callable[[Path, bytes], None],
    capsys: pytest.CaptureFixture[str],
    fmt: str,
) -> None:
    fifo = tmp_path / f"pipe.{fmt}"
    named_fifo_with_writer(fifo, _FIFO_BUILDERS[fmt](_FIFO_TAR))
    assert _main_on_fifo(fifo, ["info", str(fifo)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "format:" in out
    assert "forward-only source" in out


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is Unix-only")
@pytest.mark.parametrize("verb", ["list", "l"])
@pytest.mark.parametrize("fmt", sorted(_FIFO_BUILDERS))
def test_list_on_a_tar_or_zip_fifo_lists_every_member(
    tmp_path: Path,
    named_fifo_with_writer: Callable[[Path, bytes], None],
    capsys: pytest.CaptureFixture[str],
    fmt: str,
    verb: str,
) -> None:
    fifo = tmp_path / f"pipe.{fmt}"
    named_fifo_with_writer(fifo, _FIFO_BUILDERS[fmt](_FIFO_TAR))
    assert _main_on_fifo(fifo, [verb, str(fifo)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "a.txt" in out
    assert "b/c.txt" in out


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is Unix-only")
@pytest.mark.parametrize("patterns", [[], ["b/*"]])
@pytest.mark.parametrize("fmt", sorted(_FIFO_BUILDERS))
def test_test_on_a_tar_or_zip_fifo_verifies_in_one_pass(
    tmp_path: Path,
    named_fifo_with_writer: Callable[[Path, bytes], None],
    capsys: pytest.CaptureFixture[str],
    fmt: str,
    patterns: list[str],
) -> None:
    fifo = tmp_path / f"pipe.{fmt}"
    named_fifo_with_writer(fifo, _FIFO_BUILDERS[fmt](_FIFO_TAR))
    argv = ["test", "--hide-progress", str(fifo), *patterns]
    assert _main_on_fifo(fifo, argv) == EXIT_OK
    expected = "1 OK, 0 failed" if patterns else "2 OK, 0 failed"
    assert expected in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is Unix-only")
@pytest.mark.parametrize("patterns", [[], ["b/*"]])
@pytest.mark.parametrize("fmt", sorted(_FIFO_BUILDERS))
def test_extract_on_a_tar_or_zip_fifo_streams_the_members_out(
    tmp_path: Path,
    named_fifo_with_writer: Callable[[Path, bytes], None],
    fmt: str,
    patterns: list[str],
) -> None:
    fifo = tmp_path / f"pipe.{fmt}"
    named_fifo_with_writer(fifo, _FIFO_BUILDERS[fmt](_FIFO_TAR))
    dest = tmp_path / "out"
    argv = ["extract", "--hide-progress", str(fifo), "-d", str(dest), *patterns]
    assert _main_on_fifo(fifo, argv) == EXIT_OK
    assert (dest / "b" / "c.txt").read_bytes() == b"see"
    assert (dest / "a.txt").exists() == (not patterns)


# Only the magic bytes: the refusal comes right after detection, before the backend
# reads anything else, so no real archive of these formats is needed.
_SEEK_ONLY_PAYLOADS = {
    "7z": b"7z\xbc\xaf\x27\x1c\x00\x04" + bytes(1024),
    "rar": b"Rar!\x1a\x07\x01\x00" + bytes(1024),
    "iso": bytes(0x8001) + b"CD001\x01" + bytes(4096),
}


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is Unix-only")
@pytest.mark.parametrize("fmt", sorted(_SEEK_ONLY_PAYLOADS))
@pytest.mark.parametrize("verb", ["list", "test", "extract", "info"])
def test_verbs_on_a_seek_only_fifo_say_to_copy_it_to_a_file(
    tmp_path: Path,
    named_fifo_with_writer: Callable[[Path, bytes], None],
    capsys: pytest.CaptureFixture[str],
    verb: str,
    fmt: str,
) -> None:
    """7z, RAR and ISO need to seek, so no mode can read them from a pipe: the
    message must name the format as the user knows it (``7z``, not the enum's
    ``SEVEN_Z``) and what a CLI user can do, not a ``streaming=True`` they cannot pass.
    """
    fifo = tmp_path / f"pipe.{fmt}"
    named_fifo_with_writer(fifo, _SEEK_ONLY_PAYLOADS[fmt])
    argv = [verb, str(fifo)]
    if verb == "extract":
        argv += ["-d", str(tmp_path / "out")]
    assert _main_on_fifo(fifo, argv) == EXIT_FAIL
    err = capsys.readouterr().err
    assert f"the {fmt} format cannot be read from a pipe or device" in err
    assert "Copy the archive to a regular file first" in err
    assert "streaming=True" not in err


def _gz_bytes(data: bytes) -> bytes:
    import gzip

    return gzip.compress(data, mtime=0)


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is Unix-only")
def test_verbs_on_a_gz_fifo_read_the_single_member(
    tmp_path: Path,
    named_fifo_with_writer: Callable[[Path, bytes], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A single-file format has no member name of its own: it comes from the FIFO's
    filename, and ``extract`` writes it into the destination without a wrapper.
    """
    payload = _gz_bytes(b"hello gz")

    # Not "list.gz": the member name must be a word the verb cannot print by itself.
    listed = tmp_path / "payload.gz"
    named_fifo_with_writer(listed, payload)
    assert _main_on_fifo(listed, ["list", str(listed)]) == EXIT_OK
    assert "payload" in capsys.readouterr().out

    tested = tmp_path / "test.gz"
    named_fifo_with_writer(tested, payload)
    argv = ["test", "--hide-progress", str(tested)]
    assert _main_on_fifo(tested, argv) == EXIT_OK
    assert "1 OK, 0 failed" in capsys.readouterr().err

    extracted = tmp_path / "data.gz"
    named_fifo_with_writer(extracted, payload)
    dest = tmp_path / "out"
    argv = ["extract", "--hide-progress", str(extracted), "-d", str(dest)]
    assert _main_on_fifo(extracted, argv) == EXIT_OK
    assert (dest / "data").read_bytes() == b"hello gz"


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is Unix-only")
@pytest.mark.parametrize("fmt", sorted(_FIFO_BUILDERS))
def test_extract_on_a_tar_or_zip_fifo_without_dest_wraps_in_the_stem(
    tmp_path: Path,
    named_fifo_with_writer: Callable[[Path, bytes], None],
    monkeypatch: pytest.MonkeyPatch,
    fmt: str,
) -> None:
    """With no ``-d``, a forward-only reader has no index to choose a destination
    from, so the members go into ``./<stem>/``.
    """
    fifo = tmp_path / f"pipe.{fmt}"
    named_fifo_with_writer(fifo, _FIFO_BUILDERS[fmt](_FIFO_TAR))
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    argv = ["extract", "--hide-progress", str(fifo)]
    assert _main_on_fifo(fifo, argv) == EXIT_OK
    assert (work / "pipe" / "a.txt").read_bytes() == b"hello"
    assert (work / "pipe" / "b" / "c.txt").read_bytes() == b"see"
    assert sorted(p.name for p in work.iterdir()) == ["pipe"]


@pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is Unix-only")
@pytest.mark.parametrize("verb", ["test", "extract"])
@pytest.mark.parametrize("fmt", sorted(_FIFO_BUILDERS))
def test_no_match_pattern_on_a_tar_or_zip_fifo_fails(
    tmp_path: Path,
    named_fifo_with_writer: Callable[[Path, bytes], None],
    capsys: pytest.CaptureFixture[str],
    verb: str,
    fmt: str,
) -> None:
    """A forward-only reader has no member list to check a pattern against before the
    pass, so the empty selection is reported after it.
    """
    fifo = tmp_path / f"pipe.{fmt}"
    named_fifo_with_writer(fifo, _FIFO_BUILDERS[fmt](_FIFO_TAR))
    argv = [verb, "--hide-progress", str(fifo)]
    if verb == "extract":
        argv += ["-d", str(tmp_path / "out")]
    argv.append("nomatch*")
    assert _main_on_fifo(fifo, argv) == EXIT_FAIL
    assert "pattern matched no members: 'nomatch*'" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="no /dev/stdin on Windows")
def test_list_reads_a_tar_piped_on_dev_stdin(tmp_path: Path) -> None:
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "archivey", "list", "/dev/stdin"],
        input=_tar_bytes(_FIFO_TAR),
        capture_output=True,
        timeout=60,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == EXIT_OK, result.stderr
    assert b"a.txt" in result.stdout
    assert b"b/c.txt" in result.stdout


def test_link_verify_on_a_streaming_reader_is_a_fail_not_a_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``test`` re-opens a link it could not verify during the pass, which needs a
    random-access reader. No format the CLI streams leaves such a link today; if one
    does, the usage error from ``open()`` must count as a FAIL.

    A stub reaches the path: every link counts as unverified, and a regular TAR is
    opened in streaming mode as if it were a pipe.
    """
    from archivey.cli import common

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        member = tarfile.TarInfo("a.txt")
        member.size = 5
        tf.addfile(member, io.BytesIO(b"hello"))
        link = tarfile.TarInfo("l")
        link.type = tarfile.SYMTYPE
        link.linkname = "a.txt"
        tf.addfile(link)
    archive = tmp_path / "links.tar"
    archive.write_bytes(buf.getvalue())

    monkeypatch.setattr(common, "is_read_once", lambda _path: True)
    monkeypatch.setattr(
        test_cmd,
        "_link_needs_verification",
        lambda m: m.type is MemberType.SYMLINK,
    )
    assert main(["test", "--hide-progress", str(archive)]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "FAIL l:" in err
    assert "1 OK, 1 failed" in err


def test_can_reread_skips_only_read_once_paths(tmp_path: Path) -> None:
    """The fallback detection runs on anything but a FIFO, char device or socket.

    A block device rereads the same bytes, so it stays eligible; the case needs root and
    is not in the suite, so the predicate is pinned directly here.
    """
    regular = tmp_path / "a.zip"
    regular.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    assert _can_reread(str(regular))
    assert _can_reread(str(tmp_path))
    assert not _can_reread(str(tmp_path / "missing"))
    if os.path.exists(os.devnull) and stat.S_ISCHR(os.stat(os.devnull).st_mode):
        assert not _can_reread(os.devnull)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_can_reread_rejects_a_fifo(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert not _can_reread(str(fifo))


def test_info_on_a_directory_reports_the_directory_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`info <dir>` works: detect_format answers DIRECTORY, as open_archive reads it."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.txt").write_bytes(b"hello")
    assert main(["info", str(tree)]) == EXIT_OK
    captured = capsys.readouterr()
    assert "directory" in captured.out
    assert "cannot open" not in captured.err
    assert "password" not in captured.err


def test_default_run_on_tar_prints_no_password_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI's own provider is not a password the user supplied."""
    import tarfile

    path = tmp_path / "a.tar"
    with tarfile.open(path, mode="w") as tar:
        info = tarfile.TarInfo("a.txt")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"hello"))
    assert main(["list", str(path)]) == EXIT_OK
    assert "password" not in capsys.readouterr().err


def test_info_verbose_prints_cost_axes(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["info", "-v", str(sample_zip)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "access:      random (indexed)" in out
    assert "listing:     indexed" in out
    assert "access_cost: direct" in out
    assert "stream:      seekable" in out


def test_info_access_solid_for_tar_gz(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import gzip
    import io
    import tarfile

    tar_path = tmp_path / "a.tar"
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo("hello.txt")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"hello"))
    gz_path = tmp_path / "a.tar.gz"
    gz_path.write_bytes(gzip.compress(tar_path.read_bytes()))

    assert main(["info", str(gz_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "access:      solid (" in out
    assert "listing requires decompression" in out


def test_info_track_io_is_explicit_na(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["info", str(sample_zip), "--track-io"]) == EXIT_OK
    err = capsys.readouterr().err
    assert "track-io: n/a" in err


def test_extract_reports_renames(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    z = _zip(tmp_path / "c.zip", {"a.txt": b"new"})
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "a.txt").write_bytes(b"old")
    assert (
        main(
            [
                "extract",
                str(z),
                "-d",
                str(dest),
                "--overwrite",
                "rename",
            ]
        )
        == EXIT_OK
    )
    err = capsys.readouterr().err
    assert "renamed:" in err
    assert "extracted," in err and "renamed," in err
    assert (dest / "a.txt").read_bytes() == b"old"
    # Library rename spelling: "a (1).txt"
    assert any(p.name.startswith("a (") for p in dest.iterdir())


def test_extract_reports_a_renamed_directory_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One directory renamed around a file is one rename, however much it holds.

    Every member inside the directory follows it and so reports
    ``requested_path != path``; the CLI used to print a ``renamed:`` line for each and
    count them all, so one rename read as a dozen.
    """
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("dd/", b"")
        for i in range(3):
            zf.writestr(f"dd/f{i}", b"x")
        zf.writestr("dd/s/", b"")
        zf.writestr("dd/s/g", b"y")
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "dd").write_bytes(b"callers")
    assert (
        main(["extract", str(z), "-d", str(dest), "--overwrite", "rename"]) == EXIT_OK
    )
    err = capsys.readouterr().err
    assert _report_lines(err, "renamed:") == ["renamed: dd -> dd (1)"]
    assert "6 extracted, 1 renamed, 0 skipped" in err
    assert (dest / "dd (1)" / "s" / "g").read_bytes() == b"y"


def test_extract_reports_a_renamed_implied_directory_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """As ``test_extract_reports_a_renamed_directory_once``, with no ``dd/`` entry:
    the members imply ``dd``, which is renamed around the file all the same, and no
    result carries that rename. It is still one rename."""
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for i in range(3):
            zf.writestr(f"dd/f{i}", b"x")
        zf.writestr("dd/s/g", b"y")
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "dd").write_bytes(b"callers")
    assert (
        main(["extract", str(z), "-d", str(dest), "--overwrite", "rename"]) == EXIT_OK
    )
    err = capsys.readouterr().err
    assert _report_lines(err, "renamed:") == ["renamed: dd -> dd (1)"]
    assert "4 extracted, 1 renamed, 0 skipped" in err
    assert (dest / "dd (1)" / "s" / "g").read_bytes() == b"y"


def test_extract_reports_a_renamed_directory_stored_twice_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With the directory entry stored twice, the first copy is superseded and the
    rename is carried by the later one. The members written between the two still
    only moved with the directory, and are not reported as renames."""
    a = tmp_path / "a.tar"
    with tarfile.open(a, "w") as tf:

        def add(name: str, data: bytes | None) -> None:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

        add("dd/", None)
        for i in range(5):
            add(f"dd/f{i}", b"x")
        add("dd/", None)
        add("dd/g", b"y")
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "dd").write_bytes(b"callers")
    assert (
        main(["extract", str(a), "-d", str(dest), "--overwrite", "rename"]) == EXIT_OK
    )
    err = capsys.readouterr().err
    assert _report_lines(err, "renamed:") == ["renamed: dd -> dd (1)"]
    assert "7 extracted, 1 renamed, 1 skipped" in err
    assert (dest / "dd (1)" / "f4").read_bytes() == b"x"


def test_extract_reports_a_rename_inside_a_renamed_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A member that moved with its directory *and* was renamed on its own is still
    reported: only the inherited part of the move is collapsed."""

    def result(
        type_: MemberType, name: str, requested: str, path: str
    ) -> ExtractionResult:
        return ExtractionResult(
            ArchiveMember(type=type_, name=name),
            tmp_path / path,
            ExtractionStatus.EXTRACTED,
            None,
            requested_path=tmp_path / requested,
        )

    report = ExtractionReport(
        results=(
            result(MemberType.DIRECTORY, "dd/", "dd", "dd (1)"),
            result(MemberType.FILE, "dd/a", "dd/a", "dd (1)/a"),
            result(MemberType.FILE, "dd/b", "dd/b", "dd (1)/b (1)"),
            # An anti-item deletes what an earlier member wrote; where it deleted is
            # not a rename, though it followed the directory too.
            result(MemberType.ANTI, "dd/a", "dd/a", "dd (1)/a"),
        ),
        diagnostics=DiagnosticSummary.empty(),
    )
    err = io.StringIO()
    _report_extraction(report, target=tmp_path, verbose=False, err=err)
    assert _report_lines(err.getvalue(), "renamed:") == [
        "renamed: dd -> dd (1)",
        "renamed: dd/b -> dd (1)/b (1)",
    ]
    assert "4 extracted, 2 renamed, 0 skipped" in err.getvalue()


def test_extract_verbose_lists_members(
    sample_zip: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "out"
    assert main(["-v", "extract", str(sample_zip), "-d", str(dest)]) == EXIT_OK
    err = capsys.readouterr().err
    assert "extracted: a.txt" in err
    assert "→" in err


def test_list_missing_archive(tmp_path: Path) -> None:
    assert main(["list", str(tmp_path / "missing.zip")]) == EXIT_FAIL


def test_cli_list_unencrypted_format_without_password(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Regression: the CLI used to always pass a PasswordProvider (TTY getpass
    # fallback). Formats with SUPPORTS_PASSWORD=False (TAR, ISO, …) rejected that as
    # "does not support passwords" even when the user never passed --password.
    import tarfile

    src = tmp_path / "plain.tar"
    with tarfile.open(src, "w") as t:
        info = tarfile.TarInfo("hello.txt")
        info.size = 5
        t.addfile(info, io.BytesIO(b"hello"))

    assert main([str(src)]) == EXIT_OK
    assert "hello.txt" in capsys.readouterr().out


def test_c_is_not_integrity_alias(sample_zip: Path) -> None:
    # Integrity check is `test`/`t`; letter `c` is reserved for future `create`.
    from archivey.cli.main import _grammar

    assert "c" not in _grammar().verbs
    assert main(["t", str(sample_zip)]) == EXIT_OK
    assert main(["create", str(sample_zip)]) == EXIT_USAGE


def test_no_tqdm_progress_still_extracts(
    sample_zip: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Patch where extract_cmd looks up the helper (import-by-name binding).
    import archivey.cli.extract_cmd as extract_mod

    monkeypatch.setattr(extract_mod, "make_progress_callback", lambda **_: None)
    dest = tmp_path / "out"
    assert main(["extract", str(sample_zip), "-d", str(dest)]) == EXIT_OK
    assert (dest / "a.txt").exists()


def test_progress_callback_requires_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    from archivey.cli import progress as progress_mod

    class _NonTTY(io.StringIO):
        def isatty(self) -> bool:  # match TextIO API
            return False

    monkeypatch.setattr(progress_mod.sys, "__stderr__", _NonTTY())
    assert (
        progress_mod.make_progress_callback(hide_progress=False, stream=_NonTTY())
        is None
    )


def test_progress_callback_on_tty_updates_bar(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import types

    from archivey.cli import progress as progress_mod
    from archivey.types import ArchiveMember, ExtractionProgress, MemberType

    class _TTY(io.StringIO):
        def isatty(self) -> bool:
            return True

    created: list[object] = []

    class _FakeBar:
        def __init__(self, **kwargs: object) -> None:
            created.append(kwargs)
            self.n = 0
            self.total = kwargs.get("total")
            self.desc = kwargs.get("desc")
            self.closed = False

        def set_description(self, desc: str, refresh: bool = True) -> None:
            self.desc = desc

        def update(self, n: int) -> None:
            self.n += n

        def refresh(self) -> None:
            pass

        def close(self) -> None:
            self.closed = True

    def _fake_tqdm(**kwargs: object) -> _FakeBar:
        return _FakeBar(**kwargs)

    # Inject a fake tqdm so this runs in core-only (no real tqdm installed).
    fake_mod = types.ModuleType("tqdm")
    fake_mod.tqdm = _fake_tqdm  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "tqdm", fake_mod)

    cb = progress_mod.make_progress_callback(hide_progress=False, stream=_TTY())
    assert cb is not None

    member = ArchiveMember(type=MemberType.FILE, name="big.bin", size=100)
    cb(
        ExtractionProgress(
            member=member,
            bytes_written=40,
            total_bytes_estimated=100,
            members_done=0,
            members_total=1,
            member_bytes_written=40,
            members_extracted=0,
            members_blocked=0,
        )
    )
    cb(
        ExtractionProgress(
            member=member,
            bytes_written=100,
            total_bytes_estimated=100,
            members_done=1,
            members_total=1,
            member_bytes_written=100,
            members_extracted=1,
            members_blocked=0,
        )
    )
    assert len(created) == 1
    assert created[0]["mininterval"] == 0  # type: ignore[index]
    assert created[0]["disable"] is False  # type: ignore[index]


def test_progress_callback_without_tqdm_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    from archivey.cli import progress as progress_mod

    class _TTY(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setitem(sys.modules, "tqdm", None)  # type: ignore[arg-type]
    assert (
        progress_mod.make_progress_callback(hide_progress=False, stream=_TTY()) is None
    )


def test_track_io_reports(sample_zip: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["test", str(sample_zip), "--track-io"]) == EXIT_OK
    err = capsys.readouterr().err
    assert "track-io:" in err
    assert "bytes_decompressed=" in err


def test_test_open_failure_still_prints_summary(
    sample_zip: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Open-time failures must count as FAIL and still reach the summary (F4).
    # Indexed archives also report untested remainder (P8).
    from archivey.exceptions import ReadError
    from archivey.internal.base_reader import BaseArchiveReader

    def _immediate(self: BaseArchiveReader, members: object = None) -> object:
        raise ReadError("simulated open failure")
        yield  # pragma: no cover — make this a generator

    monkeypatch.setattr(BaseArchiveReader, "stream_members", _as_pass(_immediate))
    assert main(["test", str(sample_zip)]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "FAIL:" in err
    # sample_zip has 3 file members; archive-wide FAIL consumes one slot.
    assert "0 OK, 1 failed, 2 not tested" in err


@pytest.mark.parametrize(("mode", "suffix"), [("w:gz", ".tar.gz"), ("w", ".tar")])
def test_test_counts_a_truncated_tar_member_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, suffix: str
) -> None:
    """A TAR cut in half fails one member. The TAR pass then raises the same fault
    again as it ends (the same object for a compressed TAR, an equal new one for a
    plain TAR); that is the pass stopping, not a second failure."""
    import random

    rng = random.Random(0)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for i in range(5):
            data = rng.randbytes(200_000)
            info = tarfile.TarInfo(f"f{i}.bin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    full = buf.getvalue()
    archive = tmp_path / f"trunc{suffix}"
    archive.write_bytes(full[: len(full) // 2])

    assert main(["test", "--hide-progress", str(archive)]) == EXIT_FAIL
    lines = capsys.readouterr().err.splitlines()
    fails = [ln for ln in lines if ln.startswith("FAIL")]
    assert len(fails) == 1
    assert fails[0].startswith("FAIL f2.bin: ")
    assert "test stopped; remaining members were not tested" in lines
    # The pass-end error repeats the member's fault, so its detail is not printed again.
    assert not [ln for ln in lines if ln.startswith("archivey: ")]
    assert lines[-1] == "2 OK, 1 failed"


def test_test_prints_a_different_pass_end_fault_without_counting_it(
    sample_zip: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pass that ends right after a failed member read, on a fault the member did not
    report, prints that fault's detail and the stop notice, and counts one failure."""
    from archivey.exceptions import ReadError
    from archivey.internal.base_reader import BaseArchiveReader

    real = BaseArchiveReader.stream_members

    class _Failing(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            raise ReadError("member fault")

    def _fail_then_end(self: BaseArchiveReader, members: object = None) -> object:
        for member, stream in real(self, members):  # type: ignore[arg-type]
            if stream is None:
                continue
            stream.close()
            yield member, _Failing()
            raise ReadError("a different fault")

    monkeypatch.setattr(BaseArchiveReader, "stream_members", _as_pass(_fail_then_end))
    assert main(["test", "--hide-progress", str(sample_zip)]) == EXIT_FAIL
    lines = capsys.readouterr().err.splitlines()
    assert len([ln for ln in lines if ln.startswith("FAIL")]) == 1
    assert "archivey: a different fault" in lines
    assert "test stopped; remaining members were not tested" in lines
    assert lines[-1] == "0 OK, 1 failed, 2 not tested"


def test_test_early_abort_reports_not_tested(
    sample_zip: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After one OK, a poisoned stream leaves remaining indexed files as not tested."""
    from archivey.exceptions import ReadError
    from archivey.internal.base_reader import BaseArchiveReader

    real = BaseArchiveReader.stream_members

    def _one_then_die(self: BaseArchiveReader, members: object = None) -> object:
        yielded = False
        for item in real(self, members):
            if yielded:
                raise ReadError("simulated mid-pass failure")
            yielded = True
            yield item

    monkeypatch.setattr(BaseArchiveReader, "stream_members", _as_pass(_one_then_die))
    assert main(["test", str(sample_zip)]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "1 OK, 1 failed, 1 not tested" in err


class _StderrFailingAtFirstOk(io.StringIO):
    """A stderr that raises ``exc`` when the first ``OK`` line is written: once, as
    Ctrl-C arrives, or on that write and every later one, as a closed pipe does.
    """

    def __init__(self, exc: BaseException, *, every_later_write: bool) -> None:
        super().__init__()
        self._exc = exc
        self._every_later_write = every_later_write
        self._failed = False

    @property
    def failed(self) -> bool:
        """Whether the injected error has been raised."""
        return self._failed

    def write(self, s: str) -> int:
        if (s.startswith("OK   ") and not self._failed) or (
            self._failed and self._every_later_write
        ):
            self._failed = True
            raise self._exc
        return super().write(s)


def test_test_ctrl_c_mid_pass_exits_interrupted(sample_zip: Path) -> None:
    """Ctrl-C during the read pass ends as ``interrupted`` and 130, as in ``extract``.

    The interrupt leaves the loop while the member pass is suspended between members;
    that pass must not then stop the reader from closing.
    """
    err = _StderrFailingAtFirstOk(KeyboardInterrupt(), every_later_write=False)
    assert main(["test", "-v", str(sample_zip)], err=err) == EXIT_INTERRUPTED
    assert "interrupted" in err.getvalue()
    assert "Cannot close the archive reader" not in err.getvalue()


def test_extract_ctrl_c_mid_pass_exits_interrupted(
    sample_zip: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ctrl-C during the extraction pass ends as ``interrupted`` and 130.

    The progress callback runs inside the extraction loop while the member pass is
    suspended, so an interrupt raised there must not leave that pass blocking the
    reader's close.
    """
    import archivey.cli.extract_cmd as extract_mod

    class _InterruptingProgress:
        calls = 0

        def __call__(self, progress: object) -> None:
            self.calls += 1
            raise KeyboardInterrupt

        def close(self) -> None:
            pass

    progress = _InterruptingProgress()
    monkeypatch.setattr(extract_mod, "make_progress_callback", lambda **_: progress)
    dest = tmp_path / "out"
    assert main(["extract", str(sample_zip), "-d", str(dest)]) == EXIT_INTERRUPTED
    assert progress.calls == 1
    assert "interrupted" in capsys.readouterr().err


def test_test_closed_stderr_pipe_mid_pass_exits_broken_pipe(
    sample_zip: Path,
) -> None:
    """A stderr pipe closed during the pass gets the broken-pipe exit, not a usage
    error about closing the reader while its member pass is active, and not 0: the
    archive was only partly verified.
    """
    err = _StderrFailingAtFirstOk(
        BrokenPipeError(32, "Broken pipe"), every_later_write=True
    )
    assert main(["test", "-v", str(sample_zip)], err=err) == EXIT_BROKEN_PIPE
    # The pipe did close mid-pass: without this, a clean run passes the test too.
    assert err.failed


class _ProgressPipeClosed:
    """A progress bar whose stream lost its reader: its first update raises."""

    calls = 0

    def __call__(self, progress: object) -> None:
        self.calls += 1
        raise BrokenPipeError(32, "Broken pipe")

    def close(self) -> None:
        pass


@pytest.mark.parametrize("verb", ["test", "extract"])
def test_progress_pipe_closed_mid_pass_exits_141(
    sample_zip: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verb: str
) -> None:
    """A broken pipe raised inside the member pass is not a member failure.

    ``test`` and ``extract`` each catch ``OSError`` around the pass to report a
    failed member; a ``BrokenPipeError`` must pass through that to ``main()``. The
    report stream here stays open, so a handler that swallowed it would print a
    failure and exit 1 rather than fail again on the closed pipe.
    """
    from archivey.cli import extract_cmd

    module = test_cmd if verb == "test" else extract_cmd
    progress = _ProgressPipeClosed()
    monkeypatch.setattr(module, "make_progress_callback", lambda **_: progress)
    argv = [verb, str(sample_zip)]
    if verb == "extract":
        argv += ["-d", str(tmp_path / "out")]
    err = io.StringIO()
    assert main(argv, out=io.StringIO(), err=err) == EXIT_BROKEN_PIPE
    assert progress.calls == 1
    assert err.getvalue() == ""


class _ClosedPipeStdout(io.StringIO):
    """A stdout whose every write raises ``BrokenPipeError``, as a closed pipe does."""

    def __init__(self) -> None:
        super().__init__()
        self.writes = 0

    def write(self, s: str) -> int:
        self.writes += 1
        raise BrokenPipeError(32, "Broken pipe")


@pytest.mark.parametrize("verb", ["list", "info"])
def test_closed_stdout_pipe_exits_broken_pipe(sample_zip: Path, verb: str) -> None:
    """A verb whose stdout pipe closes exits 141 (128 + SIGPIPE), quietly."""
    out = _ClosedPipeStdout()
    err = io.StringIO()
    assert main([verb, str(sample_zip)], out=out, err=err) == EXIT_BROKEN_PIPE
    assert out.writes >= 1
    assert err.getvalue() == ""


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX only: test_reader_leaving_mid_output_exits_141 is the Windows check",
)
@pytest.mark.parametrize(
    ("closed", "argv"),
    [
        ("stdout", ["list"]),
        ("stderr", ["test", "-v"]),
        ("stderr", ["test"]),
        ("stderr", ["extract", "-v", "-d", "out"]),
    ],
)
@pytest.mark.parametrize("members", [1, 2000])
def test_closed_pipe_subprocess_exits_141_without_traceback(
    tmp_path: Path, closed: str, argv: list[str], members: int
) -> None:
    """``archivey list x | head`` and ``archivey test x 2>&1 | head`` exit 141.

    The pipe's read end is closed before the process starts, so the first write that
    reaches it fails, deterministically. With 2000 members that is a write in the
    middle of the pass; with one member it is the flush as the process ends. The
    other stream is captured: it must hold no traceback and no "Exception ignored".
    """
    import subprocess

    archive = _zip(
        tmp_path / "many.zip", {f"m{i:05d}.txt": b"x" for i in range(members)}
    )
    read_end, write_end = os.pipe()
    os.close(read_end)
    try:
        if closed == "stdout":
            streams = {"stdout": write_end, "stderr": subprocess.PIPE}
        else:
            streams = {"stdout": subprocess.PIPE, "stderr": write_end}
        proc = subprocess.run(
            [sys.executable, "-m", "archivey", *argv, str(archive)],
            check=False,
            cwd=tmp_path,
            **streams,
        )
    finally:
        os.close(write_end)
    other = proc.stderr if closed == "stdout" else proc.stdout
    assert proc.returncode == EXIT_BROKEN_PIPE, other
    _assert_no_pipe_noise(other)


def _assert_no_pipe_noise(output: bytes) -> None:
    assert b"Traceback" not in output
    assert b"Exception ignored" not in output
    assert b"Broken pipe" not in output


@pytest.mark.parametrize(
    ("closed", "argv"),
    [
        ("stdout", ["list"]),
        ("stderr", ["test", "-v"]),
        ("stderr", ["extract", "-v", "-d", "out"]),
    ],
)
def test_reader_leaving_mid_output_exits_141(
    tmp_path: Path, closed: str, argv: list[str]
) -> None:
    """``archivey list x | head -1``: the reader takes one line, then closes its end.

    Nothing is closed before the child starts, so this runs on Windows too, where a
    write to a pipe whose reader has gone fails with ERROR_NO_DATA and CPython raises
    ``OSError(EINVAL)`` for it, not ``BrokenPipeError``. The child has more to write
    than a pipe holds, so it is blocked on a write, not finished, when the reader
    leaves. On failure the message also shows what a plain write to such a pipe
    raises on this platform.
    """
    import subprocess

    archive = _zip(tmp_path / "many.zip", {f"m{i:05d}.txt": b"x" for i in range(10000)})
    other_path = tmp_path / "other.txt"
    with other_path.open("wb") as other_file:
        proc = subprocess.Popen(
            [sys.executable, "-m", "archivey", *argv, str(archive)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if closed == "stdout" else other_file,
            stderr=subprocess.PIPE if closed == "stderr" else other_file,
            cwd=tmp_path,
        )
        reader = proc.stdout if closed == "stdout" else proc.stderr
        assert reader is not None
        first = reader.readline()
        reader.close()
        returncode = proc.wait(timeout=120)
    other = other_path.read_bytes()
    assert first, other
    if returncode != EXIT_BROKEN_PIPE:
        pytest.fail(
            f"exit {returncode}, other stream {other!r}; "
            f"a plain write to a pipe whose reader left raises {_dead_pipe_probe()}"
        )
    _assert_no_pipe_noise(other)


_DEAD_PIPE_PROBE = """
import sys
try:
    while True:
        sys.stdout.write("x" * 4096 + "\\n")
        sys.stdout.flush()
except OSError as exc:
    sys.stderr.write(
        f"{type(exc).__name__} errno={exc.errno} "
        f"winerror={getattr(exc, 'winerror', None)} {exc.strerror!r}"
    )
"""


def _dead_pipe_probe() -> str:
    """What this platform raises when a pipe's reader leaves mid-write (diagnostic)."""
    import subprocess

    proc = subprocess.Popen(
        [sys.executable, "-c", _DEAD_PIPE_PROBE],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    proc.stdout.readline()
    proc.stdout.close()
    _, probe_err = proc.communicate(timeout=60)
    return probe_err.decode(errors="replace")


@pytest.mark.parametrize(
    ("exc", "on_windows", "off_windows"),
    [
        (BrokenPipeError(errno.EPIPE, "Broken pipe"), True, True),
        # What CPython raises on Windows for ERROR_NO_DATA: EINVAL, no winerror.
        (OSError(errno.EINVAL, "Invalid argument"), True, False),
        (OSError(errno.ENOSPC, "No space left on device"), False, False),
    ],
)
def test_is_dead_pipe_reads_windows_einval_as_a_closed_pipe(
    monkeypatch: pytest.MonkeyPatch, exc: OSError, on_windows: bool, off_windows: bool
) -> None:
    from archivey.cli.main import _is_dead_pipe

    monkeypatch.setattr(sys, "platform", "linux")
    assert _is_dead_pipe(exc) is off_windows
    monkeypatch.setattr(sys, "platform", "win32")
    assert _is_dead_pipe(exc) is on_windows


@pytest.mark.parametrize("winerror", [109, 232])
def test_is_dead_pipe_matches_windows_pipe_winerrors(
    monkeypatch: pytest.MonkeyPatch, winerror: int
) -> None:
    from archivey.cli.main import _is_dead_pipe

    # On POSIX the constructor ignores a fourth (winerror) argument, so set it.
    exc = OSError(errno.EIO, "I/O error")
    exc.winerror = winerror  # type: ignore[attr-defined]
    monkeypatch.setattr(sys, "platform", "linux")
    assert not _is_dead_pipe(exc)
    monkeypatch.setattr(sys, "platform", "win32")
    assert _is_dead_pipe(exc)


class _EinvalStream(io.StringIO):
    """A stream that fails as a Windows pipe does once its reader has gone."""

    def __init__(self, *, at_flush: bool) -> None:
        super().__init__()
        self.at_flush = at_flush

    def write(self, s: str) -> int:
        if not self.at_flush:
            raise OSError(errno.EINVAL, "Invalid argument")
        return super().write(s)

    def flush(self) -> None:
        raise OSError(errno.EINVAL, "Invalid argument")


@pytest.mark.parametrize("closed", ["out", "err"])
@pytest.mark.parametrize("at_flush", [False, True])
def test_windows_einval_on_output_exits_141(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    closed: str,
    at_flush: bool,
) -> None:
    """On Windows, ``EINVAL`` from the CLI's own output stream is a closed pipe."""
    from archivey.cli import main as main_mod

    monkeypatch.setattr(main_mod, "_silence_dead_streams", lambda: None)
    monkeypatch.setattr(sys, "platform", "win32")
    dead = _EinvalStream(at_flush=at_flush)
    streams = {"out": io.StringIO(), "err": io.StringIO(), closed: dead}
    # A missing archive writes to err; list of a real one writes to out.
    archive = tmp_path / ("a.zip" if closed == "out" else "missing.zip")
    if closed == "out":
        _zip(archive, {"a.txt": b"a"})
    assert main(["list", str(archive)], **streams) == EXIT_BROKEN_PIPE


def test_einval_on_output_is_not_a_closed_pipe_off_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    archive = _zip(tmp_path / "a.zip", {"a.txt": b"a"})
    err = io.StringIO()
    out = _EinvalStream(at_flush=False)
    assert main(["list", str(archive)], out=out, err=err) == EXIT_FAIL
    assert "Invalid argument" in err.getvalue()


class _FullDiskAtFlush(io.StringIO):
    """A stream redirected to a full disk: writes are buffered, the flush fails."""

    def flush(self) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")


def test_final_flush_os_error_prints_message_and_exits_1(tmp_path: Path) -> None:
    """A full disk at the final flush: ``main`` prints one line and returns 1.

    This checks the return value only. The real process, where the exit flush
    could fail again, is ``test_full_disk_on_stdout_exits_1_with_one_line``.
    """
    archive = _zip(tmp_path / "a.zip", {"a.txt": b"a"})
    err = io.StringIO()
    assert main(["list", str(archive)], out=_FullDiskAtFlush(), err=err) == EXIT_FAIL
    assert err.getvalue() == "archivey: No space left on device\n"


@pytest.mark.skipif(not os.path.exists("/dev/full"), reason="needs /dev/full")
def test_full_disk_on_stdout_exits_1_with_one_line(tmp_path: Path) -> None:
    """``archivey list x > /dev/full`` as a real process: one line, exit 1.

    Output still buffered for stdout when ``main`` returns would fail again in the
    interpreter's exit flush, which prints "Exception ignored" and exits 120, so
    ``main`` points a stream that cannot flush at the null device first.

    One member and a buffered stdout keep all the output in the buffer until
    ``main``'s final flush, so the error reaches ``main``'s ``except OSError`` arm.
    A larger archive or ``PYTHONUNBUFFERED`` fails inside the verb instead, and
    then nothing is left for the exit flush to fail on.
    """
    import subprocess

    archive = _zip(tmp_path / "a.zip", {"a.txt": b"a"})
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
    with open("/dev/full", "wb") as full:
        proc = subprocess.run(
            [sys.executable, "-m", "archivey", "list", str(archive)],
            stdin=subprocess.DEVNULL,
            stdout=full,
            stderr=subprocess.PIPE,
            cwd=tmp_path,
            env=env,
            timeout=120,
            check=False,
        )
    stderr = proc.stderr.decode(errors="replace")
    assert proc.returncode == EXIT_FAIL, stderr
    assert "Exception ignored" not in stderr
    assert stderr.splitlines() == ["archivey: No space left on device"]


def test_final_flush_interrupted_exits_130(tmp_path: Path) -> None:
    """Ctrl-C during the final flush: ``main`` returns 130 and prints "interrupted".

    This checks the return value only. A real stream that was interrupted still
    works, so the interpreter's exit flush writes what is left and the process
    exits with that code.
    """

    class _InterruptedAtFlush(io.StringIO):
        def flush(self) -> None:
            raise KeyboardInterrupt

    archive = _zip(tmp_path / "a.zip", {"a.txt": b"a"})
    err = io.StringIO()
    out = _InterruptedAtFlush()
    assert main(["list", str(archive)], out=out, err=err) == EXIT_INTERRUPTED
    assert err.getvalue() == "interrupted\n"


def test_lost_log_record_exits_141(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A warning logged to a closed stderr still exits 141.

    logging's StreamHandler swallows the write error itself, so only main()'s final
    flush sees the closed pipe. The zip's end record declares more entries than its
    central directory holds, which ``list`` reports as a warning.
    """
    import logging

    from archivey.cli import main as main_mod

    monkeypatch.setattr(main_mod, "_silence_dead_streams", lambda: None)
    # Off, as for a process whose stderr is gone: handleError writes nowhere.
    monkeypatch.setattr(logging, "raiseExceptions", False)
    archive = _zip(tmp_path / "a.zip", {f"m{i}.txt": b"x" for i in range(3)})
    data = bytearray(archive.read_bytes())
    eocd = data.rindex(b"PK\x05\x06")
    data[eocd + 8 : eocd + 12] = (7).to_bytes(2, "little") * 2
    archive.write_bytes(bytes(data))
    err = _PipeClosedAtFlush()
    out = io.StringIO()
    assert main(["list", str(archive)], out=out, err=err) == EXIT_BROKEN_PIPE
    # The record did reach the stream: the flush, not a print, raised.
    assert err.getvalue()


class _PipeClosedAtFlush(io.StringIO):
    """A block-buffered pipe whose reader left: writes land, the flush fails."""

    def flush(self) -> None:
        raise BrokenPipeError(32, "Broken pipe")


@pytest.mark.parametrize("stream_cls", [_ClosedPipeStdout, _PipeClosedAtFlush])
@pytest.mark.parametrize(
    ("argv", "closed"),
    [
        (["--help"], "stdout"),
        (["--version"], "stdout"),
        (["list", "--help"], "stdout"),
        (["extract", "-o", "x", "a.zip"], "stderr"),
        (["list"], "stderr"),
    ],
)
def test_help_and_usage_to_closed_pipe_exit_141(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    closed: str,
    stream_cls: type[io.StringIO],
) -> None:
    """argparse writes help and usage to the process streams and drops an OSError
    from that write. A closed pipe there is still 141, so a usage error whose message
    was lost is not reported as 2.
    """
    dead = stream_cls()
    monkeypatch.setattr(sys, closed, dead)
    assert main(argv) == EXIT_BROKEN_PIPE


@pytest.mark.parametrize("stream_cls", [_ClosedPipeStdout, _PipeClosedAtFlush])
def test_no_arguments_help_to_closed_stderr_exits_141(
    stream_cls: type[io.StringIO],
) -> None:
    assert main([], err=stream_cls()) == EXIT_BROKEN_PIPE


def test_error_message_to_closed_stderr_exits_141(tmp_path: Path) -> None:
    """main()'s own error report (here a missing archive) to a closed pipe: 141."""
    assert (
        main(["list", str(tmp_path / "missing.zip")], err=_ClosedPipeStdout())
        == EXIT_BROKEN_PIPE
    )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX only: the in-process tests above cover the same paths everywhere",
)
@pytest.mark.parametrize("unbuffered", ["", "1"])
@pytest.mark.parametrize(
    ("closed", "argv", "code_if_open"),
    [
        ("stdout", ["--help"], EXIT_OK),
        ("stderr", ["extract", "-o", "x", "a.zip"], EXIT_USAGE),
        ("stderr", [], EXIT_USAGE),
        ("stderr", ["list", "missing.zip"], EXIT_FAIL),
    ],
)
def test_help_and_usage_subprocess_closed_pipe_exits_141(
    tmp_path: Path,
    closed: str,
    argv: list[str],
    code_if_open: int,
    unbuffered: str,
) -> None:
    """``archivey --help | true`` exits 141, buffered or not (``PYTHONUNBUFFERED``).

    Buffered, the write that fails is the flush; unbuffered, it is argparse's own
    write. The control run with the pipe open pins that each case does write.
    """
    import subprocess

    env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
    if unbuffered:
        env["PYTHONUNBUFFERED"] = unbuffered
    cmd = [sys.executable, "-m", "archivey", *argv]
    control = subprocess.run(
        cmd, check=False, cwd=tmp_path, env=env, capture_output=True
    )
    assert control.returncode == code_if_open
    assert getattr(control, closed)
    read_end, write_end = os.pipe()
    os.close(read_end)
    try:
        streams = (
            {"stdout": write_end, "stderr": subprocess.PIPE}
            if closed == "stdout"
            else {"stdout": subprocess.PIPE, "stderr": write_end}
        )
        proc = subprocess.run(cmd, check=False, cwd=tmp_path, env=env, **streams)
    finally:
        os.close(write_end)
    other = proc.stderr if closed == "stdout" else proc.stdout
    assert proc.returncode == EXIT_BROKEN_PIPE, other
    _assert_no_pipe_noise(other)


def test_test_summary_helper() -> None:
    from archivey.cli.test_cmd import _test_summary

    assert _test_summary(ok=4, failed=0, members_total=4) == "4 OK, 0 failed"
    assert (
        _test_summary(ok=0, failed=1, members_total=4) == "0 OK, 1 failed, 3 not tested"
    )
    assert _test_summary(ok=0, failed=1, members_total=None) == "0 OK, 1 failed"
    assert (
        _test_summary(ok=1, failed=0, members_total=1, not_verified=1)
        == "1 OK, 0 failed, 1 not verified"
    )
    assert (
        _test_summary(ok=0, failed=1, members_total=3, not_verified=2)
        == "0 OK, 1 failed, 2 not tested, 2 not verified"
    )


def test_archive_stem_uses_format_extension() -> None:
    from archivey.cli.extract_cmd import _archive_stem
    from archivey.types import ArchiveFormat, ContainerFormat, StreamFormat

    assert _archive_stem(Path("photos.tar.gz"), format=ArchiveFormat.TAR_GZ) == "photos"
    assert _archive_stem(Path(".tar.gz"), format=ArchiveFormat.TAR_GZ) == "archive"
    # "." and ".." are not usable folder names: they would splatter into the cwd or
    # write into the parent directory.
    assert _archive_stem(Path("..zip"), format=ArchiveFormat.ZIP) == "archive"
    assert _archive_stem(Path("...zip"), format=ArchiveFormat.ZIP) == "archive"
    assert _archive_stem(Path("...tar.gz"), format=ArchiveFormat.TAR_GZ) == "archive"
    # The suffix-stripping fallback (name does not end in the format's extension).
    assert _archive_stem(Path("...bin"), format=ArchiveFormat.ZIP) == "archive"
    assert _archive_stem(Path("..bin"), format=ArchiveFormat.ZIP) == "archive"
    tar_z = ArchiveFormat(ContainerFormat.TAR, StreamFormat.UNIX_COMPRESS)
    assert _archive_stem(Path("data.tar.Z"), format=tar_z) == "data"


def test_smart_dest_uses_filtered_tops_when_indexed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Indexed ZIP with multi-top archive, but filter selects a single root → cwd.
    monkeypatch.chdir(tmp_path)
    z = _zip(
        tmp_path / "pack.zip",
        {"a/x.txt": b"a", "b/y.txt": b"b", "c/z.txt": b"c"},
    )
    assert main(["extract", str(z), "b/*"]) == EXIT_OK
    assert (tmp_path / "b" / "y.txt").read_bytes() == b"b"
    assert not (tmp_path / "pack").exists()
    assert not (tmp_path / "a").exists()


def test_smart_dest_hoists_single_root_when_no_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Plain TAR has no cheap index — wrap then hoist a single top-level root (R4).
    import tarfile

    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "bundle.tar"
    with tarfile.open(archive, "w") as tf:
        info = tarfile.TarInfo("root/a.txt")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    assert main(["extract", str(archive)]) == EXIT_OK
    err = capsys.readouterr().err
    assert "extracting into bundle/" in err
    assert "moved to root/" in err
    assert (tmp_path / "root" / "a.txt").read_bytes() == b"x"
    assert not (tmp_path / "bundle").exists()


def test_smart_dest_keeps_wrapper_for_multi_top_tar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import tarfile

    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "messy.tar"
    with tarfile.open(archive, "w") as tf:
        for name, data in (("a.txt", b"a"), ("b.txt", b"b")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    assert main(["extract", str(archive)]) == EXIT_OK
    assert (tmp_path / "messy" / "a.txt").read_bytes() == b"a"
    assert (tmp_path / "messy" / "b.txt").read_bytes() == b"b"
    assert not (tmp_path / "a.txt").exists()


def test_password_rejected_message_distinct_from_required() -> None:
    from archivey.exceptions import EncryptionError
    from archivey.internal.password import _PasswordCandidates

    candidates = _PasswordCandidates.from_input("wrong")
    with pytest.raises(EncryptionError, match="rejected") as caught:
        candidates.attempt(
            None,
            lambda _pwd: (_ for _ in ()).throw(EncryptionError("nope")),
        )
    assert "Password required" not in caught.value.message

    empty = _PasswordCandidates.from_input(None)
    with pytest.raises(EncryptionError, match="Password required"):
        empty.attempt(
            None,
            lambda _pwd: (_ for _ in ()).throw(EncryptionError("unreachable")),
        )


def _tar_dirs(path: Path, names: list[str]) -> Path:
    """A TAR of empty directory entries, each with mtime 0."""
    import tarfile

    with tarfile.open(path, "w") as tf:
        for name in names:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tf.addfile(info)
    return path


def _tar(path: Path, entries: dict[str, bytes]) -> Path:
    import tarfile

    with tarfile.open(path, "w") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def test_hoist_root_named_like_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # src.tar containing src/ — the "collision" is the wrapper itself; flatten in
    # place instead of renaming away (H2) or deleting extracted data (H1).
    monkeypatch.chdir(tmp_path)
    archive = _tar(tmp_path / "src.tar", {"src/f.txt": b"data"})
    for overwrite in ("rename", "replace", "error", "skip"):
        assert main(["extract", str(archive), "--overwrite", overwrite]) == EXIT_OK
        err = capsys.readouterr().err
        assert "removed wrapper; content at src/" in err
        assert "moved to src/" not in err
        assert (tmp_path / "src" / "f.txt").read_bytes() == b"data"
        assert not (tmp_path / "src (1)").exists()
        import shutil

        shutil.rmtree(tmp_path / "src")


def test_hoist_single_file_named_like_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # src.tar containing a single top-level FILE named "src".
    monkeypatch.chdir(tmp_path)
    archive = _tar(tmp_path / "src.tar", {"src": b"solo"})
    assert main(["extract", str(archive)]) == EXIT_OK
    assert (tmp_path / "src").read_bytes() == b"solo"
    assert not (tmp_path / "src (1)").exists()


@pytest.mark.parametrize("step", ["rename", "rmdir", "restore"])
def test_hoist_single_file_named_like_wrapper_restores_wrapper_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    step: str,
) -> None:
    # The wrapper steps aside to ``src (1)`` so the file can take its name. When
    # the move or the removal of ``src (1)`` fails, the wrapper is back under its
    # own name, which is the name the failure lines give.
    monkeypatch.chdir(tmp_path)
    archive = _tar(tmp_path / "src.tar", {"src": b"solo"})
    real_rename, real_rmdir = Path.rename, Path.rmdir

    def rename(self: Path, target: str | os.PathLike[str]) -> Path:
        if step == "rename" and self.parent.name == "src (1)":
            raise PermissionError("refused")
        if step == "restore" and Path(target).parent.name == "src (1)":
            # The move back into ``src (1)`` fails as well: a double fault.
            raise PermissionError("restore refused")
        return real_rename(self, target)

    def rmdir(self: Path) -> None:
        if step in ("rmdir", "restore") and self.name == "src (1)":
            raise PermissionError("refused")
        real_rmdir(self)

    monkeypatch.setattr(Path, "rename", rename)
    monkeypatch.setattr(Path, "rmdir", rmdir)
    assert main(["extract", str(archive)]) == EXIT_FAIL
    err = capsys.readouterr().err
    # A failed restore never replaces the error that stopped the hoist.
    assert _report_lines(err, "archivey: hoist failed: ") == [
        "archivey: hoist failed: refused"
    ]
    if step == "restore":
        # The file kept its place in the cwd, so the wrapper's name is taken and
        # ``src (1)`` is left behind empty. The lines name what is on disk.
        assert (tmp_path / "src").read_bytes() == b"solo"
        assert (tmp_path / "src (1)").is_dir()
        assert not any((tmp_path / "src (1)").iterdir())
        assert _report_lines(err, "files left in ") == ["files left in src (1)/"]
        return
    assert _report_lines(err, "files left in ") == ["files left in src/"]
    assert (tmp_path / "src" / "src").read_bytes() == b"solo"
    assert not (tmp_path / "src (1)").exists()


def _tar_with_locked_dirs(path: Path, names: list[str]) -> Path:
    """A tar whose directory members (a trailing ``/``) are stored ``0o555``."""
    with tarfile.open(path, "w") as tf:
        for name in names:
            info = tarfile.TarInfo(name.rstrip("/"))
            if name.endswith("/"):
                info.type = tarfile.DIRTYPE
                info.mode = 0o555
                tf.addfile(info)
            else:
                info.size = 1
                tf.addfile(info, io.BytesIO(b"x"))
    return path


def _refuse_renames_as_non_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``os.rename`` refuse what POSIX refuses a non-root user: moving an entry
    out of or into a directory without owner write, or a directory without owner
    write to another parent (its ``..`` changes). Root skips these checks, and CI may
    run as either."""
    rename = os.rename

    def no_write(path: Path) -> bool:
        st = os.lstat(path)
        return stat.S_ISDIR(st.st_mode) and not st.st_mode & stat.S_IWUSR

    def checked(src: str | Path, dst: str | Path) -> None:
        src, dst = Path(src), Path(dst)
        moves_dir = no_write(src) and src.parent.resolve() != dst.parent.resolve()
        if no_write(src.parent) or no_write(dst.parent) or moves_dir:
            raise PermissionError(13, "Permission denied", str(src))
        rename(src, dst)

    monkeypatch.setattr(os, "rename", checked)


def _unlock(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        if path.is_dir() and not path.is_symlink():
            os.chmod(path, 0o755)


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
@pytest.mark.parametrize("dry_run", [True, False], ids=["dry-run", "real"])
def test_hoist_moves_a_root_stored_without_write_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dry_run: bool
) -> None:
    """The root's stored ``0o555`` is applied when extraction ends, before the hoist
    moves it: the move still succeeds, as the dry run says, and the root keeps the
    mode."""
    monkeypatch.chdir(tmp_path)
    _refuse_renames_as_non_root(monkeypatch)
    archive = _tar_with_locked_dirs(tmp_path / "bundle.tar", ["pkg/", "pkg/a"])
    args = ["extract", str(archive), "--policy", "standard"]
    try:
        assert main([*args, "--dry-run"] if dry_run else args) == EXIT_OK
        if not dry_run:
            assert stat.S_IMODE((tmp_path / "pkg").stat().st_mode) == 0o555
            assert (tmp_path / "pkg" / "a").read_bytes() == b"x"
            assert not (tmp_path / "bundle").exists()
    finally:
        _unlock(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
def test_hoist_merges_a_root_stored_without_write_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Merged into a directory that was there: the entries move out of the locked
    root, and the existing directory keeps its own mode."""
    monkeypatch.chdir(tmp_path)
    _refuse_renames_as_non_root(monkeypatch)
    (tmp_path / "pkg").mkdir(mode=0o750)
    archive = _tar_with_locked_dirs(
        tmp_path / "bundle.tar", ["pkg/", "pkg/a", "pkg/sub/", "pkg/sub/b"]
    )
    try:
        assert main(["extract", str(archive), "--policy", "standard"]) == EXIT_OK
        assert stat.S_IMODE((tmp_path / "pkg").stat().st_mode) == 0o750
        assert stat.S_IMODE((tmp_path / "pkg" / "sub").stat().st_mode) == 0o555
        assert (tmp_path / "pkg" / "sub" / "b").read_bytes() == b"x"
        assert not (tmp_path / "bundle").exists()
    finally:
        _unlock(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
def test_a_failed_hoist_leaves_the_stored_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cwd's own ``pkg`` has no owner write, so the merge cannot move ``sub``
    into it. The hoist fails, and the directories left under the wrapper keep the
    ``0o555`` the archive stored: the hoist opened them up only for the move."""
    monkeypatch.chdir(tmp_path)
    _refuse_renames_as_non_root(monkeypatch)
    (tmp_path / "pkg").mkdir(mode=0o555)
    archive = _tar_with_locked_dirs(
        tmp_path / "bundle.tar", ["pkg/", "pkg/sub/", "pkg/sub/b"]
    )
    try:
        assert main(["extract", str(archive), "--policy", "standard"]) == EXIT_FAIL
        left = tmp_path / "bundle" / "pkg"
        assert stat.S_IMODE(left.stat().st_mode) == 0o555
        assert stat.S_IMODE((left / "sub").stat().st_mode) == 0o555
        assert (left / "sub" / "b").read_bytes() == b"x"
    finally:
        _unlock(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
def test_hoist_renames_a_root_stored_without_write_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _refuse_renames_as_non_root(monkeypatch)
    (tmp_path / "pkg").write_bytes(b"MINE")
    archive = _tar_with_locked_dirs(tmp_path / "bundle.tar", ["pkg/", "pkg/a"])
    try:
        args = ["extract", str(archive), "--policy", "standard", "--overwrite"]
        assert main([*args, "rename"]) == EXIT_OK
        assert stat.S_IMODE((tmp_path / "pkg (1)").stat().st_mode) == 0o555
        assert (tmp_path / "pkg (1)" / "a").read_bytes() == b"x"
    finally:
        _unlock(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
def test_hoist_flattens_a_root_stored_without_write_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``pkg.tar`` holding ``pkg/``: the wrapper takes the root's place, and its
    mode."""
    monkeypatch.chdir(tmp_path)
    _refuse_renames_as_non_root(monkeypatch)
    archive = _tar_with_locked_dirs(
        tmp_path / "pkg.tar", ["pkg/", "pkg/a", "pkg/sub/", "pkg/sub/b"]
    )
    try:
        assert main(["extract", str(archive), "--policy", "standard"]) == EXIT_OK
        assert stat.S_IMODE((tmp_path / "pkg").stat().st_mode) == 0o555
        assert stat.S_IMODE((tmp_path / "pkg" / "sub").stat().st_mode) == 0o555
        assert (tmp_path / "pkg" / "sub" / "b").read_bytes() == b"x"
        assert (tmp_path / "pkg" / "a").read_bytes() == b"x"
    finally:
        _unlock(tmp_path)


def _seed_existing_root(tmp_path: Path) -> None:
    (tmp_path / "root").mkdir()
    (tmp_path / "root" / "keep.txt").write_bytes(b"MINE")
    (tmp_path / "root" / "clash.txt").write_bytes(b"MINE")


def _hoist_collision_archive(tmp_path: Path) -> Path:
    return _tar(
        tmp_path / "bundle.tar",
        {"root/new.txt": b"NEW", "root/clash.txt": b"ARCHIVE"},
    )


def test_hoist_merges_like_direct_extraction_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Equivalence contract: hoisting == extracting directly into cwd. Dirs merge;
    # the colliding file gets the library's "name (1)" treatment; nothing deleted.
    monkeypatch.chdir(tmp_path)
    archive = _hoist_collision_archive(tmp_path)
    _seed_existing_root(tmp_path)
    assert main(["extract", str(archive)]) == EXIT_OK
    root = tmp_path / "root"
    assert (root / "keep.txt").read_bytes() == b"MINE"
    assert (root / "clash.txt").read_bytes() == b"MINE"
    assert (root / "clash (1).txt").read_bytes() == b"ARCHIVE"
    assert (root / "new.txt").read_bytes() == b"NEW"
    assert not (tmp_path / "bundle").exists()
    assert not (tmp_path / "root (1)").exists()


@pytest.mark.parametrize("overwrite", ["error", "skip", "replace"])
def test_hoist_collision_rename_does_not_settle_keeps_the_root_in_the_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overwrite: str,
) -> None:
    """The hoist is a convenience that never replaces or deletes anything in the cwd:
    a collision under any policy but ``rename`` keeps the whole root in the wrapper,
    with nothing moved, and the run succeeds."""
    monkeypatch.chdir(tmp_path)
    archive = _hoist_collision_archive(tmp_path)
    _seed_existing_root(tmp_path)
    assert main(["extract", str(archive), "--overwrite", overwrite]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, "kept in ") == [
        "kept in bundle/: root/clash.txt already exists"
    ]
    assert "Destination already exists" not in err
    assert err.rstrip().endswith("→ bundle/")
    assert (tmp_path / "root" / "clash.txt").read_bytes() == b"MINE"
    # No partial merge: ``new.txt`` stays with the rest of the root.
    assert not (tmp_path / "root" / "new.txt").exists()
    assert (tmp_path / "bundle" / "root" / "clash.txt").read_bytes() == b"ARCHIVE"
    assert (tmp_path / "bundle" / "root" / "new.txt").read_bytes() == b"NEW"


def test_hoist_never_deletes_colliding_tree_under_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Archive member "root/clash" is a FILE; on disk ./root/clash is a DIRECTORY.
    # replace must not rmtree the directory: the root stays in the wrapper.
    monkeypatch.chdir(tmp_path)
    archive = _tar(tmp_path / "bundle.tar", {"root/clash": b"ARCHIVE"})
    (tmp_path / "root" / "clash").mkdir(parents=True)
    (tmp_path / "root" / "clash" / "precious.txt").write_bytes(b"MINE")
    assert main(["extract", str(archive), "--overwrite", "replace"]) == EXIT_OK
    assert (tmp_path / "root" / "clash" / "precious.txt").read_bytes() == b"MINE"
    assert (tmp_path / "bundle" / "root" / "clash").read_bytes() == b"ARCHIVE"


@pytest.mark.parametrize("overwrite", ["error", "skip", "replace"])
def test_indexed_single_root_never_replaces_the_operators_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overwrite: str,
) -> None:
    """An indexed archive whose single root's name is taken in the cwd is extracted
    into a wrapper and hoisted, so ``replace`` cannot replace the operator's file
    ``top`` with the archive's directory ``top/``."""
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "one.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("top/f", b"ARCHIVE")
    (tmp_path / "top").write_bytes(b"MINE")
    assert main(["x", str(archive), "--overwrite", overwrite]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, "kept in ") == ["kept in one/: top already exists"]
    assert err.rstrip().endswith("→ one/")
    assert (tmp_path / "top").read_bytes() == b"MINE"
    assert (tmp_path / "one" / "top" / "f").read_bytes() == b"ARCHIVE"


@pytest.mark.parametrize(
    ("stored", "mine"),
    [("top /f", "top/f"), ("c\x02", "c%02")],
    ids=["trailing-space", "control-character"],
)
@pytest.mark.parametrize("overwrite", ["skip", "replace"])
def test_indexed_single_root_rewritten_onto_the_operators_entry_is_hoisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stored: str,
    mine: str,
    overwrite: str,
) -> None:
    """The stored root name is free but its written spelling is the operator's entry:
    it still goes through the wrapper, so the hoist judges from what is on disk."""
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "one.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(stored, b"ARCHIVE")
    (tmp_path / mine).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / mine).write_bytes(b"MINE")
    assert main(["x", str(archive), "--overwrite", overwrite]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, "kept in ") == [f"kept in one/: {mine} already exists"]
    assert (tmp_path / mine).read_bytes() == b"MINE"
    assert (tmp_path / "one" / mine).read_bytes() == b"ARCHIVE"


@pytest.mark.parametrize("archive_name", ["foo.tar", "foo.zip"])
def test_dry_run_names_where_rename_moves_the_root_past_a_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    archive_name: str,
) -> None:
    """The root ``foo/`` meets the operator's file ``foo``: the dry run names
    ``foo (1)/``, where the real run puts it, not ``foo/``. The archive stores
    ``foo/`` as a directory member too, which the dry run meets at the operator's
    file before it renames it."""
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / archive_name
    if archive_name.endswith(".zip"):
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("foo/", b"")
            zf.writestr("foo/x.txt", b"ARCHIVE")
    else:
        _tar_root_with_file(archive, explicit_root=True)
    (tmp_path / "foo").write_bytes(b"MINE")
    assert main(["x", str(archive), "--dry-run"]) == EXIT_OK
    dry = capsys.readouterr().err
    assert _report_lines(dry, "would move to ") == ["would move to foo (1)/"]
    assert dry.rstrip().endswith("→ foo (1)/")
    assert main(["x", str(archive)]) == EXIT_OK
    real = capsys.readouterr().err
    assert real.rstrip().endswith("→ foo (1)/")
    assert (tmp_path / "foo (1)" / "x.txt").read_bytes() == b"ARCHIVE"


def test_indexed_symlink_root_with_a_rewritten_name_lands_in_an_empty_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A rewritable root name that collides with nothing extracts straight into the cwd,
    so a symlink root stays live instead of being kept in a wrapper."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "target.txt").write_bytes(b"TARGET")
    archive = tmp_path / "one.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("t ")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "target.txt")
    assert main(["x", str(archive)]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, "kept in ") == []
    assert not (tmp_path / "one").exists()
    assert (tmp_path / "t").read_bytes() == b"TARGET"


@pytest.mark.parametrize(
    "stored",
    ["top ", "top.", "c\x02", "a<b", "q?", "x\\y", "e\x7f", "a%b<c", "100%?", "%<"],
)
def test_may_land_on_existing_matches_the_spelling_extraction_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stored: str
) -> None:
    """Pins ``_may_land_on_existing`` against the library's name policy: whatever top
    level name extraction writes for ``stored``, the check finds it in the cwd."""
    from archivey.cli.extract_cmd import _may_land_on_existing

    out = tmp_path / "out"
    archive = tmp_path / "n.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(zipfile.ZipInfo(stored), b"x")
    assert main(["x", str(archive), "-d", str(out)]) == EXIT_OK
    assert len(os.listdir(out)) == 1  # the one spelling extraction wrote
    monkeypatch.chdir(out)
    assert _may_land_on_existing(stored)


@pytest.mark.parametrize("stored", ["hi\ud800", "z\udfff."])
def test_may_land_on_existing_matches_an_escaped_lone_surrogate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stored: str
) -> None:
    """A 7z name can hold a lone surrogate, which the policy writes as its UTF-8 bytes
    escaped (``hi%ED%A0%80``); the check finds that spelling in the cwd."""
    from archivey.cli.extract_cmd import _may_land_on_existing
    from tests.test_sevenzip_surrogate_names import _surrogate_7z

    out = tmp_path / "out"
    archive = tmp_path / "n.7z"
    archive.write_bytes(_surrogate_7z([(stored, b"x")]))
    assert main(["x", str(archive), "-d", str(out)]) == EXIT_OK
    assert len(os.listdir(out)) == 1  # the one spelling extraction wrote
    monkeypatch.chdir(out)
    assert _may_land_on_existing(stored)


@pytest.mark.parametrize("overwrite", ["skip", "replace"])
def test_indexed_lone_surrogate_root_never_replaces_the_operators_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overwrite: str,
) -> None:
    from tests.test_sevenzip_surrogate_names import _surrogate_7z

    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "one.7z"
    archive.write_bytes(_surrogate_7z([("hi\ud800", b"ARCHIVE")]))
    mine = "hi%ED%A0%80"
    (tmp_path / mine).write_bytes(b"MINE")
    assert main(["x", str(archive), "--overwrite", overwrite]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, "kept in ") == [f"kept in one/: {mine} already exists"]
    assert (tmp_path / mine).read_bytes() == b"MINE"
    assert (tmp_path / "one" / mine).read_bytes() == b"ARCHIVE"


def test_may_land_on_existing_takes_linear_time_on_a_crafted_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A root of many ``<`` against entries that nearly match their escapes: the check
    compares each entry once, with no backtracking, so it answers at once."""
    from archivey.cli.extract_cmd import _may_land_on_existing

    monkeypatch.chdir(tmp_path)
    for n in range(100):
        (tmp_path / ("%41" * 80 + f"Z{n}")).mkdir()
    started = time.monotonic()
    assert _may_land_on_existing("<" * 24) is False
    assert _may_land_on_existing("<" * 4) is False
    assert time.monotonic() - started < 1


def test_may_land_on_existing_with_many_rewritable_characters_in_an_empty_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ordinary name with several spaces and escapes collides with nothing in an
    empty cwd, so the archive is not sent through the wrapper."""
    from archivey.cli.extract_cmd import _may_land_on_existing

    monkeypatch.chdir(tmp_path)
    assert _may_land_on_existing("My Holiday Photos <2024>") is False
    (tmp_path / "My Holiday Photos %3C2024%3E").mkdir()
    assert _may_land_on_existing("My Holiday Photos <2024>")


def test_may_land_on_existing_ignores_case_where_the_filesystem_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``top `` is written as ``top``, which a case-insensitive filesystem holds as the
    operator's ``TOP``; a case-sensitive one keeps them apart."""
    from archivey.cli.extract_cmd import _may_land_on_existing

    monkeypatch.chdir(tmp_path)
    (tmp_path / "TOP").mkdir()
    assert _may_land_on_existing("top ") == (not case_sensitive(tmp_path))


def test_indexed_symlink_root_lands_beside_an_entry_differing_in_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """On a case-sensitive filesystem the operator's ``T`` does not collide with the
    root ``t `` (written as ``t``), so the symlink root extracts into the cwd, live."""
    if not case_sensitive(tmp_path):
        pytest.skip("the filesystem folds case, so T and t collide")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "target.txt").write_bytes(b"TARGET")
    (tmp_path / "T").write_bytes(b"MINE")
    archive = tmp_path / "one.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("t ")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "target.txt")
    assert main(["x", str(archive)]) == EXIT_OK
    assert not (tmp_path / "one").exists()
    assert (tmp_path / "t").read_bytes() == b"TARGET"
    assert (tmp_path / "T").read_bytes() == b"MINE"


def test_indexed_single_root_renames_past_the_operators_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = tmp_path / "one.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("top/f", b"ARCHIVE")
    (tmp_path / "top").write_bytes(b"MINE")
    assert main(["x", str(archive)]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, "renamed: ") == ["renamed: top -> top (1)"]
    assert err.rstrip().endswith("→ top (1)/")
    assert (tmp_path / "top").read_bytes() == b"MINE"
    assert (tmp_path / "top (1)" / "f").read_bytes() == b"ARCHIVE"
    assert not (tmp_path / "one").exists()


def test_cli_logging_leaves_no_global_state(sample_zip: Path) -> None:
    # The D4 handler must be scoped to one invocation: a leaked handler or
    # propagate=False blinds caplog-based library tests (pytest 8.3 floor).
    import logging

    root = logging.getLogger("archivey")
    assert main(["list", str(sample_zip)]) == EXIT_OK
    assert root.handlers == []
    assert root.propagate is True
    assert root.level == logging.NOTSET


# --- cli-product review follow-ups (P3 / P5 / P6 / P10–P13 / D1) -------------------------


def test_missing_archive_uses_prose_not_errno_repr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "nope.zip"
    assert main(["list", str(missing)]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "cannot open" in err
    assert "no such file or directory" in err.lower()
    assert "[Errno" not in err


@pytest.mark.parametrize("verb", ["list", "x"])
def test_missing_archive_name_is_escaped_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], verb: str
) -> None:
    """The filename is escaped at the print site only — ``!r`` before it doubled it."""
    missing = tmp_path / "ev\u2028il.zip"
    assert main([verb, str(missing)]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "\u2028" not in err
    assert "ev\\u2028il.zip'" in err
    assert "ev\\\\u2028il.zip" not in err


def test_os_error_without_strerror_does_not_embed_a_repr() -> None:
    import errno

    from archivey.cli.main import _format_os_error

    exc = OSError(errno.EACCES, None, "ev\x1bil.zip")
    assert _format_os_error(exc) == (
        "archivey: cannot open 'ev\x1bil.zip': Permission denied"
    )


def test_extract_missing_archive_only_requires_archive(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["x"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "required: archive" in err
    assert "patterns" not in err.split("required:")[-1]


def test_dash_x_hints_bare_verb(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["-x", "a.zip"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "unrecognized arguments: -x" in err
    assert "bare words" in err
    assert "archivey x ARCHIVE" in err


def test_help_includes_examples(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "examples:" in out
    assert "archivey x archive.zip" in out


def test_password_eof_treated_as_no_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey.cli import password as password_mod
    from archivey.config import PasswordRequest
    from tests.zipcrypto import build_zipcrypto_zip

    blob = build_zipcrypto_zip(b"secret", b"zc.txt", b"hello")
    path = tmp_path / "zc.zip"
    path.write_bytes(blob)

    monkeypatch.setattr(password_mod.sys.stdin, "isatty", lambda: True)

    def _eof(_prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr(password_mod.getpass, "getpass", _eof)
    provider = password_mod.resolve_password(None)
    assert callable(provider)
    assert provider(PasswordRequest(member=None, attempt=1)) is None

    # End-to-end: EOF at prompt must not dump a traceback (P5).
    err = io.StringIO()
    assert main(["t", str(path)], out=io.StringIO(), err=err) == EXIT_FAIL
    text = err.getvalue()
    assert "Traceback" not in text
    assert "EOFError" not in text
    assert "Password required" in text


def test_password_prompt_says_a_retry_follows_a_wrong_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.cli import password as password_mod
    from archivey.config import PasswordRequest

    monkeypatch.setattr(password_mod.sys.stdin, "isatty", lambda: True)
    prompts: list[str] = []

    def _record(prompt: str = "") -> str:
        prompts.append(prompt)
        return "pw"

    monkeypatch.setattr(password_mod.getpass, "getpass", _record)
    provider = password_mod.resolve_password(None)
    assert callable(provider)
    provider(PasswordRequest(member=None, attempt=1))
    provider(PasswordRequest(member=None, attempt=2))
    assert prompts == ["Password: ", "Wrong password, try again: "]


def test_format_access_summary() -> None:
    from archivey.cli.format import format_access_summary
    from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability

    indexed = CostReceipt(
        listing_cost=ListingCost.INDEXED,
        access_cost=AccessCost.DIRECT,
        stream_capability=StreamCapability.SEEKABLE,
    )
    assert format_access_summary(indexed) == "random (indexed)"

    solid = CostReceipt(
        listing_cost=ListingCost.REQUIRES_DECOMPRESSION,
        access_cost=AccessCost.SOLID,
        stream_capability=StreamCapability.SEEKABLE,
        solid_block_count=1,
    )
    assert "solid (" in format_access_summary(solid)
    assert "1 solid block" in format_access_summary(solid)

    # The re-decode note is about access_cost, so every listing cost keeps it (a solid
    # RAR lists by scanning).
    note = "reading one member may decode earlier members in its block"
    for listing in ListingCost:
        receipt = CostReceipt(
            listing_cost=listing,
            access_cost=AccessCost.SOLID,
            stream_capability=StreamCapability.SEEKABLE,
        )
        assert note in format_access_summary(receipt), listing
    scanned = CostReceipt(
        listing_cost=ListingCost.REQUIRES_SCANNING,
        access_cost=AccessCost.SOLID,
        stream_capability=StreamCapability.SEEKABLE,
    )
    assert format_access_summary(scanned) == (f"solid (listing requires scan; {note})")


def test_list_escapes_control_bytes_in_names(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    z = _zip(
        tmp_path / "hostile.zip", {"evil\x1b[31m.txt": b"x", "line1\rok.txt": b"y"}
    )
    assert main(["list", str(z)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\\x1b" in out
    assert "\\r" in out


def test_list_marks_anti_and_non_current() -> None:
    from datetime import datetime

    from archivey.cli.format import format_member_line
    from archivey.types import ArchiveMember, MemberType

    anti = ArchiveMember(type=MemberType.ANTI, name="gone.txt")
    assert format_member_line(anti).startswith("A-")

    old = ArchiveMember(
        type=MemberType.FILE,
        name="a.txt",
        size=1,
        modified=datetime(2026, 1, 1),
        is_current=False,
    )
    assert format_member_line(old).startswith("f~")

    enc = ArchiveMember(
        type=MemberType.FILE,
        name="a.txt",
        size=1,
        is_encrypted=True,
        is_current=False,
    )
    assert format_member_line(enc).startswith("fE")


def test_extract_summary_names_single_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    z = _zip(tmp_path / "one.zip", {"root/a.txt": b"a", "root/b.txt": b"b"})
    assert main(["extract", str(z)]) == EXIT_OK
    err = capsys.readouterr().err
    assert "→ root/" in err
    assert "→ ." not in err


def test_truncated_zip_message_is_prose_not_repr(tmp_path: Path) -> None:
    import zipfile as zf

    from archivey import open_archive

    buf = io.BytesIO()
    with zf.ZipFile(buf, "w") as archive:
        archive.writestr("a.txt", "hello")
    path = tmp_path / "truncated.zip"
    path.write_bytes(buf.getvalue()[:20])
    with pytest.raises(TruncatedError) as caught:
        open_archive(path)
    msg = str(caught.value)
    assert "BadZipFile" not in msg
    assert "ArchiveFormat.ZIP" not in msg
    assert "format=ZIP" in msg
    assert "truncated" in msg.lower() or "corrupt" in msg.lower()


def test_stored_zipcrypto_provider_none_is_password_required(tmp_path: Path) -> None:
    import zipfile as zf

    from archivey import open_archive
    from archivey.exceptions import EncryptionError
    from tests.zipcrypto import build_zipcrypto_zip

    blob = build_zipcrypto_zip(
        b"secret", b"zc.txt", b"hello world", compression=zf.ZIP_STORED
    )
    path = tmp_path / "zc_stored.zip"
    path.write_bytes(blob)

    with (
        pytest.raises(EncryptionError, match="Password required") as caught,
        open_archive(path, password=lambda _r: None) as ar,
    ):
        ar.read(next(m for m in ar.members() if m.is_file))
    assert "Wrong password" not in caught.value.message


# --- Q1 / P1: extract continue-on-error + exit 3 + --stop-on-error -----------------------


def test_extract_continues_after_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from archivey.cli.exit_codes import EXIT_POLICY

    monkeypatch.chdir(tmp_path)
    archive = _tar(
        tmp_path / "evil.tar",
        {
            "../escape.txt": b"bad",
            "safe1.txt": b"ok1",
            "safe2.txt": b"ok2",
            "dir/nested.txt": b"ok3",
        },
    )
    assert main(["extract", str(archive), "-d", "out"]) == EXIT_POLICY
    err = capsys.readouterr().err
    assert "blocked:" in err
    assert "escape.txt" in err or "../escape" in err
    assert "blocked" in err.split("→")[0]  # summary mentions blocked
    assert (tmp_path / "out" / "safe1.txt").read_bytes() == b"ok1"
    assert (tmp_path / "out" / "safe2.txt").read_bytes() == b"ok2"
    assert (tmp_path / "out" / "dir" / "nested.txt").read_bytes() == b"ok3"
    assert not (tmp_path / "escape.txt").exists()


def test_extract_stop_on_error_continues_on_policy_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from archivey.cli.exit_codes import EXIT_POLICY

    monkeypatch.chdir(tmp_path)
    # Policy block under --stop-on-error: continue, extract safe members, exit 3.
    archive = _tar(
        tmp_path / "evil.tar",
        {
            "../escape.txt": b"bad",
            "safe.txt": b"ok",
        },
    )
    code = main(["extract", str(archive), "-d", "out", "--stop-on-error"])
    assert code == EXIT_POLICY
    err = capsys.readouterr().err
    assert "blocked:" in err
    assert "extraction stopped" not in err
    assert (tmp_path / "out" / "safe.txt").read_bytes() == b"ok"


def test_extract_stop_on_error_aborts_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--stop-on-error aborts on a genuine member failure (CRC), not a policy block."""
    monkeypatch.chdir(tmp_path)
    from tests.zip_corrupt import zip_with_flipped_cd_crc

    path = zip_with_flipped_cd_crc(
        tmp_path / "badcrc.zip",
        {"a.txt": b"hello", "b.txt": b"world", "c.txt": b"end"},
        corrupt_name="b.txt",
    )

    code = main(["extract", str(path), "-d", "out", "--stop-on-error"])
    assert code == EXIT_FAIL
    err = capsys.readouterr().err
    assert "extraction stopped" in err
    lines = err.splitlines()
    stop = lines.index("1 member(s) extracted before the stop")
    # The error that ended the run carries the prefix every run-ending line has.
    assert lines[stop - 1].startswith("archivey: ")
    assert (tmp_path / "out" / "a.txt").read_bytes() == b"hello"
    assert not (tmp_path / "out" / "b.txt").exists()
    assert not (tmp_path / "out" / "c.txt").exists()


def test_extract_corrupt_member_continues_with_exit_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """CRC mismatch: recoverable members extracted; exit 1 (FAILED, not policy)."""
    monkeypatch.chdir(tmp_path)
    from tests.zip_corrupt import zip_with_flipped_cd_crc

    path = zip_with_flipped_cd_crc(
        tmp_path / "badcrc.zip",
        {"a.txt": b"hello", "b.txt": b"world", "c.txt": b"end"},
        corrupt_name="b.txt",
    )

    assert main(["extract", str(path), "-d", "out"]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "failed:" in err
    assert "b.txt" in err
    assert "extraction stopped" not in err
    assert (tmp_path / "out" / "a.txt").read_bytes() == b"hello"
    assert (tmp_path / "out" / "c.txt").read_bytes() == b"end"
    assert not (tmp_path / "out" / "b.txt").exists()


def test_extract_dest_before_patterns_still_filters(
    sample_zip: Path, tmp_path: Path
) -> None:
    """Documented ``x ARCHIVE -d DEST PATTERN`` must not drop the pattern (argparse)."""
    dest = tmp_path / "dest"
    assert main(["x", str(sample_zip), "-d", str(dest), "a.txt"]) == EXIT_OK
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert not (dest / "b").exists()


def test_extract_unmatched_include_exits_one(
    sample_zip: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "dest"
    dest.mkdir()
    assert main(["x", str(sample_zip), "-d", str(dest), "*.missing"]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "warning: pattern matched no members: '*.missing'" in err
    assert list(dest.iterdir()) == []


def test_extract_unmatched_dir_pattern_hints_dash_d(
    sample_zip: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    assert main(["x", str(sample_zip), "out"]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "warning: pattern matched no members: 'out'" in err
    assert "(did you mean -d out?)" in err


def test_extract_partial_unmatched_still_extracts(
    sample_zip: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "dest"
    assert main(["x", str(sample_zip), "-d", str(dest), "a.txt", "nope.txt"]) == EXIT_OK
    err = capsys.readouterr().err
    assert "warning: pattern matched no members: 'nope.txt'" in err
    assert (dest / "a.txt").read_bytes() == b"hello"


def test_list_unmatched_include_warns_exit_zero(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["list", str(sample_zip), "*.rs"]) == EXIT_OK
    captured = capsys.readouterr()
    assert "warning: pattern matched no members: '*.rs'" in captured.err
    assert captured.out == ""


def test_test_unmatched_include_exits_one(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["t", str(sample_zip), "missing"]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "warning: pattern matched no members: 'missing'" in err
    assert "OK," not in err


def test_extract_dest_before_dash_named_pattern(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``-d`` before patterns must still accept ``-- -file.txt`` (fold + ``--``)."""
    monkeypatch.chdir(tmp_path)
    z = _zip(tmp_path / "dash.zip", {"-file.txt": b"x", "ok.txt": b"y"})
    dest = tmp_path / "out"
    assert main(["x", str(z), "-d", str(dest), "--", "-file.txt"]) == EXIT_OK
    assert (dest / "-file.txt").read_bytes() == b"x"
    assert not (dest / "ok.txt").exists()


@pytest.mark.parametrize(
    "tail",
    [["*.py", "--", "-file.txt"], ["--", "-file.txt", "*.py"]],
    ids=["pattern-before-separator", "pattern-after-separator"],
)
def test_extract_dest_then_patterns_around_double_dash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tail: list[str]
) -> None:
    """A pattern before ``--`` must not turn ``--`` and later tokens into options."""
    monkeypatch.chdir(tmp_path)
    z = _zip(tmp_path / "dash.zip", {"-file.txt": b"x", "a.py": b"y", "ok.txt": b"z"})
    dest = tmp_path / "out"
    assert main(["x", str(z), "-d", str(dest), *tail]) == EXIT_OK
    assert (dest / "-file.txt").read_bytes() == b"x"
    assert (dest / "a.py").read_bytes() == b"y"
    assert not (dest / "ok.txt").exists()


@pytest.mark.parametrize(
    "opts", [[], ["-d", "out"]], ids=["no-flags", "dest-before-separator"]
)
def test_parse_double_dash_pattern_named_double_dash(opts: list[str]) -> None:
    """The first ``--`` is the separator; a second one is a pattern on every Python."""
    argv = _inject_default_list(["x", "a.zip", *opts, "--", "--"])
    args = _parse_cli_args(build_parser(), argv)
    assert args.archive == "a.zip"
    assert args.patterns == ["--"]
    argv = _inject_default_list(["x", "a.zip", *opts, "--", "--", "b*"])
    assert _parse_cli_args(build_parser(), argv).patterns == ["--", "b*"]


@pytest.mark.parametrize(
    "opts", [[], ["-d", "{dest}"]], ids=["no-flags", "dest-before-separator"]
)
def test_extract_member_named_double_dash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, opts: list[str]
) -> None:
    """``x a.zip -- --`` extracts the member named ``--`` and nothing else."""
    z = _zip(tmp_path / "dd.zip", {"--": b"x", "other.txt": b"y"})
    dest = tmp_path / "out"
    dest.mkdir()
    # Without ``-d`` the extraction lands in the working directory.
    monkeypatch.chdir(tmp_path if opts else dest)
    flags = [o.format(dest=dest) for o in opts]
    assert main(["x", str(z), *flags, "--", "--"]) == EXIT_OK
    assert (dest / "--").read_bytes() == b"x"
    assert not (dest / "other.txt").exists()


def test_double_dash_archive_and_pattern_after_separator() -> None:
    """Archive and patterns may both follow ``--``; dash names stay positionals."""
    argv = _inject_default_list(["x", "--", "-a.zip", "-f", "--"])
    args = _parse_cli_args(build_parser(), argv)
    assert (args.archive, args.patterns) == ("-a.zip", ["-f", "--"])


def test_unknown_option_before_double_dash_still_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only tokens after ``--`` are positionals; a typo before it stays an error."""
    z = _zip(tmp_path / "a.zip", {"a.txt": b"x"})
    dest = tmp_path / "out"
    args = ["x", str(z), "-d", str(dest), "a*", "--bogus", "--", "-f"]
    assert main(args) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "unrecognized arguments: --bogus" in err
    assert "-f" not in err.split("unrecognized arguments:")[-1]


def test_extract_stop_on_error_reports_extracted_and_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Q1.5: STOP abort reports extracted vs blocked counts separately."""
    monkeypatch.chdir(tmp_path)
    from tests.zip_corrupt import zip_with_flipped_cd_crc

    path = zip_with_flipped_cd_crc(
        tmp_path / "partial.zip",
        {
            "safe.txt": b"ok",
            "../evil.txt": b"bad",
            "corrupt.txt": b"payload",
            "later.txt": b"late",
        },
        corrupt_name="corrupt.txt",
    )

    code = main(["extract", str(path), "-d", "out", "--stop-on-error"])
    assert code == EXIT_FAIL  # Q8: abort → 1
    err = capsys.readouterr().err
    assert "1 member(s) extracted, 1 blocked before the stop" in err
    assert "extraction stopped" in err
    assert (tmp_path / "out" / "safe.txt").read_bytes() == b"ok"
    assert not (tmp_path / "out" / "later.txt").exists()


def test_extract_stop_on_error_reports_members_extracted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Q1.5: STOP after a successful member still reports how many were extracted."""
    monkeypatch.chdir(tmp_path)
    from tests.zip_corrupt import zip_with_flipped_cd_crc

    path = zip_with_flipped_cd_crc(
        tmp_path / "partial.zip",
        {"safe.txt": b"ok", "corrupt.txt": b"bad", "later.txt": b"late"},
        corrupt_name="corrupt.txt",
    )

    code = main(["extract", str(path), "-d", "out", "--stop-on-error"])
    assert code == EXIT_FAIL  # Q8: abort → 1
    err = capsys.readouterr().err
    assert "1 member(s) extracted before the stop" in err
    assert "blocked" not in err.split("before the stop")[0]
    assert "extraction stopped" in err
    assert (tmp_path / "out" / "safe.txt").read_bytes() == b"ok"
    assert not (tmp_path / "out" / "later.txt").exists()


# --- --abort-on / OVERWRITTEN reporting -------------------------------------


def _collide_zip(path: Path) -> Path:
    """Two members whose names differ only by case — one destination, two members."""
    return _zip(path, {"README": b"A", "readme": b"B"})


def test_extract_reports_overwritten_member(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The REPLACE merge that used to be silent in the report is now reported."""
    archive = _collide_zip(tmp_path / "c.zip")
    dest = tmp_path / "out"
    assert (
        main(["x", str(archive), "-d", str(dest), "--overwrite", "replace"]) == EXIT_OK
    )
    err = capsys.readouterr().err
    assert "overwritten:" in err
    assert sorted(p.name for p in dest.iterdir()) == ["README"]


def test_extract_abort_on_name_collision(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _collide_zip(tmp_path / "c.zip")
    dest = tmp_path / "out"
    code = main(
        [
            "x",
            str(archive),
            "-d",
            str(dest),
            "--overwrite",
            "replace",
            "--abort-on",
            "name-collision",
        ]
    )
    assert code == EXIT_FAIL
    err = capsys.readouterr().err
    assert "Name collision" in err
    assert "extraction stopped" in err


def test_extract_abort_on_blocked_member(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _zip(tmp_path / "t.zip", {"../escape.txt": b"x", "ok.txt": b"y"})
    dest = tmp_path / "out"
    code = main(["x", str(archive), "-d", str(dest), "--abort-on", "blocked-member"])
    assert code == EXIT_FAIL
    assert "extraction stopped" in capsys.readouterr().err
    assert not (dest / "ok.txt").exists()


def test_extract_unknown_abort_on_event_is_usage_error(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "t.zip", {"a.txt": b"x"})
    assert (
        main(["x", str(archive), "-d", str(tmp_path / "o"), "--abort-on", "nonsense"])
        == EXIT_USAGE
    )


def test_extract_abort_on_name_sanitized(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _zip(tmp_path / "t.zip", {"foo.": b"x", "later.txt": b"y"})
    dest = tmp_path / "out"
    code = main(["x", str(archive), "-d", str(dest), "--abort-on", "name-sanitized"])
    assert code == EXIT_FAIL
    assert "extraction stopped" in capsys.readouterr().err
    assert not (dest / "later.txt").exists()


def test_extract_reports_nested_rewrite_with_full_relative_names(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Both sides of the arrow are full relative names — a basename would print
    'dir/foo. -> foo' and invent a destination the member never had."""
    archive = _zip(tmp_path / "t.zip", {"dir/foo.": b"x", "dir/keep.txt": b"y"})
    dest = tmp_path / "out"
    assert main(["x", str(archive), "-d", str(dest)]) == EXIT_OK
    assert "name rewritten: dir/foo. -> dir/foo" in capsys.readouterr().err


def _report_lines(err: str, marker: str) -> list[str]:
    """Stderr lines starting with ``marker``, split on ``\\n`` only.

    ``str.splitlines()`` is wrong here: it also splits on ``\\r`` and U+2028 — the exact
    characters under test — so an unescaped line would be broken in two and every "raw
    character absent" assertion would pass vacuously. A trailing ``\\r`` is stripped so a
    CRLF line ending does not read as an embedded CR.
    """
    return [ln.removesuffix("\r") for ln in err.split("\n") if ln.startswith(marker)]


# A member name carrying an ANSI erase-line plus a CR: printed raw, everything before
# the CR is wiped and the archive gets to author the whole terminal line. STRICT and
# STANDARD write the control bytes as %XX (O7), so a report line built from the path on
# disk never carries them; tests that need the raw name in such a line use
# ``--policy trusted``. Windows cannot hold the raw name at all (control bytes are
# illegal in NTFS names, WinError 123), so those tests are Unix-only.
_SPOOF_ANSI = "ev\x1b[2Kil\rSUCCESS.txt"
_ANSI_ONLY = pytest.mark.skipif(
    sys.platform == "win32",
    reason="control bytes are illegal in Windows filenames; the member cannot be written",
)

# U+2028 LINE SEPARATOR: non-printable (so it still must be escaped) but legal in a
# Windows filename, which keeps the escaping itself covered on every platform.
_SPOOF_PORTABLE = "ev\u2028il.txt"


@pytest.mark.parametrize(
    "overwrite,marker",
    [("replace", "overwritten:"), ("skip", "not overwritten:")],
)
def test_extract_escapes_member_paths_in_overwrite_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], overwrite: str, marker: str
) -> None:
    """These lines print ``requested_path``, which is built from the member's own name.

    The portable rewrite escapes only the controls 0x01-0x1F, not U+2028, so an
    unescaped path here is the display-spoofing vector ``escape_member_name`` closes.
    """
    archive = _zip(
        tmp_path / "c.zip", {_SPOOF_PORTABLE: b"A", _SPOOF_PORTABLE.upper(): b"B"}
    )
    dest = tmp_path / "out"
    main(["x", str(archive), "-d", str(dest), "--overwrite", overwrite])
    err = capsys.readouterr().err
    # Scoped to the line under test: a stray library log line carrying the same raw path
    # would otherwise fail this for a reason it does not cover.
    lines = _report_lines(err, marker)
    assert lines
    assert all("\u2028" not in ln for ln in lines)  # not the raw separator
    assert any("\\u2028" in ln for ln in lines)  # …shown losslessly instead


def test_extract_escapes_member_paths_in_rename_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ``renamed:`` line prints both sides as paths; both come from the member."""
    archive = _zip(
        tmp_path / "c.zip", {_SPOOF_PORTABLE: b"A", _SPOOF_PORTABLE.upper(): b"B"}
    )
    dest = tmp_path / "out"
    main(["x", str(archive), "-d", str(dest), "--overwrite", "rename"])
    err = capsys.readouterr().err
    lines = _report_lines(err, "renamed:")
    assert lines
    assert all("\u2028" not in ln for ln in lines)
    assert any("\\u2028" in ln for ln in lines)


@_ANSI_ONLY
@pytest.mark.parametrize(
    "overwrite,marker",
    [("replace", "overwritten:"), ("skip", "not overwritten:")],
)
def test_extract_escapes_ansi_spoof_in_overwrite_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], overwrite: str, marker: str
) -> None:
    """The real spoof: ESC[2K + CR would erase the line and rewrite it.

    TRUSTED writes the name as stored, so the raw bytes reach ``requested_path``. It has
    no collision event for a case-only pair, so the clash here is a directory member
    and then a file member of the same name, which meet as an existing entry.
    """
    archive = _zip(tmp_path / "c.zip", {f"{_SPOOF_ANSI}/": b"", _SPOOF_ANSI: b"B"})
    dest = tmp_path / "out"
    main(
        [
            "x",
            str(archive),
            "-d",
            str(dest),
            "--overwrite",
            overwrite,
            "--policy",
            "trusted",
        ]
    )
    err = capsys.readouterr().err
    lines = _report_lines(err, marker)
    assert lines
    assert all("\x1b" not in ln for ln in lines)  # no raw escape sequence
    assert all("\r" not in ln for ln in lines)  # no carriage-return line rewrite
    assert any("\\x1b[2K" in ln for ln in lines)  # …shown losslessly instead


def test_extract_escapes_error_detail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``failed:`` appends the error, whose message embeds the destination path.

    Scoped to the CLI's own line: the library also emits a ``logger.warning`` carrying
    the same raw path, which reaches the same terminal through the CLI's stderr handler.
    That is a separate layer (a log formatter concern, not a print site) and is not what
    this test covers.
    """
    archive = _zip(
        tmp_path / "c.zip", {_SPOOF_PORTABLE: b"A", _SPOOF_PORTABLE.upper(): b"B"}
    )
    dest = tmp_path / "out"
    main(["x", str(archive), "-d", str(dest), "--overwrite", "error"])
    err = capsys.readouterr().err
    failed_lines = _report_lines(err, "failed:")
    assert failed_lines
    assert all("\u2028" not in ln for ln in failed_lines)
    assert any("\\u2028" in ln for ln in failed_lines)


def test_report_lines_do_not_double_path_separators(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Escaping must not turn a native path's separators into ``\\\\``.

    ``escape_member_name`` escapes backslashes, so feeding it a Windows path would double
    every separator. Report lines render relative to the extraction root (POSIX
    separators) first, so this holds on every platform — and this test would catch the
    regression on Linux, where the doubling is otherwise invisible.
    """
    archive = _zip(tmp_path / "c.zip", {"dir/README": b"A", "dir/readme": b"B"})
    dest = tmp_path / "out"
    main(["x", str(archive), "-d", str(dest), "--overwrite", "replace"])
    lines = _report_lines(capsys.readouterr().err, "overwritten:")
    assert lines == ["overwritten: dir/README"]
    assert "\\\\" not in lines[0]


def _summary_lines(err: str) -> list[str]:
    """The closing ``N extracted, …`` line(s), split on ``\\n`` only (see _report_lines)."""
    return [ln for ln in err.split("\n") if " extracted, " in ln]


# The single-root forms of the two spoof names: a directory, not a file.
_SPOOF_ANSI_ROOT = "ev\x1b[2Kil\rSUCCESS"
_SPOOF_PORTABLE_ROOT = "ev\u2028il"


@pytest.mark.parametrize(
    "root,raw,escaped",
    [
        pytest.param(_SPOOF_PORTABLE_ROOT, "\u2028", "ev\\u2028il", id="portable"),
        pytest.param(
            _SPOOF_ANSI_ROOT,
            "\x1b",
            "ev\\x1b[2Kil\\rSUCCESS",
            id="ansi",
            marks=_ANSI_ONLY,
        ),
    ],
)
def test_extract_summary_escapes_the_single_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    root: str,
    raw: str,
    escaped: str,
) -> None:
    """The summary names the sole top-level entry — the member's own name.

    It is the last line the operator reads, the one saying where the data went, so an
    unescaped name there lets the archive write it.
    """
    monkeypatch.chdir(tmp_path)
    archive = _zip(tmp_path / "one.zip", {f"{root}/a.txt": b"a", f"{root}/b.txt": b"b"})
    # TRUSTED: STRICT would write the control bytes as %XX, and the root as printed
    # would no longer carry them.
    assert main(["x", str(archive), "--policy", "trusted"]) == EXIT_OK
    lines = _summary_lines(capsys.readouterr().err)
    assert len(lines) == 1
    assert raw not in lines[0]
    assert "\r" not in lines[0]
    assert lines[0].endswith(f"→ {escaped}/")


@pytest.mark.parametrize(
    "root,raw,escaped",
    [
        pytest.param(_SPOOF_PORTABLE_ROOT, "\u2028", "ev\\u2028il", id="portable"),
        pytest.param(
            _SPOOF_ANSI_ROOT,
            "\x1b",
            "ev\\x1b[2Kil\\rSUCCESS",
            id="ansi",
            marks=_ANSI_ONLY,
        ),
    ],
)
def test_extract_hoist_report_escapes_the_single_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    root: str,
    raw: str,
    escaped: str,
) -> None:
    """A plain tar has no index, so the CLI wraps, then hoists the sole root and says so.

    Both the ``moved to`` line and the summary print that root's name.
    """
    monkeypatch.chdir(tmp_path)
    archive = _tar(
        tmp_path / "bundle.tar", {f"{root}/a.txt": b"a", f"{root}/b.txt": b"b"}
    )
    # TRUSTED, as in the summary test above: the root keeps its raw bytes on disk.
    assert main(["x", str(archive), "--policy", "trusted"]) == EXIT_OK
    err = capsys.readouterr().err
    moved = _report_lines(err, "moved to ")
    assert moved == [f"moved to {escaped}/"]
    summary = _summary_lines(err)
    assert len(summary) == 1
    assert raw not in summary[0]
    assert summary[0].endswith(f"→ {escaped}/")


def test_extract_escapes_a_wrapper_named_after_the_archive_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The wrapper directory is the archive's filename stem, which is not the CLI's.

    An archive extracted out of another archive gets its filename from that one, and a
    shell loop over ``*.tar`` hands it over without anyone typing it.
    """
    monkeypatch.chdir(tmp_path)
    archive = _tar(
        tmp_path / f"{_SPOOF_PORTABLE_ROOT}.tar", {"a.txt": b"a", "b.txt": b"b"}
    )
    assert main(["x", str(archive)]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, "extracting into ") == ["extracting into ev\\u2028il/"]
    summary = _summary_lines(err)
    assert len(summary) == 1
    assert summary[0].endswith("→ ev\\u2028il/")
    assert "\u2028" not in err


def test_hoist_escapes_the_wrapper_it_flattens_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``ev<U+2028>il.tar`` holding ``ev<U+2028>il/``: the wrapper becomes the root."""
    monkeypatch.chdir(tmp_path)
    root = _SPOOF_PORTABLE_ROOT
    archive = _tar(tmp_path / f"{root}.tar", {f"{root}/f.txt": b"data"})
    assert main(["x", str(archive)]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, "removed wrapper; ") == [
        "removed wrapper; content at ev\\u2028il/"
    ]
    assert "\u2028" not in err


# A hostile single root colliding with an existing entry of the same name, so the hoist
# has to resolve the collision itself and print the paths it chose.
_HOSTILE_ROOT = f"root{_SPOOF_PORTABLE_ROOT}"


def _hostile_collision_archive(tmp_path: Path, name: str = "bundle.tar") -> Path:
    (tmp_path / _HOSTILE_ROOT).mkdir()
    (tmp_path / _HOSTILE_ROOT / "clash.txt").write_bytes(b"MINE")
    return _tar(tmp_path / name, {f"{_HOSTILE_ROOT}/clash.txt": b"ARCHIVE"})


@pytest.mark.parametrize(
    "overwrite,expected",
    [
        (
            "rename",
            "renamed: rootev\\u2028il/clash.txt -> rootev\\u2028il/clash (1).txt",
        ),
    ],
)
def test_hoist_escapes_the_collisions_it_resolves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overwrite: str,
    expected: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = _hostile_collision_archive(tmp_path)
    assert main(["x", str(archive), "--overwrite", overwrite]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, expected.split(":", 1)[0] + ":") == [expected]
    assert "\u2028" not in err


def test_hoist_escapes_a_collision_it_keeps_the_root_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Under ``error`` the hoist names the collision and the wrapper it kept."""
    monkeypatch.chdir(tmp_path)
    archive = _hostile_collision_archive(tmp_path, name=f"w{_SPOOF_PORTABLE_ROOT}.tar")
    assert main(["x", str(archive), "--overwrite", "error"]) == EXIT_OK
    err = capsys.readouterr().err
    assert _report_lines(err, "kept in ") == [
        "kept in wev\\u2028il/: rootev\\u2028il/clash.txt already exists"
    ]
    assert "\u2028" not in err


def test_hoist_escapes_a_collision_it_stops_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A collision the check before the move did not see (the cwd changed in between)
    still stops the hoist, which names the collision and the wrapper it left behind."""
    from archivey.cli import extract_cmd

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(extract_cmd, "_first_clash", lambda *args: None)
    archive = _hostile_collision_archive(tmp_path, name=f"w{_SPOOF_PORTABLE_ROOT}.tar")
    assert main(["x", str(archive), "--overwrite", "error"]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert _report_lines(err, "Destination already exists: ") == [
        "Destination already exists: rootev\\u2028il/clash.txt"
    ]
    assert _report_lines(err, "hoist stopped; ") == [
        "hoist stopped; remaining files left in wev\\u2028il/"
    ]
    assert "\u2028" not in err


def test_hoist_restores_the_wrapper_when_removing_it_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Every member moved out of the aside ``w (1)``, then its removal fails. The
    # wrapper is back under its own name, so ``files left in w/`` names a directory
    # that exists.
    monkeypatch.chdir(tmp_path)
    archive = _tar(tmp_path / "w.tar", {"root/a.txt": b"a"})
    real_rmdir = Path.rmdir

    def rmdir(self: Path) -> None:
        if self.name == "w (1)":
            raise PermissionError("refused")
        real_rmdir(self)

    monkeypatch.setattr(Path, "rmdir", rmdir)
    assert main(["x", str(archive)]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert _report_lines(err, "archivey: hoist failed: ") == [
        "archivey: hoist failed: refused"
    ]
    assert _report_lines(err, "files left in ") == ["files left in w/"]
    assert (tmp_path / "w").is_dir()
    assert not (tmp_path / "w (1)").exists()
    assert (tmp_path / "root" / "a.txt").read_bytes() == b"a"


def test_hoist_restore_never_replaces_a_member_the_merge_renamed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The cwd holds a file ``foo``, so ``foo.tar`` extracts into ``foo (1)/``, which
    # steps aside to ``foo (1) (1)/``. Under rename the merge gives the root ``foo/``
    # the free name ``foo (1)``. When removing the aside directory fails, the restore
    # must not rename it onto that member, and the lines name where it stays.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "foo").write_bytes(b"MINE")
    archive = _tar_dirs(tmp_path / "foo.tar", ["foo/"])
    real_rmdir = Path.rmdir

    def rmdir(self: Path) -> None:
        if self.name == "foo (1) (1)":
            raise PermissionError("refused")
        real_rmdir(self)

    monkeypatch.setattr(Path, "rmdir", rmdir)
    assert main(["x", str(archive), "--overwrite", "rename"]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert _report_lines(err, "files left in ") == ["files left in foo (1) (1)/"]
    assert (tmp_path / "foo").read_bytes() == b"MINE"
    # The member keeps its stored mtime: it was not replaced by the aside directory.
    assert (tmp_path / "foo (1)").stat().st_mtime == 0
    assert not any((tmp_path / "foo (1) (1)").iterdir())


def test_hoist_escapes_the_wrapper_when_the_move_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from archivey.cli import extract_cmd

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("refused")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(extract_cmd, "_merge_move", refuse)
    archive = _tar(tmp_path / f"w{_SPOOF_PORTABLE_ROOT}.tar", {"root/a.txt": b"a"})
    assert main(["x", str(archive)]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert _report_lines(err, "files left in ") == ["files left in wev\\u2028il/"]
    assert _report_lines(err, "archivey: hoist failed: ") == [
        "archivey: hoist failed: refused"
    ]
    assert "\u2028" not in err


# --- the hoist reports where the root landed, not where it was headed -------------


def test_hoist_names_the_free_name_a_rename_chose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The archive's sole file collides with the operator's ``a.txt``.

    The content lands at ``a (1).txt``; ``a.txt`` is the operator's own file, so a
    report naming it points at data the archive never wrote.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.txt").write_bytes(b"MINE")
    archive = _tar(tmp_path / "bundle.tar", {"a.txt": b"ARCHIVE"})
    assert main(["x", str(archive)]) == EXIT_OK
    err = capsys.readouterr().err
    assert (tmp_path / "a (1).txt").read_bytes() == b"ARCHIVE"
    assert _report_lines(err, "moved to ") == ["moved to a (1).txt"]
    assert _summary_lines(err)[0].endswith("→ a (1).txt")


@pytest.mark.parametrize(
    ("entries", "mine", "landed"),
    [
        ({"top.txt": b"ARCHIVE"}, "top.txt", "top (1).txt"),
        ({"top/": b"", "top/x.txt": b"ARCHIVE"}, "top", "top (1)/"),
    ],
    ids=["file", "dir-over-file"],
)
def test_summary_names_the_free_name_a_rename_chose_for_an_indexed_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    entries: dict[str, bytes],
    mine: str,
    landed: str,
) -> None:
    """An indexed archive whose one top is taken in the cwd goes through a wrapper and
    the hoist; the summary names where the rename put it, not the operator's own
    file."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / mine).write_bytes(b"MINE")
    archive = _zip(tmp_path / "a.zip", entries)
    assert main(["x", str(archive), "--overwrite", "rename"]) == EXIT_OK
    err = capsys.readouterr().err
    assert (tmp_path / mine).read_bytes() == b"MINE"
    assert _summary_lines(err)[0].endswith(f"→ {landed}")


def test_hoist_keeps_a_file_root_in_the_wrapper_under_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Under ``skip`` the hoist discards nothing: the archive's ``a.txt`` stays in the
    wrapper beside the operator's, and no ``moved to`` line names the operator's
    file."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.txt").write_bytes(b"MINE")
    archive = _tar(tmp_path / "bundle.tar", {"a.txt": b"ARCHIVE"})
    assert main(["x", str(archive), "--overwrite", "skip"]) == EXIT_OK
    err = capsys.readouterr().err
    assert (tmp_path / "a.txt").read_bytes() == b"MINE"
    assert (tmp_path / "bundle" / "a.txt").read_bytes() == b"ARCHIVE"
    assert _report_lines(err, "kept in ") == ["kept in bundle/: a.txt already exists"]
    assert _report_lines(err, "moved to ") == []
    assert _summary_lines(err) == ["1 extracted, 0 renamed, 0 skipped → bundle/"]


def test_hoist_does_not_mark_a_file_root_as_a_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A sole file root against an operator *directory* of the same name.

    The trailing ``/`` was read off the pre-existing entry, so the report pointed at
    the operator's directory as if it were where the file went.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.txt").mkdir()
    archive = _tar(tmp_path / "bundle.tar", {"a.txt": b"ARCHIVE"})
    assert main(["x", str(archive)]) == EXIT_OK
    err = capsys.readouterr().err
    assert (tmp_path / "a (1).txt").read_bytes() == b"ARCHIVE"
    assert _report_lines(err, "moved to ") == ["moved to a (1).txt"]
    assert _summary_lines(err)[0].endswith("→ a (1).txt")


# --- a hoist leaves what a direct extraction into the cwd leaves, and says so -------


def _tree(root: Path) -> dict[str, bytes | None]:
    """Every entry under ``root``, relative and ``/``-separated: a file's bytes, or
    ``None`` for a directory."""
    return {
        p.relative_to(root).as_posix(): None if p.is_dir() else p.read_bytes()
        for p in sorted(root.rglob("*"))
    }


def _hoist_and_direct(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    archive_name: str,
    entries: dict[str, bytes],
    mine: dict[str, bytes],
    overwrite: str = "rename",
    args: tuple[str, ...] = (),
    mine_modes: dict[str, int] | None = None,
    dir_mode: int = 0o755,
) -> tuple[tuple[dict[str, bytes | None], str], tuple[dict[str, bytes | None], str]]:
    """Extract ``entries`` once through the wrapper and hoist, and once with ``-d .``,
    each into a fresh directory that holds ``mine``, under ``--overwrite overwrite``
    and ``args``; return each tree and stderr. Both runs must exit 0.

    A name ending in ``/`` is stored as a directory, at ``dir_mode``. ``mine_modes``
    sets the mode of the operator's entries it names."""
    runs = []
    for how, extra in (("hoist", []), ("direct", ["-d", "."])):
        cwd = tmp_path / overwrite / how
        cwd.mkdir(parents=True)
        for name, data in mine.items():
            (cwd / name).parent.mkdir(parents=True, exist_ok=True)
            (cwd / name).write_bytes(data)
        for name, mode in (mine_modes or {}).items():
            (cwd / name).chmod(mode)
        archive = tmp_path / archive_name
        with tarfile.open(archive, "w") as tf:
            for name, data in entries.items():
                info = tarfile.TarInfo(name.rstrip("/"))
                if name.endswith("/"):
                    info.type = tarfile.DIRTYPE
                    info.mode = dir_mode
                    tf.addfile(info)
                else:
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
        monkeypatch.chdir(cwd)
        argv = ["x", str(archive), "--overwrite", overwrite, *args, *extra]
        assert main(argv) == EXIT_OK
        runs.append((_tree(cwd), capsys.readouterr().err))
    return runs[0], runs[1]


# The lines only the hoist prints: where the wrapper went.
_HOIST_ONLY = ("extracting into ", "moved to ", "removed wrapper")


def _as_direct(hoist_err: str) -> list[str]:
    """The hoist's stderr lines as ``-d .`` would print them, sorted: without the lines
    about the wrapper.

    Sorted because the order differs: the merge prints its own lines while it moves,
    before the per-member lines, and ``-d .`` prints every line in member order. Pass
    ``-d .``'s stderr through it too."""
    return sorted(
        ln for ln in hoist_err.split("\n") if ln and not ln.startswith(_HOIST_ONLY)
    )


@pytest.mark.parametrize(
    "entries",
    [{"foo": b"ARCHIVE"}, {"foo/": b"", "foo/x.txt": b"ARCHIVE"}],
    ids=["file-root", "dir-root"],
)
def test_hoist_renames_a_root_as_a_direct_extraction_does(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    entries: dict[str, bytes],
) -> None:
    """``foo.tar`` holding ``foo``, with the operator's own ``foo`` in the cwd: the
    hoist renames the root to ``foo (1)``, the name ``-d .`` gives it.

    It used to move the root to ``foo (2)``, as its own wrapper held ``foo (1)``.
    """
    (hoisted, hoist_err), (direct, direct_err) = _hoist_and_direct(
        tmp_path, monkeypatch, capsys, "foo.tar", entries, {"foo": b"MINE"}
    )
    assert "extracting into foo (1)/" in hoist_err
    # Nothing was flattened: the root moved, under a new name.
    assert "moved to foo (1)" in hoist_err
    assert "removed wrapper" not in hoist_err
    assert hoisted == direct
    assert hoisted["foo"] == b"MINE"
    assert _report_lines(hoist_err, "renamed: ") == ["renamed: foo -> foo (1)"]
    assert _report_lines(direct_err, "renamed: ") == ["renamed: foo -> foo (1)"]


@pytest.mark.parametrize(
    "mine",
    [{}, {"top": b"MINE"}],
    ids=["root-kept-its-name", "root-renamed"],
)
def test_hoist_reports_member_paths_where_they_landed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mine: dict[str, bytes],
) -> None:
    """The per-member lines name each member where it is after the hoist.

    They named it inside the wrapper (``t/top/c%02``), which the hoist removed.
    """
    entries = {"top/": b"", "top/c\x02": b"c", "top/a\x01b/f": b"f"}
    (hoisted, hoist_err), (direct, direct_err) = _hoist_and_direct(
        tmp_path, monkeypatch, capsys, "t.tar", entries, mine
    )
    assert "extracting into t/" in hoist_err
    assert hoisted == direct
    root = "top (1)" if mine else "top"
    rewritten = _report_lines(hoist_err, "name rewritten: ")
    assert rewritten == _report_lines(direct_err, "name rewritten: ")
    assert sorted(rewritten) == [
        f"name rewritten: top/a\\x01b/f -> {root}/a%01b/f",
        f"name rewritten: top/c\\x02 -> {root}/c%02",
    ]
    assert _report_lines(hoist_err, "renamed: ") == _report_lines(
        direct_err, "renamed: "
    )


@pytest.mark.parametrize(
    ("archive_name", "entries", "mine", "args"),
    [
        (
            "t.tar",
            {"top/": b"", "top/c\x02": b"ARCHIVE"},
            {"top/c%02": b"MINE"},
            (),
        ),
        (
            "t3.tar",
            {"top/": b"", "top/a\x01": b"A", "top/c\x02": b"ARCHIVE"},
            {"top/c%02": b"MINE"},
            (),
        ),
        ("c.tar", {"c\x02": b"ARCHIVE"}, {"c%02": b"MINE"}, ()),
        ("c.tar", {"c\x02": b"ARCHIVE"}, {"c%02": b"MINE"}, ("-v",)),
        (
            "c.tar",
            {"/c\x02": b"ARCHIVE"},
            {"c%02": b"MINE"},
            ("--policy", "standard"),
        ),
    ],
    ids=[
        "collision-inside-root",
        "collision-inside-root-after-another-line",
        "collision-at-root",
        "collision-at-root-verbose",
        "collision-at-rerooted-root",
    ],
)
def test_hoist_reports_what_the_merge_renamed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    archive_name: str,
    entries: dict[str, bytes],
    mine: dict[str, bytes],
    args: tuple[str, ...],
) -> None:
    """A member whose rewritten name collides with the operator's file while the
    hoist merges under ``rename``: the layout and the per-member lines are those of
    ``-d .``. The line names ``c%02 (1)``, where the member is; it used to name
    ``c%02``.
    """
    (hoisted, hoist_err), (direct, direct_err) = _hoist_and_direct(
        tmp_path, monkeypatch, capsys, archive_name, entries, mine, "rename", args
    )
    assert hoisted == direct
    assert _as_direct(hoist_err) == _as_direct(direct_err)
    if archive_name == "t3.tar":
        # The order the cli spec states: the merge's own line, then the per-member ones.
        lines = hoist_err.split("\n")
        rewritten = [
            i for i, ln in enumerate(lines) if ln.startswith("name rewritten: ")
        ]
        assert len(rewritten) == 2
        assert lines.index("renamed: top/c%02 -> top/c%02 (1)") < min(rewritten)


def test_hoist_reports_an_existing_directory_keeping_its_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The archive's ``top/`` (0755) merges into the operator's ``top/`` (0700): the
    operator's keeps its mode, and the hoist says so with the line ``-d .`` prints.

    Only the library printed it, and after a hoist the library never meets the
    operator's directory: the merge does.

    On Windows a mode is only the read-only attribute, and 0700 is as writable as
    0755, so the operator's directory there is a read-only one (0500, shown as 0555)."""
    mine_mode, shown = (0o500, 0o555) if os.name == "nt" else (0o700, 0o700)
    (hoisted, hoist_err), (direct, direct_err) = _hoist_and_direct(
        tmp_path,
        monkeypatch,
        capsys,
        "t.tar",
        {"top/": b"", "top/a.txt": b"ARCHIVE"},
        {"top/m": b"MINE"},
        mine_modes={"top": mine_mode},
    )
    assert hoisted == direct
    line = f"kept existing directory's mode {shown:04o}: top"
    assert _report_lines(direct_err, "kept ") == [line]
    assert _report_lines(hoist_err, "kept ") == [line]
    assert _as_direct(hoist_err) == _as_direct(direct_err)
    for how in ("hoist", "direct"):
        assert (tmp_path / "rename" / how / "top").stat().st_mode & 0o777 == shown


@pytest.mark.skipif(os.name == "nt", reason="simulates Windows modes with chmod")
@pytest.mark.parametrize(
    ("mine_mode", "member_mode", "kept"),
    [
        (0o700, 0o755, None),
        (0o500, 0o755, 0o555),
        (0o700, 0o555, 0o777),
        (0o500, 0o555, None),
    ],
    ids=["both-writable", "mine-read-only", "member-read-only", "both-read-only"],
)
def test_hoist_and_direct_agree_on_a_kept_mode_under_windows_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mine_mode: int,
    member_mode: int,
    kept: int | None,
) -> None:
    """Simulated on POSIX: on Windows a directory's mode is only its read-only
    attribute, which ``os.stat`` shows as ``0o777`` or ``0o555``. The hoist compares
    the mode extraction gave the archive's ``top/``; ``-d .`` compares the member's
    mode as Windows stores it. Both print the line exactly when the read-only
    attribute differs, and with the same mode. STANDARD keeps a directory's stored
    mode; STRICT would make every one 0755."""
    from archivey.internal import extraction

    real_chmod = os.chmod

    def windows_chmod(path, mode, *args, **kwargs):  # type: ignore[no-untyped-def]
        st = os.stat(path, dir_fd=kwargs.get("dir_fd"))
        if stat.S_ISDIR(st.st_mode):
            mode = 0o777 if mode & stat.S_IWUSR else 0o555
        real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(extraction, "_WINDOWS", True)
    monkeypatch.setattr(os, "chmod", windows_chmod)
    (hoisted, hoist_err), (direct, direct_err) = _hoist_and_direct(
        tmp_path,
        monkeypatch,
        capsys,
        "t.tar",
        {"top/": b""},
        {"top/m": b"MINE"},
        args=("--policy", "standard"),
        mine_modes={"top": mine_mode},
        dir_mode=member_mode,
    )
    assert hoisted == direct
    lines = [] if kept is None else [f"kept existing directory's mode {kept:04o}: top"]
    assert _report_lines(direct_err, "kept ") == lines
    assert _report_lines(hoist_err, "kept ") == lines
    assert _as_direct(hoist_err) == _as_direct(direct_err)
    shown = 0o777 if mine_mode & stat.S_IWUSR else 0o555
    for how in ("hoist", "direct"):
        assert (tmp_path / "rename" / how / "top").stat().st_mode & 0o777 == shown


def test_stopped_hoist_names_members_left_in_the_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When the cwd changes after the check, the hoist stops at the operator's
    ``c%02`` under ``--overwrite error`` and leaves the member in the wrapper: its
    line names ``c/c%02``, where it is, not the operator's ``c%02``."""
    from archivey.cli import extract_cmd

    monkeypatch.setattr(extract_cmd, "_first_clash", lambda *args: None)
    archive = tmp_path / "c.tar"
    with tarfile.open(archive, "w") as tf:
        info = tarfile.TarInfo("c\x02")
        info.size = 7
        tf.addfile(info, io.BytesIO(b"ARCHIVE"))
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "c%02").write_bytes(b"MINE")
    monkeypatch.chdir(cwd)
    assert main(["x", str(archive), "--overwrite", "error"]) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "hoist stopped; remaining files left in c/" in err
    assert _report_lines(err, "name rewritten: ") == [
        "name rewritten: c\\x02 -> c/c%02"
    ]
    assert (cwd / "c" / "c%02").read_bytes() == b"ARCHIVE"
    assert (cwd / "c%02").read_bytes() == b"MINE"


def test_flatten_failing_part_way_names_each_entry_where_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``s/s/a.txt`` moved up to ``s/a.txt`` before the flatten failed on ``b.txt``:
    each is named where it is, not both inside the directory ``a.txt`` left."""
    from archivey.cli import extract_cmd

    monkeypatch.chdir(tmp_path)
    (tmp_path / "s" / "s").mkdir(parents=True)
    for name in ("a.txt", "b.txt"):
        (tmp_path / "s" / "s" / name).write_bytes(b"x")
    real_rename = extract_cmd._rename
    calls = []

    def rename_once(src: Path, dest: Path) -> None:
        calls.append(src)
        if len(calls) > 1:
            raise OSError(28, "No space left on device")
        real_rename(src, dest)

    monkeypatch.setattr(extract_cmd, "_rename", rename_once)
    result = extract_cmd.maybe_hoist_single_root(
        Path("s"), overwrite=OverwritePolicy.RENAME, err=io.StringIO()
    )
    assert not result.ok
    assert (tmp_path / "s" / "a.txt").exists()
    assert (tmp_path / "s" / "s" / "b.txt").exists()
    target, moves = Path("s"), result.moves
    assert extract_cmd._relative_name(Path("s/s/a.txt"), target, moves) == "s/a.txt"
    assert extract_cmd._relative_name(Path("s/s/b.txt"), target, moves) == "s/s/b.txt"


def test_relative_name_falls_back_to_forward_slashes() -> None:
    """A path outside the root is reported whole — ``/``-separated, never native.

    Pinned with a Windows-flavoured path so the check has teeth on a POSIX runner,
    where ``str()`` of a native path already has forward slashes.
    """
    from pathlib import PureWindowsPath

    from archivey.cli.extract_cmd import _relative_name

    landed = PureWindowsPath("C:/out/elsewhere/a.txt")
    assert _relative_name(landed, PureWindowsPath("D:/target")) == (
        "C:/out/elsewhere/a.txt"
    )


def test_unmatched_pattern_hint_escapes_the_suggested_dest(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ``-d`` hint repeats the pattern; it is escaped like the ``!r`` form beside it."""
    assert main(["x", str(sample_zip), "ev\x1bil/"]) == EXIT_FAIL
    lines = _report_lines(capsys.readouterr().err, "warning: pattern matched")
    assert lines == [
        "warning: pattern matched no members: 'ev\\x1bil/' (did you mean -d ev\\x1bil?)"
    ]


def test_escape_path_renders_forward_slashes() -> None:
    """A native path is ``/``-separated before escaping, so separators never double."""
    from archivey.cli.format import escape_path

    assert escape_path(Path("dir") / "sub" / "a.txt") == "dir/sub/a.txt"
    assert escape_path(Path("dir") / "ev\x1bil") == "dir/ev\\x1bil"


def _write_zip_with_comment(path: Path, comment: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"hi")
        zf.comment = comment
    return path


def test_info_escapes_the_archive_comment_on_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The comment reaches **stdout**, so ``2>/dev/null`` hides nothing.

    A ZIP comment is arbitrary bytes and ``info`` is the verb an operator runs to learn
    what a file is before touching it; printed raw, the archive picks that answer.
    """
    archive = _write_zip_with_comment(
        tmp_path / "cmt.zip", b"ev\x1b[2Kil\rSAFE ARCHIVE\nsecond line"
    )
    assert main(["info", str(archive)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\r" not in out
    lines = [ln for ln in out.split("\n") if ln.startswith("comment:")]
    assert lines == ["comment:     ev\\x1b[2Kil\\rSAFE ARCHIVE\\nsecond line"]


def test_info_leaves_an_ordinary_comment_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _write_zip_with_comment(tmp_path / "cmt.zip", "Café release".encode())
    assert main(["info", str(archive)]) == EXIT_OK
    assert "comment:     Café release\n" in capsys.readouterr().out


def test_info_escapes_every_value_it_prints() -> None:
    """Not only the comment: version strings and ``extra`` entries come from backends.

    Pinned on the line helper because no fixture carries a hostile version or ``extra``
    value today; the point is that a new one cannot reach the terminal raw.
    """
    from archivey.cli.info_cmd import _line

    out = io.StringIO()
    _line("extra.x\x1bkey", "v\x1b[2K\rspoof", out)
    _line("solid", True, out)
    assert out.getvalue() == (
        "extra.x\\x1bkey: v\\x1b[2K\\rspoof\n" + "solid:       True\n"
    )


def test_info_open_failure_is_not_escaped_twice(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An archivey exception has escaped its own message; ``info`` must not redo it."""
    bad = tmp_path / f"{_SPOOF_PORTABLE_ROOT}.zip"
    # Cut inside the first local header: no member to list.
    bad.write_bytes(b"PK\x03\x04" + b"\x00" * 20)
    assert main(["info", str(bad)]) != EXIT_OK
    err = capsys.readouterr().err
    open_lines = _report_lines(err, "open:")
    assert len(open_lines) == 1
    assert "ev\\u2028il.zip" in open_lines[0]  # escaped once, by the exception
    assert "ev\\\\u2028il.zip" not in open_lines[0]  # …and not again


# --- O9: archive-derived text on the LOG path, not just the print path -------------


def _log_through_cli_handler(msg: str, *args: object, **kwargs: object) -> str:
    """Emit one record through the handler ``cli_logging`` installs, return the output."""
    import logging

    from archivey.cli.logging_config import cli_logging

    err = io.StringIO()
    with cli_logging(verbose=False, err=err):
        logging.getLogger("archivey.test").warning(msg, *args, **kwargs)
    return err.getvalue()


def test_log_records_escape_archive_derived_text() -> None:
    """The log path carries archive text too, and reaches the same stderr.

    It is closed at the source rather than at the handler: the exception escapes its own
    message, so interpolating it into a record cannot reintroduce the spoof. This is the
    real shape of the only library site that logs one (``extraction.py``'s
    ``"Skipping %s %r: %s"``).
    """
    exc = ArchiveyError("Destination already exists: /out/ev\x1b[2Kil\rSPOOF.txt")
    out = _log_through_cli_handler("Skipping %s %r: %s", "file", "ev\x1b[2Kil.txt", exc)
    assert "\x1b" not in out  # no raw escape sequence
    assert "\r" not in out.rstrip("\n")  # no carriage-return line rewrite
    assert "\\x1b[2K" in out  # …shown losslessly instead


def test_log_records_escape_diagnostic_messages() -> None:
    """``diagnostics_collector`` logs ``"%s"`` of a diagnostic message verbatim.

    That is the one library log site whose interpolation is not an exception and not
    ``%r``, so the diagnostic escapes its own message for the same reason an exception
    does.
    """
    from archivey.diagnostics import (
        Diagnostic,
        DiagnosticCode,
        MemberNameControlsContext,
    )

    diagnostic = Diagnostic(
        occurrence_id="1",
        code=DiagnosticCode.MEMBER_NAME_BIDI_CONTROL,
        message="Member name has controls: /out/ev\x1b[2Kil\rSPOOF.txt",
        context=MemberNameControlsContext(member_name="ev\x1b[2Kil.txt"),
    )
    out = _log_through_cli_handler("%s", diagnostic.message)
    assert "\x1b" not in out
    assert "\\x1b[2K" in out
    # …while the structured channel keeps the real value for a JSON sink.
    assert diagnostic.context.member_name == "ev\x1b[2Kil.txt"


def test_log_records_keep_tracebacks_readable() -> None:
    """Escaping the message must not collapse a multi-line traceback onto one line.

    The traceback is rendered by the stdlib from the exception, not escaped as a block —
    and its final line is safe on its own, because it is the exception's escaped message.
    """
    try:
        raise ArchiveyError("boom: /out/ev\x1b[2Kil\rSPOOF.txt")
    except ArchiveyError:
        out = _log_through_cli_handler("failed", exc_info=True)
    assert "Traceback (most recent call last):" in out
    assert out.count("\n") > 2  # still multi-line
    assert "\x1b" not in out  # …and the final line carries no raw escape
    assert "\\x1b[2K" in out


def test_library_log_records_reach_other_handlers_unescaped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``cli_logging`` leaves ``propagate`` alone, and no longer rewrites records.

    Escaping moved to the message's source, so the CLI handler is an ordinary
    ``logging.Formatter`` again — an embedding app's handler, or caplog here, sees
    exactly the record the library emitted, args included.
    """
    import logging

    from archivey.cli.logging_config import cli_logging

    err = io.StringIO()
    with (
        caplog.at_level(logging.WARNING, logger="archivey.test"),
        cli_logging(verbose=False, err=err),
    ):
        logging.getLogger("archivey.test").warning("name: %r", "ev\x1b[2Kil.txt")

    assert caplog.records[-1].getMessage() == "name: 'ev\\x1b[2Kil.txt'"
    assert caplog.records[-1].args == ("ev\x1b[2Kil.txt",)


def test_uncaught_exception_traceback_reaches_stderr_inert() -> None:
    """The route that no display site can guard: the interpreter prints the traceback.

    A formatter never sees this, and neither does a print site — the interpreter renders
    the exception itself, and its final line is ``str(exc)``. This is why the escaping
    lives at construction rather than at the CLI's handler. Run out-of-process so the
    real ``sys.excepthook`` path is exercised, not a captured string.
    """
    import subprocess

    code = (
        "from archivey.exceptions import ExtractionError\n"
        "raise ExtractionError('Destination exists: /out/ev\\x1b[2Kil\\rSPOOF.txt')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert proc.returncode != 0
    assert "\x1b" not in proc.stderr  # no raw escape sequence reached the terminal
    assert "\\x1b[2K" in proc.stderr  # …shown losslessly on the traceback's last line
    assert "Traceback (most recent call last):" in proc.stderr


def test_log_escaping_leaves_ordinary_messages_alone() -> None:
    """No cosmetic churn for the overwhelmingly common case."""
    out = _log_through_cli_handler("Skipping file %r: plain reason", "dir/file.txt")
    assert out == "WARNING: Skipping file 'dir/file.txt': plain reason\n"


def test_abort_notice_escapes_the_error_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The abort path prints the exception itself, not a report line.

    ``NameCollisionError``'s message embeds the already-written path, which is built
    from the member name — the same spoof class as the log path, reached through a
    different print site. Uses the Windows-legal spoof so the print site is covered on
    every platform; the ANSI variant below is the real erase-and-rewrite sequence.
    """
    archive = _zip(
        tmp_path / "c.zip", {_SPOOF_PORTABLE: b"A", _SPOOF_PORTABLE.upper(): b"B"}
    )
    dest = tmp_path / "out"
    main(["x", str(archive), "-d", str(dest), "--abort-on", "name-collision"])
    err = capsys.readouterr().err
    assert "Name collision" in err
    assert " " not in err
    assert "\\u2028" in err


def test_abort_notice_escapes_an_ansi_spoof(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real spoof through the abort print site.

    The default policy writes the control bytes as %XX, so the path in the notice is
    already safe; the member name it also carries is the stored one, raw bytes and
    all. With the bytes escaped on disk the member is written on Windows too, so this
    runs on every platform.
    """
    archive = _zip(tmp_path / "c.zip", {_SPOOF_ANSI: b"A", _SPOOF_ANSI.upper(): b"B"})
    dest = tmp_path / "out"
    main(["x", str(archive), "-d", str(dest), "--abort-on", "name-collision"])
    err = capsys.readouterr().err
    assert "Name collision" in err
    assert "\x1b" not in err
    assert "\r" not in err
    assert "EV\\x1b[2KIL\\rSUCCESS.TXT" in err


def test_test_verb_escapes_failure_detail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``archivey test`` appends the exception to its FAIL line; that is a print site too.

    Driven through the real verb: the member read raises an ``ArchiveyError`` whose
    message embeds a member-derived path, which is how a hostile name reaches this line.
    """
    from archivey.exceptions import ArchiveyError

    archive = _zip(tmp_path / "t.zip", {"a.txt": b"A"})

    def boom(*_args: object, **_kwargs: object):
        # Raise from the iterator, not the call: the FAIL branch wraps ``next(it)``,
        # while a call-time raise lands in main()'s top-level handler instead.
        def _gen():
            raise ArchiveyError(f"Error reading member: /out/{_SPOOF_ANSI}")
            yield  # pragma: no cover - unreachable, makes this a generator

        return MemberPass._new(_gen())

    monkeypatch.setattr(
        "archivey.internal.base_reader.BaseArchiveReader.stream_members", boom
    )
    main(["test", str(archive)])
    err = capsys.readouterr().err
    lines = _report_lines(err, "FAIL")
    assert lines, err
    assert all("\x1b" not in ln for ln in lines)
    assert any("\\x1b[2K" in ln for ln in lines)


def test_dunder_main_is_importable_without_running_the_cli() -> None:
    """``python -m archivey`` runs the module as ``__main__``; a plain import must not.

    Without the ``if __name__`` guard, importing ``archivey.__main__`` — which any
    package walker, docs autoapi pass or import-based coverage warm-up does — ran the
    CLI against whatever ``sys.argv`` the host happened to have and exited from inside
    the import.
    """
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-c", "import archivey.__main__; print('imported')"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "imported" in proc.stdout
    assert "usage:" not in proc.stderr


# --- S24-K3: a bare ``--`` takes the default verb ahead of the separator ---


def test_inject_default_list_puts_verb_before_separator() -> None:
    assert _inject_default_list(["--", "-w.zip"]) == ["list", "--", "-w.zip"]
    assert _inject_default_list(["--track-io", "--", "a.zip"]) == [
        "--track-io",
        "list",
        "--",
        "a.zip",
    ]
    # After ``--`` every token is a positional, so a verb-shaped word is an archive name.
    assert _inject_default_list(["--", "list"]) == ["list", "--", "list"]
    # A spelled verb before ``--`` is left alone.
    assert _inject_default_list(["list", "--", "a.zip"]) == ["list", "--", "a.zip"]


def test_inject_default_list_skips_only_pre_verb_option_values() -> None:
    # A value-taking option the main parser knows: its value is not the verb.
    assert _inject_default_list(["--password", "list", "a.zip"]) == [
        "--password",
        "list",
        "list",
        "a.zip",
    ]


@pytest.mark.parametrize(
    "flag",
    ["--abort-on", "--policy", "--overwrite", "-d", "--dest", "--exclude"],
)
def test_verb_option_before_verb_is_named_as_unrecognized(
    flag: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # The main parser does not know a verb's options, so it does not consume their
    # value. The value is then the first positional, and an injection that skipped it
    # blamed the value as an invalid verb instead of naming the misplaced flag.
    assert main([flag, "blocked-member", "x", "a.zip"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert f"unrecognized arguments: {flag}" in err
    assert "invalid choice" not in err
    # ...and names the verb it belongs to.
    assert f"({flag} is an option of '" in err
    assert "; it goes after " in err


def test_verb_option_hint_names_every_verb_that_takes_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--policy=strict", "a.zip"]) == EXIT_USAGE
    assert (
        "(--policy is an option of 'extract'; "
        "it goes after that verb: archivey extract ARCHIVE --policy ...)"
    ) in capsys.readouterr().err
    assert main(["--exclude", "p", "a.zip"]) == EXIT_USAGE
    assert (
        "(--exclude is an option of 'list', 'test', 'extract', 'cat'; "
        "it goes after one of those verbs)"
    ) in capsys.readouterr().err


def test_verb_option_after_another_verb_is_not_called_misplaced(
    sample_zip: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The flag already follows a verb, just not one that takes it.
    assert main(["list", str(sample_zip), "--policy", "strict"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "(--policy is an option of 'extract';" in err
    assert "put it after the verb" not in err


def test_tar_flag_hint_matches_whole_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # ``--my-list`` contains ``-l`` but is not the tar spelling of ``l``.
    assert main(["x", "a.zip", "--my-list"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "unrecognized arguments: --my-list" in err
    assert "archivey l" not in err
    # A stray positional is not a bundle either, even when its letters include i/l/t.
    assert main(["info", "a.zip", "list"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "unrecognized arguments: list" in err
    assert "bare words" not in err


@pytest.mark.parametrize(
    ("bundle", "verb"),
    [
        ("-xvf", "x"),
        ("-tzf", "t"),
        ("-zxvf", "x"),
        ("-l", "l"),
        ("-xZf", "x"),
        ("-xmf", "x"),
        ("-xhf", "x"),
    ],
)
def test_tar_flag_hint_matches_short_option_bundles(
    bundle: str, verb: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # ``tar -xvf`` habit: the bundle's first verb letter is the verb meant.
    assert main([bundle, "a.tar"]) == EXIT_USAGE
    assert f"try 'archivey {verb} ARCHIVE'" in capsys.readouterr().err


@pytest.mark.parametrize(
    "word",
    ["-exclude", "-file", "-name", "-dest", "-max", "-math", "-mix", "-all", "-tail"],
)
def test_tar_flag_hint_skips_single_dash_words(
    word: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # A mistyped long option is not a tar bundle: ``-exclude`` does not mean ``x``.
    assert main(["l", "a.zip", word, "a*"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert f"unrecognized arguments: {word}" in err
    assert "bare words" not in err


def test_double_dash_lists_dash_named_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    _zip(tmp_path / "-w.zip", {"inner.txt": b"x"})
    assert main(["--", "-w.zip"]) == EXIT_OK
    assert "inner.txt" in capsys.readouterr().out


# --- The bpo-26240 workaround matches the ``pattern`` metavar ---


def test_missing_archive_message_omits_optional_patterns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["x"]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "the following arguments are required: archive\n" in err
    assert "pattern" not in err.splitlines()[-1]


# --- S24-K2: the CLI's own wrap directory never goes through a symlink ---


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"cannot create symlinks here: {exc}")


def test_smart_dest_steps_aside_from_dangling_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    z = _zip(tmp_path / "pkg.zip", {"a.txt": b"a", "b.txt": b"b"})
    _symlink_or_skip(tmp_path / "pkg", tmp_path / "nowhere")
    assert main(["x", str(z)]) == EXIT_OK
    assert (tmp_path / "pkg (1)" / "a.txt").read_bytes() == b"a"
    assert not (tmp_path / "nowhere").exists()


def test_smart_dest_does_not_follow_symlink_to_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    z = _zip(tmp_path / "pkg.zip", {"a.txt": b"a", "b.txt": b"b"})
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _symlink_or_skip(tmp_path / "pkg", elsewhere)
    assert main(["x", str(z), "--overwrite", "replace"]) == EXIT_OK
    assert list(elsewhere.iterdir()) == []
    assert (tmp_path / "pkg (1)" / "b.txt").read_bytes() == b"b"


# --- The wrapper named after the archive is always a folder this run creates ---


@pytest.mark.parametrize("overwrite", ["error", "skip", "replace", "rename"])
def test_smart_dest_steps_aside_from_a_file_at_the_wrapper_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overwrite: str,
) -> None:
    # An archive with no extension: its stem is its own name, so the file is in the way.
    monkeypatch.chdir(tmp_path)
    archive = _zip(tmp_path / "backup", {"a.txt": b"a", "b.txt": b"b"})
    assert main(["x", "--overwrite", overwrite, str(archive)]) == EXIT_OK
    assert "extracting into backup (1)/" in capsys.readouterr().err
    assert (tmp_path / "backup (1)" / "a.txt").read_bytes() == b"a"
    assert archive.is_file()


@pytest.mark.parametrize("overwrite", ["error", "skip", "replace", "rename"])
def test_smart_dest_never_reuses_an_existing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overwrite: str
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.txt").write_bytes(b"mine")
    z = _zip(tmp_path / "pkg.zip", {"a.txt": b"a", "b.txt": b"b"})
    assert main(["x", "--overwrite", overwrite, str(z)]) == EXIT_OK
    assert sorted(p.name for p in (tmp_path / "pkg").iterdir()) == ["a.txt"]
    assert (tmp_path / "pkg" / "a.txt").read_bytes() == b"mine"
    assert (tmp_path / "pkg (1)" / "a.txt").read_bytes() == b"a"
    assert (tmp_path / "pkg (1)" / "b.txt").read_bytes() == b"b"


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("overwrite", ["error", "skip", "replace", "rename"])
def test_hoist_runs_when_a_directory_has_the_wrapper_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overwrite: str,
    dry_run: bool,
) -> None:
    # Whether the single root moves up depends on the archive alone.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "bundle").mkdir()
    (tmp_path / "bundle" / "notes.txt").write_bytes(b"mine")
    archive = _tar(tmp_path / "bundle.tar", {"root/a.txt": b"x"})
    args = ["x", "--overwrite", overwrite, str(archive)]
    args += ["--dry-run"] if dry_run else []
    assert main(args) == EXIT_OK
    err = capsys.readouterr().err
    assert "into bundle (1)/" in err
    needle = "would move to root/" if dry_run else "moved to root/"
    assert needle in err
    assert "already there" not in err
    assert sorted(p.name for p in (tmp_path / "bundle").iterdir()) == ["notes.txt"]
    assert not (tmp_path / "bundle (1)").exists()
    if not dry_run:
        assert (tmp_path / "root" / "a.txt").read_bytes() == b"x"


@pytest.mark.parametrize(
    ("overwrite", "code", "expected", "leftover"),
    [
        # A colliding file keeps the whole root in the new wrapper; nothing moves.
        *(
            (
                overwrite,
                EXIT_OK,
                {"src/a.txt": b"mine-a", "src/c.txt": b"mine-c"},
                {"src (1)/src/a.txt": b"new-a", "src (1)/src/b.txt": b"new-b"},
            )
            for overwrite in ("error", "replace", "skip")
        ),
        (
            "rename",
            EXIT_OK,
            {
                "src/a.txt": b"mine-a",
                "src/a (1).txt": b"new-a",
                "src/b.txt": b"new-b",
                "src/c.txt": b"mine-c",
            },
            {},
        ),
    ],
)
def test_hoist_merges_root_named_like_stem_into_existing_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overwrite: str,
    code: int,
    expected: dict[str, bytes],
    leftover: dict[str, bytes],
) -> None:
    # src.tar holding src/, with ./src taken: the wrapper is "src (1)/", the sole
    # root no longer shares its name, so it is merged into ./src under the policy
    # instead of flattened in place.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_bytes(b"mine-a")
    (tmp_path / "src" / "c.txt").write_bytes(b"mine-c")
    archive = _tar(tmp_path / "src.tar", {"src/a.txt": b"new-a", "src/b.txt": b"new-b"})
    assert main(["x", "--overwrite", overwrite, str(archive)]) == code
    assert "into src (1)/" in capsys.readouterr().err
    found = {
        p.relative_to(tmp_path).as_posix(): p.read_bytes()
        for p in tmp_path.rglob("*")
        if p.is_file() and p != archive
    }
    assert found == {**expected, **leftover}
    if not leftover:
        assert not (tmp_path / "src (1)").exists()


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("overwrite", ["rename", "replace", "error", "skip"])
@pytest.mark.parametrize("root", ["foo (1)", "FOO (1)"])
def test_hoist_moves_a_root_named_like_the_wrappers_aside_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    root: str,
    overwrite: str,
    dry_run: bool,
) -> None:
    # foo.tar holding "foo (1)/": the wrapper is foo/, and the hoist steps it aside
    # before the merge. The aside directory must not be the root's destination, or
    # the root merges into the wrapper itself and loses a path component.
    # "FOO (1)" is that same entry only on a case-insensitive filesystem: the case
    # runs everywhere, but only macOS and Windows runs can fail it.
    monkeypatch.chdir(tmp_path)
    archive = _tar(tmp_path / "foo.tar", {f"{root}/x.txt": b"x"})
    args = ["x", "--overwrite", overwrite, str(archive)]
    args += ["--dry-run"] if dry_run else []
    assert main(args) == EXIT_OK
    err = capsys.readouterr().err
    assert "into foo/" in err
    assert (f"would move to {root}/" if dry_run else f"moved to {root}/") in err
    assert "hoist failed" not in err
    if dry_run:
        assert sorted(p.name for p in tmp_path.iterdir()) == ["foo.tar"]
    else:
        assert (tmp_path / root / "x.txt").read_bytes() == b"x"
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted([root, "foo.tar"])


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("overwrite", ["rename", "replace", "error", "skip"])
@pytest.mark.parametrize(
    ("stem", "member", "top"),
    [("file", "FILE", "FILE"), ("plain", "PLAIN/a", "PLAIN/")],
)
def test_hoist_moves_a_root_named_like_the_wrapper_but_for_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stem: str,
    member: str,
    top: str,
    overwrite: str,
    dry_run: bool,
) -> None:
    # file.tar holding the file "FILE" and plain.tar holding the directory "PLAIN/":
    # the wrapper is file/ or plain/, and the root keeps its own spelling, as a
    # direct extraction writes it. On a case-insensitive filesystem ./FILE is the
    # wrapper itself, which is no collision with the operator's data. Runs
    # everywhere. macOS can fail it through the clash check. Windows can fail it
    # through the clash check too, and through the in-place test, where paths
    # compare equal across case (PLAIN/ then lands at ./plain/). Linux cannot,
    # because the names differ.
    monkeypatch.chdir(tmp_path)
    archive = _tar(tmp_path / f"{stem}.tar", {member: b"x"})
    args = ["x", "--overwrite", overwrite, str(archive)]
    args += ["--dry-run"] if dry_run else []
    assert main(args) == EXIT_OK
    err = capsys.readouterr().err
    assert f"into {stem}/" in err
    assert (f"would move to {top}" if dry_run else f"moved to {top}") in err
    assert "keep in" not in err
    assert "kept in" not in err
    if dry_run:
        assert sorted(p.name for p in tmp_path.iterdir()) == [f"{stem}.tar"]
    else:
        assert (tmp_path / member).read_bytes() == b"x"
        listed = sorted(p.name for p in tmp_path.iterdir())
        assert listed == sorted([top.rstrip("/"), f"{stem}.tar"])


def _tar_root_with_file(path: Path, *, explicit_root: bool) -> Path:
    """``foo.tar``-style archive holding ``<stem>/x.txt``, with or without a stored
    ``<stem>/`` directory entry."""
    with tarfile.open(path, "w") as tf:
        stem = path.name.removesuffix(".tar")
        if explicit_root:
            info = tarfile.TarInfo(stem)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tf.addfile(info)
        info = tarfile.TarInfo(f"{stem}/x.txt")
        info.size = 7
        tf.addfile(info, io.BytesIO(b"ARCHIVE"))
    return path


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("explicit_root", [False, True], ids=["implied", "stored"])
@pytest.mark.parametrize("overwrite", ["error", "skip", "replace", "rename"])
def test_hoist_keeps_the_root_when_the_operators_file_has_its_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overwrite: str,
    explicit_root: bool,
    dry_run: bool,
) -> None:
    """``foo.tar`` holding ``foo/x.txt``, with the operator's file ``foo``: no policy
    but ``rename`` can merge a directory into a file without deleting it, so the root
    stays in the wrapper ``foo (1)/`` and the run succeeds. ``rename`` moves the root
    to ``foo (1)``, as before. The dry run says the same."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    archive = _tar_root_with_file(tmp_path / "foo.tar", explicit_root=explicit_root)
    (cwd / "foo").write_bytes(b"MINE")
    args = ["x", "--overwrite", overwrite, str(archive)]
    args += ["--dry-run"] if dry_run else []
    assert main(args) == EXIT_OK
    err = capsys.readouterr().err
    assert "into foo (1)/" in err
    if overwrite == "rename":
        assert _report_lines(err, "would keep in " if dry_run else "kept in ") == []
        if not dry_run:
            assert (cwd / "foo (1)" / "x.txt").read_bytes() == b"ARCHIVE"
    else:
        prefix = "would keep in " if dry_run else "kept in "
        assert _report_lines(err, prefix) == [f"{prefix}foo (1)/: foo already exists"]
        assert err.rstrip().endswith("→ foo (1)/")
        if not dry_run:
            assert (cwd / "foo (1)" / "foo" / "x.txt").read_bytes() == b"ARCHIVE"
    assert (cwd / "foo").read_bytes() == b"MINE"
    if dry_run:
        assert sorted(p.name for p in cwd.iterdir()) == ["foo"]


@pytest.mark.parametrize("dry_run", [False, True])
def test_hoist_keeps_the_root_on_a_deep_clash_under_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    dry_run: bool,
) -> None:
    """A clash deep inside the operator's ``src/`` keeps the whole root in the
    wrapper under ``error``: nothing moves, not even the members that would not
    clash, and the run succeeds. The dry run predicts the same."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    (cwd / "src" / "lib").mkdir(parents=True)
    (cwd / "src" / "lib" / "x.txt").write_bytes(b"MINE")
    archive = _tar(
        tmp_path / "pkg.tar",
        {"src/a.txt": b"new-a", "src/lib/x.txt": b"new-x", "src/z.txt": b"new-z"},
    )
    args = ["x", "--overwrite", "error", str(archive)]
    args += ["--dry-run"] if dry_run else []
    assert main(args) == EXIT_OK
    err = capsys.readouterr().err
    prefix = "would keep in " if dry_run else "kept in "
    assert _report_lines(err, prefix) == [f"{prefix}pkg/: src/lib/x.txt already exists"]
    assert err.rstrip().endswith("→ pkg/")
    found = {
        p.relative_to(cwd).as_posix(): p.read_bytes()
        for p in cwd.rglob("*")
        if p.is_file()
    }
    expected = {"src/lib/x.txt": b"MINE"}
    if not dry_run:
        expected |= {
            "pkg/src/a.txt": b"new-a",
            "pkg/src/lib/x.txt": b"new-x",
            "pkg/src/z.txt": b"new-z",
        }
    assert found == expected


def test_extract_dot_dot_stem_writes_under_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "...zip" strips to "..": the wrapper must not be the parent directory.
    cwd = tmp_path / "work"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    archive = _zip(cwd / "...zip", {"a.txt": b"a", "b.txt": b"b"})
    assert main(["x", "--overwrite", "error", str(archive)]) == EXIT_OK
    assert (cwd / "archive" / "a.txt").read_bytes() == b"a"
    assert (cwd / "archive" / "b.txt").read_bytes() == b"b"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["work"]


# --- S24-K6: an incomplete ``test`` run exits nonzero even with no failure ---


def test_test_early_stop_without_error_exits_fail(
    sample_zip: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.base_reader import BaseArchiveReader

    real = BaseArchiveReader.stream_members

    def _one_then_stop(self: BaseArchiveReader, members: object = None) -> object:
        for item in real(self, members):
            yield item
            return

    monkeypatch.setattr(BaseArchiveReader, "stream_members", _as_pass(_one_then_stop))
    assert main(["test", str(sample_zip)]) == EXIT_FAIL
    assert "1 OK, 0 failed, 2 not tested" in capsys.readouterr().err


def test_extract_reports_reroots_once_not_per_member(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A ``tar -P`` backup re-roots every member; one summary line says so, and the
    per-member lines appear only under --verbose, including for a member whose name
    was also rewritten for portability."""
    archive = _tar(
        tmp_path / "t.tar",
        {"/etc/a": b"1", "/etc/b": b"2", "/var/log/c": b"3", "/d/y\udcff": b"4"},
    )
    dest = tmp_path / "out"
    assert main(["x", str(archive), "-d", str(dest), "--policy", "standard"]) == EXIT_OK
    err = capsys.readouterr().err
    assert "re-rooted 4 absolute member names inside the destination" in err
    assert "re-rooted: " not in err
    assert "name rewritten:" not in err
    assert (dest / "etc" / "a").read_bytes() == b"1"

    dest2 = tmp_path / "out2"
    assert (
        main(["x", str(archive), "-d", str(dest2), "--policy", "standard", "-v"])
        == EXIT_OK
    )
    err = capsys.readouterr().err
    assert "re-rooted: /etc/a -> etc/a" in err
    assert "re-rooted: /var/log/c -> var/log/c" in err
    assert "re-rooted: /d/y\\xff -> d/y%FF" in err
    assert "name rewritten:" not in err


def _tar_with_dirs(path: Path, names: list[str]) -> Path:
    import tarfile

    with tarfile.open(path, "w") as tf:
        for name in names:
            info = tarfile.TarInfo(name)
            if name.endswith("/"):
                # TarInfo's default mode is 0o644, without search permission.
                # archivey applies it only after the directory's members are written.
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.size = 1
                tf.addfile(info, io.BytesIO(b"x"))
    return path


@pytest.mark.parametrize(
    ("names", "extra_args"),
    [
        # No -d: the smart enclosing directory adds a component to every path.
        (["/etc/a", "/etc/b"], []),
        # Directory members keep their trailing ``/``; their paths do not.
        (["/etc/", "/etc/a", "/var/", "/var/log/", "/var/log/c"], ["-d", "out"]),
        # A collision suffix makes the path differ by more than the root.
        (["etc/a", "/etc/a"], ["-d", "out", "--overwrite", "rename"]),
    ],
    ids=["no-dest", "directories", "collision-rename"],
)
def test_extract_reroot_never_prints_a_default_rewrite_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    names: list[str],
    extra_args: list[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    archive = _tar_with_dirs(tmp_path / "backup.tar", names)
    assert main(["x", str(archive), "--policy", "standard", *extra_args]) == EXIT_OK
    err = capsys.readouterr().err
    assert "name rewritten:" not in err
    assert "re-rooted: " not in err
    rooted = sum(1 for n in names if n.startswith("/"))
    assert f"re-rooted {rooted} absolute member name" in err


# --- `archivey test` reports a symlink the same way on every format ---

_FIXTURES = Path(__file__).parent / "fixtures"


def _zip_with_links(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"alpha\n")
        for name, target in (("link", "a.txt"), ("dangling", "nowhere")):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            zf.writestr(info, target.encode())
    return path


def _tar_with_links(path: Path) -> Path:
    with tarfile.open(path, "w") as tf:
        data = b"alpha\n"
        info = tarfile.TarInfo("a.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        for name, target in (("link", "a.txt"), ("dangling", "nowhere")):
            link = tarfile.TarInfo(name)
            link.type = tarfile.SYMTYPE
            link.linkname = target
            tf.addfile(link)
    return path


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(_zip_with_links, id="zip"),
        pytest.param(_tar_with_links, id="tar"),
        pytest.param(
            lambda _: _FIXTURES / "sevenzip" / "links_mid_folder_solid.7z", id="7z"
        ),
        pytest.param(
            lambda _: _FIXTURES / "rar" / "symlinks_solid__rar4.rar",
            id="rar4",
            marks=requires_binary("unrar"),
        ),
        pytest.param(
            lambda _: _FIXTURES / "rar" / "symlinks_solid__.rar",
            id="rar5",
            marks=requires_binary("unrar"),
        ),
    ],
)
def test_test_verb_skips_every_readable_symlink_alike(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make: Callable[[Path], Path],
) -> None:
    """A symlink whose target the pass read prints ``skip`` and is not counted.

    7z and RAR4 keep a symlink's target as member data. A random-access pass used to
    leave it unread, so ``test`` opened each such link again after the pass (on a
    solid 7z, a second decode of its folder) and counted it ``OK``, where ZIP, RAR5
    and TAR printed ``skip``.
    """
    archive = make(tmp_path / "links.archive")
    with open_archive(archive) as reader:
        listed = reader.members()
        links = [m.name for m in listed if m.type is MemberType.SYMLINK]
        files = [m.name for m in listed if m.is_file]
    assert links and files

    def _no_reopen(*_args: object) -> None:
        raise AssertionError("a link with a read target was opened again")

    monkeypatch.setattr(test_cmd, "_verify_link", _no_reopen)
    assert main(["test", "-v", "--hide-progress", str(archive)]) == EXIT_OK
    lines = capsys.readouterr().err.splitlines()
    for name in links:
        assert f"skip {name}" in lines
        assert f"OK   {name}" not in lines
    assert f"{len(files)} OK, 0 failed" in lines


# --- --probe-content ------------------------------------------------------------------


def _raw_lzma(path: Path, data: bytes) -> Path:
    """A raw LZMA Alone stream under a name no extension rule knows."""
    import lzma

    path.write_bytes(lzma.compress(data, format=lzma.FORMAT_ALONE))
    return path


@pytest.mark.parametrize("before_verb", [True, False], ids=["global", "after-verb"])
@pytest.mark.parametrize("verb", ["list", "test", "extract", "info"])
def test_probe_content_recognises_a_raw_stream_with_an_unknown_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], verb: str, before_verb: bool
) -> None:
    src = _raw_lzma(tmp_path / "data.bi5", b"payload " * 64)
    rest = [str(src)] + (["-d", str(tmp_path / "out")] if verb == "extract" else [])
    argv = (
        ["--probe-content", verb, *rest]
        if before_verb
        else [verb, *rest, "--probe-content"]
    )
    assert main([*argv, "--hide-progress"]) == EXIT_OK
    if verb == "extract":
        (written,) = (tmp_path / "out").iterdir()
        assert written.read_bytes() == b"payload " * 64


def test_without_probe_content_the_refusal_names_the_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = _raw_lzma(tmp_path / "data.bi5", b"payload")
    assert main(["list", str(src)]) == EXIT_FAIL
    assert "on the command line, pass --probe-content" in capsys.readouterr().err
