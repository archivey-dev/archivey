"""Guard: a test runs the ``7z`` CLI through :func:`tests.conftest.run_7z`.

A ``7z`` run with no timeout once hung on a Windows CI leg. The per-test timeout then
killed the xdist worker and left no traceback. ``run_7z`` sets a timeout and gives the
child no stdin, so the hang becomes a ``subprocess.TimeoutExpired`` in the test that
caused it.

The scan reads every ``.py`` file under ``tests/`` and reports each process call
(``subprocess.run`` and the other runners, ``os.system``, ``os.popen``, ``os.exec*``,
``os.spawn*``) whose program is a literal naming the 7-Zip CLI, or whose program it
cannot read as a string literal (a variable, a call, a starred list). A literal names
the 7-Zip CLI when its file name without suffix is ``7z``, ``7zz`` or ``7za``, so
``/usr/bin/7z``, ``7z.exe`` and Homebrew's ``7zz`` count. Calls that start
``sys.executable`` or another literal program (``rar``, ``xz``, ``git``) are not
reported: the rule is about ``7z``, and reporting every such call would list 56
files, most of which never run ``7z``. The body of ``run_7z`` in ``tests/conftest.py``
is the helper itself and is not reported; a function of that name anywhere else is
scanned like any other code. The scan also reports ``import subprocess as X``,
``import os as X`` and a ``from subprocess``/``from os`` import of a runner name,
because a call through those names hides from the scan.

Not every file is converted yet. ``_UNCONVERTED`` maps each remaining file to the
number of calls the scan reports in it, so a new reported call in any file fails, and
a converted file must be taken off the list. Some entries run a program the scan
cannot name, which may not be ``7z``; their count still stops a new ``7z`` call from
hiding among them.

Mutations it was checked against: adding ``subprocess.run(["7z", "l", str(driver)])``
to a test in ``tests/test_sevenzip_reader.py`` fails it. So does each of these, added
to ``tests/test_zip.py`` (on the list with two): a third direct ``["7z", ...]`` call;
a ``def run_7z`` wrapper that calls ``subprocess.run(["7z", *args])``; and a
``subprocess.run(["7zz", ...])`` call.
"""

from __future__ import annotations

import ast
from pathlib import Path, PureWindowsPath

_TESTS = Path(__file__).resolve().parent
_HELPER_HOME = _TESTS / "conftest.py"
_HELPER = "run_7z"
_SEVEN_ZIP_PROGRAMS = frozenset({"7z", "7zz", "7za"})
_SUBPROCESS_RUNNERS = frozenset(
    {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
    }
)

# Files that still run ``7z``, or a program the scan cannot name, directly, with the
# number of such calls in each. Lower or remove an entry when you convert calls.
_UNCONVERTED: dict[str, int] = {
    # Each reported call starts the literal "7z".
    "test_audit2_cross_format.py": 1,
    "test_audit2_zip.py": 1,
    "test_audit_cross_format.py": 2,
    "test_audit_sevenzip.py": 2,
    "test_decoder_limits.py": 4,
    "test_detection.py": 1,
    "test_error_translation.py": 1,
    "test_key_derivation_budget.py": 2,
    "test_link_target_cap.py": 1,
    "test_listing_limits.py": 1,
    "test_password.py": 4,
    "test_sevenzip_arm64.py": 3,
    "test_sevenzip_bcj2.py": 1,
    "test_sevenzip_parser_hardening.py": 1,
    "test_sevenzip_password_confirm.py": 1,
    "test_surplus_input.py": 2,
    "test_volumes.py": 1,
    "test_windows_reparse.py": 1,
    "test_zip.py": 2,
    "test_zip_aes.py": 2,
    "test_zip_native_codecs.py": 2,
    "test_zip_parser.py": 1,
    # At least one reported call starts a program the scan cannot name.
    "atheris_fuzz/__main__.py": 1,
    "fuzz_tar_parser.py": 2,
    "sample_archives.py": 2,
    "test_cli.py": 2,
    "test_codecs.py": 3,
    "test_extraction.py": 1,
    "test_iso_trailing_data.py": 1,
    "test_public_api.py": 1,
    "test_rar_unrar_names.py": 1,
    "test_review_loop_gate.py": 3,
    "test_sevenzip_surrogate_names.py": 1,
    "test_tar_parser_differential.py": 3,
    "test_utf16_surrogate_names.py": 1,
}


def _is_runner(module: str, name: str) -> bool:
    if module == "subprocess":
        return name in _SUBPROCESS_RUNNERS
    return module == "os" and (
        name in {"system", "popen"} or name.startswith(("exec", "spawn"))
    )


def _program(arg: ast.expr | None) -> str | None:
    """The program a process call starts, or ``None`` when it is not a literal."""
    while isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        arg = arg.left
    if isinstance(arg, ast.List) and arg.elts:
        arg = arg.elts[0]
        if ast.unparse(arg) == "sys.executable":
            return "sys.executable"
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        words = arg.value.split()
        return words[0] if words else None
    return None


def _may_run_7z(program: str | None) -> bool:
    """Whether a call that starts ``program`` runs, or may run, the 7-Zip CLI."""
    if program is None:
        return True
    return PureWindowsPath(program).stem.lower() in _SEVEN_ZIP_PROGRAMS


def _calls_that_bypass_run_7z(path: Path) -> list[str]:
    """Each place in ``path`` that runs ``7z``, or may run it, without the helper."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    in_helper = {
        id(node)
        for func in (tree.body if path.resolve() == _HELPER_HOME else ())
        if isinstance(func, ast.FunctionDef) and func.name == _HELPER
        for node in ast.walk(func)
    }
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(
                (node.lineno, f"import {alias.name} as {alias.asname}")
                for alias in node.names
                if alias.name in {"subprocess", "os"} and alias.asname
            )
        elif isinstance(node, ast.ImportFrom) and node.module in {"subprocess", "os"}:
            found.extend(
                (node.lineno, f"from {node.module} import {alias.name}")
                for alias in node.names
                if alias.name == "*" or _is_runner(node.module, alias.name)
            )
        elif (
            isinstance(node, ast.Call)
            and id(node) not in in_helper
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and _is_runner(node.func.value.id, node.func.attr)
            and _may_run_7z(_program(node.args[0] if node.args else None))
        ):
            found.append((node.lineno, f"{ast.unparse(node.func)}(...)"))
    return [f"{line}: {what}" for line, what in sorted(found)]


def test_7z_cli_runs_go_through_the_bounded_helper() -> None:
    found = {
        path.relative_to(_TESTS).as_posix(): calls
        for path in sorted(_TESTS.rglob("*.py"))
        if (calls := _calls_that_bypass_run_7z(path))
    }
    wrong = {
        name: calls
        for name, calls in found.items()
        if len(calls) != _UNCONVERTED.get(name)
    }
    gone = sorted(_UNCONVERTED.keys() - found.keys())
    assert not wrong and not gone, (
        "A reported call that runs 7z must go through tests.conftest.run_7z. A "
        "reported call that starts another program the scan cannot name (a "
        "variable, a call) is allowed: add its file to _UNCONVERTED or raise the "
        "file's count. When you convert calls, lower or remove the count.\n"
        f"Count differs: {wrong}\nNo longer reported: {gone}"
    )


def test_the_scan_finds_each_way_to_bypass_the_helper(tmp_path: Path) -> None:
    """The scan above must not pass because it cannot see a call.

    The sample is not ``tests/conftest.py``, so the call inside its ``run_7z`` is
    reported.
    """
    sample = tmp_path / "sample.py"
    sample.write_text(
        "import os, subprocess, sys\n"
        "import subprocess as sp\n"
        "from subprocess import TimeoutExpired, run\n"
        "subprocess.run([sys.executable, '-c', 'pass'])\n"
        "subprocess.run(['xz', '-d', 'x.xz'])\n"
        "subprocess.run(['rar', 'a'] + ['x.rar'])\n"
        "subprocess.run(['7z', 'a', 'x.7z'])\n"
        "subprocess.check_output(['7z', 'l'] + ['x.7z'])\n"
        "cmd = ['7z', 'l']\n"
        "subprocess.Popen(cmd)\n"
        "os.system('7z t x.7z')\n"
        "def run_7z(args):\n"
        "    return subprocess.run(['7z', *args])\n"
        "subprocess.run(['/usr/local/bin/7zz', 'l'])\n"
        "subprocess.run(['7z.exe', 'l'])\n"
        "subprocess.run(['7zip-notes', 'l'])\n",
        encoding="utf-8",
    )
    assert _calls_that_bypass_run_7z(sample) == [
        "2: import subprocess as sp",
        "3: from subprocess import run",
        "7: subprocess.run(...)",
        "8: subprocess.check_output(...)",
        "10: subprocess.Popen(...)",
        "11: os.system(...)",
        "13: subprocess.run(...)",
        "14: subprocess.run(...)",
        "15: subprocess.run(...)",
    ]
