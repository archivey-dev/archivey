"""Stress the rapidgzip child-process path under pytest, and catch a stalled test.

gzip, zlib and raw DEFLATE decode through rapidgzip in a child process, which rapidgzip
aborts on every stream that ends early. In 2026-10 the cut-stream tests stalled the main
CI step and lost pytest-xdist workers with no output: each abort wrote a core dump of
several GB to the runner's crash handler while the test waited. The children now turn
their core dumps off; ``dev-docs/investigations/rapidgzip-worker-deaths.md`` has the
cause and the measurements. This harness stays for the next stall on that path.

Under xdist a worker that dies of SIGSEGV or SIGABRT prints ``Fatal Python error`` (CI
sets ``PYTHONFAULTHANDLER=1``); one that pytest-timeout's thread method ends, or that
SIGKILL ends, prints nothing. So the harness watches each test itself.

Each iteration runs pytest in a fresh process group, so a stall or a crash ends one
iteration and not the harness. A small plugin, loaded into pytest and into every xdist
worker, logs each test's start and finish and each rapidgzip child's spawn, death and
return code. When a test runs past ``--stall`` seconds, the harness captures stacks of
the worker and of every process under it before anything is killed: the kernel's view
(``/proc/<pid>/wchan``, ``/proc/<pid>/task/*/stack``), Python's (``faulthandler`` on
SIGUSR1, registered by the plugin), ``gdb`` if present, and ``py-spy`` if present. The
rapidgzip and PPMd children are not dumpable, by design, so for them ``wchan`` (it reads
``0``), the task stacks, ``gdb`` and ``py-spy`` all need root or ``CAP_SYS_PTRACE``.
Without either, only ``/proc/<pid>/status`` is left: its ``State`` line shows that a
child sleeps, not where.

Scenarios (``--scenarios``):

- ``serial``: the module in one process (``-p no:xdist``);
- ``xdist``: the module under ``-n auto``; ``xdist_2x``: under ``-n 2*nproc``;
- ``contended``: ``-n auto`` plus ``--burners`` CPU-burning processes (default nproc);
- ``suite_neighbours``: the module with the other test modules that the main CI step
  runs and that use rapidgzip, under ``-n auto``;
- ``file_mode_only``: the ``-file`` cases of the cut-stream test, ``--repeat`` times
  each (the plugin parametrizes them, as pytest-repeat does), under ``-n auto``;
- ``main_step`` (not in the default set; several minutes a run): the main CI step's
  whole-suite command.

::

    uv run --no-sync python scripts/rapidgzip_resume_stress.py
    uv run --no-sync python scripts/rapidgzip_resume_stress.py 50 --scenarios xdist contended

Exit code is non-zero if any iteration failed, crashed, timed out or stalled. Console
output is ASCII-safe.
"""

from __future__ import annotations

import argparse
import collections
import os
import platform
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_MODULE = "tests/test_rapidgzip_resume.py"
_CUT_FILE_K = "test_a_cut_stream_delivers_what_the_standard_library_delivers and file"

# The modules the main CI step (.github/workflows/ci.yml, "Run tests") leaves out.
_MAIN_STEP_IGNORES: tuple[str, ...] = (
    "tests/test_property_safety.py",
    "tests/test_rapidgzip_deflate_zlib.py",
    "tests/test_accelerator_shutdown.py",
    "tests/test_accelerator_corruption.py",
    "tests/test_ppmd_raw_streams.py",
)

_DEFAULT_SCENARIOS: tuple[str, ...] = (
    "serial",
    "xdist",
    "xdist_2x",
    "contended",
    "suite_neighbours",
    "file_mode_only",
)
_ALL_SCENARIOS: tuple[str, ...] = (*_DEFAULT_SCENARIOS, "main_step")

_PLUGIN_NAME = "_rgz_stress_plugin"
_PLUGIN = textwrap.dedent(
    '''\
    """Loaded by scripts/rapidgzip_resume_stress.py into pytest and its xdist workers."""
    import faulthandler
    import os
    import signal
    import time

    import pytest

    _DIR = os.environ["ARCHIVEY_RGZ_STRESS_DIR"]
    _PID = os.getpid()
    _LOG = open(os.path.join(_DIR, f"events-{_PID}.log"), "a", buffering=1)
    _DUMP = open(os.path.join(_DIR, f"faulthandler-{_PID}.txt"), "w")
    faulthandler.register(signal.SIGUSR1, file=_DUMP, all_threads=True)


    def _event(*parts):
        _LOG.write("\\t".join([f"{time.time():.3f}", *map(str, parts)]) + "\\n")
        _LOG.flush()


    def pytest_configure(config):
        try:
            from archivey.internal.streams.codecs import rapidgzip_child as rc
        except ImportError:
            return
        real_spawn, real_died, real_reap = rc.spawn, rc.RapidgzipChildStream._child_died, rc._reap

        def spawn(*args, **kwargs):
            proc = real_spawn(*args, **kwargs)
            _event("child_spawn", proc.pid)
            return proc

        def died(self, *, caused_by_source):
            proc, started = self._proc, time.monotonic()
            try:
                return real_died(self, caused_by_source=caused_by_source)
            finally:
                _event(
                    "child_died",
                    getattr(proc, "pid", None),
                    getattr(proc, "returncode", None),
                    f"{time.monotonic() - started:.3f}",
                )

        def reap(proc, stderr, *, kill=False):
            started = time.monotonic()
            try:
                return real_reap(proc, stderr, kill=kill)
            finally:
                _event("child_reaped", proc.pid, proc.returncode, f"{time.monotonic() - started:.3f}")

        rc.spawn = spawn
        rc.RapidgzipChildStream._child_died = died
        rc._reap = reap


    _REPEAT = int(os.environ.get("ARCHIVEY_RGZ_STRESS_REPEAT", "1"))


    @pytest.fixture
    def _rgz_stress_repeat(request):
        return request.param


    def pytest_generate_tests(metafunc):
        if _REPEAT > 1:
            metafunc.fixturenames.append("_rgz_stress_repeat")
            metafunc.parametrize(
                "_rgz_stress_repeat", range(_REPEAT), ids=lambda i: f"r{i}"
            )


    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_protocol(item, nextitem):
        _event("start", item.nodeid)
        yield
        _event("finish", item.nodeid)
    '''
)


def _safe_print(msg: str) -> None:
    sys.stdout.write(msg.encode("ascii", "replace").decode("ascii") + "\n")
    sys.stdout.flush()


def _format_rc(returncode: int | None) -> str:
    if returncode is None:
        return "none"
    if returncode < 0:
        try:
            return f"{returncode} ({signal.Signals(-returncode).name})"
        except ValueError:
            return f"{returncode} (signal {-returncode})"
    return str(returncode)


def _read(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"<{exc.__class__.__name__}: {exc}>"


def core_settings() -> str:
    """``core_pattern`` and the core-size limit, which decide what a crash costs."""
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)

    def show(value: int) -> str:
        return "unlimited" if value == resource.RLIM_INFINITY else str(value)

    pattern = _read("/proc/sys/kernel/core_pattern").strip()
    return f"core_pattern={pattern!r} RLIMIT_CORE={show(soft)}/{show(hard)}"


# --- the process tree ----------------------------------------------------------------


def _children_map() -> dict[int, list[int]]:
    children: dict[int, list[int]] = collections.defaultdict(list)
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        # The command name is in parentheses and may hold spaces.
        fields = stat[stat.rfind(")") + 2 :].split()
        children[int(fields[1])].append(int(entry.name))
    return children


def _descendants(pid: int) -> list[int]:
    children = _children_map()
    found, todo = [], [pid]
    while todo:
        for child in children.get(todo.pop(), []):
            found.append(child)
            todo.append(child)
    return found


def _rss_kib(pids: list[int]) -> int:
    total = 0
    for pid in pids:
        for line in _read(f"/proc/{pid}/status").splitlines():
            if line.startswith("VmRSS:"):
                total += int(line.split()[1])
    return total


# Added under a failed attach to a child: the decoder children are not dumpable.
_NOT_DUMPABLE = (
    "    (the rapidgzip and PPMd decoder children turn off dumping at start, so "
    "attaching to one, or reading its wchan and stacks, needs root or CAP_SYS_PTRACE)"
)


def _capture_one(pid: int, out: list[str], *, python_dump: Path | None) -> None:
    out.append(f"===== pid {pid}: {_read(f'/proc/{pid}/cmdline').replace(chr(0), ' ')}")
    for line in _read(f"/proc/{pid}/status").splitlines():
        if line.split(":")[0] in (
            "Name",
            "State",
            "PPid",
            "Threads",
            "VmRSS",
            "SigBlk",
        ):
            out.append(line)
    out.append(f"wchan: {_read(f'/proc/{pid}/wchan')}")
    tasks = Path(f"/proc/{pid}/task")
    for task in (
        sorted(tasks.iterdir(), key=lambda p: int(p.name)) if tasks.exists() else []
    ):
        stat = _read(task / "stat")
        state = stat[stat.rfind(")") + 2 :].split()[:1]
        out.append(
            f"--- task {task.name} comm={_read(task / 'comm').strip()} "
            f"state={state} wchan={_read(task / 'wchan')}"
        )
        stack = _read(task / "stack").strip()
        if stack:
            out.append(textwrap.indent(stack, "    "))
    if python_dump is not None:
        # The plugin registered faulthandler on SIGUSR1 in every pytest process.
        try:
            # Earlier captures are in the same file: keep only this one's dump.
            before = len(_read(python_dump))
            os.kill(pid, signal.SIGUSR1)
            time.sleep(1.0)
            out.append("--- faulthandler (SIGUSR1)")
            out.append(_read(python_dump)[before:])
        except OSError as exc:
            out.append(f"--- faulthandler: {exc}")
    for tool, argv in (
        ("py-spy", ["py-spy", "dump", "--native", "--pid", str(pid)]),
        (
            "gdb",
            [
                "gdb", "-batch", "-nx", "-p", str(pid),
                "-ex", "set pagination off", "-ex", "thread apply all bt",
            ],
        ),
    ):  # fmt: skip
        if shutil.which(tool) is None:
            out.append(f"--- {tool}: not installed")
            continue
        try:
            done = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=120,
                check=False,
            )
            out.append(f"--- {tool} (rc={done.returncode})")
            out.append(done.stdout.strip())
            if done.returncode:
                out.append(done.stderr.strip()[-2000:])
                if python_dump is None:  # a child of pytest, not pytest itself
                    out.append(_NOT_DUMPABLE)
        except subprocess.TimeoutExpired:
            out.append(f"--- {tool}: timed out")


def capture_stall(pid: int, work: Path, why: str) -> Path:
    """Stacks of a stalled pytest process and of everything under it, to a file."""
    out = [f"stall capture at {time.strftime('%H:%M:%S')}: {why}"]
    out.append(f"loadavg: {_read('/proc/loadavg').strip()}")
    _capture_one(pid, out, python_dump=work / f"faulthandler-{pid}.txt")
    for child in _descendants(pid):
        _capture_one(child, out, python_dump=None)
    path = work / f"stall-{pid}-{int(time.time())}.txt"
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return path


# --- one iteration -------------------------------------------------------------------


@dataclass
class Events:
    """What the plugin logged, across pytest and its workers."""

    open_tests: dict[int, tuple[str, float]] = field(default_factory=dict)
    last_started: tuple[float, str] = (0.0, "")
    durations: list[tuple[float, str]] = field(default_factory=list)
    child_deaths: collections.Counter[str] = field(default_factory=collections.Counter)
    child_died_secs: float = 0.0
    child_reaped_secs: float = 0.0
    children: int = 0


def read_events(work: Path) -> Events:
    events = Events()
    for log in work.glob("events-*.log"):
        pid = int(log.stem.split("-")[1])
        started: dict[str, float] = {}
        for line in _read(log).splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            when, kind = float(parts[0]), parts[1]
            if kind == "start":
                started[parts[2]] = when
                events.open_tests[pid] = (parts[2], when)
                events.last_started = max(events.last_started, (when, parts[2]))
            elif kind == "finish":
                events.durations.append((when - started.pop(parts[2], when), parts[2]))
                events.open_tests.pop(pid, None)
            elif kind == "child_spawn":
                events.children += 1
            elif kind == "child_died":
                rc = None if parts[3] == "None" else int(parts[3])
                events.child_deaths[_format_rc(rc)] += 1
                events.child_died_secs = max(events.child_died_secs, float(parts[4]))
            elif kind == "child_reaped":
                events.child_reaped_secs = max(
                    events.child_reaped_secs, float(parts[4])
                )
    return events


@dataclass
class Result:
    scenario: str
    index: int
    returncode: int | None
    seconds: float
    status: str  # ok, FAIL, WORKER-DIED, STALL, TIMEOUT
    events: Events
    failed: list[str]
    crashed_workers: list[str]
    stalls: list[Path]
    peak_rss_mib: float
    log: Path


def run_iteration(
    scenario: str, index: int, argv: list[str], env: dict[str, str], work: Path,
    *, burners: int, stall: float, hard_timeout: float,
) -> Result:  # fmt: skip
    work.mkdir(parents=True, exist_ok=True)
    (work / f"{_PLUGIN_NAME}.py").write_text(_PLUGIN, encoding="utf-8")
    env = dict(env, ARCHIVEY_RGZ_STRESS_DIR=str(work))
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(work), env.get("PYTHONPATH")])
    )
    log_path = work / "pytest.log"

    burner_procs = [
        subprocess.Popen([sys.executable, "-c", "while True: pass"])
        for _ in range(burners)
    ]
    started = time.time()
    status = "ok"
    stalls: list[Path] = []
    captured: set[tuple[int, str]] = set()
    peak_rss = 0
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            argv, cwd=_REPO_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )  # fmt: skip
        try:
            while proc.poll() is None:
                time.sleep(1.0)
                tree = [proc.pid, *_descendants(proc.pid)]
                peak_rss = max(peak_rss, _rss_kib(tree))
                now = time.time()
                for pid, (nodeid, since) in read_events(work).open_tests.items():
                    if now - since > stall and (pid, nodeid) not in captured:
                        captured.add((pid, nodeid))
                        status = "STALL"
                        why = f"{nodeid} running for {now - since:.0f} s in pid {pid}"
                        _safe_print(f"    stall: {why}; capturing stacks")
                        stalls.append(capture_stall(pid, work, why))
                if now - started > hard_timeout:
                    status = "TIMEOUT"
                    _safe_print(f"    iteration ran past {hard_timeout:.0f} s; killing")
                    if not stalls:
                        stalls.append(capture_stall(proc.pid, work, "hard timeout"))
                    os.killpg(proc.pid, signal.SIGKILL)
                    break
        finally:
            for burner in burner_procs:
                burner.kill()
                burner.wait()
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    seconds = time.time() - started
    text = _read(log_path)
    failed = re.findall(r"^(?:FAILED|ERROR) (\S+)", text, re.MULTILINE)
    crashed = re.findall(r"worker '(\w+)' crashed while running '([^']+)'", text)
    crashed_workers = [f"{worker}: {nodeid}" for worker, nodeid in crashed]
    if status == "ok" and crashed_workers:
        status = "WORKER-DIED"
    elif status == "ok" and proc.returncode != 0:
        status = "FAIL"
    return Result(
        scenario, index, proc.returncode, seconds, status, read_events(work), failed,
        crashed_workers, stalls, peak_rss / 1024, log_path,
    )  # fmt: skip


# --- scenarios -----------------------------------------------------------------------


def _neighbours() -> list[str]:
    """Test modules the main CI step runs that use rapidgzip, other than the module."""
    found = []
    for path in sorted((_REPO_ROOT / "tests").glob("test_*.py")):
        rel = path.relative_to(_REPO_ROOT).as_posix()
        if rel == _MODULE or rel in _MAIN_STEP_IGNORES:
            continue
        if "rapidgzip" in path.read_text(encoding="utf-8", errors="replace"):
            found.append(rel)
    return found


def scenario_command(
    scenario: str, args: argparse.Namespace
) -> tuple[list[str], int, int]:
    """``(pytest argv, burner count, repeat)`` for one scenario."""
    nproc = os.cpu_count() or 1
    base = [
        sys.executable, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider",
        "-p", _PLUGIN_NAME, "-o", "addopts=", f"--timeout={args.timeout}",
        "-o", f"timeout_method={args.timeout_method}",
    ]  # fmt: skip
    if scenario == "serial":
        return [*base, "-p", "no:xdist", _MODULE], 0, 1
    if scenario == "xdist":
        return [*base, "-n", "auto", _MODULE], 0, 1
    if scenario == "xdist_2x":
        return [*base, "-n", str(2 * nproc), _MODULE], 0, 1
    if scenario == "contended":
        return [*base, "-n", "auto", _MODULE], args.burners or nproc, 1
    if scenario == "suite_neighbours":
        return [*base, "-n", "auto", _MODULE, *_neighbours()], 0, 1
    if scenario == "file_mode_only":
        return [*base, "-n", "auto", "-k", _CUT_FILE_K, _MODULE], 0, args.repeat
    if scenario == "main_step":
        ignores = [f"--ignore={path}" for path in _MAIN_STEP_IGNORES]
        # addopts is cleared above; keep its marker filter, as the main step has it.
        marker = ["-m", "not ppmd_native_stress"]
        return [*base, "-n", "auto", *marker, "tests/", *ignores], 0, 1
    raise ValueError(f"unknown scenario: {scenario}")


# --- the report ----------------------------------------------------------------------


def summarize(
    results: list[Result], scenarios: list[str], args: argparse.Namespace
) -> str:
    lines = [
        "# rapidgzip resume stress results",
        "",
        f"- platform: `{platform.platform()}`, {os.cpu_count()} CPUs",
        f"- python: `{sys.version.split()[0]}`",
        f"- {core_settings()}",
        f"- PYTHONFAULTHANDLER: `{'unset' if args.no_faulthandler else '1'}`",
        (
            f"- per-test timeout: {args.timeout} s ({args.timeout_method}); "
            f"stall capture after {args.stall:.0f} s"
        ),
        "",
        (
            "| scenario | iterations | ok | failed | worker died | stalled | timed out "
            "| slowest test (s) | slowest child death (s) | children | child deaths "
            "| peak RSS (MiB) |"
        ),
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]  # fmt: skip
    for scenario in scenarios:
        mine = [r for r in results if r.scenario == scenario]
        if not mine:
            continue
        count = collections.Counter(r.status for r in mine)
        deaths: collections.Counter[str] = collections.Counter()
        for r in mine:
            deaths.update(r.events.child_deaths)
        slowest = max((d for r in mine for d, _ in r.events.durations), default=0.0)
        lines.append(
            f"| `{scenario}` | {len(mine)} | {count['ok']} | {count['FAIL']} "
            f"| {count['WORKER-DIED']} | {count['STALL']} | {count['TIMEOUT']} "
            f"| {slowest:.1f} | {max(r.events.child_died_secs for r in mine):.2f} "
            f"| {sum(r.events.children for r in mine)} "
            f"| {', '.join(f'{k}: {v}' for k, v in sorted(deaths.items())) or '-'} "
            f"| {max(r.peak_rss_mib for r in mine):.0f} |"
        )
    lines.append("")
    durations: dict[str, list[float]] = collections.defaultdict(list)
    for r in results:
        for seconds, nodeid in r.events.durations:
            durations[nodeid].append(seconds)
    slow = sorted(((max(v), k, len(v)) for k, v in durations.items()), reverse=True)[:8]
    if slow:
        lines += ["## Slowest tests (worst run)", ""]
        lines += [f"- {s:.2f} s over {n} runs: `{k}`" for s, k, n in slow]
        lines.append("")
    bad = [r for r in results if r.status != "ok"]
    if bad:
        lines += ["## Iterations that were not clean", ""]
        for r in bad:
            lines.append(
                f"- `{r.scenario}` #{r.index}: **{r.status}**, rc {_format_rc(r.returncode)}, "
                f"{r.seconds:.1f} s, last test started `{r.events.last_started[1]}`"
            )
            lines += [f"  - failed: `{f}`" for f in r.failed[:10]]
            lines += [f"  - worker died: `{w}`" for w in r.crashed_workers]
            lines += [f"  - stack capture: `{p}`" for p in r.stalls]
        lines.append("")
    lines.append(
        "A clean run is not a fix: report the rate as failures in iterations per "
        "scenario. See `dev-docs/investigations/rapidgzip-worker-deaths.md`."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "iterations", nargs="?", type=int,
        default=int(os.environ.get("ARCHIVEY_RGZ_STRESS_ITERS", "10")),
        help="Iterations per scenario (default: env ARCHIVEY_RGZ_STRESS_ITERS or 10)",
    )  # fmt: skip
    parser.add_argument(
        "--scenarios", nargs="+", default=list(_DEFAULT_SCENARIOS),
        choices=list(_ALL_SCENARIOS),
    )  # fmt: skip
    parser.add_argument(
        "--timeout", type=int, default=60, help="pytest --timeout (60, as CI)"
    )
    parser.add_argument(
        "--timeout-method", choices=["signal", "thread"], default="signal",
        help="signal (default) fails the test with a traceback; thread is what CI uses",
    )  # fmt: skip
    parser.add_argument(
        "--stall", type=float, default=30.0,
        help="Capture stacks when one test runs this long (seconds, default 30)",
    )  # fmt: skip
    parser.add_argument(
        "--iteration-timeout", type=float, default=1800.0,
        help="Kill an iteration's process group after this long (default 1800 s)",
    )  # fmt: skip
    parser.add_argument(
        "--burners", type=int, default=0, help="contended: CPU burners (default nproc)"
    )
    parser.add_argument(
        "--repeat", type=int, default=10, help="file_mode_only: runs of each case"
    )
    parser.add_argument(
        "--no-faulthandler", action="store_true", help="Do not set PYTHONFAULTHANDLER"
    )
    parser.add_argument(
        "--keep", type=Path, default=None, help="Keep iteration logs under this dir"
    )
    parser.add_argument(
        "--summary", type=Path, default=None, help="Write a Markdown summary here"
    )
    args = parser.parse_args(argv)

    try:
        import rapidgzip  # noqa: F401
    except ImportError:
        _safe_print(
            "rapidgzip is not installed; nothing to stress (install archivey[all])."
        )
        return 2

    scenarios = list(dict.fromkeys(args.scenarios))
    _safe_print(
        f"rapidgzip resume stress: scenarios={scenarios} iterations={args.iterations} "
        f"platform={platform.platform()} cpus={os.cpu_count()} "
        f"python={sys.version.split()[0]}"
    )
    _safe_print(core_settings())

    base_env = os.environ.copy()
    base_env.pop("PYTEST_ADDOPTS", None)
    base_env["PYTHONIOENCODING"] = "utf-8"
    base_env["PYTHONPATH"] = os.pathsep.join(
        filter(
            None, [str(_REPO_ROOT / "src"), str(_REPO_ROOT), base_env.get("PYTHONPATH")]
        )
    )
    if args.no_faulthandler:
        base_env.pop("PYTHONFAULTHANDLER", None)
    else:
        base_env["PYTHONFAULTHANDLER"] = "1"

    results: list[Result] = []
    root = args.keep or Path(tempfile.mkdtemp(prefix="archivey-rgz-stress-"))
    try:
        for scenario in scenarios:
            command, burners, repeat = scenario_command(scenario, args)
            env = dict(base_env, ARCHIVEY_RGZ_STRESS_REPEAT=str(repeat))
            _safe_print(f"== scenario {scenario}: {' '.join(command[2:])}")
            if burners:
                _safe_print(f"   with {burners} CPU burners")
            for i in range(1, args.iterations + 1):
                result = run_iteration(
                    scenario, i, command, env, root / scenario / f"iter-{i:04d}",
                    burners=burners, stall=args.stall,
                    hard_timeout=args.iteration_timeout,
                )  # fmt: skip
                results.append(result)
                slowest = max(result.events.durations, default=(0.0, "-"))
                _safe_print(
                    f"  [{scenario} {i}/{args.iterations}] {result.status} "
                    f"rc={_format_rc(result.returncode)} {result.seconds:.1f}s "
                    f"tests={len(result.events.durations)} "
                    f"children={result.events.children} "
                    f"deaths={dict(result.events.child_deaths)} "
                    f"slowest={slowest[0]:.1f}s rss={result.peak_rss_mib:.0f}MiB"
                )
                if result.status != "ok":
                    _safe_print(
                        f"    last test started: {result.events.last_started[1]}"
                    )
                    for line in (result.failed + result.crashed_workers)[:10]:
                        _safe_print(f"    {line}")
                    tail = "\n".join(_read(result.log).strip().splitlines()[-15:])
                    _safe_print(textwrap.indent(tail, "    | "))
    finally:
        summary = summarize(results, scenarios, args)
        if args.summary is not None:
            args.summary.write_text(summary, encoding="utf-8")
        gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if gh_summary:
            with open(gh_summary, "a", encoding="utf-8") as fh:
                fh.write(summary)
        _safe_print(summary)
        if args.keep is None:
            # Keep the logs of any iteration that was not clean.
            if any(r.status != "ok" for r in results):
                _safe_print(f"Logs of unclean iterations kept under {root}")
            else:
                shutil.rmtree(root, ignore_errors=True)
    return 1 if any(r.status != "ok" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
