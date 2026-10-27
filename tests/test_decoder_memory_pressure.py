"""In-process native decoders tell PyPy's GC what they hold outside its heap, and a
decoder's close ends its liblzma decoders at once (``native_memory``).

Without that, PyPy keeps every dropped decoder's buffers until a major collection
that the GC heap's own growth never calls for, and ``fork`` (``subprocess``) then fails
with ``ENOMEM`` against the grown process heap.
"""

from __future__ import annotations

import lzma
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from archivey import MemberType, open_archive
from archivey.internal.streams import decompressor_stream, native_memory
from archivey.internal.streams.codecs import deps, isolated
from archivey.internal.streams.codecs.isolated import IN_PROCESS
from archivey.internal.streams.decompressor_stream import release_decoder_children
from tests.conftest import requires_binary, run_7z
from tests.streams_util import make_lzip_member

_TYPICAL = 8 << 20


@pytest.mark.parametrize(
    ("memlimit", "filters", "expected"),
    [
        (None, None, _TYPICAL),
        (1 << 20, None, 1 << 20),
        (None, [{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 30}], 1 << 30),
        (None, [{"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2}], _TYPICAL),
        (None, [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16}], 1 << 16),
        (None, [{"id": lzma.FILTER_DELTA}], _TYPICAL),
    ],
)
def test_the_lzma_estimate_is_the_dictionary_capped_by_memlimit(
    memlimit: int | None, filters: list[dict[str, int]] | None, expected: int
) -> None:
    assert isolated._lzma_decoder_memory(memlimit, filters) == expected


def test_each_in_process_decoder_reports_its_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    noted: list[int] = []
    monkeypatch.setattr(
        isolated, "note_native_memory", lambda decoder, n: noted.append(n)
    )
    IN_PROCESS.lzma_decompressor(format=lzma.FORMAT_XZ)
    IN_PROCESS.lzma_decompressor(
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 24}],
    )
    IN_PROCESS.bz2_decompressor()
    expected = [_TYPICAL, 1 << 24, 3600 << 10]
    if deps.zstd is not None:
        IN_PROCESS.zstd_decompressor()
        log_max = deps.zstd.DecompressionParameter.window_log_max
        IN_PROCESS.zstd_decompressor({log_max: 20})
        IN_PROCESS.zstd_decompressor({log_max: 31})
        expected += [_TYPICAL, 1 << 20, _TYPICAL]
    if IN_PROCESS.package_available(deps.brotli):
        IN_PROCESS.brotli_decompressor()
        expected.append(4 << 20)
    assert noted == expected


class _Holder:
    def __init__(self) -> None:
        self.decoder = lzma.LZMADecompressor()


def test_close_ends_an_in_process_lzma_decoder_only_on_pypy() -> None:
    data = lzma.compress(b"x" * 100)
    holder = _Holder()
    holder.decoder.decompress(data[:20])
    release_decoder_children(holder)
    release_decoder_children(holder)  # a second close does nothing more
    if deps.UNDER_PYPY:
        with pytest.raises(lzma.LZMAError):
            holder.decoder.decompress(data[20:])
    else:
        assert holder.decoder.decompress(data[20:]) == b"x" * 100


def _payload() -> bytes:
    return random.Random(5).randbytes(1 << 17) * 4


def _single_file(tmp_path: Path, kind: str) -> Path:
    data = _payload()
    if kind == "xz":
        written = lzma.compress(data, format=lzma.FORMAT_XZ)
    elif kind == "lzma":
        written = lzma.compress(data, format=lzma.FORMAT_ALONE)
    else:
        written = make_lzip_member(data)
    path = tmp_path / f"a.bin.{'lz' if kind == 'lzip' else kind}"
    path.write_bytes(written)
    return path


def _by_7z(tmp_path: Path, kind: str) -> Path:
    (tmp_path / "a.bin").write_bytes(_payload())
    flags = {
        "7z-lzma2": ["-t7z", "-m0=LZMA2"],
        "7z-bcj-lzma": ["-t7z", "-m0=BCJ", "-m1=LZMA"],
        "zip-lzma": ["-tzip", "-mm=LZMA"],
    }[kind]
    archive = tmp_path / f"a.{kind.split('-')[0]}"
    run_7z(["a", *flags, str(archive), "a.bin"], cwd=tmp_path, check=True)
    return archive


def _ended_at_close(path: Path, monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """The liblzma decoders ``close`` ends while a member stream is half read."""
    ended: list[object] = []
    recording = False

    def record(decoder: object) -> None:
        if recording:
            ended.append(decoder)

    monkeypatch.setattr(decompressor_stream, "end_lzma_decoder", record)
    with open_archive(path) as ar:
        (member,) = (m for m in ar.members() if m.type is MemberType.FILE)
        stream = ar.open(member)
        assert stream.read(10) == _payload()[:10]
        recording = True
        stream.close()
    return ended


@pytest.mark.parametrize("kind", ["xz", "lzma", "lzip"])
def test_closing_a_member_ends_its_liblzma_decoder(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``release_decoder_children`` finds the decompressor wherever an lzma-family
    decoder keeps it. On CPython ending one is a no-op, so the walk is checked here
    by recording what it reaches."""
    ended = _ended_at_close(_single_file(tmp_path, kind), monkeypatch)
    assert any(type(d) is lzma.LZMADecompressor for d in ended), kind


@requires_binary("7z")
@pytest.mark.parametrize("kind", ["7z-lzma2", "7z-bcj-lzma", "zip-lzma"])
def test_closing_an_archive_member_ends_its_liblzma_decoder(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ended = _ended_at_close(_by_7z(tmp_path, kind), monkeypatch)
    assert any(type(d) is lzma.LZMADecompressor for d in ended), kind


# With the accounting, dropped decoders pile up only until PyPy's next major collection
# frees them, and glibc reuses that memory for the next ones: growth levels off at however
# much pressure PyPy lets build first, which is large and varies from run to run. After
# 800 drops it reached 3,725 MiB in an xdist worker (PR 901) and 2,120 MiB in a fresh
# interpreter (PR 951), and both passed on re-runs. Without the accounting nothing frees
# them and growth is linear, 8 MiB per drop (6.4 GB measured for 800 in PR 927).
#
# So the test asserts the shape, not a height: of _DROPS drops, the second half must add
# under 2 GiB. Derived, not run, since the test needs PyPy and no session could run one:
# without the add_memory_pressure call growth is linear again, so the second 800 would
# add about 6,400 MiB against that bound, and 2 GiB of headroom over a levelled curve is
# itself unmeasured until the job summary shows real curves. A curve that is flat at any
# height passes, short of the loose 10 GiB ceiling. The drops run in a fresh interpreter
# because the worker reading was 1.76 times the fresh one, likely because PyPy's threshold
# scales with the heap the last collection left (inferred, not reproduced). The estimates
# themselves are pinned exactly by the tests above. The child prints each sample as it
# takes it, so a crashed or timed-out child still shows its curve, and a CI run records
# the curve in the job summary whether the test passes or not.
_DROPS = 1600
_EVERY = 200
_PILE_UP_CHILD = f"""
import lzma
from pathlib import Path

from archivey.internal.streams.codecs.isolated import IN_PROCESS


def private_writable_mib():
    total = 0
    for line in Path("/proc/self/maps").read_text().splitlines():
        span, perms = line.split()[:2]
        if "w" in perms and perms.endswith("p"):
            lo, hi = (int(x, 16) for x in span.split("-"))
            total += hi - lo
    return total >> 20


data = lzma.compress(b"x" * 100)
before = private_writable_mib()
for i in range(1, {_DROPS + 1}):
    IN_PROCESS.lzma_decompressor(format=lzma.FORMAT_XZ).decompress(data)
    if i % {_EVERY} == 0:
        print(private_writable_mib() - before, flush=True)
"""


@pytest.mark.skipif(
    not native_memory.UNDER_PYPY or not sys.platform.startswith("linux"),
    reason="PyPy's deferred freeing of native buffers, measured through /proc",
)
@pytest.mark.timeout(300, func_only=True)
def test_dropped_xz_decoders_do_not_pile_up_on_pypy() -> None:
    """Dropped xz decoders level off; without the accounting they climb 8 MiB a drop."""
    try:
        done = subprocess.run(
            [sys.executable, "-c", _PILE_UP_CHILD],
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
        stdout, stderr, returncode = done.stdout, done.stderr, done.returncode
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or b""  # bytes even with text=True
        stdout = out.decode() if isinstance(out, bytes) else out
        stderr, returncode = "timed out", None
    # One short line: CI prints only the first line of a failure, cut at 220 characters.
    curve = f"MiB per {_EVERY} drops: {' '.join(stdout.split())}"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"PyPy xz decoder pile-up, {curve}\n\n")
    last_err = stderr.strip().splitlines()[-1:] or [""]
    assert returncode == 0, f"{curve}; child: {last_err[0][:120]}"
    growth = [int(mib) for mib in stdout.split()]
    assert len(growth) == _DROPS // _EVERY, curve
    assert growth[-1] - growth[len(growth) // 2 - 1] < 2048, curve
    assert max(growth) < 10240, curve
