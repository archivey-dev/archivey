"""Mutation fuzzing over the declarative corpus (``testing-contract``: mutation robustness).

Every corpus archive is deterministically mutated — fixed-ratio truncations plus
header/trailer-biased random cuts, bit flips, zeroed blocks, garbage prefixes/suffixes
— and fed back through the full read path with the
**invariant**: archivey either succeeds or raises a typed ``ArchiveyError``; it never
raises a raw third-party/codec exception, never hangs (each parametrized case carries its
own ``pytest-timeout`` budget), never aborts the process, and a successful extraction must
leave the destination root a directory (replacing it with a file is a path-safety failure). This is the pre-native-parser
layer of the fuzzing program (``dev-docs/threat-model.md`` O5): the corpus doubles as the seed
set, and the same seeds feed the Phase-6 Atheris harnesses later.

Tests are parametrized by ``(archive, format, mutation kind)`` so a hang or failure names a
single slice (e.g. ``adversarial-tar-tar.gz-bitflip``) and ``-k`` can target it without
running every other kind for that archive.

Determinism: every mutation is derived from a seed of ``(entry id, format, harness
version)``. Each mutation *kind* uses its own RNG sub-seed so raising
``ARCHIVEY_FUZZ_MUTATIONS`` only appends more cases of that kind and never perturbs
earlier ones. Bit flips, zero blocks, and junk are also reproducible from their
``[desc]`` alone (offset / mask / size / hex junk are embedded in the label).

Reproduce a single failure::

    ARCHIVEY_FUZZ_SELECT='bitflip@305:0x20' \\
    uv run pytest tests/test_mutation_fuzz.py -k adversarial-tar-tar.gz-bitflip

**Stateful-dest bugs:** the loop gives every mutation a fresh extraction directory and
checks that a successful extract leaves that root a directory (so a corrupt ``"."`` file
member is caught here). Re-extracting to a destination that already exists as a
non-directory file is covered in ``tests/test_extraction.py`` (``_ensure_dest_root``).

Run only one mutation kind across the corpus::

    uv run pytest tests/test_mutation_fuzz.py -k bitflip

On timeout or an unexpected error, pytest prints the active mutation and a repro
command (same shape as invariant failures) via ``active_mutation_report()`` in
``conftest.py``.

The format is passed explicitly to ``open_archive`` — a mutated magic must reach the
*parser*, not bounce off detection — and detection itself is exercised separately with
the mutated bytes.

**Scope: the deterministic parsing path.** The harness forces the ``[seekable]``
accelerators (``rapidgzip``/``indexed_bzip2``) **off**, so it exercises archivey's own
zero-dependency parsing and its exception-translation contract — the surface archivey
controls. Those C++ accelerators can *busy-loop* on crafted input (a hang no Python-level
timeout can interrupt), so they are fuzzed by the Atheris accelerator targets instead,
under libFuzzer's own per-input timeout and RSS cap (``tests/atheris_fuzz/targets.py``,
``dev-docs/threat-model.md`` O5).
"""

from __future__ import annotations

import io
import os
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from random import Random

import pytest

from archivey import (
    AcceleratorMode,
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyError,
    ExtractionLimits,
    FormatSupport,
    OnError,
    OverwritePolicy,
    detect_format,
    format_availability,
    open_archive,
)
from tests.conftest import binary_refusal
from tests.sample_archives import (
    CORPUS,
    FORMAT_KEYS,
    CorpusEntry,
    F,
    corpus_archive_path,
    skip_unless_runnable,
)

_RAR_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rar"

# Bump to change every derived mutation (a fresh sweep of the mutation space).
HARNESS_VERSION = 1

# Mutations per (archive × kind); the whole harness stays in the tens-of-milliseconds
# range per combination. Raise locally for a deeper run: ARCHIVEY_FUZZ_MUTATIONS=50.
_N = int(os.environ.get("ARCHIVEY_FUZZ_MUTATIONS", "6"))

# Per-(archive, format, mutation-kind) timeout (seconds). Deep sweeps may need more:
# ARCHIVEY_FUZZ_TIMEOUT=120 ARCHIVEY_FUZZ_MUTATIONS=2000 pytest ...
_FUZZ_TIMEOUT = float(os.environ.get("ARCHIVEY_FUZZ_TIMEOUT", "30"))

# Run only mutations whose description contains this substring (exact repro aid).
_FUZZ_SELECT = os.environ.get("ARCHIVEY_FUZZ_SELECT")

# Run only mutation kinds whose name contains this substring (e.g. ``bitflip``).
_FUZZ_KIND = os.environ.get("ARCHIVEY_FUZZ_KIND")

# Cap what we pull from any (possibly lying) member stream, and keep extraction cheap.
_READ_CAP = 1 << 20
_FUZZ_LIMITS = ExtractionLimits(
    max_extracted_bytes=8 << 20, max_ratio=1000.0, max_entries=10_000
)

# Force the deterministic zero-dep codec path (see module docstring): the accelerators are
# third-party C++ and can hang on crafted input, which is out of scope for this layer.
_FUZZ_CONFIG = ArchiveyConfig(
    use_rapidgzip=AcceleratorMode.OFF, use_indexed_bzip2=AcceleratorMode.OFF
)

# The mutated bytes have no file name, so by default detection would run no content probe;
# always_probe_content keeps the probe decoders under the detection invariant below.
_DETECT_CONFIG = ArchiveyConfig(always_probe_content=True)

MUTATION_KINDS: tuple[str, ...] = ("truncate", "bitflip", "zero", "junk")

# Only file-backed formats are mutated ("dir" has no byte stream to corrupt).
_PARAMS = [
    pytest.param(entry, key, kind, id=f"{entry.id}-{key}-{kind}")
    for entry in CORPUS
    for key in entry.formats
    if key != "dir"
    for kind in MUTATION_KINDS
    if _FUZZ_KIND is None or _FUZZ_KIND in kind
]

# Static RAR fixtures: RAR shapes the declarative CORPUS cannot reach, because its
# builder emits neither ``-s`` (solid) nor ``-hp`` (header encryption) nor ``-v``
# (volumes) — and because the ``rar`` writer is deliberately off CI's PATH, so every
# declarative ``rar`` row skips there (audit: the T7 ``corpus-matrix.md`` under
# ``review/archive/2026-07-28-debt-ledger/``). These are committed bytes, so they
# mutate wherever ``unrar`` exists, which CI does install.
_STATIC_RAR_SOURCES: tuple[tuple[CorpusEntry, Path], ...] = (
    (
        CorpusEntry("basic-solid-rar5", (), ("rar",), requires_binaries=("unrar",)),
        _RAR_FIXTURES / "basic_solid__.rar",
    ),
    (
        CorpusEntry("basic-solid-rar4", (), ("rar",), requires_binaries=("unrar",)),
        _RAR_FIXTURES / "basic_solid__rar4.rar",
    ),
    # Encrypted headers: mutations land in ciphertext the parser must decrypt before it
    # can read any name, so a corrupt block must still fail typed rather than crash the
    # native RAR3/RAR5 header decryptor. The member carries the fixture password so
    # ``_exercise`` gets past the header at all.
    (
        CorpusEntry(
            "encrypted-header-rar5",
            (F("x", b"", password="header_password"),),
            ("rar",),
            requires_binaries=("unrar",),
            encrypt_header=True,
        ),
        _RAR_FIXTURES / "encrypted_header__.rar",
    ),
    (
        CorpusEntry(
            "encrypted-header-rar4",
            (F("x", b"", password="header_password"),),
            ("rar",),
            requires_binaries=("unrar",),
            encrypt_header=True,
        ),
        _RAR_FIXTURES / "encrypted_header__rar4.rar",
    ),
    # First volume of a RAR5 set, mutated as a lone stream: this exercises the
    # volume-flagged header path under corruption. It is NOT multi-volume *joining*
    # coverage — the siblings are not offered to the reader here (see the audit doc).
    (
        CorpusEntry("volume-first-rar5", (), ("rar",), requires_binaries=("unrar",)),
        _RAR_FIXTURES / "tinyvol.part1.rar",
    ),
)

_STATIC_RAR_PARAMS = [
    pytest.param(entry, path, kind, id=f"{entry.id}-rar-{kind}")
    for entry, path in _STATIC_RAR_SOURCES
    for kind in MUTATION_KINDS
    if _FUZZ_KIND is None or _FUZZ_KIND in kind
]


def _skip_unless_static_rar_runnable() -> None:
    """Skip static-RAR mutation when the reader or ``unrar`` decompressor is absent."""
    availability = format_availability(ArchiveFormat.RAR)
    if availability.support is FormatSupport.NONE:
        pytest.skip(
            f"format 'rar' not readable here: {availability.missing or 'no backend'}"
        )
    if (refusal := binary_refusal("unrar")) is not None:
        pytest.skip(f"unrar unavailable: {refusal}")


@dataclass(frozen=True)
class _ActiveFuzz:
    entry_id: str
    key: str
    kind: str
    seed: str
    desc: str


# Set for the mutation currently under test; read by conftest on timeout/failure.
_ACTIVE_FUZZ: _ActiveFuzz | None = None


def mutation_seed(entry: CorpusEntry, key: str) -> str:
    """Stable seed string for an (archive, format) pair."""
    return f"{entry.id}|{key}|v{HARNESS_VERSION}"


def mutation_kind(desc: str) -> str:
    """Map a mutation label to its parametrized kind."""
    if desc.startswith("truncate@"):
        return "truncate"
    if desc.startswith("bitflip@"):
        return "bitflip"
    if desc.startswith("zero@"):
        return "zero"
    if desc.startswith(("append-junk@", "prepend-junk@")):
        return "junk"
    raise ValueError(f"unknown mutation description: {desc!r}")


def _rng(seed: str, kind: str) -> Random:
    return Random(f"{seed}|{kind}")


def _biased_truncate_cut(rng: Random, n: int) -> int:
    """Return ``cut`` in ``[1, n - 1]`` biased toward header and trailer regions.

    ``data[:cut]`` drops the tail, so a low cut keeps only header bytes and a cut
    just shy of ``n`` chops the trailer/EOCD while leaving the header intact.
    """
    if n <= 1:
        return 1
    last = n - 1
    band = max(1, n // 8)
    roll = rng.random()
    if roll < 0.40:
        return rng.randrange(1, min(band, last) + 1)
    if roll < 0.80:
        low = max(1, last - band + 1)
        return rng.randrange(low, last + 1)
    mid_lo = min(band + 1, last)
    mid_hi = max(mid_lo, last - band)
    if mid_lo >= mid_hi:
        return rng.randrange(1, last + 1)
    return rng.randrange(mid_lo, mid_hi + 1)


def apply_mutation(data: bytes, desc: str) -> bytes:
    """Rebuild mutated bytes from a mutation label (no RNG needed)."""
    if desc.startswith("truncate@"):
        cut = int(desc.split("@", 1)[1])
        return data[:cut]
    if desc.startswith("bitflip@"):
        spec = desc.split("@", 1)[1]
        pos_s, bit_s = spec.split(":")
        pos = int(pos_s)
        bit = int(bit_s, 16)
        return data[:pos] + bytes([data[pos] ^ bit]) + data[pos + 1 :]
    if desc.startswith("zero@"):
        spec = desc.split("@", 1)[1]
        pos_s, size_s = spec.split("+")
        pos, size = int(pos_s), int(size_s)
        return data[:pos] + b"\x00" * size + data[pos + size :]
    if desc.startswith("append-junk@"):
        junk = bytes.fromhex(desc.split("@", 1)[1])
        return data + junk
    if desc.startswith("prepend-junk@"):
        junk = bytes.fromhex(desc.split("@", 1)[1])
        return junk + data
    raise ValueError(f"unknown mutation description: {desc!r}")


def _mutations_for_kind(
    data: bytes, seed: str, kind: str
) -> Iterator[tuple[str, bytes]]:
    """Yield ``(description, mutated_bytes)`` for one mutation kind (deduplicated)."""
    n = len(data)

    if kind == "truncate":
        seen_cuts: set[int] = set()
        for frac in (0.02, 0.25, 0.5, 0.9, 0.99):
            cut = max(1, int(n * frac))
            if cut in seen_cuts:
                continue
            seen_cuts.add(cut)
            yield f"truncate@{cut}", data[:cut]
        if n <= 1:
            return
        target = min(len(seen_cuts) + _N, n - 1)
        if len(seen_cuts) >= target:
            return
        rng = _rng(seed, "truncate")
        remaining = target - len(seen_cuts)
        max_attempts = remaining + max(32, remaining * 4)
        attempts = 0
        while len(seen_cuts) < target and attempts < max_attempts:
            attempts += 1
            cut = _biased_truncate_cut(rng, n)
            if cut in seen_cuts:
                continue
            seen_cuts.add(cut)
            yield f"truncate@{cut}", data[:cut]
        return

    if kind == "bitflip":
        cap = n * 8  # one flip per (byte offset, bit mask)
        budget = min(_N, cap)
        if budget >= cap:
            for pos in range(n):
                for bit_i in range(8):
                    bit = 1 << bit_i
                    desc = f"bitflip@{pos}:{bit:#04x}"
                    yield (
                        desc,
                        data[:pos] + bytes([data[pos] ^ bit]) + data[pos + 1 :],
                    )
            return
        rng = _rng(seed, "bitflip")
        seen: set[str] = set()
        max_attempts = budget + max(64, budget * 4)
        attempts = 0
        while len(seen) < budget and attempts < max_attempts:
            attempts += 1
            pos = rng.randrange(n)
            bit = 1 << rng.randrange(8)
            desc = f"bitflip@{pos}:{bit:#04x}"
            if desc in seen:
                continue
            seen.add(desc)
            yield (
                desc,
                data[:pos] + bytes([data[pos] ^ bit]) + data[pos + 1 :],
            )
        return

    if kind == "zero":
        budget = min(_N // 2 or 1, n * 3)  # three block sizes: 4, 16, 64
        rng = _rng(seed, "zero")
        seen = set[str]()
        max_attempts = budget + max(32, budget * 4)
        attempts = 0
        while len(seen) < budget and attempts < max_attempts:
            attempts += 1
            pos = rng.randrange(n)
            size = min(rng.choice((4, 16, 64)), n - pos)
            desc = f"zero@{pos}+{size}"
            if desc in seen:
                continue
            seen.add(desc)
            yield desc, data[:pos] + b"\x00" * size + data[pos + size :]
        return

    if kind == "junk":
        rng = _rng(seed, "junk")
        junk = rng.randbytes(48)
        yield f"append-junk@{junk.hex()}", data + junk
        yield f"prepend-junk@{junk.hex()}", junk + data
        return

    raise ValueError(f"unknown mutation kind: {kind!r}")


def _mutations(data: bytes, seed: str) -> Iterator[tuple[str, bytes]]:
    """Yield every mutation across all kinds (harness helper / repro scripts)."""
    for kind in MUTATION_KINDS:
        yield from _mutations_for_kind(data, seed, kind)


def _select_matches_kind(select: str, kind: str) -> bool:
    if kind == "junk":
        return select.startswith(("append-junk@", "prepend-junk@"))
    return select.startswith(f"{kind}@")


def _repro_command(entry_id: str, key: str, kind: str, desc: str) -> str:
    parts = [f"ARCHIVEY_FUZZ_SELECT={desc!r}", "uv", "run", "pytest"]
    parts.append("tests/test_mutation_fuzz.py")
    parts.append(f"-k {entry_id}-{key}-{kind}")
    return " ".join(parts)


def _mutations_for_test(
    data: bytes, seed: str, kind: str
) -> Iterator[tuple[str, bytes]]:
    """Mutations to run in the parametrized test (honours ``ARCHIVEY_FUZZ_SELECT``)."""
    if _FUZZ_SELECT is None:
        yield from _mutations_for_kind(data, seed, kind)
        return

    if not _select_matches_kind(_FUZZ_SELECT, kind):
        return

    # Exact label: rebuild bytes directly — no dependence on ``_N`` or the RNG stream.
    try:
        yield _FUZZ_SELECT, apply_mutation(data, _FUZZ_SELECT)
        return
    except ValueError:
        pass

    # Substring filter (partial select) over the generated set.
    for desc, mutated in _mutations_for_kind(data, seed, kind):
        if _FUZZ_SELECT in desc:
            yield desc, mutated


def _mutation_context(
    entry_id: str,
    key: str,
    kind: str,
    seed: str,
    desc: str,
    *,
    headline: str,
) -> str:
    return (
        f"{headline} for {entry_id}-{key}-{kind} "
        f"seed={seed!r} mutation [{desc}]: "
        f"(repro: {_repro_command(entry_id, key, kind, desc)})"
    )


def _set_active_mutation(
    entry: CorpusEntry, key: str, kind: str, seed: str, desc: str
) -> None:
    global _ACTIVE_FUZZ
    _ACTIVE_FUZZ = _ActiveFuzz(entry.id, key, kind, seed, desc)


def _clear_active_mutation() -> None:
    global _ACTIVE_FUZZ
    _ACTIVE_FUZZ = None


def active_mutation_report() -> str | None:
    """Repro context for the in-flight mutation (used by conftest on timeout)."""
    active = _ACTIVE_FUZZ
    if active is None:
        return None
    return _mutation_context(
        active.entry_id,
        active.key,
        active.kind,
        active.seed,
        active.desc,
        headline="timed out or failed while running",
    )


def _failure_context(
    entry: CorpusEntry, key: str, kind: str, seed: str, desc: str
) -> str:
    return _mutation_context(
        entry.id, key, kind, seed, desc, headline="invariant violated"
    )


def _exercise(
    mutated: bytes,
    entry: CorpusEntry,
    key: str,
    out_dir: Path,
    kind: str,
    seed: str,
    desc: str,
) -> None:
    """The invariant: full read path over corrupted bytes -> success or ArchiveyError.

    On success the extraction root must remain a directory — replacing it with a file
    (e.g. a corrupt member named ``"."``) is treated as a path-safety failure.
    """
    try:
        with open_archive(
            io.BytesIO(mutated),
            format=FORMAT_KEYS[key],
            password=list(entry.passwords) or None,
            config=_FUZZ_CONFIG,
        ) as ar:
            members = ar.members()
            for member in members:
                if not member.is_file:
                    continue
                try:
                    with ar.open(member) as f:
                        # Track bytes locally: solid / forward-only streams are not
                        # seekable, so ``f.tell()`` would raise a raw OSError and
                        # break the typed-error invariant.
                        got = 0
                        while True:
                            chunk = f.read(1 << 16)
                            if not chunk:
                                break
                            got += len(chunk)
                            if got > _READ_CAP:
                                break
                except ArchiveyError:
                    pass  # per-member decode failure: exactly the contract
            ar.extract_all(
                out_dir,
                on_error=OnError.CONTINUE,
                overwrite=OverwritePolicy.REPLACE,
                limits=_FUZZ_LIMITS,
            )
    except ArchiveyError:
        return  # typed failure: the contract holds
    except Exception as exc:  # noqa: BLE001 - the harness exists to catch exactly this
        pytest.fail(
            f"{_failure_context(entry, key, kind, seed, desc)} "
            f"raw {type(exc).__name__}: {exc!r}"
        )

    if not out_dir.is_dir():
        pytest.fail(
            f"{_failure_context(entry, key, kind, seed, desc)} "
            f"extraction root is no longer a directory: {out_dir!r} "
            f"(is_file={out_dir.is_file()})"
        )


@pytest.mark.timeout(_FUZZ_TIMEOUT)
@pytest.mark.parametrize(("entry", "key", "kind"), _PARAMS)
def test_mutations_fail_typed_or_succeed(
    entry: CorpusEntry, key: str, kind: str, tmp_path: Path
) -> None:
    skip_unless_runnable(entry, key)
    source = corpus_archive_path(entry, key, tmp_path)
    data = source.read_bytes()
    seed = mutation_seed(entry, key)

    for desc, mutated in _mutations_for_test(data, seed, kind):
        _set_active_mutation(entry, key, kind, seed, desc)
        # One extraction tree per mutation; deleted before the next iteration so deep
        # sweeps (ARCHIVEY_FUZZ_MUTATIONS=5000) do not accumulate under tmp_path.
        with tempfile.TemporaryDirectory(prefix="out-", dir=tmp_path) as out_raw:
            out_dir = Path(out_raw)
            _exercise(mutated, entry, key, out_dir, kind, seed, desc)

            # Detection must uphold the same invariant on arbitrary bytes, content probes
            # included (it may return any format, or raise FormatDetectionError — never a
            # raw codec exception).
            try:
                detect_format(io.BytesIO(mutated), config=_DETECT_CONFIG)
            except ArchiveyError:
                pass
            except Exception as exc:  # noqa: BLE001 - invariant check
                pytest.fail(
                    f"{_failure_context(entry, key, kind, seed, desc)} "
                    f"detect_format raw {type(exc).__name__}: {exc!r}"
                )

    _clear_active_mutation()


@pytest.mark.timeout(_FUZZ_TIMEOUT)
@pytest.mark.parametrize(("entry", "path", "kind"), _STATIC_RAR_PARAMS)
def test_static_rar_mutations_fail_typed_or_succeed(
    entry: CorpusEntry, path: Path, kind: str, tmp_path: Path
) -> None:
    """Solid / header-encrypted / volume RAR4/RAR5 under the declarative mutation
    invariant: any corruption fails typed or succeeds, never raw or hanging."""
    _skip_unless_static_rar_runnable()
    data = path.read_bytes()
    key = "rar"
    seed = mutation_seed(entry, key)

    for desc, mutated in _mutations_for_test(data, seed, kind):
        _set_active_mutation(entry, key, kind, seed, desc)
        with tempfile.TemporaryDirectory(prefix="out-", dir=tmp_path) as out_raw:
            out_dir = Path(out_raw)
            _exercise(mutated, entry, key, out_dir, kind, seed, desc)

            try:
                detect_format(io.BytesIO(mutated), config=_DETECT_CONFIG)
            except ArchiveyError:
                pass
            except Exception as exc:  # noqa: BLE001 - invariant check
                pytest.fail(
                    f"{_failure_context(entry, key, kind, seed, desc)} "
                    f"detect_format raw {type(exc).__name__}: {exc!r}"
                )

    _clear_active_mutation()
