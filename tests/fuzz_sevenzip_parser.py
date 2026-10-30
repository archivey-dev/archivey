"""Env-gated mutation harness for the native 7z header parser.

Run locally with::

    ARCHIVEY_FUZZ=1 uv run --no-sync pytest tests/fuzz_sevenzip_parser.py
"""

from __future__ import annotations

import io
import os
from collections.abc import Iterable
from pathlib import Path
from random import Random

import pytest

from archivey import ArchiveyError
from archivey.internal.backends.sevenzip_parser import MAGIC_7Z
from archivey.internal.backends.sevenzip_reader import load_sevenzip_archive
from archivey.internal.password import _PasswordCandidates
from tests.sample_archives import CORPUS, CorpusEntry, corpus_archive_path

pytestmark = pytest.mark.skipif(
    os.environ.get("ARCHIVEY_FUZZ") != "1",
    reason="set ARCHIVEY_FUZZ=1 to run the 7z parser fuzz harness",
)

_HARNESS_VERSION = 1
_SEED_ENTRY_IDS = {"basic", "encoding", "large", "encrypted-header", "sevenzip-ppmd"}
# The corpus password, so an encrypted header reaches the folder pipeline.
_PASSWORDS = ["", "password"]


def _corpus_seed_entries() -> Iterable[CorpusEntry]:
    for entry in CORPUS:
        if entry.id in _SEED_ENTRY_IDS and "7z" in entry.formats:
            yield entry


def _seed_bytes(tmp_path: Path) -> list[bytes]:
    pytest.importorskip("py7zr")
    seeds = [
        b"",
        MAGIC_7Z,
        MAGIC_7Z + bytes(26),
        b"not a 7z archive",
        MAGIC_7Z + b"\x00\x04" + b"\xff" * 24,
    ]
    for entry in _corpus_seed_entries():
        seeds.append(corpus_archive_path(entry, "7z", tmp_path).read_bytes())
    return seeds


def _mutations(seed: bytes, label: str) -> Iterable[bytes]:
    yield seed
    if seed:
        yield seed[: max(1, len(seed) // 2)]
        yield seed + b"\x00" * 32
        rng = Random(f"sevenzip-parser|{label}|v{_HARNESS_VERSION}")
        for _ in range(8):
            data = bytearray(seed)
            offset = rng.randrange(len(data))
            data[offset] ^= 1 << rng.randrange(8)
            yield bytes(data)


def test_load_sevenzip_archive_fuzz_harness(tmp_path: Path) -> None:
    for index, seed in enumerate(_seed_bytes(tmp_path)):
        for mutated in _mutations(seed, str(index)):
            try:
                load_sevenzip_archive(
                    io.BytesIO(mutated),
                    passwords=_PasswordCandidates.from_input(_PASSWORDS),
                )
            except ArchiveyError:
                pass
