"""Find the shortest member that Debian's patched ``unar`` writes as nothing.

Usage (from the repo root)::

    uv run python scripts/find_unar_probe_member.py
    uv run python scripts/find_unar_probe_member.py --check-unar /usr/bin/unar
    uv run python scripts/find_unar_probe_member.py --validate 300 --check-unar /usr/bin/unar

Requires the RARLAB ``rar`` binary on ``PATH``. The answer is the member of
``_RAR5_PROBE_ARCHIVE`` in ``src/archivey/internal/external/unar.py`` and of the
``unar_drop*`` fixtures (``scripts/gen_rar_fixtures.py``).

Why a member is dropped
-----------------------

Debian's ``CSInputBuffer-bit-string-reading.patch`` makes XADMaster's bit reader raise
end of file when a read asks for more bits than are left in the member's packed data.
XADMaster decodes each Huffman symbol by first peeking a fixed number of bits, the
code's table size: the length of the longest code in that table, at most 10
(``CSInputNextSymbolUsingCode`` in ``XADPrefixCode.m``). It then consumes only as many
bits as the code it found. Near the end of the data the peek can run past the last
byte although the code itself fits. The RAR5 decoder swallows the error and the member
comes out empty, with exit 0.

So a member is dropped when, at some symbol, the bits left are fewer than that table's
size. The bits used in the last packed byte only matter through this: a last symbol
whose code is ``L`` bits long, read from a table of size ``T``, fails when ``T - L`` is
more than the unused bits of the last byte. That is why the dropped members measured
before mostly had 7 or 8 bits used in that byte, and why many such members still
decode.

:func:`patched_unar_runs_short` replays the bit reads of XADMaster's RAR5 decoder
(``XADRAR50Handle.m``) without producing output, and reports whether one of them
asks for bits past the end. ``--validate N`` measures that against a real patched
``unar``: it compresses N generated members alone and N two-member solid archives, and
reports every archive where the model and ``unar`` disagree. On 2026-10-02 it agreed
with Ubuntu 24.04's ``unar`` 1.10.1 package on all of ``--validate 300``.

The search
----------

``rar`` stores a member when compressing does not make it smaller, so very short
members are never compressed. The search tries every string over ``--alphabet`` in
order of length, then lexicographically, compresses each with ``rar a -ma5 -m3``, and
returns the first compressed member the model says is dropped. With RAR 7.00 and the
default alphabet ``ab`` that is ``aaaaabababbabb``, 14 bytes; no string over ``ab``
of 13 bytes or fewer is both compressed and dropped. ``--after hello`` searches for the
second member of a solid archive instead, as ``unar_drop_solid__.rar`` needs: there the
answer is ``ababbaa``, 7 bytes. That member reuses the Huffman tables of the member
before it instead of storing its own, so it compresses at lengths a member alone cannot,
and the floor above does not apply. Another ``rar`` build may compress differently, so
rerun this after a ``rar`` upgrade and check the result with ``--check-unar`` on a
patched build.
"""

from __future__ import annotations

import argparse
import itertools
import os
import random
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

# XADPrefixCode.m ``TableMaxSize``: no lookup peeks more bits than this.
_TABLE_MAX_SIZE = 10
_MAX_CODE_LENGTH = 15
# Main, offset, low-offset and length tables, in the order RAR5 stores their lengths.
_TABLE_SIZES = (306, 64, 16, 44)


class _BitReader:
    """MSB-first reader over the packed data that records any read past its end."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.end = len(data) * 8
        self.ran_out = False

    def need(self, count: int) -> None:
        if self.pos + count > self.end:
            self.ran_out = True

    def bit(self) -> int:
        self.need(1)
        pos = self.pos
        self.pos += 1
        if pos >= self.end:
            return 0
        return (self.data[pos >> 3] >> (7 - (pos & 7))) & 1

    def bits(self, count: int) -> int:
        self.need(count)
        value = 0
        for _ in range(count):
            value = (value << 1) | self.bit()
        return value

    def align(self) -> None:
        self.pos = (self.pos + 7) & ~7


class _PrefixCode:
    """A canonical RAR5 Huffman code, decoded the way XADMaster peeks for it."""

    def __init__(self, lengths: Sequence[int]) -> None:
        used = [length for length in lengths if length]
        # XADPrefixCode ``_makeTable``: the longest code, capped; an empty table peeks
        # the cap.
        self.table_size = min(max(used), _TABLE_MAX_SIZE) if used else _TABLE_MAX_SIZE
        self.codes: dict[tuple[int, int], int] = {}
        code = 0
        for length in range(1, _MAX_CODE_LENGTH + 1):
            for symbol, symbol_length in enumerate(lengths):
                if symbol_length == length:
                    self.codes[(length, code)] = symbol
                    code += 1
            code <<= 1

    def symbol(self, reader: _BitReader) -> int:
        # ``CSInputPeekBitString(buf, tablesize)`` comes first, whatever the code's
        # length; that peek is what the patch turns into end of file.
        reader.need(self.table_size)
        code = 0
        for length in range(1, _MAX_CODE_LENGTH + 1):
            code = (code << 1) | reader.bit()
            symbol = self.codes.get((length, code))
            if symbol is not None:
                return symbol
        raise ValueError("invalid prefix code in the packed data")


def _read_tables(reader: _BitReader) -> tuple[_PrefixCode, ...]:
    """``allocAndParseCodes``: the precode, then the four tables' code lengths."""
    pre: list[int] = []
    while len(pre) < 20:
        length = reader.bits(4)
        if length == 15:
            count = reader.bits(4) + 2
            pre += [15] if count == 2 else [0] * min(count, 20 - len(pre))
        else:
            pre.append(length)
    precode = _PrefixCode(pre)
    total = sum(_TABLE_SIZES)
    lengths: list[int] = []
    while len(lengths) < total:
        value = precode.symbol(reader)
        if value < 16:
            lengths.append(value)
            continue
        if value in (16, 18):
            count = reader.bits(3) + 3
        else:
            count = reader.bits(7) + 11
        if value < 18:
            if not lengths:
                raise ValueError("a repeat before the first code length")
            fill = lengths[-1]
        else:
            fill = 0
        lengths += [fill] * min(count, total - len(lengths))
    tables = []
    start = 0
    for size in _TABLE_SIZES:
        tables.append(_PrefixCode(lengths[start : start + size]))
        start += size
    return tuple(tables)


def _match_length(reader: _BitReader, symbol: int) -> int:
    """``ReadLengthWithSymbol``."""
    if symbol < 8:
        return symbol + 2
    extra = symbol // 4 - 1
    return ((4 + (symbol & 3)) << extra) + 2 + reader.bits(extra)


@dataclass
class SolidState:
    """What a solid member inherits from the one before: its tables, the last length."""

    tables: tuple[_PrefixCode, ...] = ()
    last_length: int = 0


def patched_unar_runs_short(
    packed: bytes, size: int, state: SolidState | None = None
) -> bool:
    """Whether Debian's patched ``unar`` stops before writing ``size`` bytes.

    ``packed`` is one RAR5 member's compressed data (method 1-5, not stored). This
    follows ``expandToPosition`` and ``readBlockHeader`` in ``XADRAR50Handle.m`` read
    for read, counting output bytes instead of producing them, and answers true as soon
    as a read asks for bits past the end of ``packed``. It also answers true when the
    blocks end before ``size`` bytes are out.

    For the members of a solid archive, pass one ``state`` to each in turn: a solid
    member's first block may reuse the tables of the member before it.
    """
    if state is None:
        state = SolidState()
    reader = _BitReader(packed)
    tables = state.tables
    block_end = 0
    last_block = False

    def block_header() -> None:
        nonlocal tables, block_end, last_block
        reader.align()
        flags = reader.bits(8)
        reader.bits(8)  # header checksum
        size_bytes = ((flags >> 3) & 3) + 1
        block_size = 0
        for index in range(size_bytes):
            block_size |= reader.bits(8) << (8 * index)
        # The low three flag bits: how many bits of the block's last byte are used,
        # less one.
        block_end = reader.pos + block_size * 8 + (flags & 7) + 1 - 8
        last_block = bool(flags & 0x40)
        if flags & 0x80:
            tables = _read_tables(reader)

    block_header()
    out = 0
    last_length = state.last_length
    while out < size and not reader.ran_out:
        while reader.pos >= block_end:
            if last_block:
                return True
            block_header()
        main, offsets, low_offsets, lengths = tables
        symbol = main.symbol(reader)
        if symbol < 256:
            out += 1
        elif symbol == 256:  # a filter: two filter integers, the type, maybe channels
            for _ in range(2):
                reader.bits(8 * (reader.bits(2) + 1))
            if reader.bits(3) == 0:
                reader.bits(5)
        elif symbol == 257:
            out += last_length
        elif symbol < 262:
            last_length = _match_length(reader, lengths.symbol(reader))
            out += last_length
        else:
            length = _match_length(reader, symbol - 262)
            slot = offsets.symbol(reader)
            if slot < 4:
                distance = slot + 1
            else:
                extra = slot // 2 - 1
                if extra >= 4:
                    low = reader.bits(extra - 4) << 4 if extra > 4 else 0
                    low += low_offsets.symbol(reader)
                else:
                    low = reader.bits(extra)
                distance = ((2 + (slot & 1)) << extra) + low + 1
            length += (distance > 0x100) + (distance > 0x2000) + (distance > 0x40000)
            last_length = length
            out += length
    state.tables = tables
    state.last_length = last_length
    return reader.ran_out


def _vint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


class Entry(NamedTuple):
    """One FILE entry of a RAR5 archive."""

    packed: bytes
    method: int  # 0 is stored
    size: int  # unpacked size, as the header declares it


def members_data(archive: bytes) -> list[Entry]:
    """The FILE entries of a RAR5 archive, in archive order."""
    if not archive.startswith(b"Rar!\x1a\x07\x01\x00"):
        raise ValueError("not a RAR5 archive")
    found = []
    pos = 8
    while pos < len(archive):
        pos += 4  # header CRC32
        header_size, body = _vint(archive, pos)
        header_end = body + header_size
        header_type, body = _vint(archive, body)
        header_flags, body = _vint(archive, body)
        if header_flags & 0x01:
            _, body = _vint(archive, body)  # extra area size
        data_size = 0
        if header_flags & 0x02:
            data_size, body = _vint(archive, body)
        if header_type == 2:
            file_flags, body = _vint(archive, body)
            size, body = _vint(archive, body)
            _, body = _vint(archive, body)  # attributes
            if file_flags & 0x02:
                body += 4  # mtime
            if file_flags & 0x04:
                body += 4  # data CRC32
            compression, body = _vint(archive, body)
            method = (compression >> 7) & 7
            packed = archive[header_end : header_end + data_size]
            found.append(Entry(packed, method, size))
        pos = header_end + data_size
    return found


def _compress(rar: str, member: bytes, after: bytes | None, workdir: Path) -> bytes:
    """``f.txt`` holding ``member``; with ``after``, a solid archive with ``a.txt``
    holding ``after`` first, as ``gen_rar_fixtures.py`` builds them."""
    names = []
    extra = []
    if after is not None:
        (workdir / "a.txt").write_bytes(after)
        names.append("a.txt")
        extra.append("-s")
    (workdir / "f.txt").write_bytes(member)
    names.append("f.txt")
    archive = workdir / "probe.rar"
    archive.unlink(missing_ok=True)
    subprocess.run(
        [rar, "a", "-idq", "-ma5", "-m3", *extra, str(archive), *names],
        cwd=workdir,
        check=True,
    )
    return archive.read_bytes()


def _first_short(archive: bytes, count: int) -> int | None:
    """The index of the first member the model says a patched ``unar`` runs short
    on, or ``count`` when it says none; ``None`` when a member is stored.
    ``ValueError`` when the archive does not hold exactly ``count`` members or the
    model cannot decode the packed data: either way the model cannot judge it."""
    entries = members_data(archive)
    if len(entries) != count:
        raise ValueError(f"{len(entries)} members, not {count}")
    if any(entry.method == 0 for entry in entries):
        return None
    state = SolidState()
    for index, entry in enumerate(entries):
        if patched_unar_runs_short(entry.packed, entry.size, state):
            return index
    return count


def is_dropped(
    rar: str, member: bytes, after: bytes | None, workdir: Path
) -> bool | None:
    """``member`` is compressed by ``rar`` and, by the model, dropped by a patched
    ``unar``; with ``after``, as the second member of a solid archive whose first
    member decodes. ``None`` when the model cannot decode the packed data."""
    count = 1 if after is None else 2
    try:
        # A first member dropped already is not the member being searched for.
        return _first_short(_compress(rar, member, after, workdir), count) == count - 1
    except ValueError:
        # Data the model cannot decode: not a member it can vouch for. The search
        # counts it and moves on instead of stopping.
        return None


def _candidates(alphabet: bytes, length: int) -> Iterator[bytes]:
    for letters in itertools.product(alphabet, repeat=length):
        yield bytes(letters)


def _first_dropped(
    args: tuple[str, bytes | None, list[bytes]],
) -> tuple[bytes | None, int]:
    """The first dropped member of a chunk, and how many before it the model could
    not decode."""
    rar, after, members = args
    unmodelled = 0
    with tempfile.TemporaryDirectory() as td:
        for member in members:
            dropped = is_dropped(rar, member, after, Path(td))
            if dropped is None:
                unmodelled += 1
            elif dropped:
                return member, unmodelled
    return None, unmodelled


def find(
    rar: str, alphabet: bytes, after: bytes | None, max_length: int, jobs: int
) -> tuple[bytes | None, int]:
    """The first dropped member, by length then lexicographically, or ``None``; and
    how many candidates before it the model could not decode."""
    unmodelled = 0
    with ProcessPoolExecutor(jobs) as pool:
        for length in range(1, max_length + 1):
            members = list(_candidates(alphabet, length))
            chunk = max(1, len(members) // (jobs * 8))
            chunks = [members[i : i + chunk] for i in range(0, len(members), chunk)]
            # ``map`` keeps the chunks in order, so the first hit is the first member.
            for hit, skipped in pool.map(
                _first_dropped, [(rar, after, c) for c in chunks]
            ):
                unmodelled += skipped
                if hit is not None:
                    return hit, unmodelled
    return None, unmodelled


def _unar_output(
    unar: str, archive: bytes, index: int, workdir: Path
) -> tuple[bytes, int]:
    """What ``unar`` writes for the member at ``index`` of ``archive``, and its exit
    status."""
    path = workdir / "archive.rar"
    path.write_bytes(archive)
    proc = subprocess.run(
        [unar, "-o", "-", "-q", "-i", "--", str(path), str(index)],
        capture_output=True,
        check=False,
    )
    return proc.stdout, proc.returncode


def _validation_cases(count: int) -> Iterator[tuple[bytes, bytes | None]]:
    """``count`` lone members, then ``count`` solid pairs, the same on every run."""
    rnd = random.Random(0)
    words = [b"alpha", b"beta", b"gamma", b"delta", b"el", b"lea", b"tag", b"ma", b"da"]
    for index in range(count):
        kind = index % 3
        if kind == 0:
            yield b" ".join(rnd.choice(words) for _ in range(rnd.randint(4, 40))), None
        elif kind == 1:
            yield (
                bytes(rnd.choice(b"abc \nxyz") for _ in range(rnd.randint(20, 300))),
                None,
            )
        else:
            noise = bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 50)))
            yield noise + b"x" * rnd.randint(10, 100), None
    for _ in range(count):
        first = bytes(rnd.choice(b"abcde \n") for _ in range(rnd.randint(3, 60)))
        second = bytes(rnd.choice(b"abxy \n") for _ in range(rnd.randint(5, 60)))
        yield second, first


def validate(rar: str, unar: str, count: int) -> int:
    """Compare the model with ``unar`` on generated archives; non-zero on a failure.

    A failure is a case that disagrees, that ``unar`` exits non-zero on, or that the
    model cannot judge, and a run that compares nothing: it has shown no agreement.

    ``unar`` agrees with "dropped" only with the patch's signature, nothing written and
    exit 0, as ``--check-unar`` and ``unar_rar5_probe_failure`` read it; a case with a
    non-zero exit is neither an agreement nor a disagreement. A solid pair whose first
    member the model says runs short is decided by that member (``unar`` never reaches
    the second): it is scored as an agreement or a disagreement like any other, and
    the agreements among them are also tallied on their own.
    """
    agree = disagree = stored = failed = by_first = unjudged = 0
    with tempfile.TemporaryDirectory() as td:
        for member, after in _validation_cases(count):
            # One archive for both verdicts, so they judge the same bytes.
            archive = _compress(rar, member, after, Path(td))
            members = 1 if after is None else 2
            try:
                first = _first_short(archive, members)
            except ValueError as exc:
                unjudged += 1
                print(f"model cannot judge ({exc}): member={member!r} after={after!r}")
                continue
            if first is None:
                stored += 1
                continue
            predicted = first < members
            out, status = _unar_output(unar, archive, members - 1, Path(td))
            if status != 0:
                failed += 1
                print(f"{unar} exited {status}: member={member!r} after={after!r}")
                continue
            if predicted == (out != member):
                agree += 1
                if first < members - 1:
                    by_first += 1
                continue
            disagree += 1
            print(
                f"disagree: model says {'dropped' if predicted else 'decoded'}, "
                f"{unar} wrote {len(out)} of {len(member)} bytes: "
                f"member={member!r} after={after!r}"
            )
    print(
        f"{agree} agree ({by_first} of them solid pairs decided by the first member), "
        f"{disagree} disagree, {failed} with a non-zero exit, "
        f"{unjudged} the model cannot judge, {stored} skipped as stored"
    )
    if agree + disagree == 0:
        # Nothing was compared, so nothing was shown to agree.
        print("no case was compared with unar", file=sys.stderr)
        return 1
    return disagree + failed + unjudged


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--rar", default="rar", help="RARLAB rar binary")
    parser.add_argument("--alphabet", default="ab", help="bytes to build members from")
    parser.add_argument(
        "--after",
        help="search for the second member of a solid archive whose first is this text",
    )
    parser.add_argument("--max-length", type=int, default=16)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument(
        "--check-unar",
        metavar="UNAR",
        help="a patched unar: run it on the result, which must come out empty "
        "with exit 0; with --validate, the unar to compare the model with",
    )
    parser.add_argument(
        "--validate",
        type=int,
        metavar="N",
        help="instead of searching, compare the model with --check-unar on N "
        "generated members and N solid pairs; exit 1 on any disagreement or "
        "non-zero exit",
    )
    args = parser.parse_args(argv)
    rar = shutil.which(args.rar)
    if rar is None:
        print(f"{args.rar}: not found", file=sys.stderr)
        return 2
    if args.validate is not None:
        if not args.check_unar:
            print("--validate needs --check-unar", file=sys.stderr)
            return 2
        return 1 if validate(rar, args.check_unar, args.validate) else 0
    alphabet = bytes(sorted(set(args.alphabet.encode("latin-1"))))
    after = None if args.after is None else args.after.encode("latin-1")
    member, unmodelled = find(rar, alphabet, after, args.max_length, args.jobs)
    if unmodelled:
        # Each is a candidate the answer might have been: the model needs work.
        print(
            f"warning: the model could not decode {unmodelled} compressed candidates",
            file=sys.stderr,
        )
    if member is None:
        print(f"no member up to {args.max_length} bytes", file=sys.stderr)
        return 1
    print(f"{len(member)} bytes: {member!r}")
    if args.check_unar:
        with tempfile.TemporaryDirectory() as td:
            archive = _compress(rar, member, after, Path(td))
            index = 0 if after is None else 1
            out, status = _unar_output(args.check_unar, archive, index, Path(td))
        print(f"{args.check_unar} wrote {len(out)} bytes, exit status {status}")
        # The patch's signature, as ``unar_rar5_probe_failure`` matches it.
        if out or status != 0:
            print("not the patched unar's signature (nothing, exit 0)", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
