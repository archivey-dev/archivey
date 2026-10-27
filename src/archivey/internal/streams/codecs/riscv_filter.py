"""RISC-V branch-conversion filter decoder: 7z method ``0x0B``, liblzma filter ``0x0B``.

7-Zip 24 added this filter and writes it on request (``-m0=RISCV``, ``-mf=RISCV``);
7-Zip 26.05 did not pick it by itself for a Go ``riscv64`` executable, and whether any
input makes it do so is untested here. Python's ``lzma`` refuses filter id 11 in a raw
chain, as it refuses ARM64, and ``pybcj`` has no RISC-V filter, so this module decodes
it in Python. liblzma 5.6 and later decode an ``.xz`` stream with the filter inside
their own stream decoder; an older liblzma refuses it there.

The algorithm is liblzma's ``riscv_decode`` (``src/liblzma/simple/riscv.c``, xz 5.6).
7-Zip's ``z7_BranchConv_RISCV_Dec`` (``C/Bra.c``) produces the same bytes; the tests
check that against archives 7-Zip 26.05 writes. Instructions are 2-byte aligned (the
C extension), so every even offset from the start of the stream is examined:

- **JAL** with ``rd`` = ``x1`` or ``x5`` (first byte ``0xEF``, second byte with bits
  0, 2 and 3 clear): the encoder stored the absolute target, its bits in a plain
  order. Decoding subtracts the instruction's ``pc`` and scatters the 21-bit offset
  back into the J-type immediate. The next examined offset is 4 bytes on.
- **AUIPC** (low 7 bits ``0x17``) with ``rd`` not ``x0`` or ``x2``, followed by an
  instruction that uses ``rd`` as its base register and a 12-bit immediate: the
  encoder turned the pair into a "fake" AUIPC with ``rd`` = ``x2`` and stored the
  absolute address big-endian in the second word. The test of the second word is
  liblzma's ``NOT_AUIPC_PAIR``; when it fails the next examined offset is 6 bytes on.
- **AUIPC** with ``rd`` = ``x2``: either such an encoded pair, which decoding turns
  back into the real pair (``NOT_SPECIAL_AUIPC`` picks these out), or a real
  ``x2`` / ``x0`` AUIPC pair the encoder rewrote into the fake form, which decoding
  restores. A converted pair moves the next examined offset 8 bytes on.

``pc`` is the 32-bit position of the instruction: the coder's start offset (7z coder
properties, a multiple of 2) plus the instruction's offset in the stream, wrapping at
2**32. A converted instruction may need up to 8 bytes, so the last 7 bytes of a buffer
are only examined once more input arrives; at the end of the stream they are passed
through unchanged, as liblzma and 7-Zip do.

Where the time goes. As in ``arm64_filter``, the Python loop runs once per
*candidate*, not per halfword: the byte at every even offset is copied out with one
stride slice and translated to ``0x01`` for a possible JAL or AUIPC, and
``bytes.find`` walks the candidates at memchr speed.
"""

from __future__ import annotations

# liblzma's LZMA_FILTER_RISCV and the 7z method id are the same number.
FILTER_RISCV = 0x0B

_M32 = 0xFFFFFFFF
# 0x01 for a first byte that may start a converted instruction: 0xEF (JAL) or one
# whose low 7 bits are 0x17 (AUIPC).
_CANDIDATES = bytes(1 if b == 0xEF or (b & 0x7F) == 0x17 else 0 for b in range(256))


def riscv_decode(data: bytes, pc: int) -> bytes:
    """Decode what can be decoded of ``data``; ``pc`` is ``data[0]``'s position.

    ``pc`` must be a multiple of 2 (the planner refuses any other start offset). The
    result is a prefix of the decoded stream, as long as liblzma's ``riscv_decode``
    says is final: every byte up to the first even offset it did not examine, which
    leaves 0 to 7 bytes of ``data`` (all of it under 8 bytes). The caller keeps those
    bytes for the next call, or passes them through at the end of the stream.
    """
    if len(data) < 8:
        return b""
    last = len(data) - 8  # the last offset an instruction may start at
    marks = data[0 : last + 1 : 2].translate(_CANDIDATES)
    k = marks.find(1)
    if k < 0:
        return data[: (last // 2 + 1) * 2]
    buf = bytearray(data)
    find = marks.find
    resume = 0  # the next offset liblzma would examine
    while k >= 0:
        i = k << 1
        first = buf[i]
        if first == 0xEF:
            # JAL: only rd = x1 (ra) and rd = x5 (t0) were converted.
            b1 = buf[i + 1]
            if b1 & 0x0D:
                k = find(1, k + 1)
                continue
            addr = (
                (((b1 & 0xF0) << 13) | (buf[i + 2] << 9) | (buf[i + 3] << 1)) - pc - i
            )
            addr &= _M32
            buf[i + 1] = (b1 & 0x0F) | ((addr >> 8) & 0xF0)
            buf[i + 2] = (
                ((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)
            )
            buf[i + 3] = ((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)
            resume = i + 4
        else:
            inst = int.from_bytes(buf[i : i + 4], "little")
            if inst & 0xE80:
                # AUIPC whose rd is not x0 or x2: a pair the encoder left as it was
                # unless the next word uses rd with a 12-bit immediate.
                inst2 = int.from_bytes(buf[i + 4 : i + 8], "little")
                if ((inst << 8) ^ (inst2 - 3)) & 0xF8003:
                    resume = i + 6
                    k = find(1, resume >> 1)
                    continue
                # A real pair the encoder rewrote into the fake (x2) form: restore it.
                addr = ((inst & 0xFFFFF000) + (inst2 >> 20)) & _M32
                inst = 0x17 | (2 << 7) | ((inst2 << 12) & _M32)
                inst2 = addr
            else:
                # AUIPC with rd x0 or x2: an encoded pair when it has the encoder's
                # special form (liblzma's NOT_SPECIAL_AUIPC, negated).
                rs1 = inst >> 27
                if (((inst - 0x3117) << 18) & _M32) >= (rs1 & 0x1D):
                    resume = i + 4
                    k = find(1, resume >> 1)
                    continue
                addr = (int.from_bytes(buf[i + 4 : i + 8], "big") - (pc + i)) & _M32
                inst2 = ((inst >> 12) | (addr << 20)) & _M32
                inst = 0x17 | (rs1 << 7) | ((addr + 0x800) & 0xFFFFF000)
            buf[i : i + 4] = inst.to_bytes(4, "little")
            buf[i + 4 : i + 8] = inst2.to_bytes(4, "little")
            resume = i + 8
        k = find(1, resume >> 1)
    return bytes(buf[: max(resume, (last // 2 + 1) * 2)])
