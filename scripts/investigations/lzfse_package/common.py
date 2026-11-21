"""Shared helpers for the `lzfse` package evaluation (DMG plan, Part A0).

Run every script with an interpreter that has the `lzfse` package installed. The
prototype decoder is imported from the DMG change's resources, so the comparison is
against the code Part A ports.
"""

from __future__ import annotations

import os
import struct
import sys

ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
PROTOTYPE = os.path.join(
    ROOT, "openspec", "changes", "dmg-reader", "resources", "prototype"
)
FIXTURES = os.path.join(
    ROOT, "openspec", "changes", "dmg-reader", "resources", "fixtures"
)
if not os.path.isdir(PROTOTYPE):  # after the change is archived
    PROTOTYPE = os.path.join(ROOT, "openspec", "changes", "archive")
sys.path.insert(0, PROTOTYPE)

from dmgproto import lzfse as proto  # noqa: E402

ENDOFSTREAM = b"bvx$"
UNCOMPRESSED = b"bvx-"
V1 = b"bvx1"
V2 = b"bvx2"
LZVN = b"bvxn"
# sizeof(lzfse_compressed_block_header_v1): 770 bytes of fields, padded to 4-byte alignment
V1_HEADER = 772


class BadStream(ValueError):
    """The block walk refused the stream before any decoder ran."""


def walk_blocks(
    src: bytes, *, strict: bool = False
) -> tuple[int, list[tuple[bytes, int, int]]]:
    """Walk the block headers of an LZFSE stream without decoding anything.

    Returns the sum of the declared raw sizes and the blocks as (magic, n_raw, block
    length). Every header field that sets a length is checked against the input, so a
    caller can compare the declared total with its own limit before any native call.
    With ``strict``, a bvx2 header must also pass the prototype's own header checks
    (counts within the block limits, a literal count that is a multiple of 4, initial
    states in range), which Apple's decoder checks only in part.
    """
    pos = 0
    total = 0
    blocks: list[tuple[bytes, int, int]] = []
    while True:
        if pos + 4 > len(src):
            raise BadStream("no end-of-stream block")
        magic = bytes(src[pos : pos + 4])
        if magic == ENDOFSTREAM:
            return total, blocks
        if magic == UNCOMPRESSED:
            if pos + 8 > len(src):
                raise BadStream("truncated bvx- header")
            (n_raw,) = struct.unpack_from("<I", src, pos + 4)
            length = 8 + n_raw
        elif magic == LZVN:
            if pos + 12 > len(src):
                raise BadStream("truncated bvxn header")
            n_raw, n_payload = struct.unpack_from("<II", src, pos + 4)
            length = 12 + n_payload
        elif magic == V1:
            if pos + V1_HEADER > len(src):
                raise BadStream("truncated bvx1 header")
            n_raw, _n_payload, _nl, _nm, n_lit_payload, n_lmd_payload = (
                struct.unpack_from("<6I", src, pos + 4)
            )
            length = V1_HEADER + n_lit_payload + n_lmd_payload
        elif magic == V2:
            if pos + 32 > len(src):
                raise BadStream("truncated bvx2 header")
            n_raw, p0, p1, p2 = struct.unpack_from("<IQQQ", src, pos + 4)
            n_lit_payload = (p0 >> 20) & 0xFFFFF
            n_lmd_payload = (p1 >> 40) & 0xFFFFF
            header_size = p2 & 0xFFFFFFFF
            if header_size < 32:
                raise BadStream("bvx2 header size under 32")
            if strict:
                n_literals = p0 & 0xFFFFF
                n_matches = (p0 >> 40) & 0xFFFFF
                lit_states = [(p1 >> (10 * i)) & 0x3FF for i in range(4)]
                l_state, m_state, d_state = (
                    (p2 >> 32) & 0x3FF,
                    (p2 >> 42) & 0x3FF,
                    (p2 >> 52) & 0x3FF,
                )
                if n_literals > 40000 or n_literals % 4 or n_matches > 10000:
                    raise BadStream("bvx2 block counts out of range")
                if (
                    max(lit_states) >= 1024
                    or l_state >= 64
                    or m_state >= 64
                    or d_state >= 256
                ):
                    raise BadStream("bvx2 initial state out of range")
            length = header_size + n_lit_payload + n_lmd_payload
        else:
            raise BadStream(f"unknown block magic {magic!r}")
        if pos + length > len(src):
            raise BadStream(f"{magic.decode()} block runs past the input")
        total += n_raw
        blocks.append((magic, n_raw, length))
        pos += length


def binding_capped(module, src: bytes, limit: int) -> bytes:
    """What a capped call through the binding has to look like: walk first, then call."""
    total, _ = walk_blocks(src)
    if total > limit:
        raise BadStream(f"declared {total} bytes, over the {limit}-byte limit")
    if total == 0:
        return b""  # the binding raises on any stream that decodes to nothing
    out = module.decompress(src)
    # The walk does not bound a bvx2 block's output: the fuzz reached this 1,078 times.
    # It stays AssertionError so that results/fuzz.json keeps its keys.
    if len(out) > limit:
        raise AssertionError("binding returned more than the limit")
    return out


def binding_checked(module, src: bytes, limit: int) -> bytes:
    """The strictest call the binding allows: strict walk, then the output length must
    be the declared total (Apple's decoder does not hold a bvx2 block to its n_raw)."""
    total, _ = walk_blocks(src, strict=True)
    if total > limit:
        raise BadStream(f"declared {total} bytes, over the {limit}-byte limit")
    if total == 0:
        return b""
    out = module.decompress(src)
    if len(out) != total:
        raise BadStream(f"decoded {len(out)} bytes, the blocks declare {total}")
    return out


def wrap_lzvn(payload: bytes, n_raw: int) -> bytes:
    """A raw LZVN payload (decmpfs types 7 and 8) as a one-block LZFSE stream."""
    return LZVN + struct.pack("<II", n_raw, len(payload)) + payload + ENDOFSTREAM


def proto_decode(src: bytes, limit: int) -> bytes:
    return proto.decompress(src, limit)


def set_memory_limit(nbytes: int) -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (nbytes, nbytes))
