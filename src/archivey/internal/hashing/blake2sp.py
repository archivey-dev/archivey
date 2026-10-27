"""RAR5 BLAKE2sp hasher on stdlib blake2s (zero-dependency)."""

from __future__ import annotations

import hashlib

PARALLELISM_DEGREE = 8
DIGEST_SIZE = 32
_BLOCK_SIZE = 64  # BLAKE2S_BLOCKBYTES
_BUF_SIZE = PARALLELISM_DEGREE * _BLOCK_SIZE  # 512


class Blake2sp:
    """Incremental BLAKE2sp hasher with a ``hashlib``-shaped interface."""

    digest_size = DIGEST_SIZE

    def __init__(self) -> None:
        self._leaves = [
            hashlib.blake2s(
                digest_size=DIGEST_SIZE,
                fanout=PARALLELISM_DEGREE,
                depth=2,
                leaf_size=0,
                node_offset=i,
                node_depth=0,
                inner_size=DIGEST_SIZE,
                last_node=(i == PARALLELISM_DEGREE - 1),
            )
            for i in range(PARALLELISM_DEGREE)
        ]
        self._buf = bytearray()
        self._finalized = False
        self._digest: bytes | None = None

    def update(self, data: bytes, /) -> None:
        if self._finalized:
            raise ValueError("cannot update() a finalized Blake2sp hasher")
        if not data:
            return
        # Fill residual buffer to a full PARALLELISM*BLOCK stride, then process.
        if self._buf:
            need = _BUF_SIZE - len(self._buf)
            if len(data) < need:
                self._buf.extend(data)
                return
            self._buf.extend(data[:need])
            self._process_full_buffer(self._buf)
            self._buf.clear()
            data = data[need:]
        while len(data) >= _BUF_SIZE:
            self._process_full_buffer(data[:_BUF_SIZE])
            data = data[_BUF_SIZE:]
        if data:
            self._buf.extend(data)

    def _process_full_buffer(self, buf: bytes | bytearray) -> None:
        for i in range(PARALLELISM_DEGREE):
            start = i * _BLOCK_SIZE
            self._leaves[i].update(buf[start : start + _BLOCK_SIZE])

    def digest(self) -> bytes:
        if self._digest is not None:
            return self._digest
        self._finalized = True
        # Distribute the residual buffer across leaves (ref blake2sp_final layout).
        for i in range(PARALLELISM_DEGREE):
            start = i * _BLOCK_SIZE
            if len(self._buf) > start:
                left = len(self._buf) - start
                left = min(left, _BLOCK_SIZE)
                self._leaves[i].update(self._buf[start : start + left])
        root = hashlib.blake2s(
            digest_size=DIGEST_SIZE,
            fanout=PARALLELISM_DEGREE,
            depth=2,
            leaf_size=0,
            node_offset=0,
            node_depth=1,
            inner_size=DIGEST_SIZE,
            last_node=True,
        )
        for leaf in self._leaves:
            root.update(leaf.digest())
        self._digest = root.digest()
        return self._digest


def blake2sp(data: bytes = b"") -> bytes:
    """One-shot BLAKE2sp digest of ``data``."""
    h = Blake2sp()
    h.update(data)
    return h.digest()
