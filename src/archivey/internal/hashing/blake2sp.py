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

    def update(self, data: bytes | bytearray | memoryview, /) -> None:
        if self._finalized:
            raise ValueError("cannot update() a finalized Blake2sp hasher")
        if not data:
            return
        # Walk a view by offset: slicing ``data`` would copy the rest of it at every
        # stride, so one large update() would be quadratic in its size. The cast makes
        # the offsets count bytes for any buffer, whatever its item size. Every view is
        # released before returning, so the caller can resize its buffer at once (on
        # PyPy a dropped view lives until the next collection).
        with memoryview(data) as raw, raw.cast("B") as view:
            self._absorb(view)

    def _absorb(self, view: memoryview) -> None:
        pos = 0
        end = len(view)
        # Fill residual buffer to a full PARALLELISM*BLOCK stride, then process.
        if self._buf:
            need = _BUF_SIZE - len(self._buf)
            if end < need:
                self._buf.extend(view)
                return
            with view[:need] as head:
                self._buf.extend(head)
            with memoryview(self._buf) as full:
                self._process_full_buffer(full)
            self._buf.clear()
            pos = need
        while end - pos >= _BUF_SIZE:
            with view[pos : pos + _BUF_SIZE] as stride:
                self._process_full_buffer(stride)
            pos += _BUF_SIZE
        if pos < end:
            with view[pos:] as tail:
                self._buf.extend(tail)

    def _process_full_buffer(self, buf: memoryview) -> None:
        for i in range(PARALLELISM_DEGREE):
            start = i * _BLOCK_SIZE
            with buf[start : start + _BLOCK_SIZE] as block:
                self._leaves[i].update(block)

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
